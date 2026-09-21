// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Draft-03 section 3.5.1 direct revocation of an AuthorityDelegationV1: issuance under a
// caller-supplied `now`, the issuer-only authorization rule of section 3.5, independent
// recomputation of the identifier and the cascade transaction identity, the store's
// first-wins rule, the resolver's three answers, and what a revoked ancestor does to
// chain verification.
//
// Every record in this file is minted by the module under test. No digest, identifier or
// signature is written down by hand.

import test from 'node:test'
import assert from 'node:assert/strict'
import { publicKeyFromPrivate } from '../../src/crypto/keys.js'
import {
  AUTHORITY_DELEGATION_RECORD_TYPE,
  AUTHORITY_DELEGATION_VERSION,
  REPUTATION_PROFILE_V1,
  REVERSIBILITY_PROFILE_V1,
  SCOPE_PROFILE_V1,
  VALUES_PROFILE_V1,
  issueAuthorityDelegation,
  issueSubAuthorityDelegation,
  verifyAuthorityDelegationChain,
} from '../../src/v2/authority-delegation/index.js'
import type {
  AuthorityChainVerificationOptions,
  AuthorityDelegationBodyV1,
  AuthorityDelegationV1,
} from '../../src/v2/authority-delegation/index.js'
import {
  AUTHORITY_REVOCATION_ID_DOMAIN,
  AUTHORITY_REVOCATION_CASCADE_TRANSACTION_DOMAIN,
  AUTHORITY_REVOCATION_RECORD_TYPE,
  AUTHORITY_REVOCATION_VERSION,
  InMemoryAuthorityRevocationStore,
  authorityRevocationBody,
  authorityRevocationCascadeOrigin,
  computeAuthorityRevocationCascadeTransactionId,
  computeAuthorityRevocationId,
  createAuthorityRevocationResolver,
  issueAuthorityRevocation,
  signAuthorityRevocation,
  verifyAuthorityRevocation,
} from '../../src/v2/authority-revocation/index.js'
import type { AuthorityRevocationV1 } from '../../src/v2/authority-revocation/index.js'
import { canonicalizeJCS } from '../../src/core/canonical-jcs.js'
import { createHash } from 'node:crypto'

const ROOT_KEY = '11'.repeat(32)
const CHILD_KEY = '22'.repeat(32)
const IMPOSTOR_KEY = '33'.repeat(32)

const ROOT_ISSUER = 'did:example:root'
const ROOT_SUBJECT = 'did:example:agent-a'
const CHILD_SUBJECT = 'did:example:agent-b'
const IMPOSTOR = 'did:example:impostor'

const ROOT_VM = `${ROOT_ISSUER}#key-1`
const CHILD_VM = `${ROOT_SUBJECT}#key-1`
const IMPOSTOR_VM = `${IMPOSTOR}#key-1`

const publicKeys = new Map([
  [ROOT_VM, publicKeyFromPrivate(ROOT_KEY)],
  [CHILD_VM, publicKeyFromPrivate(CHILD_KEY)],
  [IMPOSTOR_VM, publicKeyFromPrivate(IMPOSTOR_KEY)],
])

function resolveVerificationKey(_controller: string, method: string): string | null {
  return publicKeys.get(method) ?? null
}

const NOW = '2026-07-18T22:10:00.000Z'
const REVOKED_AT = '2026-07-18T22:20:00.000Z'
const NONCE = 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf'

function rootBody(): AuthorityDelegationBodyV1 {
  return {
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: null,
    issuer: ROOT_ISSUER,
    subject: ROOT_SUBJECT,
    verification_method: ROOT_VM,
    issued_at: '2026-07-18T22:00:00.000Z',
    nonce: '00112233445566778899aabbccddeeff',
    authority: {
      scope: { profile: SCOPE_PROFILE_V1, grants: ['commerce:*'] },
      spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '100', cumulative: '100' },
      depth: { remaining: 3 },
      time: { not_before: '2026-07-18T22:00:00.000Z', not_after: '2026-07-18T23:00:00.000Z' },
      reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 80 },
      values: { profile: VALUES_PROFILE_V1, required: ['F-001', 'F-003'] },
      reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'compensable' },
    },
  }
}

function childBody(parent: AuthorityDelegationV1): AuthorityDelegationBodyV1 {
  return {
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: parent.delegation_id,
    issuer: ROOT_SUBJECT,
    subject: CHILD_SUBJECT,
    verification_method: CHILD_VM,
    issued_at: '2026-07-18T22:05:00.000Z',
    nonce: 'ffeeddccbbaa99887766554433221100',
    authority: {
      scope: { profile: SCOPE_PROFILE_V1, grants: ['commerce:checkout'] },
      spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '80', cumulative: '80' },
      depth: { remaining: 2 },
      time: { not_before: '2026-07-18T22:05:00.000Z', not_after: '2026-07-18T22:55:00.000Z' },
      reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 70 },
      values: { profile: VALUES_PROFILE_V1, required: ['F-001', 'F-003', 'F-004'] },
      reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'tentative' },
    },
  }
}

function root(): AuthorityDelegationV1 {
  return issueAuthorityDelegation(rootBody(), ROOT_KEY)
}

function child(parent: AuthorityDelegationV1): AuthorityDelegationV1 {
  return issueSubAuthorityDelegation(parent, childBody(parent), CHILD_KEY, {
    now: NOW,
    resolveVerificationKey,
    resolveRevocation: () => 'active',
  })
}

/** A direct revocation of `delegation` signed by its own issuer. */
function revokeByIssuer(
  delegation: AuthorityDelegationV1,
  overrides: { revoked_at?: string; nonce?: string; detail?: string } = {},
): AuthorityRevocationV1 {
  return issueAuthorityRevocation(
    delegation,
    {
      now: overrides.revoked_at ?? REVOKED_AT,
      revoker: ROOT_ISSUER,
      verification_method: ROOT_VM,
      reason_code: 'key_compromise',
      ...(overrides.detail === undefined ? {} : { detail: overrides.detail }),
      nonce: overrides.nonce ?? NONCE,
    },
    ROOT_KEY,
  )
}

const verifyOptions = { resolveVerificationKey }

test('issues and verifies a direct revocation of the delegation its issuer signed', () => {
  const delegation = root()
  const revocation = revokeByIssuer(delegation)

  assert.equal(revocation.record_type, 'aps:authority-revocation:v1')
  assert.equal(revocation.delegation_id, delegation.delegation_id)
  assert.equal(revocation.revoker, delegation.issuer)
  assert.equal(revocation.revoked_at, REVOKED_AT)
  assert.equal(revocation.reason_code, 'key_compromise')
  assert.ok(!Object.prototype.hasOwnProperty.call(revocation, 'detail'))

  const result = verifyAuthorityRevocation(revocation, delegation, verifyOptions)
  assert.equal(result.state, 'valid')
  assert.equal(result.valid, true)
  assert.deepEqual(result.failures, [])
})

test('optional detail rides inside the signed content when supplied', () => {
  const delegation = root()
  const revocation = revokeByIssuer(delegation, { detail: 'reported by the operator' })
  assert.equal(revocation.detail, 'reported by the operator')
  assert.equal(verifyAuthorityRevocation(revocation, delegation, verifyOptions).state, 'valid')

  // Removing it changes the body, so the identifier no longer recomputes.
  const { detail: _detail, ...withoutDetail } = revocation
  assert.equal(
    verifyAuthorityRevocation(withoutDetail, delegation, verifyOptions).failures[0].code,
    'CASCADE_TRANSACTION_MISMATCH',
  )
})

test('revocation_id recomputes independently from the domain tag and JCS of the body', () => {
  const delegation = root()
  const revocation = revokeByIssuer(delegation)
  const body = authorityRevocationBody(revocation)

  // Rebuilt here from the published tag and the canonicalizer, not by calling the
  // module's own compute helper, so the construction is checked rather than echoed.
  const digest = createHash('sha256')
    .update(AUTHORITY_REVOCATION_ID_DOMAIN + canonicalizeJCS(body), 'utf8')
    .digest('hex')
  assert.equal(revocation.revocation_id, `sha256:${digest}`)
  assert.equal(computeAuthorityRevocationId(body), revocation.revocation_id)
})

test('cascade_transaction_id recomputes independently from its own domain tag', () => {
  const delegation = root()
  const revocation = revokeByIssuer(delegation)
  const origin = authorityRevocationCascadeOrigin(authorityRevocationBody(revocation))

  const digest = createHash('sha256')
    .update(AUTHORITY_REVOCATION_CASCADE_TRANSACTION_DOMAIN + canonicalizeJCS(origin), 'utf8')
    .digest('hex')
  assert.equal(revocation.cascade_transaction_id, `sha256:${digest}`)
  assert.equal(computeAuthorityRevocationCascadeTransactionId(origin), revocation.cascade_transaction_id)
  assert.notEqual(revocation.cascade_transaction_id, revocation.revocation_id)
})

test('issuance with the same inputs is byte deterministic', () => {
  const delegation = root()
  const first = revokeByIssuer(delegation)
  const second = revokeByIssuer(delegation)
  assert.equal(canonicalizeJCS(first), canonicalizeJCS(second))
  assert.equal(first.signature, second.signature)
  assert.equal(first.revocation_id, second.revocation_id)

  // A different nonce is a different record and a different cascade.
  const third = revokeByIssuer(delegation, { nonce: 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' })
  assert.notEqual(third.revocation_id, first.revocation_id)
  assert.notEqual(third.cascade_transaction_id, first.cascade_transaction_id)
})

test('a revoker who is not the target delegation issuer is refused at issuance', () => {
  const delegation = root()
  assert.throws(
    () => issueAuthorityRevocation(
      delegation,
      {
        now: REVOKED_AT,
        revoker: IMPOSTOR,
        verification_method: IMPOSTOR_VM,
        reason_code: 'key_compromise',
        nonce: NONCE,
      },
      IMPOSTOR_KEY,
    ),
    /REVOKER_NOT_ISSUER/,
  )
})

test('a record naming the issuer but signed by another key does not verify', () => {
  const delegation = root()
  // The claimed revoker and verification_method are the issuer's; only the signing key
  // is somebody else's. The resolver answers under the TARGET delegation's issuer, so
  // the impostor's signature is checked against the issuer's public key and fails.
  const forged = issueAuthorityRevocation(
    delegation,
    {
      now: REVOKED_AT,
      revoker: ROOT_ISSUER,
      verification_method: ROOT_VM,
      reason_code: 'key_compromise',
      nonce: NONCE,
    },
    IMPOSTOR_KEY,
  )
  const result = verifyAuthorityRevocation(forged, delegation, verifyOptions)
  assert.equal(result.state, 'invalid')
  assert.equal(result.failures[0].code, 'SIGNATURE_INVALID')
})

test('a self-consistent record signed by a non-issuer is rejected by the verifier', () => {
  const delegation = root()
  // Minted outside issueAuthorityRevocation, which would refuse it, so the verifier's own
  // issuer check is what has to catch it. Every digest and the signature come from the
  // module's published helpers; nothing here is written down by hand.
  const origin = {
    record_type: AUTHORITY_REVOCATION_RECORD_TYPE,
    version: AUTHORITY_REVOCATION_VERSION,
    delegation_id: delegation.delegation_id,
    revoker: IMPOSTOR,
    verification_method: IMPOSTOR_VM,
    revoked_at: REVOKED_AT,
    reason_code: 'key_compromise',
    nonce: NONCE,
  } as const
  const body = {
    ...origin,
    cascade_transaction_id: computeAuthorityRevocationCascadeTransactionId(origin),
  }
  const unsigned = { ...body, revocation_id: computeAuthorityRevocationId(body) }
  const forged: AuthorityRevocationV1 = {
    ...unsigned,
    signature: signAuthorityRevocation(unsigned, IMPOSTOR_KEY),
  }

  const result = verifyAuthorityRevocation(forged, delegation, verifyOptions)
  assert.equal(result.state, 'invalid')
  assert.equal(result.failures[0].code, 'REVOKER_NOT_ISSUER')

  // And it can never become a 'revoked' answer, even sitting inside a store.
  const store = new InMemoryAuthorityRevocationStore()
  store.put(forged)
  assert.equal(createAuthorityRevocationResolver(store, verifyOptions)(delegation), 'unknown')
})

test('a valid revocation of one delegation does not verify against another', () => {
  const parent = root()
  const descendant = child(parent)
  const revocation = revokeByIssuer(parent)
  const result = verifyAuthorityRevocation(revocation, descendant, verifyOptions)
  assert.equal(result.state, 'invalid')
  assert.equal(result.failures[0].code, 'TARGET_MISMATCH')
})

test('a tampered field breaks the identifier or the signature', () => {
  const delegation = root()
  const revocation = revokeByIssuer(delegation)

  // reason_code is inside the cascade origin, the identifier body and the signature, so
  // the first recomputation already fails.
  assert.equal(
    verifyAuthorityRevocation({ ...revocation, reason_code: 'operator_request' }, delegation, verifyOptions)
      .failures[0].code,
    'CASCADE_TRANSACTION_MISMATCH',
  )
  // revoked_at, likewise.
  assert.equal(
    verifyAuthorityRevocation({ ...revocation, revoked_at: '2026-07-18T22:30:00.000Z' }, delegation, verifyOptions)
      .failures[0].code,
    'CASCADE_TRANSACTION_MISMATCH',
  )
  // cascade_transaction_id alone: it is not part of its own preimage, so the mismatch is
  // reported against the value the record carries.
  const otherTransaction = revokeByIssuer(delegation, { nonce: 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf' })
  assert.equal(
    verifyAuthorityRevocation(
      { ...revocation, cascade_transaction_id: otherTransaction.cascade_transaction_id },
      delegation,
      verifyOptions,
    ).failures[0].code,
    'CASCADE_TRANSACTION_MISMATCH',
  )
  // revocation_id alone: outside its own preimage, inside the signature's.
  assert.equal(
    verifyAuthorityRevocation(
      { ...revocation, revocation_id: otherTransaction.revocation_id },
      delegation,
      verifyOptions,
    ).failures[0].code,
    'ID_MISMATCH',
  )
  // The signature is the only member inside neither preimage.
  assert.equal(
    verifyAuthorityRevocation(
      { ...revocation, signature: otherTransaction.signature },
      delegation,
      verifyOptions,
    ).failures[0].code,
    'SIGNATURE_INVALID',
  )
})

test('verification fails closed on an unusable resolver', () => {
  const delegation = root()
  const revocation = revokeByIssuer(delegation)

  assert.equal(
    verifyAuthorityRevocation(revocation, delegation, { resolveVerificationKey: () => null }).state,
    'indeterminate',
  )
  assert.equal(
    verifyAuthorityRevocation(revocation, delegation, {
      resolveVerificationKey: () => { throw new Error('offline') },
    }).state,
    'indeterminate',
  )
  assert.equal(
    verifyAuthorityRevocation(revocation, delegation, {
      resolveVerificationKey: () => ({ outcome: 'unreachable' }),
    }).failures[0].code,
    'KEY_UNREACHABLE',
  )
  assert.equal(verifyAuthorityRevocation({ record_type: 'nope' }, delegation, verifyOptions).state, 'unsupported')
  assert.equal(verifyAuthorityRevocation(null, delegation, verifyOptions).state, 'invalid')
})

test('store keeps the first revocation and returns it for a repeated request', () => {
  const delegation = root()
  const store = new InMemoryAuthorityRevocationStore()
  const first = revokeByIssuer(delegation)
  const second = revokeByIssuer(delegation, {
    revoked_at: '2026-07-18T22:40:00.000Z',
    nonce: 'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf',
  })
  assert.notEqual(second.revocation_id, first.revocation_id)

  assert.equal(store.put(first).revocation_id, first.revocation_id)
  const returned = store.put(second)
  assert.equal(returned.revocation_id, first.revocation_id)
  assert.equal(returned.revoked_at, REVOKED_AT)
  assert.equal(store.get(delegation.delegation_id)?.revocation_id, first.revocation_id)
  assert.equal(store.tracks(delegation.delegation_id), true)
})

test('resolver: revoked, tracked active, untracked unknown', () => {
  const delegation = root()
  const store = new InMemoryAuthorityRevocationStore()
  const resolve = createAuthorityRevocationResolver(store, verifyOptions)

  assert.equal(resolve(delegation), 'unknown')
  store.track(delegation.delegation_id)
  assert.equal(resolve(delegation), 'active')
  store.put(revokeByIssuer(delegation))
  assert.equal(resolve(delegation), 'revoked')
})

test('a stored record that does not verify resolves unknown, never revoked or active', () => {
  const delegation = root()
  const store = new InMemoryAuthorityRevocationStore()
  store.track(delegation.delegation_id)
  const revocation = revokeByIssuer(delegation)
  store.put({ ...revocation, signature: '0'.repeat(128) })

  const resolve = createAuthorityRevocationResolver(store, verifyOptions)
  assert.equal(resolve(delegation), 'unknown')
})

test('a revoked root makes a valid child chain fail with the existing REVOKED outcome', () => {
  const parent = root()
  const descendant = child(parent)
  const store = new InMemoryAuthorityRevocationStore()
  store.track(parent.delegation_id)
  store.track(descendant.delegation_id)

  const options = (): AuthorityChainVerificationOptions => ({
    now: NOW,
    resolveVerificationKey,
    trustRoot: candidate => candidate.delegation_id === parent.delegation_id,
    resolveRevocation: createAuthorityRevocationResolver(store, verifyOptions),
  })

  const before = verifyAuthorityDelegationChain([parent, descendant], options())
  assert.equal(before.state, 'valid')

  store.put(revokeByIssuer(parent))

  const after = verifyAuthorityDelegationChain([parent, descendant], options())
  assert.equal(after.state, 'invalid')
  assert.equal(after.failures[0].code, 'REVOKED')
  assert.equal(after.failures[0].index, 0)

  // The descendant carries no revocation record of its own. Enforcement against it comes
  // from the ancestor in its chain, not from a cascade-derived record.
  assert.equal(store.get(descendant.delegation_id), undefined)
})

test('a revoked parent cannot mint a further child', () => {
  const parent = root()
  const store = new InMemoryAuthorityRevocationStore()
  store.track(parent.delegation_id)
  store.put(revokeByIssuer(parent))

  assert.throws(
    () => issueSubAuthorityDelegation(parent, childBody(parent), CHILD_KEY, {
      now: NOW,
      resolveVerificationKey,
      resolveRevocation: createAuthorityRevocationResolver(store, verifyOptions),
    }),
    /REVOKED/,
  )
})

test('an untracked root yields indeterminate, never valid', () => {
  const parent = root()
  const descendant = child(parent)
  const store = new InMemoryAuthorityRevocationStore()
  store.track(descendant.delegation_id)

  const outcome = verifyAuthorityDelegationChain([parent, descendant], {
    now: NOW,
    resolveVerificationKey,
    trustRoot: candidate => candidate.delegation_id === parent.delegation_id,
    resolveRevocation: createAuthorityRevocationResolver(store, verifyOptions),
  })
  assert.equal(outcome.state, 'indeterminate')
  assert.equal(outcome.valid, false)
  assert.equal(outcome.failures[0].code, 'REVOCATION_UNKNOWN')
  assert.equal(outcome.failures[0].index, 0)
})
