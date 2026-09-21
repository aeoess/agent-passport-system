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
  recordAuthorityRevocation,
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

/** A self-consistent revocation naming a non-issuer as its revoker, signed by that
 *  non-issuer. issueAuthorityRevocation() refuses to mint one, so it is assembled from the
 *  module's own published helpers; every digest and the signature still come from the
 *  module under test. verifyAuthorityRevocation() rejects it with REVOKER_NOT_ISSUER. */
function revokeByNonIssuer(delegation: AuthorityDelegationV1): AuthorityRevocationV1 {
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
  return { ...unsigned, signature: signAuthorityRevocation(unsigned, IMPOSTOR_KEY) }
}

const verifyOptions = { resolveVerificationKey }

/** Move `candidate` into `store` through the verifying mutation path, the only supported
 *  way a revocation enters a store. */
function record(
  store: InMemoryAuthorityRevocationStore,
  delegation: AuthorityDelegationV1,
  candidate: unknown,
) {
  return recordAuthorityRevocation(store, delegation, candidate, verifyOptions)
}

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

  // The mutation path refuses to record it at all, so it never reaches the store.
  const store = new InMemoryAuthorityRevocationStore()
  const refused = record(store, delegation, forged)
  assert.equal(refused.recorded, false)
  assert.equal(store.get(delegation.delegation_id), undefined)

  // And forced past that gate, straight onto the persistence primitive, it still can never
  // become a 'revoked' answer: the resolver verifies again on the way out.
  store.insertVerifiedRevocation(forged)
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

test('a verification_method that is not DID-fragment shaped issues and verifies', () => {
  const delegation = root()
  // Nothing in this module requires a method identifier to be a fragment of the identifier
  // that controls it. This one shares no prefix with the revoker at all; whether it belongs
  // to the issuer is settled by the resolver, which is handed target.issuer.
  const OPAQUE_VM = 'urn:example:hsm/slot-3'
  const revocation = issueAuthorityRevocation(
    delegation,
    {
      now: REVOKED_AT,
      revoker: ROOT_ISSUER,
      verification_method: OPAQUE_VM,
      reason_code: 'key_compromise',
      nonce: NONCE,
    },
    ROOT_KEY,
  )
  assert.equal(revocation.verification_method, OPAQUE_VM)
  assert.ok(!OPAQUE_VM.startsWith(`${ROOT_ISSUER}#`))

  // The resolver answers for this method only under the target delegation's issuer, so a
  // 'valid' here is key resolution making the decision, not a string shape.
  let seenController: string | undefined
  const result = verifyAuthorityRevocation(revocation, delegation, {
    resolveVerificationKey: (controller, method) => {
      seenController = controller
      return controller === ROOT_ISSUER && method === OPAQUE_VM
        ? publicKeyFromPrivate(ROOT_KEY)
        : null
    },
  })
  assert.equal(result.state, 'valid')
  assert.equal(result.valid, true)
  assert.equal(seenController, delegation.issuer)

  // And the same record under a resolver that does not bind the method to this issuer is
  // indeterminate, never valid.
  assert.equal(
    verifyAuthorityRevocation(revocation, delegation, { resolveVerificationKey: () => null }).state,
    'indeterminate',
  )
})

test('a reason_code outside the old lowercase grammar issues and verifies', () => {
  const delegation = root()
  // Uppercase and a space: rejected by the grammar this module used to impose, accepted
  // now, because section 3.5.1 asks for a machine-readable reason code and fixes no
  // grammar for one.
  const REASON = 'Key Compromise'
  const revocation = issueAuthorityRevocation(
    delegation,
    {
      now: REVOKED_AT,
      revoker: ROOT_ISSUER,
      verification_method: ROOT_VM,
      reason_code: REASON,
      nonce: NONCE,
    },
    ROOT_KEY,
  )
  assert.equal(revocation.reason_code, REASON)
  assert.equal(verifyAuthorityRevocation(revocation, delegation, verifyOptions).state, 'valid')

  // An empty reason_code is still refused: the member carries a value or the record is not
  // valid.
  assert.throws(
    () => issueAuthorityRevocation(
      delegation,
      {
        now: REVOKED_AT,
        revoker: ROOT_ISSUER,
        verification_method: ROOT_VM,
        reason_code: '',
        nonce: NONCE,
      },
      ROOT_KEY,
    ),
    /reason_code/,
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

  const accepted = record(store, delegation, first)
  assert.equal(accepted.inserted, true)
  assert.ok(accepted.stored)
  assert.equal(accepted.stored.revocation_id, first.revocation_id)

  const returned = record(store, delegation, second)
  assert.equal(returned.inserted, false)
  assert.ok(returned.stored)
  assert.equal(returned.stored.revocation_id, first.revocation_id)
  assert.equal(returned.stored.revoked_at, REVOKED_AT)
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
  record(store, delegation, revokeByIssuer(delegation))
  assert.equal(resolve(delegation), 'revoked')
})

test('a stored record that does not verify resolves unknown, never revoked or active', () => {
  const delegation = root()
  const store = new InMemoryAuthorityRevocationStore()
  store.track(delegation.delegation_id)
  const revocation = revokeByIssuer(delegation)
  const broken = { ...revocation, signature: '0'.repeat(128) }

  // The mutation path refuses it, so reaching this state at all means going around it,
  // straight onto the persistence primitive.
  assert.equal(record(store, delegation, broken).recorded, false)
  store.insertVerifiedRevocation(broken)

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

  record(store, parent, revokeByIssuer(parent))

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
  record(store, parent, revokeByIssuer(parent))

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

test('an invalid record cannot take the first-wins slot from the valid one behind it', () => {
  const delegation = root()
  const store = new InMemoryAuthorityRevocationStore()
  store.track(delegation.delegation_id)
  const resolve = createAuthorityRevocationResolver(store, verifyOptions)

  // An arbitrary object naming the delegation: refused, and the store is not touched.
  const garbage = record(store, delegation, { delegation_id: delegation.delegation_id })
  assert.equal(garbage.recorded, false)
  assert.equal(garbage.inserted, false)
  assert.equal(garbage.stored, undefined)
  assert.equal(garbage.verification.valid, false)
  assert.equal(store.get(delegation.delegation_id), undefined)

  // A self-consistent record signed by a party who is not the issuer: refused on its own
  // authorization failure, not on a schema complaint.
  const unauthorized = record(store, delegation, revokeByNonIssuer(delegation))
  assert.equal(unauthorized.recorded, false)
  assert.equal(unauthorized.stored, undefined)
  assert.equal(unauthorized.verification.failures[0].code, 'REVOKER_NOT_ISSUER')
  assert.equal(store.get(delegation.delegation_id), undefined)

  // The slot is therefore still open. Under the defect this closes, either refused record
  // held it, the write below was discarded, and this delegation could never be revoked.
  assert.equal(resolve(delegation), 'active')
  const valid = revokeByIssuer(delegation)
  const accepted = record(store, delegation, valid)
  assert.equal(accepted.recorded, true)
  assert.equal(accepted.inserted, true)
  assert.ok(accepted.stored)
  assert.equal(accepted.stored.revocation_id, valid.revocation_id)
  assert.equal(resolve(delegation), 'revoked')
})

test('a second valid revocation returns the stored first record, byte identical', () => {
  const delegation = root()
  const store = new InMemoryAuthorityRevocationStore()
  const first = revokeByIssuer(delegation)
  const second = revokeByIssuer(delegation, {
    revoked_at: '2026-07-18T22:45:00.000Z',
    nonce: 'e0e1e2e3e4e5e6e7e8e9eaebecedeeef',
  })
  assert.notEqual(second.revocation_id, first.revocation_id)
  // Both are genuinely valid, so what separates them is arrival order and nothing else.
  assert.equal(verifyAuthorityRevocation(first, delegation, verifyOptions).state, 'valid')
  assert.equal(verifyAuthorityRevocation(second, delegation, verifyOptions).state, 'valid')

  assert.equal(record(store, delegation, first).inserted, true)

  const later = record(store, delegation, second)
  assert.equal(later.recorded, true)
  assert.equal(later.inserted, false)
  assert.equal(later.verification.state, 'valid')
  assert.ok(later.stored)
  assert.equal(canonicalizeJCS(later.stored), canonicalizeJCS(first))
  assert.equal(canonicalizeJCS(store.get(delegation.delegation_id)), canonicalizeJCS(first))
  assert.equal(later.stored.revoked_at, REVOKED_AT)
})

test('a refused request is never handed the record already stored', () => {
  const delegation = root()
  const store = new InMemoryAuthorityRevocationStore()
  const first = revokeByIssuer(delegation)
  assert.equal(record(store, delegation, first).inserted, true)

  // Unauthorized, arriving after a valid record exists.
  const unauthorized = record(store, delegation, revokeByNonIssuer(delegation))
  assert.equal(unauthorized.recorded, false)
  assert.equal(unauthorized.inserted, false)
  // Not the stored record, and not the candidate either.
  assert.equal(unauthorized.stored, undefined)
  assert.equal(unauthorized.verification.state, 'invalid')
  assert.equal(unauthorized.verification.failures[0].code, 'REVOKER_NOT_ISSUER')

  // Structurally invalid, same answer.
  const broken = record(store, delegation, { ...first, signature: '0'.repeat(128) })
  assert.equal(broken.recorded, false)
  assert.equal(broken.stored, undefined)
  assert.equal(broken.verification.failures[0].code, 'SIGNATURE_INVALID')

  // Neither refusal disturbed what the store holds.
  assert.equal(canonicalizeJCS(store.get(delegation.delegation_id)), canonicalizeJCS(first))
  assert.equal(createAuthorityRevocationResolver(store, verifyOptions)(delegation), 'revoked')
})
