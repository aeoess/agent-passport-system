// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Coverage for the parent-verification checks issueSubAuthorityDelegation runs
// before signing a child: draft section 3.6 (lines 695-704) requires an issuer
// minting a child to verify the parent delegation's signature and temporal
// validity before signing, and to refuse to issue under an expired,
// not-yet-valid, or revoked parent; lines 589-592 treat an unknown revocation
// state as indeterminate, never as valid.
//
// Each case below asserts only the thrown message's SDK code, which
// issueSubAuthorityDelegation always names in parentheses at the end of the
// Error message.

import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../../src/crypto/keys.js'
import {
  AUTHORITY_DELEGATION_RECORD_TYPE,
  AUTHORITY_DELEGATION_VERSION,
  REPUTATION_PROFILE_V1,
  REVERSIBILITY_PROFILE_V1,
  SCOPE_PROFILE_V1,
  VALUES_PROFILE_V1,
  authorityDelegationBody,
  computeAuthorityDelegationId,
  issueAuthorityDelegation,
  issueSubAuthorityDelegation,
  signAuthorityDelegation,
  verifyAuthorityDelegationChain,
} from '../../src/v2/authority-delegation/index.js'
import type {
  AuthorityDelegationBodyV1,
  AuthorityDelegationV1,
  RevocationResolution,
  VerificationKeyResolver,
} from '../../src/v2/authority-delegation/index.js'

const ROOT_ISSUER = 'did:example:root'
const ROOT_SUBJECT = 'did:example:agent-a'
const CHILD_SUBJECT = 'did:example:agent-b'
const ROOT_VM = `${ROOT_ISSUER}#key-1`
const CHILD_VM = `${ROOT_SUBJECT}#key-1`

const ROOT_NOT_BEFORE = '2026-07-18T22:00:00.000Z'
const ROOT_NOT_AFTER = '2026-07-18T23:00:00.000Z'

function rootBody(nonce = '00112233445566778899aabbccddeeff'): AuthorityDelegationBodyV1 {
  return {
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: null,
    issuer: ROOT_ISSUER,
    subject: ROOT_SUBJECT,
    verification_method: ROOT_VM,
    issued_at: ROOT_NOT_BEFORE,
    nonce,
    authority: {
      scope: { profile: SCOPE_PROFILE_V1, grants: ['commerce:*'] },
      spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '100', cumulative: '100' },
      depth: { remaining: 3 },
      time: { not_before: ROOT_NOT_BEFORE, not_after: ROOT_NOT_AFTER },
      reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 80 },
      values: { profile: VALUES_PROFILE_V1, required: ['F-001', 'F-003'] },
      reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'compensable' },
    },
  }
}

function childBody(parent: AuthorityDelegationV1, nonce = '102132435465768798a9bacbdcedfe0f'): AuthorityDelegationBodyV1 {
  return {
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: parent.delegation_id,
    issuer: parent.subject,
    subject: CHILD_SUBJECT,
    verification_method: CHILD_VM,
    issued_at: '2026-07-18T22:00:01.000Z',
    nonce,
    authority: {
      scope: { profile: SCOPE_PROFILE_V1, grants: ['commerce:checkout'] },
      spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '80', cumulative: '80' },
      depth: { remaining: 2 },
      time: { not_before: '2026-07-18T22:00:01.000Z', not_after: '2026-07-18T22:50:00.000Z' },
      reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 70 },
      values: { profile: VALUES_PROFILE_V1, required: ['F-001', 'F-003', 'F-004'] },
      reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'tentative' },
    },
  }
}

const rootKeys = generateKeyPair()
const childKeys = generateKeyPair()
const root = issueAuthorityDelegation(rootBody(), rootKeys.privateKey)

function resolveRootKey(_issuer: string, method: string): string | null {
  return method === root.verification_method ? rootKeys.publicKey : null
}

interface OptionsOverride {
  now?: string
  resolveVerificationKey?: VerificationKeyResolver
  resolveRevocation?: (delegation: AuthorityDelegationV1) => RevocationResolution
}

function options(over: OptionsOverride = {}): {
  now: string
  resolveVerificationKey: VerificationKeyResolver
  resolveRevocation: (delegation: AuthorityDelegationV1) => RevocationResolution
} {
  return {
    now: ROOT_NOT_BEFORE,
    resolveVerificationKey: resolveRootKey,
    resolveRevocation: () => 'active',
    ...over,
  }
}

function throwsCode(action: () => unknown, code: string): void {
  assert.throws(action, new RegExp(`\\(${code}\\)`))
}

test('a valid parent and body: issues the child and the pair verifies', () => {
  const child = issueSubAuthorityDelegation(root, childBody(root), childKeys.privateKey, options())
  const checked = verifyAuthorityDelegationChain([root, child], {
    now: '2026-07-18T22:10:00.000Z',
    resolveVerificationKey: (_issuer, method) =>
      (method === root.verification_method ? rootKeys.publicKey
        : method === child.verification_method ? childKeys.publicKey
        : null),
    trustRoot: () => true,
    resolveRevocation: () => 'active',
  })
  assert.equal(checked.state, 'valid')
})

test('a malformed now gives NONCANONICAL_VALUE', () => {
  throwsCode(
    () => issueSubAuthorityDelegation(root, childBody(root), childKeys.privateKey, options({ now: '2026-07-18T22:00:00Z' })),
    'NONCANONICAL_VALUE',
  )
})

test('a parent failing shape gives its first failure code', () => {
  const badParent: AuthorityDelegationV1 = { ...root, nonce: 'not-thirty-two-hex-characters' }
  throwsCode(
    () => issueSubAuthorityDelegation(badParent, childBody(root), childKeys.privateKey, options()),
    'NONCANONICAL_VALUE',
  )
})

test('a parent whose delegation_id no longer matches (nonce changed, id kept, re-signed) gives ID_MISMATCH', () => {
  const mutatedBody = rootBody('ffeeddccbbaa99887766554433221100')
  const reSigned: AuthorityDelegationV1 = {
    ...mutatedBody,
    delegation_id: root.delegation_id,
    signature: signAuthorityDelegation({ ...mutatedBody, delegation_id: root.delegation_id }, rootKeys.privateKey),
  }
  throwsCode(
    () => issueSubAuthorityDelegation(reSigned, childBody(root), childKeys.privateKey, options()),
    'ID_MISMATCH',
  )
})

test('the resolver returning null, returning undefined, or throwing gives KEY_RESOLUTION_FAILED', () => {
  throwsCode(
    () => issueSubAuthorityDelegation(root, childBody(root), childKeys.privateKey, options({ resolveVerificationKey: () => null })),
    'KEY_RESOLUTION_FAILED',
  )
  throwsCode(
    () => issueSubAuthorityDelegation(root, childBody(root), childKeys.privateKey, options({ resolveVerificationKey: (() => undefined) as never })),
    'KEY_RESOLUTION_FAILED',
  )
  throwsCode(
    () => issueSubAuthorityDelegation(root, childBody(root), childKeys.privateKey, options({
      resolveVerificationKey: () => { throw new Error('jwks unreachable') },
    })),
    'KEY_RESOLUTION_FAILED',
  )
})

test('a corrupted parent signature gives SIGNATURE_INVALID', () => {
  const corrupted: AuthorityDelegationV1 = {
    ...root,
    signature: root.signature.slice(0, -1) + (root.signature.endsWith('0') ? '1' : '0'),
  }
  throwsCode(
    () => issueSubAuthorityDelegation(corrupted, childBody(root), childKeys.privateKey, options()),
    'SIGNATURE_INVALID',
  )
})

test('now before the parents not_before gives NOT_YET_VALID', () => {
  throwsCode(
    () => issueSubAuthorityDelegation(root, childBody(root), childKeys.privateKey, options({ now: '2026-07-18T21:59:59.000Z' })),
    'NOT_YET_VALID',
  )
})

test('now at the parents not_after gives EXPIRED, while the childs issued_at is still inside the window', () => {
  const body = childBody(root)
  assert.ok(body.issued_at >= root.authority.time.not_before && body.issued_at < root.authority.time.not_after)
  throwsCode(
    () => issueSubAuthorityDelegation(root, body, childKeys.privateKey, options({ now: ROOT_NOT_AFTER })),
    'EXPIRED',
  )
})

test('revocation revoked gives REVOKED', () => {
  throwsCode(
    () => issueSubAuthorityDelegation(root, childBody(root), childKeys.privateKey, options({ resolveRevocation: () => 'revoked' })),
    'REVOKED',
  )
})

test('revocation unknown, a non-string, or a throw gives REVOCATION_UNKNOWN', () => {
  throwsCode(
    () => issueSubAuthorityDelegation(root, childBody(root), childKeys.privateKey, options({ resolveRevocation: () => 'unknown' })),
    'REVOCATION_UNKNOWN',
  )
  throwsCode(
    () => issueSubAuthorityDelegation(root, childBody(root), childKeys.privateKey, options({ resolveRevocation: (() => 1) as never })),
    'REVOCATION_UNKNOWN',
  )
  throwsCode(
    () => issueSubAuthorityDelegation(root, childBody(root), childKeys.privateKey, options({
      resolveRevocation: () => { throw new Error('registry unreachable') },
    })),
    'REVOCATION_UNKNOWN',
  )
})

test('the existing body checks still refuse: scope widening', () => {
  const widened = childBody(root)
  widened.authority.scope.grants = ['admin:root']
  throwsCode(
    () => issueSubAuthorityDelegation(root, widened, childKeys.privateKey, options()),
    'SCOPE_WIDENING',
  )
})

test('the body-shape refusal names its first failure code in parentheses, like every other refusal here', () => {
  const uppercaseNonce = rootBody('00112233445566778899AABBCCDDEEFF')
  assert.throws(
    () => issueAuthorityDelegation(uppercaseNonce, rootKeys.privateKey),
    /^Error: authority delegation body invalid: nonce must be 32 lowercase hex characters \(NONCANONICAL_VALUE\)$/,
  )
})

const SCHEMA_INVALID_MESSAGE = /\(SCHEMA_INVALID\)$/

test('root: a body already carrying delegation_id refuses (SCHEMA_INVALID)', () => {
  const withId = {
    ...rootBody(),
    delegation_id: `sha256:${'0'.repeat(64)}`,
  } as unknown as AuthorityDelegationBodyV1
  assert.throws(() => issueAuthorityDelegation(withId, rootKeys.privateKey), SCHEMA_INVALID_MESSAGE)
})

test('root: a body already carrying signature refuses (SCHEMA_INVALID)', () => {
  const withSignature = {
    ...rootBody(),
    signature: '0'.repeat(128),
  } as unknown as AuthorityDelegationBodyV1
  assert.throws(() => issueAuthorityDelegation(withSignature, rootKeys.privateKey), SCHEMA_INVALID_MESSAGE)
})

test('root: a body carrying an own delegation_id member set to undefined still refuses (SCHEMA_INVALID)', () => {
  const withUndefinedId = {
    ...rootBody(),
    delegation_id: undefined,
  } as unknown as AuthorityDelegationBodyV1
  assert.ok(Object.prototype.hasOwnProperty.call(withUndefinedId, 'delegation_id'))
  assert.throws(() => issueAuthorityDelegation(withUndefinedId, rootKeys.privateKey), SCHEMA_INVALID_MESSAGE)
})

test('child under a sound parent: a body already carrying delegation_id refuses (SCHEMA_INVALID)', () => {
  const withId = {
    ...childBody(root),
    delegation_id: `sha256:${'0'.repeat(64)}`,
  } as unknown as AuthorityDelegationBodyV1
  assert.throws(
    () => issueSubAuthorityDelegation(root, withId, childKeys.privateKey, options()),
    SCHEMA_INVALID_MESSAGE,
  )
})

test('child under a sound parent: a body already carrying signature refuses (SCHEMA_INVALID)', () => {
  const withSignature = {
    ...childBody(root),
    signature: '0'.repeat(128),
  } as unknown as AuthorityDelegationBodyV1
  assert.throws(
    () => issueSubAuthorityDelegation(root, withSignature, childKeys.privateKey, options()),
    SCHEMA_INVALID_MESSAGE,
  )
})

test('child: a revoked parent together with a body carrying signature refuses REVOKED, parent checks run first', () => {
  const withSignature = {
    ...childBody(root),
    signature: '0'.repeat(128),
  } as unknown as AuthorityDelegationBodyV1
  throwsCode(
    () => issueSubAuthorityDelegation(root, withSignature, childKeys.privateKey, options({ resolveRevocation: () => 'revoked' })),
    'REVOKED',
  )
})

test('the same sound root and child bodies, without the extra member, still issue and verify', () => {
  const rBody = rootBody()
  const r = issueAuthorityDelegation(rBody, rootKeys.privateKey)
  const cBody = childBody(r)
  const c = issueSubAuthorityDelegation(r, cBody, childKeys.privateKey, options({
    resolveVerificationKey: (_issuer, method) => (method === r.verification_method ? rootKeys.publicKey : null),
  }))
  const checked = verifyAuthorityDelegationChain([r, c], {
    now: '2026-07-18T22:10:00.000Z',
    resolveVerificationKey: (_issuer, method) =>
      (method === r.verification_method ? rootKeys.publicKey
        : method === c.verification_method ? childKeys.publicKey
        : null),
    trustRoot: () => true,
    resolveRevocation: () => 'active',
  })
  assert.equal(checked.state, 'valid')
  assert.equal(c.delegation_id, computeAuthorityDelegationId(authorityDelegationBody(c)))
})
