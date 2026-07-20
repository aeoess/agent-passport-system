// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, publicKeyFromPrivate } from '../../src/crypto/keys.js'
import {
  AUTHORITY_DELEGATION_RECORD_TYPE,
  AUTHORITY_DELEGATION_VERSION,
  REPUTATION_PROFILE_V1,
  REVERSIBILITY_PROFILE_V1,
  SCOPE_PROFILE_V1,
  VALUES_PROFILE_V1,
  compareAuthority,
  computeAuthorityDelegationId,
  authorityDelegationBody,
  issueAuthorityDelegation,
  issueSubAuthorityDelegation,
  parseAuthorityDelegationJson,
  verifyAuthorityDelegationChain,
} from '../../src/v2/authority-delegation/index.js'
import type {
  AuthorityDelegationBodyV1,
  AuthorityDelegationV1,
  AuthorityVectorV1,
} from '../../src/v2/authority-delegation/index.js'

function rootAuthority(): AuthorityVectorV1 {
  return {
    scope: { profile: SCOPE_PROFILE_V1, grants: ['commerce:*'] },
    spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '100', cumulative: '100' },
    depth: { remaining: 3 },
    time: { not_before: '2026-07-18T22:00:00.000Z', not_after: '2026-07-18T23:00:00.000Z' },
    reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 80 },
    values: { profile: VALUES_PROFILE_V1, required: ['F-001', 'F-003'] },
    reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'compensable' },
  }
}

function rootBody(): AuthorityDelegationBodyV1 {
  return {
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: null,
    issuer: 'did:example:root',
    subject: 'did:example:agent-a',
    verification_method: 'did:example:root#key-1',
    issued_at: '2026-07-18T22:00:00.000Z',
    nonce: '00112233445566778899aabbccddeeff',
    authority: rootAuthority(),
  }
}

function childBody(parent: AuthorityDelegationV1, subject = 'did:example:agent-b', nonce = '102132435465768798a9bacbdcedfe0f'): AuthorityDelegationBodyV1 {
  return {
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: parent.delegation_id,
    issuer: parent.subject,
    subject,
    verification_method: `${parent.subject}#key-1`,
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

test('authority delegation v1 cross-language known-answer vector is stable', () => {
  const seed = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
  const delegation = issueAuthorityDelegation(rootBody(), seed)
  assert.equal(publicKeyFromPrivate(seed), '03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8')
  assert.equal(delegation.delegation_id, 'sha256:44ab6d778b1a1b9acf4fadb07772892ae33e7b5dba84152a0a1af501e9bbb40a')
  assert.equal(delegation.signature, 'b070ad54a75b44b4340333e0b381f83d4e474b3149188e3f5846a38ad29863eab9e65e245d1c457e0e539e19d3ca813987ea6848f20a4f212754ebd10cf24200')
  assert.deepEqual(parseAuthorityDelegationJson(JSON.stringify(delegation)), delegation)
})

test('strict wire parser rejects unknown and duplicate members', () => {
  const seed = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
  const wire = JSON.stringify(issueAuthorityDelegation(rootBody(), seed))
  assert.throws(
    () => parseAuthorityDelegationJson(wire.replace('"version":"1.0"', '"version":"1.0","future":true')),
    /SCHEMA_INVALID/,
  )
  assert.throws(
    () => parseAuthorityDelegationJson(wire.replace('"version":"1.0"', '"version":"1.0","version":"1.0"')),
    /duplicate JSON object member/,
  )
  assert.throws(
    () => parseAuthorityDelegationJson(wire.replace('did:example:root', 'did:example:\\ud800')),
    /SCHEMA_INVALID/,
  )
  assert.throws(
    () => parseAuthorityDelegationJson(wire.replace('"remaining":3', '"remaining":3.0')),
    /non-integer JSON numbers/,
  )
})

test('v1 ID and Ed25519 signature inputs are deterministic and full chain validates', () => {
  const rootKeys = generateKeyPair()
  const childKeys = generateKeyPair()
  const root = issueAuthorityDelegation(rootBody(), rootKeys.privateKey)
  const again = issueAuthorityDelegation(rootBody(), rootKeys.privateKey)
  assert.deepEqual(again, root)
  assert.equal(root.delegation_id, computeAuthorityDelegationId(authorityDelegationBody(root)))

  const child = issueSubAuthorityDelegation(root, childBody(root), childKeys.privateKey)
  const keys = new Map([
    [root.verification_method, rootKeys.publicKey],
    [child.verification_method, childKeys.publicKey],
  ])
  const checked = verifyAuthorityDelegationChain([root, child], {
    now: '2026-07-18T22:10:00.000Z',
    resolveVerificationKey: (_issuer, method) => keys.get(method) ?? null,
    trustRoot: candidate => candidate.issuer === 'did:example:root',
    resolveRevocation: () => 'active',
  })
  assert.equal(checked.state, 'valid')
  assert.equal(checked.valid, true)

  const tampered = structuredClone(child)
  tampered.authority.reputation.ceiling = 69
  const rejected = verifyAuthorityDelegationChain([root, tampered], {
    now: '2026-07-18T22:10:00.000Z',
    resolveVerificationKey: (_issuer, method) => keys.get(method) ?? null,
    trustRoot: () => true,
    resolveRevocation: () => 'active',
  })
  assert.equal(rejected.failures[0]?.code, 'ID_MISMATCH')
})

test('each of the seven authority facets rejects outward movement', () => {
  const parent = rootAuthority()
  const base = childBody({ delegation_id: `sha256:${'0'.repeat(64)}` } as AuthorityDelegationV1).authority
  assert.deepEqual(compareAuthority(parent, base), [])

  const cases: Array<[string, (value: AuthorityVectorV1, parentValue: AuthorityVectorV1) => void, string]> = [
    ['scope', value => { value.scope.grants = ['admin:root'] }, 'SCOPE_WIDENING'],
    ['spend', value => { value.spend = { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '101', cumulative: '101' } }, 'SPEND_WIDENING'],
    ['depth', value => { value.depth.remaining = 3 }, 'DEPTH_WIDENING'],
    ['time', value => { value.time.not_after = '2026-07-19T00:00:00.000Z' }, 'TIME_WIDENING'],
    ['reputation', value => { value.reputation.ceiling = 81 }, 'REPUTATION_WIDENING'],
    ['values', value => { value.values.required = ['F-001'] }, 'VALUES_WEAKENING'],
    ['reversibility', (value, parentValue) => {
      parentValue.reversibility.ceiling = 'tentative'
      value.reversibility.ceiling = 'irreversible'
    }, 'REVERSIBILITY_WIDENING'],
  ]
  for (const [name, mutate, expected] of cases) {
    const child = structuredClone(base)
    const localParent = structuredClone(parent)
    mutate(child, localParent)
    assert.ok(compareAuthority(localParent, child).some(item => item.code === expected), `${name} must reject`)
  }
})

test('unknown revocation state is indeterminate rather than valid', () => {
  const keys = generateKeyPair()
  const root = issueAuthorityDelegation(rootBody(), keys.privateKey)
  const checked = verifyAuthorityDelegationChain([root], {
    now: '2026-07-18T22:10:00.000Z',
    resolveVerificationKey: () => keys.publicKey,
    trustRoot: () => true,
    resolveRevocation: () => 'unknown',
  })
  assert.equal(checked.state, 'indeterminate')
  assert.equal(checked.failures[0]?.code, 'REVOCATION_UNKNOWN')
})
