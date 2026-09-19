// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Draft section 3.2, lines 511 and 536-537: "A child's not_before MUST NOT
// predate its issued_at" is stated within "Let child be directly delegated
// from parent". A root (parent_delegation_id null) has no parent and is
// exempt: its time.not_before may predate its issued_at. The window must
// still be non-empty, and a child must still be issued inside its parent's
// window; those checks are unchanged.

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
  validateAuthorityDelegationShape,
  verifyAuthorityDelegationChain,
} from '../../src/v2/authority-delegation/index.js'
import type {
  AuthorityDelegationBodyV1,
  AuthorityDelegationV1,
  AuthorityVectorV1,
} from '../../src/v2/authority-delegation/index.js'

const ROOT_KEY = '11'.repeat(32)
const ROOT_PUB = publicKeyFromPrivate(ROOT_KEY)

const ROOT_ISSUER = 'did:example:root'
const ROOT_SUBJECT = 'did:example:agent-a'
const CHILD_SUBJECT = 'did:example:agent-b'
const ROOT_VM = `${ROOT_ISSUER}#key-1`
const CHILD_VM = `${ROOT_SUBJECT}#key-1`

function rootAuthorityWithTime(time: { not_before: string; not_after: string }): AuthorityVectorV1 {
  return {
    scope: { profile: SCOPE_PROFILE_V1, grants: ['commerce:*'] },
    spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '100', cumulative: '100' },
    depth: { remaining: 3 },
    time,
    reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 80 },
    values: { profile: VALUES_PROFILE_V1, required: ['F-001', 'F-003'] },
    reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'compensable' },
  }
}

function childAuthorityWithTime(time: { not_before: string; not_after: string }): AuthorityVectorV1 {
  return {
    scope: { profile: SCOPE_PROFILE_V1, grants: ['commerce:checkout'] },
    spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '80', cumulative: '80' },
    depth: { remaining: 2 },
    time,
    reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 70 },
    values: { profile: VALUES_PROFILE_V1, required: ['F-001', 'F-003', 'F-004'] },
    reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'tentative' },
  }
}

function rootBodyWith(issuedAt: string, time: { not_before: string; not_after: string }): AuthorityDelegationBodyV1 {
  return {
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: null,
    issuer: ROOT_ISSUER,
    subject: ROOT_SUBJECT,
    verification_method: ROOT_VM,
    issued_at: issuedAt,
    nonce: '00112233445566778899aabbccddeeff',
    authority: rootAuthorityWithTime(time),
  }
}

/** A root whose window opens one hour before issued_at: 21:00 open, 22:00 issued, 23:00 close. */
function rootBodyWithEarlyWindow(): AuthorityDelegationBodyV1 {
  return rootBodyWith('2026-07-18T22:00:00.000Z', {
    not_before: '2026-07-18T21:00:00.000Z',
    not_after: '2026-07-18T23:00:00.000Z',
  })
}

function childBodyWith(
  root: AuthorityDelegationV1,
  issuedAt: string,
  time: { not_before: string; not_after: string },
): AuthorityDelegationBodyV1 {
  return {
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: root.delegation_id,
    issuer: root.subject,
    subject: CHILD_SUBJECT,
    verification_method: CHILD_VM,
    issued_at: issuedAt,
    nonce: '102132435465768798a9bacbdcedfe0f',
    authority: childAuthorityWithTime(time),
  }
}

/** Builds a syntactically closed record around a body without going through
 *  issueAuthorityDelegation's own shape check, so a body that is expected to
 *  fail validateAuthorityDelegationShape can still be handed to it or to
 *  verifyAuthorityDelegationChain. The placeholder id/signature are never
 *  checked for correctness by the shape check, only for format. */
function unsignedRecord(body: AuthorityDelegationBodyV1): AuthorityDelegationV1 {
  return { ...body, delegation_id: `sha256:${'0'.repeat(64)}`, signature: '0'.repeat(128) }
}

test('a root whose not_before is one hour before its issued_at verifies valid at a now inside its window', () => {
  const root = issueAuthorityDelegation(rootBodyWithEarlyWindow(), ROOT_KEY)
  const checked = verifyAuthorityDelegationChain([root], {
    now: '2026-07-18T22:30:00.000Z',
    resolveVerificationKey: (_issuer, method) => (method === ROOT_VM ? ROOT_PUB : null),
    trustRoot: candidate => candidate.delegation_id === root.delegation_id,
    resolveRevocation: () => 'active',
  })
  assert.equal(checked.state, 'valid')
  assert.equal(checked.valid, true)
  assert.deepEqual(checked.failures, [])
})

test('issueAuthorityDelegation accepts a root body whose not_before predates its issued_at', () => {
  assert.doesNotThrow(() => issueAuthorityDelegation(rootBodyWithEarlyWindow(), ROOT_KEY))
})

test('a child whose not_before predates its issued_at still verifies invalid SCHEMA_INVALID at index 1', () => {
  const root = issueAuthorityDelegation(
    rootBodyWith('2026-07-18T22:00:00.000Z', {
      not_before: '2026-07-18T22:00:00.000Z',
      not_after: '2026-07-18T23:00:00.000Z',
    }),
    ROOT_KEY,
  )
  const child = unsignedRecord(childBodyWith(root, '2026-07-18T22:10:00.000Z', {
    not_before: '2026-07-18T22:05:00.000Z',
    not_after: '2026-07-18T22:50:00.000Z',
  }))
  const checked = verifyAuthorityDelegationChain([root, child], {
    now: '2026-07-18T22:20:00.000Z',
    resolveVerificationKey: (_issuer, method) => (method === ROOT_VM ? ROOT_PUB : null),
    trustRoot: candidate => candidate.delegation_id === root.delegation_id,
    resolveRevocation: () => 'active',
  })
  assert.equal(checked.state, 'invalid')
  assert.equal(checked.failures[0]?.code, 'SCHEMA_INVALID')
  assert.equal(checked.failures[0]?.index, 1)
})

test('a root with an empty window (not_before equal to not_after) is still SCHEMA_INVALID', () => {
  const body = rootBodyWith('2026-07-18T22:00:00.000Z', {
    not_before: '2026-07-18T22:00:00.000Z',
    not_after: '2026-07-18T22:00:00.000Z',
  })
  const failures = validateAuthorityDelegationShape(unsignedRecord(body))
  assert.ok(
    failures.some(item => item.code === 'SCHEMA_INVALID' && item.message === 'time window must be non-empty'),
    JSON.stringify(failures),
  )
})
