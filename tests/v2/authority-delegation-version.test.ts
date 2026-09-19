// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Item 5 coverage: record_type and version.
//
// - A version or record_type that is not a string is malformed input:
//   SCHEMA_INVALID.
// - A record_type recognised as the v1 type, carrying a version string other
//   than the v1 version, is unsupported without ever being judged against the
//   v1 body schema: no exact-keys check, no facet or value checks. The
//   record-wide I-JSON check still runs first.
// - An unrecognised record_type string keeps today's behaviour: unsupported,
//   plus the v1 checks.
// See src/v2/authority-delegation/schema.ts.

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
  computeAuthorityDelegationId,
  signAuthorityDelegation,
  verifyAuthorityDelegationChain,
} from '../../src/v2/authority-delegation/index.js'
import type {
  AuthorityChainVerificationOptions,
  AuthorityDelegationBodyV1,
  AuthorityDelegationV1,
} from '../../src/v2/authority-delegation/index.js'

const ROOT_KEY = '11'.repeat(32)
const ROOT_PUB = publicKeyFromPrivate(ROOT_KEY)
const ROOT_ISSUER = 'did:example:root'
const ROOT_SUBJECT = 'did:example:agent-a'
const ROOT_VM = `${ROOT_ISSUER}#key-1`
const STANDARD_NOW = '2026-07-18T22:10:00.000Z'

function resolveVerificationKey(_issuer: string, method: string): string | null {
  return method === ROOT_VM ? ROOT_PUB : null
}

function activeOptions(now: string, trustedId: string): AuthorityChainVerificationOptions {
  return {
    now,
    resolveVerificationKey,
    trustRoot: candidate => candidate.delegation_id === trustedId,
    resolveRevocation: () => 'active',
  }
}

function standardRootBody(): AuthorityDelegationBodyV1 {
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

/** Every case here builds a body that does not conform to AuthorityDelegationBodyV1
 *  (a non-string version, an extra member, a missing member), so this signs a plain
 *  record instead of a typed body. JCS canonicalizes any JSON-representable value
 *  that carries no lone surrogate, so every vector below gets a real delegation_id
 *  and signature rather than a placeholder. */
function sign(body: Record<string, unknown>, privateKey: string): AuthorityDelegationV1 {
  const delegation_id = computeAuthorityDelegationId(body as unknown as AuthorityDelegationBodyV1)
  const signature = signAuthorityDelegation(
    { ...body, delegation_id } as unknown as Omit<AuthorityDelegationV1, 'signature'>,
    privateKey,
  )
  return { ...body, delegation_id, signature } as unknown as AuthorityDelegationV1
}

function mutableBody(): Record<string, unknown> {
  return structuredClone(standardRootBody()) as unknown as Record<string, unknown>
}

function codesOf(checked: { failures: { code: string }[] }): string[] {
  return checked.failures.map(item => item.code)
}

test('a version that is a JSON number is malformed input: SCHEMA_INVALID', () => {
  const body = mutableBody()
  body.version = 1
  const root = sign(body, ROOT_KEY)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'invalid')
  assert.deepEqual(codesOf(checked), ['SCHEMA_INVALID'])
})

test('a version that is a JSON array is malformed input: SCHEMA_INVALID', () => {
  const body = mutableBody()
  body.version = ['1.0']
  const root = sign(body, ROOT_KEY)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'invalid')
  assert.deepEqual(codesOf(checked), ['SCHEMA_INVALID'])
})

test('a record_type that is a JSON number is malformed input, the same as a non-string version: SCHEMA_INVALID', () => {
  const body = mutableBody()
  body.record_type = 7
  const root = sign(body, ROOT_KEY)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'invalid')
  assert.deepEqual(codesOf(checked), ['SCHEMA_INVALID'])
})

test('the v1 record_type with an unrecognised version is unsupported without judging the v1 body schema: extra top-level member and an eighth facet', () => {
  const body = mutableBody()
  body.version = '2.0'
  body.extensions = {}
  ;(body.authority as Record<string, unknown>).risk = { profile: 'x', ceiling: 1 }
  const root = sign(body, ROOT_KEY)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'unsupported')
  assert.deepEqual(codesOf(checked), ['UNSUPPORTED_VERSION'])
})

test('the v1 record_type with an unrecognised version is unsupported without judging the v1 body schema: no nonce member', () => {
  const body = mutableBody()
  body.version = '1.1'
  delete body.nonce
  const root = sign(body, ROOT_KEY)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'unsupported')
  assert.deepEqual(codesOf(checked), ['UNSUPPORTED_VERSION'])
})

test('an unrecognised version alongside a noncharacter elsewhere in the record is SCHEMA_INVALID and UNSUPPORTED_VERSION', () => {
  const body = mutableBody()
  body.version = '2.0'
  body.subject = `${ROOT_SUBJECT}﷐`
  const root = sign(body, ROOT_KEY)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'invalid')
  assert.deepEqual(codesOf(checked), ['SCHEMA_INVALID', 'UNSUPPORTED_VERSION'])
})

test('the v1 record_type with an unrecognised version over an otherwise valid v1 body is unsupported', () => {
  const body = mutableBody()
  body.version = '2.0'
  const root = sign(body, ROOT_KEY)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'unsupported')
  assert.deepEqual(codesOf(checked), ['UNSUPPORTED_VERSION'])
})

test('an unrecognised record_type over an otherwise valid v1 body keeps today\'s behaviour: unsupported, judged by the v1 schema', () => {
  const body = mutableBody()
  body.record_type = 'aps:authority-delegation:v2'
  const root = sign(body, ROOT_KEY)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'unsupported')
  assert.deepEqual(codesOf(checked), ['UNSUPPORTED_VERSION'])
})

test('a facet profile that is not a string is SCHEMA_INVALID, unchanged by this rule', () => {
  const body = mutableBody()
  ;(body.authority as Record<string, unknown>).reputation = { profile: 5, ceiling: 80 }
  const root = sign(body, ROOT_KEY)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'invalid')
  assert.deepEqual(codesOf(checked), ['SCHEMA_INVALID'])
})

test('an unsupported facet profile is unsupported, unchanged by this rule', () => {
  const body = mutableBody()
  ;(body.authority as Record<string, unknown>).scope = { profile: 'aps-hierarchical-v2', grants: ['commerce/checkout'] }
  const root = sign(body, ROOT_KEY)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'unsupported')
  assert.deepEqual(codesOf(checked), ['UNSUPPORTED_PROFILE'])
})
