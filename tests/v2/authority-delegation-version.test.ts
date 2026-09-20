// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// record_type and version coverage.
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
  body.subject = `${ROOT_SUBJECT}\uFDD0`
  const root = sign(body, ROOT_KEY)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'unsupported')
  assert.deepEqual(codesOf(checked), ['UNSUPPORTED_VERSION'])
})

test('the v1 record_type with an unrecognised version over an otherwise valid v1 body is unsupported', () => {
  const body = mutableBody()
  body.version = '2.0'
  const root = sign(body, ROOT_KEY)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'unsupported')
  assert.deepEqual(codesOf(checked), ['UNSUPPORTED_VERSION'])
})

test('an unrecognised record_type is unsupported and carries its own code', () => {
  const body = mutableBody()
  body.record_type = 'aps:authority-delegation:v2'
  const root = sign(body, ROOT_KEY)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'unsupported')
  assert.deepEqual(codesOf(checked), ['UNSUPPORTED_RECORD_TYPE'])
})

test('an unrecognised record_type is not judged against the v1 body schema at all', () => {
  // Was: the extra member made this SCHEMA_INVALID, because an unrecognised record_type
  // was still run through the v1 body checks. Recognition precedes v1 schema evaluation,
  // and a record this schema does not claim is returned unjudged, so the body's own
  // defects are not reported against a schema that is not its schema.
  const body = mutableBody()
  body.record_type = 'aps:authority-delegation:v2'
  body.extensions = {}
  const root = sign(body, ROOT_KEY)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'unsupported')
  assert.deepEqual(codesOf(checked), ['UNSUPPORTED_RECORD_TYPE'])
})

test('a record_type or version that is not a string is invalid, because no recognition is possible', () => {
  for (const mutate of [
    (body: Record<string, unknown>) => { body.record_type = 5 },
    (body: Record<string, unknown>) => { body.version = ['1.0'] },
  ]) {
    const body = mutableBody()
    mutate(body)
    const root = sign(body, ROOT_KEY)
    const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
    assert.equal(checked.state, 'invalid')
    assert.deepEqual(codesOf(checked), ['SCHEMA_INVALID'])
  }
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

// ── The record-wide I-JSON check also rejects a non-finite number (JSON has
// no NaN or Infinity) and a value of type undefined, bigint, function or
// symbol: none of these are JSON, so a value carrying one is not I-JSON
// either. JCS itself refuses to canonicalize any of them (a non-finite
// number, or undefined at any depth), so the placeholder below stands in for
// a delegation_id and signature that can never actually be derived, the same
// way sign() above stands in for a value JCS can canonicalize. ──

function unsignable(body: Record<string, unknown>): AuthorityDelegationV1 {
  return {
    ...body,
    delegation_id: `sha256:${'0'.repeat(64)}`,
    signature: '0'.repeat(128),
  } as unknown as AuthorityDelegationV1
}

test('an unrecognised version alongside a non-finite number elsewhere is SCHEMA_INVALID and UNSUPPORTED_VERSION', () => {
  const body = mutableBody()
  body.version = '2.0'
  body.extensions = { x: Infinity }
  ;(body.authority as Record<string, unknown>).risk = { profile: 'x', ceiling: 1 }
  const root = unsignable(body)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'unsupported')
  assert.deepEqual(codesOf(checked), ['UNSUPPORTED_VERSION'])
})

test('an unsupported reputation profile with a non-finite ceiling is SCHEMA_INVALID and UNSUPPORTED_PROFILE', () => {
  const body = mutableBody()
  ;(body.authority as Record<string, unknown>).reputation = { profile: 'aps-score-0-1000-v1', ceiling: Infinity }
  const root = unsignable(body)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'invalid')
  assert.deepEqual(codesOf(checked), ['SCHEMA_INVALID', 'UNSUPPORTED_PROFILE'])
})

test('an eighth, unrecognised facet holding undefined is SCHEMA_INVALID', () => {
  const body = mutableBody()
  ;(body.authority as Record<string, unknown>).risk = { profile: 'x', ceiling: undefined }
  const root = unsignable(body)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'invalid')
  assert.deepEqual(codesOf(checked), ['SCHEMA_INVALID', 'SCHEMA_INVALID'])
})

// --- No SDK grammar becomes protocol, as ruled --------------------------------------

test('a spend unit the draft admits is no longer refused by an SDK grammar', () => {
  // Draft line 466 shows "iso4217:USD:minor" and states no grammar at all. The previous
  // pattern refused a unit carrying a space, a slash or a non-ASCII character, which is
  // an SDK rule presented as a protocol rejection.
  for (const unit of ['iso4217:USD:minor', 'USD cents', 'urn:x:units/kWh', 'creditsµ', 'x'.repeat(400)]) {
    const body = mutableBody()
    ;(body.authority as Record<string, Record<string, unknown>>).spend = {
      mode: 'bounded', unit, per_action: '5000', cumulative: '10000',
    }
    const root = sign(body, ROOT_KEY)
    const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
    assert.equal(checked.state, 'valid', unit)
  }
  // An empty unit is still refused: a bounded spend has to name one.
  const empty = mutableBody()
  ;(empty.authority as Record<string, Record<string, unknown>>).spend = {
    mode: 'bounded', unit: '', per_action: '5000', cumulative: '10000',
  }
  const emptyRoot = sign(empty, ROOT_KEY)
  assert.equal(verifyAuthorityDelegationChain([emptyRoot], activeOptions(STANDARD_NOW, emptyRoot.delegation_id)).state, 'invalid')
})

test('a values identifier is profile-defined, so no SDK pattern judges it', () => {
  for (const identifier of ['F-001', 'urn:values:fairness', 'policy/no-deception', '价值']) {
    const body = mutableBody()
    ;(body.authority as Record<string, Record<string, unknown>>).values = {
      profile: 'aps-values-identifiers-v1', required: [identifier],
    }
    const root = sign(body, ROOT_KEY)
    const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
    assert.equal(checked.state, 'valid', identifier)
  }
})

test('a scope grant obeys the stated requirement and nothing narrower', () => {
  const accepted = ['commerce:checkout', 'a:b:c:d:e:f:g:h:i:j:k:l:m:n:o:p:q:r', 'x'.repeat(400), 'A_B', 'v1.2+3', 'commerce:*', '*']
  for (const grant of accepted) {
    const body = mutableBody()
    ;(body.authority as Record<string, Record<string, unknown>>).scope = {
      profile: 'aps-hierarchical-v1', grants: [grant],
    }
    const root = sign(body, ROOT_KEY)
    assert.equal(
      verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id)).state,
      'valid',
      grant,
    )
  }
  // Still refused, because the draft states these: a non-ASCII grant, an empty segment,
  // a wildcard that is not the terminal segment, and an empty grant.
  for (const grant of ['commerce:é', 'commerce::checkout', 'commerce:*:checkout', '*:checkout', '']) {
    const body = mutableBody()
    ;(body.authority as Record<string, Record<string, unknown>>).scope = {
      profile: 'aps-hierarchical-v1', grants: [grant],
    }
    const root = sign(body, ROOT_KEY)
    assert.equal(
      verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id)).state,
      'invalid',
      grant,
    )
  }
})

test('an identifier over this implementation ceiling is indeterminate, never a conformance failure', () => {
  const body = mutableBody()
  body.subject = `did:example:${'x'.repeat(1100)}`
  const root = sign(body, ROOT_KEY)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'indeterminate')
  assert.deepEqual(codesOf(checked), ['RESOURCE_LIMIT'])
})

// --- Section 3.3 is phase major over the whole chain, as ruled ---------------------

test('the first failing listed phase decides, not the first failing member', () => {
  // Two faults in one chain, in different phases and different members. The draft lists
  // delegation_id (phase 2) before duplicate identifiers (phase 4), so the id mismatch
  // decides whatever member each sits on. This verifier used to walk member by member,
  // running phases 2, 3 and 4 inside one pass, so the answer depended on which member
  // carried which fault.
  const root = sign(mutableBody(), ROOT_KEY)
  const tampered = structuredClone(root) as Record<string, unknown>
  tampered.delegation_id = `sha256:${'0'.repeat(64)}`
  // Member 0 repeats member 1's identifier, so a member-major pass would reach the
  // duplicate on the later member only after the earlier member's id check.
  const chain = [root, tampered] as unknown as Record<string, unknown>[]
  const checked = verifyAuthorityDelegationChain(chain, activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'invalid')
  assert.deepEqual(codesOf(checked), ['ID_MISMATCH'])
  assert.equal(checked.failures[0].index, 1, 'the member carrying the phase-2 fault')
})

test('within one phase the lowest member index wins', () => {
  const rootBody = mutableBody()
  const root = sign(rootBody, ROOT_KEY)
  const first = structuredClone(root) as Record<string, unknown>
  const second = structuredClone(root) as Record<string, unknown>
  first.delegation_id = `sha256:${'1'.repeat(64)}`
  second.delegation_id = `sha256:${'2'.repeat(64)}`
  const checked = verifyAuthorityDelegationChain(
    [first, second] as unknown as Record<string, unknown>[],
    activeOptions(STANDARD_NOW, root.delegation_id),
  )
  assert.deepEqual(codesOf(checked), ['ID_MISMATCH'])
  assert.equal(checked.failures[0].index, 0)
})

test('root trust is consulted before the root parent_delegation_id check, as the list orders them', () => {
  // Root trust is phase 5 and parent_delegation_id is phase 6. A root carrying a
  // non-null parent under an untrusted policy reports the trust answer, not the parent
  // one. This ordering was the other way round.
  const body = mutableBody()
  body.parent_delegation_id = `sha256:${'a'.repeat(64)}`
  const root = sign(body, ROOT_KEY)
  const untrusted = { ...activeOptions(STANDARD_NOW, root.delegation_id), trustRoot: () => false }
  const checked = verifyAuthorityDelegationChain([root], untrusted)
  assert.equal(checked.state, 'invalid')
  assert.deepEqual(codesOf(checked), ['ROOT_UNTRUSTED'])

  // With a trusting policy the parent check is reached and reports its own code.
  const trusted = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.deepEqual(codesOf(trusted), ['PARENT_MISMATCH'])
})
