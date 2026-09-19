// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Draft-03 reconciliation coverage for src/v2/authority-delegation: the RFC
// 3339 exact-millisecond timestamp grammar (integer arithmetic, never Date),
// string-order timestamp comparison throughout the module, the reversibility
// ceiling no longer being coerced with String(), and the "an unsupported
// facet profile is unsupported" rule for the four profiled facets.

import test from 'node:test'
import assert from 'node:assert/strict'
import { publicKeyFromPrivate } from '../../src/crypto/keys.js'
import {
  AUTHORITY_DELEGATION_RECORD_TYPE,
  AUTHORITY_DELEGATION_VERSION,
  InMemoryAuthorityBudgetLedger,
  REPUTATION_PROFILE_V1,
  REVERSIBILITY_PROFILE_V1,
  SCOPE_PROFILE_V1,
  VALUES_PROFILE_V1,
  compareCanonicalTimestamps,
  computeAuthorityDelegationId,
  isCanonicalTimestamp,
  issueAuthorityDelegation,
  issueSubAuthorityDelegation,
  signAuthorityDelegation,
  verifyAuthorityDelegationChain,
} from '../../src/v2/authority-delegation/index.js'
import type {
  AuthorityChainVerificationOptions,
  AuthorityDelegationBodyV1,
  AuthorityDelegationV1,
  AuthorityVectorV1,
} from '../../src/v2/authority-delegation/index.js'

const ROOT_KEY = '11'.repeat(32)
const CHILD_KEY = '22'.repeat(32)
const ROOT_PUB = publicKeyFromPrivate(ROOT_KEY)
const CHILD_PUB = publicKeyFromPrivate(CHILD_KEY)

const ROOT_ISSUER = 'did:example:root'
const ROOT_SUBJECT = 'did:example:agent-a'
const CHILD_SUBJECT = 'did:example:agent-b'
const ROOT_VM = `${ROOT_ISSUER}#key-1`
const CHILD_VM = `${ROOT_SUBJECT}#key-1`
const STANDARD_NOW = '2026-07-18T22:10:00.000Z'

const publicKeys = new Map([
  [ROOT_VM, ROOT_PUB],
  [CHILD_VM, CHILD_PUB],
])

function resolveVerificationKey(_issuer: string, method: string): string | null {
  return publicKeys.get(method) ?? null
}

function activeOptions(now: string, trustedId: string): AuthorityChainVerificationOptions {
  return {
    now,
    resolveVerificationKey,
    trustRoot: candidate => candidate.delegation_id === trustedId,
    resolveRevocation: () => 'active',
  }
}

/** Sign a body directly, bypassing issueAuthorityDelegation's own shape check. */
function sign(body: AuthorityDelegationBodyV1, privateKey: string): AuthorityDelegationV1 {
  const delegation_id = computeAuthorityDelegationId(body)
  const signature = signAuthorityDelegation({ ...body, delegation_id }, privateKey)
  return { ...body, delegation_id, signature }
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

/** The root+child pair used by tests 3 and 5: a leap second sits inside both windows. */
function buildLeapSecondChain(): [AuthorityDelegationV1, AuthorityDelegationV1] {
  const root = issueAuthorityDelegation(
    rootBodyWith('2016-12-31T23:59:59.000Z', {
      not_before: '2016-12-31T23:59:59.000Z',
      not_after: '2017-01-01T00:00:01.000Z',
    }),
    ROOT_KEY,
  )
  const child = issueSubAuthorityDelegation(
    root,
    childBodyWith(root, '2016-12-31T23:59:60.000Z', {
      not_before: '2016-12-31T23:59:60.000Z',
      not_after: '2017-01-01T00:00:00.500Z',
    }),
    CHILD_KEY,
    {
      now: '2016-12-31T23:59:60.000Z',
      resolveVerificationKey,
      resolveRevocation: () => 'active',
    },
  )
  return [root, child]
}

test('isCanonicalTimestamp: exact RFC 3339 UTC-millisecond grammar with real calendar days', () => {
  const valid = [
    '2016-12-31T23:59:60.000Z',
    '0000-02-29T00:00:00.000Z',
    '2028-02-29T23:59:60.999Z',
    '2026-07-18T22:00:00.000Z',
    // RFC 3339 section 5.7 and Appendix D: second 60 at 23:59 on
    // the last day of its month.
    '2026-06-30T23:59:60.000Z',
    '2027-02-28T23:59:60.000Z',
    '0000-02-29T23:59:60.000Z',
  ]
  for (const value of valid) {
    assert.equal(isCanonicalTimestamp(value), true, value)
  }

  const invalid: unknown[] = [
    '2016-12-31T23:59:61.000Z',
    '2026-07-18T24:00:00.000Z',
    '2026-02-30T00:00:00.000Z',
    '2027-02-29T00:00:00.000Z',
    '2026-07-18T22:00:00Z',
    '2026-07-18T22:00:00.000+00:00',
    '2026-07-18t22:00:00.000z',
    ['2026-07-18T22:00:00.000Z'],
    0,
    null,
    // RFC 3339 section 5.7 and Appendix D: second 60 is valid only
    // at 23:59 on the last day of its month; 2026-04-08T12:00:60.000Z was
    // formerly accepted here and now moves to this list.
    '2026-04-08T12:00:60.000Z',
    '2026-06-29T23:59:60.000Z',
    '2016-12-31T23:58:60.000Z',
    '2016-12-31T22:59:60.000Z',
    '2028-02-28T23:59:60.000Z',
    '2027-02-29T23:59:60.000Z',
  ]
  for (const value of invalid) {
    assert.equal(isCanonicalTimestamp(value), false, JSON.stringify(value))
  }
})

test('compareCanonicalTimestamps: string order tracks time order through a leap second and a year rollover', () => {
  const chain = [
    '2016-12-31T23:59:59.999Z',
    '2016-12-31T23:59:60.000Z',
    '2016-12-31T23:59:60.999Z',
    '2017-01-01T00:00:00.000Z',
  ]
  for (let i = 0; i < chain.length - 1; i++) {
    assert.equal(compareCanonicalTimestamps(chain[i], chain[i + 1]), -1, `${chain[i]} should sort before ${chain[i + 1]}`)
    assert.equal(compareCanonicalTimestamps(chain[i + 1], chain[i]), 1, `${chain[i + 1]} should sort after ${chain[i]}`)
  }
  assert.equal(compareCanonicalTimestamps('2016-12-31T23:59:60.000Z', '2016-12-31T23:59:60.000Z'), 0)
})

test('a leap-second delegation chain verifies valid at a leap-second verification clock', () => {
  const [root, child] = buildLeapSecondChain()
  const checked = verifyAuthorityDelegationChain([root, child], activeOptions('2016-12-31T23:59:60.500Z', root.delegation_id))
  assert.equal(checked.state, 'valid')
  assert.equal(checked.valid, true)
  assert.deepEqual(checked.failures, [])
})

test('TIME_WIDENING is caught across a leap second, where Date.parse would give NaN >= NaN', () => {
  const root = issueAuthorityDelegation(
    rootBodyWith('2016-12-31T23:59:59.000Z', {
      not_before: '2016-12-31T23:59:59.000Z',
      not_after: '2016-12-31T23:59:60.999Z',
    }),
    ROOT_KEY,
  )
  // Built with issueAuthorityDelegation directly, not issueSubAuthorityDelegation: the
  // child is shape-valid on its own, but widens the parent's window at the chain level,
  // which is exactly what issueSubAuthorityDelegation would refuse to issue.
  const child = issueAuthorityDelegation(
    childBodyWith(root, '2016-12-31T23:59:60.000Z', {
      not_before: '2016-12-31T23:59:60.000Z',
      not_after: '2017-01-01T00:00:00.000Z',
    }),
    CHILD_KEY,
  )
  const checked = verifyAuthorityDelegationChain([root, child], activeOptions('2016-12-31T23:59:60.500Z', root.delegation_id))
  assert.equal(checked.state, 'invalid')
  assert.equal(checked.failures[0]?.code, 'TIME_WIDENING')
  assert.equal(checked.failures[0]?.index, 1)
})

test('EXPIRED is reported at the half-open ceiling: now equal to not_after expires the record', () => {
  const [root, child] = buildLeapSecondChain()
  const checked = verifyAuthorityDelegationChain([root, child], activeOptions('2017-01-01T00:00:01.000Z', root.delegation_id))
  assert.equal(checked.state, 'invalid')
  assert.equal(checked.failures[0]?.code, 'EXPIRED')
  assert.equal(checked.failures[0]?.index, 0)
})

test('year 0000 is accepted end to end, including a leap day inside the window', () => {
  const root = issueAuthorityDelegation(
    rootBodyWith('0000-01-01T00:00:00.000Z', {
      not_before: '0000-01-01T00:00:00.000Z',
      not_after: '0000-12-31T23:59:59.999Z',
    }),
    ROOT_KEY,
  )
  const checked = verifyAuthorityDelegationChain([root], activeOptions('0000-02-29T12:00:00.000Z', root.delegation_id))
  assert.equal(checked.state, 'valid')
  assert.equal(checked.valid, true)
})

test('reversibility ceiling is not coerced with String(): an array or a number is SCHEMA_INVALID', () => {
  for (const ceiling of [['compensable'], 1]) {
    const body = structuredClone(standardRootBody())
    ;(body.authority.reversibility as unknown as Record<string, unknown>).ceiling = ceiling
    const root = sign(body, ROOT_KEY)
    const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
    assert.equal(checked.state, 'invalid', JSON.stringify(ceiling))
    assert.equal(checked.failures[0]?.code, 'SCHEMA_INVALID', JSON.stringify(ceiling))
    assert.equal(checked.failures[0]?.index, 0, JSON.stringify(ceiling))
  }
})

test('an unsupported facet profile is unsupported: content is never judged once the profile is unrecognized', () => {
  const cases: Array<[string, (authority: Record<string, unknown>) => void]> = [
    ['scope: unsupported profile with an invalid grant', authority => {
      authority.scope = { profile: 'aps-hierarchical-v2', grants: ['commerce/checkout'] }
    }],
    ['scope: unsupported profile with an extra member', authority => {
      authority.scope = { profile: 'aps-hierarchical-v2', grants: ['commerce:*'], exclusions: [] }
    }],
    ['reputation: unsupported profile with an out-of-range ceiling', authority => {
      authority.reputation = { profile: 'aps-score-0-1000-v1', ceiling: 800 }
    }],
    ['values: unsupported profile with a non-identifier entry', authority => {
      authority.values = { profile: 'x values v2', required: ['not an identifier!'] }
    }],
    ['reversibility: unsupported profile with a foreign ceiling value', authority => {
      authority.reversibility = { profile: 'aps-tci-v2', ceiling: 'reversible' }
    }],
  ]
  for (const [name, mutate] of cases) {
    const body = structuredClone(standardRootBody())
    mutate(body.authority as unknown as Record<string, unknown>)
    const root = sign(body, ROOT_KEY)
    const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
    assert.equal(checked.state, 'unsupported', name)
    assert.deepEqual(checked.failures.map(item => item.code), ['UNSUPPORTED_PROFILE'], name)
    assert.equal(checked.failures[0]?.index, 0, name)
  }
})

test('a facet with no profile member, or a non-string profile, is SCHEMA_INVALID rather than unsupported', () => {
  const noProfile = structuredClone(standardRootBody())
  ;(noProfile.authority as unknown as Record<string, unknown>).scope = { grants: ['commerce:*'] }
  const rootA = sign(noProfile, ROOT_KEY)
  const checkedA = verifyAuthorityDelegationChain([rootA], activeOptions(STANDARD_NOW, rootA.delegation_id))
  assert.equal(checkedA.state, 'invalid')
  assert.equal(checkedA.failures[0]?.code, 'SCHEMA_INVALID')

  const numericProfile = structuredClone(standardRootBody())
  ;(numericProfile.authority as unknown as Record<string, unknown>).reputation = { profile: 5, ceiling: 80 }
  const rootB = sign(numericProfile, ROOT_KEY)
  const checkedB = verifyAuthorityDelegationChain([rootB], activeOptions(STANDARD_NOW, rootB.delegation_id))
  assert.equal(checkedB.state, 'invalid')
  assert.equal(checkedB.failures[0]?.code, 'SCHEMA_INVALID')
})

// ── Second round: record-wide I-JSON (RFC 7493 section 2.1), key resolver
// null/undefined equivalence, and budget ledger input guards. ──

/** A record whose JCS cannot be computed because it carries a lone surrogate:
 *  placeholder delegation_id and signature stand in for values that can never
 *  actually be derived, matching the shape validator's field-format checks. */
function unsignable(body: AuthorityDelegationBodyV1): AuthorityDelegationV1 {
  return { ...body, delegation_id: `sha256:${'0'.repeat(64)}`, signature: '0'.repeat(128) }
}

/** Builds an array nested `depth` levels deep, iteratively (no recursion). */
function nestedArray(depth: number): unknown[] {
  let arr: unknown[] = []
  for (let i = 1; i < depth; i++) arr = [arr]
  return arr
}

test('a noncharacter code point in issuer is SCHEMA_INVALID, decoded from its surrogate pair when needed', () => {
  const noncharacters = ['\uFDD0', '\uFFFF', '\u{1FFFE}', '\u{10FFFF}']
  for (const mark of noncharacters) {
    const body = structuredClone(standardRootBody())
    body.issuer = `did:example:principal${mark}`
    const root = sign(body, ROOT_KEY)
    const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
    assert.equal(checked.state, 'invalid', JSON.stringify(mark))
    assert.deepEqual(checked.failures.map(item => item.code), ['SCHEMA_INVALID'], JSON.stringify(mark))
  }
})

test('a lone surrogate in subject is SCHEMA_INVALID even when JCS cannot be computed', () => {
  const body = structuredClone(standardRootBody())
  body.subject = `${ROOT_SUBJECT}\ud800`
  const root = unsignable(body)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'invalid')
  assert.deepEqual(checked.failures.map(item => item.code), ['SCHEMA_INVALID'])
})

test('an unsupported scope profile with a noncharacter is SCHEMA_INVALID and UNSUPPORTED_PROFILE', () => {
  const body = structuredClone(standardRootBody())
  ;(body.authority as unknown as Record<string, unknown>).scope = {
    profile: 'aps-hierarchical-v2\uFFFF',
    grants: ['commerce:*'],
  }
  const root = sign(body, ROOT_KEY)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'invalid')
  assert.deepEqual(checked.failures.map(item => item.code), ['SCHEMA_INVALID', 'UNSUPPORTED_PROFILE'])
})

test('an unsupported values profile with a lone surrogate is SCHEMA_INVALID and UNSUPPORTED_PROFILE', () => {
  const body = structuredClone(standardRootBody())
  ;(body.authority as unknown as Record<string, unknown>).values = { profile: '\ud800', required: [] }
  const root = unsignable(body)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'invalid')
  assert.deepEqual(checked.failures.map(item => item.code), ['SCHEMA_INVALID', 'UNSUPPORTED_PROFILE'])
})

test('an unsupported version with a noncharacter is SCHEMA_INVALID and UNSUPPORTED_VERSION', () => {
  const body = structuredClone(standardRootBody())
  ;(body as unknown as Record<string, unknown>).version = '2.0\uFDD0'
  const root = sign(body, ROOT_KEY)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'invalid')
  assert.deepEqual(checked.failures.map(item => item.code), ['SCHEMA_INVALID', 'UNSUPPORTED_VERSION'])
})

test('a pathologically deep nested array under an unsupported scope profile does not throw', () => {
  const body = structuredClone(standardRootBody())
  ;(body.authority as unknown as Record<string, unknown>).scope = {
    profile: 'aps-hierarchical-v2',
    grants: [nestedArray(100000)],
  }
  const root = unsignable(body)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'unsupported')
})

test('a cyclic array under an unsupported scope profile does not throw', () => {
  const cyclic: unknown[] = []
  cyclic.push(cyclic)
  const body = structuredClone(standardRootBody())
  ;(body.authority as unknown as Record<string, unknown>).scope = {
    profile: 'aps-hierarchical-v2',
    grants: [cyclic],
  }
  const root = unsignable(body)
  const checked = verifyAuthorityDelegationChain([root], activeOptions(STANDARD_NOW, root.delegation_id))
  assert.equal(checked.state, 'unsupported')
})

test('a key resolver returning undefined for the root is indeterminate, KEY_RESOLUTION_FAILED, at index 0', () => {
  const root = issueAuthorityDelegation(standardRootBody(), ROOT_KEY)
  const checked = verifyAuthorityDelegationChain([root], {
    now: STANDARD_NOW,
    resolveVerificationKey: (() => undefined) as never,
    trustRoot: () => true,
    resolveRevocation: () => 'active',
  })
  assert.equal(checked.state, 'indeterminate')
  assert.equal(checked.failures[0]?.code, 'KEY_RESOLUTION_FAILED')
  assert.equal(checked.failures[0]?.index, 0)
})

test('budget reserve rejects a non-string actionRef instead of coercing it into a Map key, and a non-array verifiedChain instead of throwing', () => {
  const root = issueAuthorityDelegation(standardRootBody(), ROOT_KEY)
  const unit = 'iso4217:USD:minor'
  const ledger = new InMemoryAuthorityBudgetLedger()
  const badRef = ['ab'.repeat(32)] as any

  assert.deepEqual(ledger.reserve([root], badRef, unit, '1'), { ok: false, code: 'CONFLICT' })
  assert.deepEqual(ledger.reserve([root], badRef, unit, '1'), { ok: false, code: 'CONFLICT' })
  assert.deepEqual(ledger.reserve([root], badRef, unit, '1'), { ok: false, code: 'CONFLICT' })
  assert.equal(ledger.counter(root.delegation_id).reserved, '0')

  assert.equal(ledger.reserve(null as any, 'a'.repeat(64), unit, '1').code, 'CONFLICT')
  assert.equal(ledger.reserve({ 0: root } as any, 'b'.repeat(64), unit, '1').code, 'CONFLICT')
})
