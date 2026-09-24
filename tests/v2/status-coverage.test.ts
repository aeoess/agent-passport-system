// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Conformance and cross-language parity for the PROPOSED multi-source status decision.
//
// Every expectation comes from conformance/status-coverage/v0/vectors.json, which is the
// SHARED fixture: the Python SDK vendors a byte-identical copy and runs the same cases
// through its own port. Expectations are hand specified in the vectors, never computed by
// the code under test, so the test is not circular. The file's SHA-256 is pinned in both
// repositories, so the two copies can be shown identical without either repo importing the
// other.

import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  STATUS_ANSWERS,
  DETERMINATE_STATUS_ANSWERS,
  STATUS_USE_BASES,
  STATUS_COVERAGE_REASON_CODES,
  StatusCoverageError,
  decideMultiSourceStatus,
} from '../../src/v2/status-coverage/index.js'
import type { MultiSourceStatusInput } from '../../src/v2/status-coverage/index.js'
import { verifyAuthorityDelegationChain } from '../../src/v2/authority-delegation/verify.js'

const here = dirname(fileURLToPath(import.meta.url))
const vectorsPath = join(here, '..', '..', 'conformance', 'status-coverage', 'v0', 'vectors.json')
const vectorsBytes = readFileSync(vectorsPath)

/** Pinned so the Python SDK's vendored copy can be shown byte identical. If this moves,
 *  the Python repo's copy and its own pin move with it, in the same change. */
const VECTORS_SHA256 = 'dc3c0165d9e90488a772c14ffe2ba64fefe90c504b7d48d8aa3cd916bd6649e5'

interface DecisionCase {
  id: string
  tests: string
  input: Record<string, unknown>
  expected: {
    outcome: string
    reason_code: string
    lifecycle: Record<string, unknown>
    basis: Record<string, unknown>
  }
}

interface ErrorCase {
  id: string
  tests: string
  input: Record<string, unknown>
  expected: { error_code: string }
}

interface Vectors {
  profile: string
  vocabulary: {
    status_answers: string[]
    determinate_status_answers: string[]
    status_use_bases: string[]
    reason_codes: string[]
  }
  decision_cases: DecisionCase[]
  error_cases: ErrorCase[]
}

const vectors = JSON.parse(vectorsBytes.toString('utf8')) as Vectors

/** The vectors use the wire names. The TypeScript surface uses camelCase for the three
 *  parameters that are not part of the record, exactly as the Python port uses snake_case
 *  keyword arguments. Nothing else is translated. */
function toInput(raw: Record<string, unknown>): MultiSourceStatusInput {
  return {
    authority_ref: raw.authority_ref,
    trustPolicy: raw.trust_policy,
    answers: raw.answers,
    conflictPolicy: raw.conflict_policy,
    stalePolicy: raw.stale_policy,
    now: raw.now,
  } as unknown as MultiSourceStatusInput
}

/** JSON-shaped view of a decision, so the comparison against the shared vectors is the
 *  same comparison the Python port makes. `undefined` never survives JSON, so the round
 *  trip also proves the result carries no undefined-valued field. */
function asJson(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value))
}

describe('status-coverage: shared fixture', () => {
  test('the vectors file is the pinned bytes', () => {
    const digest = createHash('sha256').update(vectorsBytes).digest('hex')
    assert.equal(digest, VECTORS_SHA256)
  })

  test('the fixture declares the profile this module implements', () => {
    assert.equal(vectors.profile, 'aps-status-coverage-v0')
  })

  test('the vocabulary in the fixture is the vocabulary in the code', () => {
    assert.deepEqual([...STATUS_ANSWERS], vectors.vocabulary.status_answers)
    assert.deepEqual(
      [...DETERMINATE_STATUS_ANSWERS],
      vectors.vocabulary.determinate_status_answers,
    )
    assert.deepEqual([...STATUS_USE_BASES], vectors.vocabulary.status_use_bases)
    assert.deepEqual([...STATUS_COVERAGE_REASON_CODES], vectors.vocabulary.reason_codes)
  })

  test('every case id is unique', () => {
    const ids = [
      ...vectors.decision_cases.map(c => c.id),
      ...vectors.error_cases.map(c => c.id),
    ]
    assert.equal(new Set(ids).size, ids.length)
  })
})

describe('status-coverage: decision vectors', () => {
  for (const vector of vectors.decision_cases) {
    test(`${vector.id}: ${vector.tests}`, () => {
      const decision = decideMultiSourceStatus(toInput(vector.input))
      assert.equal(decision.outcome, vector.expected.outcome)
      assert.equal(decision.reason_code, vector.expected.reason_code)
      assert.deepEqual(asJson(decision.lifecycle), vector.expected.lifecycle)
      assert.deepEqual(asJson(decision.basis), vector.expected.basis)
    })
  }
})

describe('status-coverage: refusals', () => {
  for (const vector of vectors.error_cases) {
    test(`${vector.id}: ${vector.tests}`, () => {
      assert.throws(
        () => decideMultiSourceStatus(toInput(vector.input)),
        (error: unknown) => {
          assert.ok(error instanceof StatusCoverageError)
          assert.equal(error.code, vector.expected.error_code)
          return true
        },
      )
    })
  }
})

const baseInput: MultiSourceStatusInput = {
  authority_ref: 'delegation:alpha',
  trustPolicy: {
    mode: 'online',
    sources: {
      required: [{ source_id: 'registry-a', freshness_bound_s: 300 }],
      silence_is: 'coverage_gap',
    },
  },
  answers: [{ source_id: 'registry-a', answer: 'active', as_of: '2026-09-20T11:59:00Z' }],
  conflictPolicy: 'deny_with_conflict',
  stalePolicy: { stale_revoked_still_counts: true, stale_active_still_counts: false },
  now: '2026-09-20T12:00:00Z',
}

describe('status-coverage: properties the vectors cannot state', () => {
  test('a later boundary never rewrites an earlier decision', () => {
    // SC-02 then SC-18. The earlier record is held across the later decision and compared
    // afterwards. Later findings never rewrite earlier receipts: the second boundary is a
    // new decision that says nothing about the first.
    const earlierVector = vectors.decision_cases.find(
      c => c.id === 'SC-02-two-sources-agree-active-admits',
    )
    const laterVector = vectors.decision_cases.find(c => c.id === 'SC-18-later-boundary-conflicts')
    assert.ok(earlierVector && laterVector)
    const earlier = decideMultiSourceStatus(toInput(earlierVector.input))
    const earlierSnapshot = JSON.stringify(earlier)
    const later = decideMultiSourceStatus(toInput(laterVector.input))
    assert.equal(later.outcome, 'denied')
    assert.equal(JSON.stringify(earlier), earlierSnapshot)
    assert.equal(earlier.outcome, 'authorized')
  })

  test('the decision and its basis are frozen', () => {
    const decision = decideMultiSourceStatus(baseInput)
    assert.ok(Object.isFrozen(decision))
    assert.ok(Object.isFrozen(decision.basis))
    assert.ok(Object.isFrozen(decision.basis.coverage))
    assert.ok(Object.isFrozen(decision.basis.sources_consulted))
    assert.ok(Object.isFrozen(decision.basis.sources_consulted[0]))
  })

  test('the caller input is not mutated', () => {
    const before = JSON.stringify(baseInput)
    decideMultiSourceStatus(baseInput)
    assert.equal(JSON.stringify(baseInput), before)
  })

  test('the module reads no clock: the same input decides the same way twice', () => {
    const first = decideMultiSourceStatus(baseInput)
    const second = decideMultiSourceStatus(baseInput)
    assert.deepEqual(asJson(first), asJson(second))
  })

  test('a null as_of on an unavailable answer is the same as an absent one', () => {
    // Python has one absent value where TypeScript has two. A vector that writes
    // "as_of": null must not decide differently from one that omits the key.
    const withNull = decideMultiSourceStatus({
      ...baseInput,
      answers: [{ source_id: 'registry-a', answer: 'unavailable', as_of: undefined }],
    })
    const rawNull = decideMultiSourceStatus(
      toInput({
        authority_ref: 'delegation:alpha',
        trust_policy: baseInput.trustPolicy,
        answers: [{ source_id: 'registry-a', answer: 'unavailable', as_of: null }],
        conflict_policy: 'deny_with_conflict',
        stale_policy: baseInput.stalePolicy,
        now: '2026-09-20T12:00:00Z',
      }),
    )
    assert.deepEqual(asJson(withNull), asJson(rawNull))
    assert.equal(rawNull.reason_code, 'STATUS_NO_USABLE_OBSERVATION')
  })

  test('a not_established decision always names at least one establishment limb', () => {
    for (const vector of vectors.decision_cases) {
      const decision = decideMultiSourceStatus(toInput(vector.input))
      if (decision.lifecycle.verdict === 'not_established') {
        assert.ok(
          decision.lifecycle.missing !== undefined && decision.lifecycle.missing.length > 0,
          `${vector.id} returned not_established with no limb`,
        )
      }
    }
  })

  test('a conflict never makes the artifact invalid and never admits', () => {
    for (const vector of vectors.decision_cases) {
      const decision = decideMultiSourceStatus(toInput(vector.input))
      if (decision.basis.conflict !== null) {
        assert.equal(decision.lifecycle.verdict, 'not_established')
        assert.notEqual(decision.outcome, 'authorized')
      }
    }
  })

  test('an offline admission always records the snapshot and the age it admitted at', () => {
    // The `offline-admit-without-recording` control: an admission whose record cannot be
    // recomputed from itself is the defect this field exists to catch.
    for (const vector of vectors.decision_cases) {
      const decision = decideMultiSourceStatus(toInput(vector.input))
      if (decision.reason_code === 'ADMITTED_ON_SNAPSHOT_WITHIN_DECLARED_BOUND') {
        assert.equal(decision.outcome, 'authorized')
        assert.ok(decision.basis.snapshot !== null)
        assert.ok(typeof decision.basis.snapshot?.as_of === 'string')
        assert.ok(typeof decision.basis.snapshot?.age_s === 'number')
        assert.ok(typeof decision.basis.snapshot?.declared_bound_s === 'number')
        assert.ok(
          (decision.basis.snapshot?.age_s ?? 1) <= (decision.basis.snapshot?.declared_bound_s ?? 0),
        )
      } else {
        assert.equal(decision.basis.snapshot, null)
      }
    }
  })

  test('the basis echoes both policies and the silence reading back', () => {
    // A record that does not say which reading produced it cannot be compared against a
    // record produced under the other reading.
    const decision = decideMultiSourceStatus(baseInput)
    assert.equal(decision.basis.conflict_policy, 'deny_with_conflict')
    assert.equal(decision.basis.stale_policy.stale_revoked_still_counts, true)
    assert.equal(decision.basis.stale_policy.stale_active_still_counts, false)
    assert.equal(decision.basis.silence_is, 'coverage_gap')
    assert.deepEqual(Object.keys(decision.basis.stale_policy).sort(), [
      'stale_active_still_counts',
      'stale_revoked_still_counts',
    ])
  })
})

describe('status-coverage: nothing existing changed', () => {
  test('chain verification still returns its own four-value vocabulary', () => {
    // The module is reported ALONGSIDE a chain result and never merged into it. A chain
    // with no members is still whatever the chain verifier already said it was.
    const result = verifyAuthorityDelegationChain([], {
      now: '2026-09-20T12:00:00Z',
      resolveVerificationKey: () => null,
      trustRoot: () => false,
      resolveRevocation: () => 'active',
    })
    assert.ok(['valid', 'invalid', 'indeterminate', 'unsupported'].includes(result.state))
    assert.equal((result as unknown as Record<string, unknown>).lifecycle, undefined)
    assert.equal((result as unknown as Record<string, unknown>).basis, undefined)
  })
})
