// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Conformance and cross-language parity for the PROPOSED non-time bounds module.
//
// Every expectation comes from conformance/authority-bounds/v0/vectors.json, which is the
// SHARED fixture: the Python SDK vendors a byte-identical copy and runs the same cases
// through its own port. The file's SHA-256 is pinned in both repositories, so the two copies
// can be shown identical without either repo importing the other, and a one-sided edit fails
// on the side that was edited.
//
// On circularity. Every verdict, reason code, missing-limb set and refusal code in the file
// is hand specified. The `signature` and `exhaustion_id` byte values were minted once by the
// TypeScript implementation, and their purpose is the cross-language check: the Python port
// signs and content-addresses the same bodies and has to produce the same characters. Reading
// them back here proves determinism, and reading them in Python proves parity.

import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  AUTHORITY_BOUND_TYPE,
  AUTHORITY_BOUND_FULFILMENT_TYPE,
  AUTHORITY_EXHAUSTION_TYPE,
  BOUND_KINDS,
  BOUND_STATES,
  BOUND_REASON_CODES,
  FULFILMENT_REASON_CODES,
  ATTESTOR_ROLE_ANSWERS,
  AuthorityBoundError,
  assessFulfilment,
  evaluateBound,
  issueAuthorityBoundFulfilment,
  issueAuthorityExhaustion,
  verifyAuthorityExhaustion,
  signAuthorityBoundFulfilment,
  signAuthorityExhaustion,
  computeAuthorityExhaustionId,
  isPurposePermitted,
  purposeCategory,
  type AttestorRoleAnswer,
  type AuthorityBound,
  type AuthorityBoundFulfilment,
  type AuthorityBoundFulfilmentBody,
  type AuthorityExhaustion,
  type BoundEvaluation,
} from '../../src/v2/bounds/index.js'
import { verifyAuthorityDelegationChain } from '../../src/v2/authority-delegation/verify.js'
import { InMemoryAuthorityBudgetLedger } from '../../src/v2/authority-delegation/budget.js'
import { isPurposePermitted as isPurposePermittedOriginal } from '../../src/core/data-lifecycle.js'

const here = dirname(fileURLToPath(import.meta.url))
const vectorsPath = join(here, '..', '..', 'conformance', 'authority-bounds', 'v0', 'vectors.json')
const vectorsBytes = readFileSync(vectorsPath)

/** Pinned so the Python SDK's vendored copy can be shown byte identical. If this moves, the
 *  Python repo's copy and its own pin move with it, in the same change. */
const VECTORS_SHA256 = '7d8818f4d28661876bfc73a8ae7f2dce27e132ee942706d10a6ae8c460dac7f2'

interface RoleTable {
  [party: string]: AttestorRoleAnswer
}

interface Vectors {
  profile: string
  vocabulary: {
    bound_kinds: string[]
    bound_states: string[]
    bound_reason_codes: string[]
    fulfilment_reason_codes: string[]
    attestor_role_answers: string[]
  }
  record_types: { bound: string; fulfilment: string; exhaustion: string }
  keys: Record<string, { private_key: string; public_key: string }>
  resolvers: { roles: RoleTable; keys: Record<string, string> }
  assessment_cases: Array<{
    id: string
    bound: AuthorityBound
    record: AuthorityBoundFulfilment
    at_instant: string
    expected: {
      accepted: boolean
      reason_code: string
      role_answer?: string
      missing?: string[]
    }
  }>
  evaluation_cases: Array<{
    id: string
    bound: AuthorityBound
    fulfilments: AuthorityBoundFulfilment[]
    at_instant: string
    consumed?: string
    budget_counter?: { committed: string; reserved: string }
    expected: {
      bound_state: string
      reason_code: string
      ending: string | null
      lifecycle: { verdict: string; reason_code: string; missing?: string[] }
      remaining?: string
      fulfilment_reason_codes: string[]
    }
  }>
  purpose_membership_cases: Array<{
    id: string
    requested: string
    allowed: string[]
    expected: boolean
  }>
  purpose_category_cases: Array<{ id: string; purpose: string; expected: string }>
  exhaustion_record_cases: Array<{
    id: string
    record: AuthorityExhaustion
    unresolvable_key?: boolean
    expected: { status: string; failures: string[]; evidence_length?: number }
  }>
  refusal_cases: Array<{
    id: string
    bound?: AuthorityBound
    consumed?: string
    with_records?: boolean
    omit_resolver?: string
    evaluation_of?: string
    expected_error_code: string
  }>
  signature_cases: Array<{
    id: string
    body?: AuthorityBoundFulfilmentBody
    exhaustion_body?: Omit<AuthorityExhaustion, 'signature' | 'exhaustion_id'>
    private_key: string
    expected_signature: string
    expected_exhaustion_id?: string
  }>
}

const vectors = JSON.parse(vectorsBytes.toString('utf8')) as Vectors

const resolveAttestorRole = (attestor: string): AttestorRoleAnswer =>
  vectors.resolvers.roles[attestor] ?? 'unknown'
const resolveVerificationKey = (_attestor: string, method: string): string | null =>
  vectors.resolvers.keys[method] ?? null

describe('v2/bounds: shared fixture', () => {
  test('the vectors file is the pinned bytes', () => {
    assert.equal(createHash('sha256').update(vectorsBytes).digest('hex'), VECTORS_SHA256)
  })

  test('the module vocabulary matches the fixture vocabulary exactly', () => {
    assert.deepEqual([...BOUND_KINDS], vectors.vocabulary.bound_kinds)
    assert.deepEqual([...BOUND_STATES], vectors.vocabulary.bound_states)
    assert.deepEqual([...BOUND_REASON_CODES], vectors.vocabulary.bound_reason_codes)
    assert.deepEqual([...FULFILMENT_REASON_CODES], vectors.vocabulary.fulfilment_reason_codes)
    assert.deepEqual([...ATTESTOR_ROLE_ANSWERS], vectors.vocabulary.attestor_role_answers)
  })

  test('the record types are the proposed ones, not aps: ones', () => {
    assert.equal(AUTHORITY_BOUND_TYPE, vectors.record_types.bound)
    assert.equal(AUTHORITY_BOUND_FULFILMENT_TYPE, vectors.record_types.fulfilment)
    assert.equal(AUTHORITY_EXHAUSTION_TYPE, vectors.record_types.exhaustion)
    for (const value of Object.values(vectors.record_types)) {
      assert.ok(value.startsWith('proposed:'), `${value} must be marked proposed on the wire`)
    }
  })
})

describe('v2/bounds: assessing one fulfilment record', () => {
  for (const vec of vectors.assessment_cases) {
    test(vec.id, () => {
      const got = assessFulfilment({
        bound: vec.bound,
        record: vec.record,
        atInstant: vec.at_instant,
        resolveAttestorRole,
        resolveVerificationKey,
      })
      assert.equal(got.accepted, vec.expected.accepted)
      assert.equal(got.reason_code, vec.expected.reason_code)
      if (vec.expected.role_answer === undefined) {
        assert.equal(got.role_answer, undefined)
      } else {
        assert.equal(got.role_answer, vec.expected.role_answer)
      }
      if (vec.expected.missing === undefined) {
        assert.equal(got.missing, undefined)
      } else {
        assert.deepEqual([...(got.missing ?? [])], vec.expected.missing)
      }
    })
  }
})

describe('v2/bounds: evaluating a bound', () => {
  for (const vec of vectors.evaluation_cases) {
    test(vec.id, () => {
      const got = evaluateBound({
        bound: vec.bound,
        fulfilments: vec.fulfilments,
        atInstant: vec.at_instant,
        resolveAttestorRole,
        resolveVerificationKey,
        ...(vec.consumed !== undefined ? { consumed: vec.consumed } : {}),
        ...(vec.budget_counter !== undefined ? { budgetCounter: vec.budget_counter } : {}),
      })
      assert.equal(got.bound_state, vec.expected.bound_state)
      assert.equal(got.reason_code, vec.expected.reason_code)
      assert.equal(got.ending, vec.expected.ending)
      assert.equal(got.lifecycle.verdict, vec.expected.lifecycle.verdict)
      assert.equal(got.lifecycle.reason_code, vec.expected.lifecycle.reason_code)
      if (vec.expected.lifecycle.missing === undefined) {
        assert.equal(got.lifecycle.missing, undefined)
      } else {
        assert.deepEqual([...(got.lifecycle.missing ?? [])], vec.expected.lifecycle.missing)
      }
      if (vec.expected.remaining === undefined) {
        assert.equal(got.remaining, undefined)
      } else {
        assert.equal(got.remaining, vec.expected.remaining)
      }
      assert.deepEqual(
        got.fulfilments.map(f => f.reason_code),
        vec.expected.fulfilment_reason_codes,
      )
      // `ending` is exhaustion exactly when the state is exhausted, and never anything else.
      assert.equal(got.ending, got.bound_state === 'exhausted' ? 'exhaustion' : null)
    })
  }
})

describe('v2/bounds: purpose membership, which is not exhaustion', () => {
  for (const vec of vectors.purpose_membership_cases) {
    test(vec.id, () => {
      assert.equal(isPurposePermitted(vec.requested, vec.allowed), vec.expected)
    })
  }
  for (const vec of vectors.purpose_category_cases) {
    test(vec.id, () => {
      assert.equal(purposeCategory(vec.purpose), vec.expected)
    })
  }
  test('the re-export is the same function object the old path exports', () => {
    assert.equal(isPurposePermitted, isPurposePermittedOriginal)
  })
})

describe('v2/bounds: the optional exhaustion record', () => {
  for (const vec of vectors.exhaustion_record_cases) {
    test(vec.id, () => {
      const resolve = vec.unresolvable_key === true ? () => null : () => vectors.keys.boundary.public_key
      const got = verifyAuthorityExhaustion(vec.record, resolve)
      assert.equal(got.status, vec.expected.status)
      assert.deepEqual([...got.failures], vec.expected.failures)
      if (vec.expected.evidence_length !== undefined) {
        assert.equal(vec.record.evidence.length, vec.expected.evidence_length)
      }
    })
  }
})

describe('v2/bounds: refusals', () => {
  const purposeBound = vectors.evaluation_cases[0].bound
  const notEstablishedCase = vectors.evaluation_cases.find(
    v => v.expected.bound_state === 'not_established',
  )
  assert.ok(notEstablishedCase, 'the fixture must carry a not_established evaluation case')

  test('AB-R-01-an-exhaustion-record-cannot-be-minted-for-a-state-that-is-not-exhausted', () => {
    const evaluation: BoundEvaluation = evaluateBound({
      bound: notEstablishedCase.bound,
      fulfilments: notEstablishedCase.fulfilments,
      atInstant: notEstablishedCase.at_instant,
      resolveAttestorRole,
      resolveVerificationKey,
    })
    assert.equal(evaluation.bound_state, 'not_established')
    assert.throws(
      () =>
        issueAuthorityExhaustion(
          evaluation,
          purposeBound.delegation_id,
          {
            boundary: 'did:example:boundary',
            verification_method: 'did:example:boundary#k1',
            found_at: '2026-09-23T10:00:00.000Z',
          },
          vectors.keys.boundary.private_key,
        ),
      (error: unknown) =>
        error instanceof AuthorityBoundError &&
        error.code === 'EXHAUSTION_STATE_NOT_EXHAUSTED',
    )
  })

  for (const vec of vectors.refusal_cases.filter(v => v.id !== 'AB-R-01-an-exhaustion-record-cannot-be-minted-for-a-state-that-is-not-exhausted')) {
    test(vec.id, () => {
      const bound = vec.bound as AuthorityBound
      const withRecords = vec.with_records === true
      const source = vectors.evaluation_cases.find(v => v.fulfilments.length > 0)
      assert.ok(source, 'the fixture must carry an evaluation case with records')
      assert.throws(
        () =>
          evaluateBound({
            bound,
            fulfilments: withRecords ? source.fulfilments : [],
            atInstant: '2026-09-23T10:00:00.000Z',
            ...(vec.omit_resolver === 'role' ? {} : { resolveAttestorRole }),
            ...(vec.omit_resolver === 'key' ? {} : { resolveVerificationKey }),
            ...(vec.consumed !== undefined ? { consumed: vec.consumed } : {}),
          }),
        (error: unknown) =>
          error instanceof AuthorityBoundError && error.code === vec.expected_error_code,
      )
    })
  }
})

describe('v2/bounds: byte determinism across languages', () => {
  for (const vec of vectors.signature_cases) {
    test(vec.id, () => {
      if (vec.body !== undefined) {
        assert.equal(signAuthorityBoundFulfilment(vec.body, vec.private_key), vec.expected_signature)
        const reissued = issueAuthorityBoundFulfilment(
          {
            bound_id: vec.body.bound_id,
            delegation_id: vec.body.delegation_id,
            attestor: vec.body.attestor,
            verification_method: vec.body.verification_method,
            attested_at: vec.body.attested_at,
            outcome: vec.body.outcome,
            reason_code: vec.body.reason_code,
            ...(vec.body.detail !== undefined ? { detail: vec.body.detail } : {}),
          },
          vec.private_key,
        )
        assert.equal(reissued.signature, vec.expected_signature)
      }
      if (vec.exhaustion_body !== undefined) {
        const id = computeAuthorityExhaustionId(vec.exhaustion_body)
        assert.equal(id, vec.expected_exhaustion_id)
        assert.equal(
          signAuthorityExhaustion({ ...vec.exhaustion_body, exhaustion_id: id }, vec.private_key),
          vec.expected_signature,
        )
      }
    })
  }
})

describe('v2/bounds: nothing existing changed', () => {
  test('a bound evaluation is never merged into a chain result', () => {
    // A three-field empty chain call, to show the chain verifier's own contract is untouched
    // by importing this module: it still returns one of the four draft-03 states with a
    // stable failure code, and `evaluateBound` has no way to reach into it.
    const chain = verifyAuthorityDelegationChain([], {
      now: '2026-09-23T10:00:00.000Z',
      resolveVerificationKey: () => null,
      trustRoot: () => false,
      resolveRevocation: () => ({ status: 'active' }) as never,
    })
    assert.ok(['valid', 'invalid', 'indeterminate', 'unsupported'].includes(chain.state))
    assert.equal(Object.prototype.hasOwnProperty.call(chain, 'bound_state'), false)
    assert.equal(Object.prototype.hasOwnProperty.call(chain, 'ending'), false)
  })

  test('the budget kind reads the ledger counter shape rather than a shape of its own', () => {
    const ledger = new InMemoryAuthorityBudgetLedger()
    const counter = ledger.counter('sha256:' + 'a'.repeat(64))
    const budgetCase = vectors.evaluation_cases.find(v => v.bound.kind === 'budget')
    assert.ok(budgetCase, 'the fixture must carry a budget evaluation case')
    // The empty ledger's counter is a valid input to evaluateBound without translation.
    const got = evaluateBound({
      bound: budgetCase.bound,
      atInstant: '2026-09-22T14:00:00.000Z',
      budgetCounter: counter,
    })
    assert.equal(got.bound_state, 'not_reached')
    assert.equal(got.ending, null)
  })

  test('a purpose bound with no records and no resolvers does not throw', () => {
    const purposeCase = vectors.evaluation_cases[0]
    const got = evaluateBound({
      bound: purposeCase.bound,
      atInstant: purposeCase.at_instant,
    })
    assert.equal(got.bound_state, 'not_reached')
  })
})
