// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Conformance and cross-language parity for the PROPOSED lifecycle state vocabulary.
//
// Every expectation comes from conformance/lifecycle-state/v0/vectors.json, which is the
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
  LIFECYCLE_VERDICTS,
  BOUNDARY_OUTCOMES,
  ESTABLISHMENT_GAPS,
  ESTABLISHED_NEGATIVE_SHAPES,
  LifecycleStateError,
  lifecycleState,
  notEstablished,
  resolveEstablishedNegative,
  mapAuthorityValidationToLifecycle,
  isLifecycleVerdict,
  isBoundaryOutcome,
  isEstablishmentGap,
} from '../../src/v2/lifecycle-state/index.js'
import { verifyAuthorityDelegationChain } from '../../src/v2/authority-delegation/verify.js'
import type { AuthorityValidationResult } from '../../src/v2/authority-delegation/types.js'

const here = dirname(fileURLToPath(import.meta.url))
const vectorsPath = join(here, '..', '..', 'conformance', 'lifecycle-state', 'v0', 'vectors.json')
const vectorsBytes = readFileSync(vectorsPath)

/** Pinned so the Python SDK's vendored copy can be shown byte identical. If this moves,
 *  the Python repo's copy and its own pin move with it, in the same change. */
const VECTORS_SHA256 = 'e2efab4001ee7593cdd38a3f6bfb9d35e9946e865f93ae62c71c8587d1cccf6f'

interface Vectors {
  profile: string
  vocabulary: {
    verdicts: string[]
    boundary_outcomes: string[]
    establishment_gaps: string[]
    established_negative_shapes: string[]
  }
  constructor_cases: Array<{
    id: string
    input: Record<string, unknown>
    expected: { ok: boolean; result?: Record<string, unknown>; error_code?: string }
  }>
  established_negative_cases: Array<{
    id: string
    shape: string
    expected: Record<string, unknown>
  }>
  mapping_cases: Array<{
    id: string
    chain_result: AuthorityValidationResult
    options?: { not_yet_valid_as_not_yet_effective?: boolean }
    expected: {
      verdict: string
      reason_code: string
      missing?: string[]
      not_verdict?: string[]
      missing_excludes?: string[]
    }
  }>
}

const vectors = JSON.parse(vectorsBytes.toString('utf8')) as Vectors

describe('lifecycle-state: shared fixture', () => {
  test('the vectors file is the pinned bytes', () => {
    assert.equal(createHash('sha256').update(vectorsBytes).digest('hex'), VECTORS_SHA256)
  })

  test('the module vocabulary matches the fixture vocabulary exactly', () => {
    assert.deepEqual([...LIFECYCLE_VERDICTS], vectors.vocabulary.verdicts)
    assert.deepEqual([...BOUNDARY_OUTCOMES], vectors.vocabulary.boundary_outcomes)
    assert.deepEqual([...ESTABLISHMENT_GAPS], vectors.vocabulary.establishment_gaps)
    assert.deepEqual([...ESTABLISHED_NEGATIVE_SHAPES], vectors.vocabulary.established_negative_shapes)
  })

  test('there are exactly six artifact verdicts', () => {
    assert.equal(LIFECYCLE_VERDICTS.length, 6)
  })
})

describe('lifecycle-state: constructor cases', () => {
  for (const vector of vectors.constructor_cases) {
    test(vector.id, () => {
      if (vector.expected.ok) {
        const result = lifecycleState(vector.input as never)
        assert.deepEqual(JSON.parse(JSON.stringify(result)), vector.expected.result)
        // No truthiness shortcut: not_established is not a boolean's false branch.
        assert.equal('valid' in (result as object), false)
      } else {
        assert.throws(
          () => lifecycleState(vector.input as never),
          (error: unknown) => {
            assert.ok(error instanceof LifecycleStateError, `${vector.id}: wrong error type`)
            assert.equal(error.code, vector.expected.error_code)
            return true
          },
        )
      }
    })
  }
})

describe('lifecycle-state: established negatives', () => {
  for (const vector of vectors.established_negative_cases) {
    test(vector.id, () => {
      if (vector.expected.error_code !== undefined) {
        assert.throws(
          () => resolveEstablishedNegative(vector.shape as never),
          (error: unknown) => {
            assert.ok(error instanceof LifecycleStateError)
            assert.equal(error.code, vector.expected.error_code)
            return true
          },
        )
        return
      }
      const resolution = resolveEstablishedNegative(vector.shape as never)
      assert.deepEqual(
        JSON.parse(JSON.stringify({ ...resolution, shape: undefined })),
        { ...vector.expected },
      )
      // None of the three is ever the evidential not established.
      const output = 'verdict' in resolution ? resolution.verdict : resolution.outcome
      assert.notEqual(output, 'not_established')
    })
  }
})

describe('lifecycle-state: mapping from an existing chain result', () => {
  for (const vector of vectors.mapping_cases) {
    test(vector.id, () => {
      const options =
        vector.options?.not_yet_valid_as_not_yet_effective === undefined
          ? undefined
          : { notYetValidAsNotYetEffective: vector.options.not_yet_valid_as_not_yet_effective }
      const result = mapAuthorityValidationToLifecycle(vector.chain_result, options)
      assert.equal(result.verdict, vector.expected.verdict, `${vector.id}: verdict`)
      assert.equal(result.reason_code, vector.expected.reason_code, `${vector.id}: reason_code`)
      if (vector.expected.missing !== undefined) {
        assert.deepEqual([...(result.missing ?? [])], vector.expected.missing)
      } else {
        assert.equal(result.missing, undefined)
      }
      for (const forbidden of vector.expected.not_verdict ?? []) {
        assert.notEqual(result.verdict, forbidden)
      }
      for (const forbidden of vector.expected.missing_excludes ?? []) {
        assert.equal((result.missing ?? []).includes(forbidden as never), false)
      }
    })
  }

  test('the mapping never mutates the result it was given', () => {
    const input: AuthorityValidationResult = {
      state: 'invalid',
      valid: false,
      failures: [{ code: 'REVOKED', message: 'revoked' }],
    }
    const before = JSON.stringify(input)
    mapAuthorityValidationToLifecycle(input)
    assert.equal(JSON.stringify(input), before)
  })

  test('an unrecognised chain state is not established, not invalid', () => {
    const result = mapAuthorityValidationToLifecycle({
      state: 'perhaps' as never,
      valid: false,
      failures: [],
    })
    assert.equal(result.verdict, 'not_established')
    assert.equal(result.reason_code, 'CHAIN_STATE_UNRECOGNISED')
    assert.deepEqual([...(result.missing ?? [])], ['source'])
  })
})

describe('lifecycle-state: existing behaviour is unchanged', () => {
  // The point of the module is that it is a second vocabulary reported alongside the
  // draft-03 one, never in place of it. This runs the real chain verifier and asserts its
  // four-value answer is what it always was, then maps it without touching it.
  test('verifyAuthorityDelegationChain still returns the draft-03 four-value result', () => {
    const chainResult = verifyAuthorityDelegationChain([] as never, {
      now: '2026-09-23T00:00:00Z',
      resolveVerificationKey: () => null,
      trustRoot: () => true,
      resolveRevocation: () => 'active',
    })
    assert.ok(['valid', 'invalid', 'indeterminate', 'unsupported'].includes(chainResult.state))
    assert.equal(typeof chainResult.valid, 'boolean')
    const lifecycle = mapAuthorityValidationToLifecycle(chainResult)
    assert.ok(isLifecycleVerdict(lifecycle.verdict))
    // Composite shape: the chain result is carried whole, not replaced.
    const composite = { chain: chainResult, lifecycle }
    assert.equal(composite.chain.state, chainResult.state)
  })
})

describe('lifecycle-state: predicates and helpers', () => {
  test('predicates accept only their own vocabulary', () => {
    assert.equal(isLifecycleVerdict('restricted'), true)
    assert.equal(isLifecycleVerdict('exercisable'), false)
    assert.equal(isLifecycleVerdict('authorized'), false)
    assert.equal(isBoundaryOutcome('denied'), true)
    assert.equal(isBoundaryOutcome('invalid'), false)
    assert.equal(isEstablishmentGap('coverage'), true)
    assert.equal(isEstablishmentGap('standing'), false)
  })

  test('notEstablished carries its limbs through the same rules', () => {
    const result = notEstablished(['freshness'], 'STATUS_STALE_BEYOND_BOUND')
    assert.equal(result.verdict, 'not_established')
    assert.deepEqual([...(result.missing ?? [])], ['freshness'])
    assert.throws(() => notEstablished([], 'STATUS_STALE_BEYOND_BOUND'), LifecycleStateError)
  })

  test('a built result is frozen', () => {
    const result = lifecycleState({ verdict: 'valid', reason_code: 'CHAIN_VALID' })
    assert.equal(Object.isFrozen(result), true)
  })
})
