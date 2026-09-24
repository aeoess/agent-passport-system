// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Conformance and cross-language parity for the PROPOSED suspension-cause module.
//
// Every expectation comes from conformance/suspension-causes/v0/vectors.json, which is the
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
  PAUSE_KINDS,
  RELEASE_STANDINGS,
  SUSPENSION_CAUSE_TYPE,
  SUSPENSION_RELEASE_TYPE,
  SUSPENSION_REASON_CODES,
  SuspensionCauseError,
  evaluatePauseState,
  explainPauseState,
  composeChainAndPause,
  suspensionRecordPreimage,
  type PauseStateInput,
  type ReleaseStanding,
  type SuspensionCause,
  type SuspensionRelease,
} from '../../src/v2/suspension/index.js'
import { lifecycleState, notEstablished } from '../../src/v2/lifecycle-state/state.js'
import type { LifecycleStateResult } from '../../src/v2/lifecycle-state/types.js'

const here = dirname(fileURLToPath(import.meta.url))
const vectorsPath = join(here, '..', '..', 'conformance', 'suspension-causes', 'v0', 'vectors.json')
const vectorsBytes = readFileSync(vectorsPath)

/** Pinned so the Python SDK's vendored copy can be shown byte identical. If this moves, the
 *  Python repo's copy and its own pin move with it, in the same change. */
const VECTORS_SHA256 = 'fc4c04b53299d35cb7bc810565f5bf8b7a1fea1d5b2e53478778a3642728df97'

interface ExpectedState {
  verdict: string
  reason_code: string
  missing?: string[]
  outstanding?: Array<{ id: string; kind: string; reason_code: string }>
  cause_dispositions?: Record<string, string>
  released_by?: Record<string, string>
  release_dispositions?: Record<string, string>
  release_cause_dispositions?: Record<string, string>
  release_cause_count?: Record<string, number>
}

interface Vectors {
  profile: string
  clock: Record<string, string>
  delegation_id: string
  other_delegation_id: string
  verification_keys: Record<string, string>
  causes: Record<string, SuspensionCause>
  releases: Record<string, SuspensionRelease>
  standing_resolver: {
    standing_registry: Record<string, string[]>
    standing_unknown: Array<{ release_id: string; cause_id: string }>
  }
  cases: Array<{
    id: string
    causes: string[]
    releases: string[]
    at: string
    expected: ExpectedState
  }>
  compose_cases: Array<{
    id: string
    chain: ExpectedState
    pause: ExpectedState
    expected: ExpectedState
  }>
  error_cases: Array<{
    id: string
    mutation: string
    causes: string[]
    releases: string[]
    at: string
    expected_error_code: string
  }>
}

const vectors = JSON.parse(vectorsBytes.toString('utf8')) as Vectors

/** The fixture's standing resolver, implemented exactly as `standing_resolver.rule` states.
 *  It is a fixture object, not a mechanism this work proposes: nothing in the concept
 *  document says what establishes that a party holds standing over a cause. */
function fixtureStanding(release: SuspensionRelease, cause: SuspensionCause): ReleaseStanding {
  const unknown = vectors.standing_resolver.standing_unknown.some(
    entry => entry.release_id === release.release_id && entry.cause_id === cause.cause_id,
  )
  if (unknown) return 'unknown'
  const holders = vectors.standing_resolver.standing_registry[cause.cause_id] ?? []
  return holders.includes(release.issuer) ? 'has_standing' : 'no_standing'
}

/** Resolves by `verification_method` alone, deliberately ignoring the `signer` argument, so
 *  that a record whose method belongs to somebody other than the party it names still gets a
 *  key and is caught by the binding check rather than by a missing key. */
function fixtureKey(_signer: string, verificationMethod: string): string | null {
  return vectors.verification_keys[verificationMethod] ?? null
}

function inputFor(vector: { causes: string[]; releases: string[]; at: string }): PauseStateInput {
  return {
    delegationId: vectors.delegation_id,
    causes: vector.causes.map(name => vectors.causes[name]),
    releases: vector.releases.map(name => vectors.releases[name]),
    atInstant: vectors.clock[vector.at],
    resolveReleaseStanding: fixtureStanding,
    resolveVerificationKey: fixtureKey,
  }
}

function buildState(spec: ExpectedState): LifecycleStateResult {
  if (spec.verdict === 'not_established') {
    return notEstablished(spec.missing as never, spec.reason_code)
  }
  return lifecycleState({
    verdict: spec.verdict as never,
    reason_code: spec.reason_code,
    ...(spec.outstanding === undefined ? {} : { outstanding: spec.outstanding }),
  })
}

describe('suspension-causes: shared fixture', () => {
  test('the vectors file is the pinned bytes', () => {
    const digest = createHash('sha256').update(vectorsBytes).digest('hex')
    assert.equal(digest, VECTORS_SHA256)
  })

  test('the profile and status are what both SDKs expect', () => {
    assert.equal(vectors.profile, 'aps-suspension-causes-v0')
    assert.equal((vectors as unknown as { status: string }).status, 'proposed')
  })

  test('the record types carry the proposed namespace', () => {
    assert.equal(SUSPENSION_CAUSE_TYPE, 'proposed:aps:suspension-cause:v0')
    assert.equal(SUSPENSION_RELEASE_TYPE, 'proposed:aps:cause-release:v0')
  })

  test('the vocabularies are the two and three values the module documents', () => {
    assert.deepEqual([...PAUSE_KINDS], ['suspension', 'restriction'])
    assert.deepEqual([...RELEASE_STANDINGS], ['has_standing', 'no_standing', 'unknown'])
  })

  test('every reason code is SCREAMING_SNAKE_CASE and unique', () => {
    const seen = new Set<string>()
    for (const code of SUSPENSION_REASON_CODES) {
      assert.match(code, /^[A-Z][A-Z0-9_]*$/, `${code} is not SCREAMING_SNAKE_CASE`)
      assert.equal(seen.has(code), false, `${code} appears twice`)
      seen.add(code)
    }
  })
})

describe('suspension-causes: cause evaluation vectors', () => {
  for (const vector of vectors.cases) {
    test(vector.id, () => {
      const explanation = explainPauseState(inputFor(vector))
      const state = explanation.state
      const expected = vector.expected

      assert.equal(state.verdict, expected.verdict, 'verdict')
      assert.equal(state.reason_code, expected.reason_code, 'reason_code')

      if (expected.missing === undefined) {
        assert.equal(state.missing, undefined, 'missing must be absent')
      } else {
        assert.deepEqual([...(state.missing ?? [])], expected.missing, 'missing')
      }

      // The whole of CAND-05 in one field: a SET, never a count and never a boolean.
      const outstanding = (state.outstanding ?? []).map(c => ({
        id: c.id,
        kind: c.kind,
        reason_code: c.reason_code,
      }))
      if (expected.outstanding === undefined) {
        assert.equal(state.outstanding, undefined, 'outstanding must be absent')
        assert.deepEqual([...explanation.outstanding], [], 'explanation outstanding')
      } else {
        assert.deepEqual(outstanding, expected.outstanding, 'outstanding set')
        assert.deepEqual(
          explanation.outstanding.map(c => ({ id: c.id, kind: c.kind, reason_code: c.reason_code })),
          expected.outstanding,
          'explanation outstanding',
        )
      }

      const byCause = new Map(explanation.causes.map(d => [d.cause_id, d]))
      for (const [causeId, disposition] of Object.entries(expected.cause_dispositions ?? {})) {
        assert.equal(byCause.get(causeId)?.disposition, disposition, `cause ${causeId}`)
      }
      for (const [causeId, releaseId] of Object.entries(expected.released_by ?? {})) {
        assert.equal(byCause.get(causeId)?.released_by, releaseId, `released_by ${causeId}`)
      }

      const byRelease = new Map(explanation.releases.map(d => [d.release_id, d]))
      for (const [releaseId, disposition] of Object.entries(expected.release_dispositions ?? {})) {
        assert.equal(byRelease.get(releaseId)?.disposition, disposition, `release ${releaseId}`)
      }
      for (const [key, disposition] of Object.entries(expected.release_cause_dispositions ?? {})) {
        const [releaseId, causeId] = key.split('|')
        const entry = byRelease.get(releaseId)?.causes.find(c => c.cause_id === causeId)
        assert.equal(entry?.disposition, disposition, `release ${releaseId} cause ${causeId}`)
      }
      for (const [releaseId, count] of Object.entries(expected.release_cause_count ?? {})) {
        assert.equal(byRelease.get(releaseId)?.causes.length, count, `release ${releaseId} arity`)
      }

      // One entry per input record, in input order, with nothing dropped.
      assert.equal(explanation.causes.length, vector.causes.length)
      assert.equal(explanation.releases.length, vector.releases.length)

      // evaluatePauseState is the same computation returning only the state.
      assert.deepEqual(evaluatePauseState(inputFor(vector)), state)
    })
  }
})

describe('suspension-causes: composition with a chain result', () => {
  for (const vector of vectors.compose_cases) {
    test(vector.id, () => {
      const composed = composeChainAndPause(buildState(vector.chain), buildState(vector.pause))
      assert.deepEqual(composed, buildState(vector.expected))
    })
  }

  test('a release never clears a revocation, for every pause verdict this module can reach', () => {
    const revoked = lifecycleState({ verdict: 'invalid', reason_code: 'REVOKED' })
    const pauseStates = [
      lifecycleState({ verdict: 'valid', reason_code: 'NO_CAUSE_PRESENTED' }),
      lifecycleState({ verdict: 'valid', reason_code: 'NO_CAUSE_IN_EVIDENCE' }),
      lifecycleState({ verdict: 'valid', reason_code: 'ALL_CAUSES_RELEASED' }),
      lifecycleState({
        verdict: 'suspended',
        reason_code: 'CAUSES_OUTSTANDING',
        outstanding: [{ id: 'c', kind: 'suspension', reason_code: 'R' }],
      }),
      lifecycleState({
        verdict: 'restricted',
        reason_code: 'CAUSES_OUTSTANDING',
        outstanding: [{ id: 'c', kind: 'restriction', reason_code: 'R' }],
      }),
      notEstablished(['source'], 'RELEASE_STANDING_NOT_ESTABLISHED'),
    ]
    for (const pause of pauseStates) {
      assert.deepEqual(composeChainAndPause(revoked, pause), revoked, pause.reason_code)
    }
  })

  test('a non-LifecycleStateResult argument is a caller error', () => {
    const ok = lifecycleState({ verdict: 'valid', reason_code: 'CHAIN_VALID' })
    assert.throws(
      () => composeChainAndPause(null as never, ok),
      (e: SuspensionCauseError) => e.code === 'INPUT_MALFORMED',
    )
    assert.throws(
      () => composeChainAndPause(ok, undefined as never),
      (e: SuspensionCauseError) => e.code === 'INPUT_MALFORMED',
    )
  })
})

describe('suspension-causes: malformed input is a caller error, never a verdict', () => {
  for (const vector of vectors.error_cases) {
    test(vector.id, () => {
      const base = inputFor(vector)
      let input: PauseStateInput = base
      switch (vector.mutation) {
        case 'duplicate_cause_id':
        case 'duplicate_release_id':
          break
        case 'cause_kind_unknown':
          input = { ...base, causes: [{ ...base.causes[0], kind: 'quarantine' as never }] }
          break
        case 'cause_drop_reason_code': {
          const { reason_code: _drop, ...rest } = base.causes[0]
          input = { ...base, causes: [rest as unknown as SuspensionCause] }
          break
        }
        case 'standing_resolver_returns_maybe':
          input = { ...base, resolveReleaseStanding: () => 'maybe' as never }
          break
        case 'release_cause_ids_string':
          input = {
            ...base,
            releases: [{ ...base.releases[0], cause_ids: 'sc-cause-reg' as never }],
          }
          break
        default:
          throw new Error(`unknown mutation ${vector.mutation}`)
      }
      assert.throws(
        () => evaluatePauseState(input),
        (e: SuspensionCauseError) => {
          assert.ok(e instanceof SuspensionCauseError)
          assert.equal(e.code, vector.expected_error_code)
          return true
        },
      )
    })
  }
})

describe('suspension-causes: properties the vectors cannot state', () => {
  test('the single-flag representation is not reachable: the result carries a set', () => {
    // The LC-B-024 mistake, stated as a property. With three causes and one effective
    // release, an implementation holding a boolean would report everything cleared.
    const state = evaluatePauseState(
      inputFor({ causes: ['REG', 'FIRM', 'DECREE'], releases: ['REL_REG_BY_REGULATOR'], at: 'T_EVAL' }),
    )
    assert.equal(state.verdict, 'suspended')
    assert.equal(state.outstanding?.length, 2)
    assert.equal(typeof (state as unknown as { valid?: unknown }).valid, 'undefined')
  })

  test('release_authority on the cause is never read by the evaluator', () => {
    // Cross-cutting constraint 7: standing is resolved outside the record, always. Rewrite
    // the registry so the stranger DOES hold standing and the same release now works, which
    // shows the resolver is the only thing deciding.
    const cause = vectors.causes.REG_SELF_NOMINATING
    const release = vectors.releases.REL_REG_SELF_BY_STRANGER
    assert.equal(cause.release_authority, release.issuer, 'fixture precondition')

    const withoutStanding = evaluatePauseState({
      delegationId: vectors.delegation_id,
      causes: [cause],
      releases: [release],
      atInstant: vectors.clock.T_EVAL,
      resolveReleaseStanding: () => 'no_standing',
      resolveVerificationKey: fixtureKey,
    })
    assert.equal(withoutStanding.verdict, 'suspended')

    const withStanding = evaluatePauseState({
      delegationId: vectors.delegation_id,
      causes: [cause],
      releases: [release],
      atInstant: vectors.clock.T_EVAL,
      resolveReleaseStanding: () => 'has_standing',
      resolveVerificationKey: fixtureKey,
    })
    assert.equal(withStanding.verdict, 'valid')
    assert.equal(withStanding.reason_code, 'ALL_CAUSES_RELEASED')
  })

  test('no precedence order among causes: presentation order does not change the answer', () => {
    // CAND-05 defines no precedence order and says so. The outstanding set is sorted by
    // cause_id, which is a presentation choice with no claim behind it.
    const forward = evaluatePauseState(
      inputFor({ causes: ['REG', 'FIRM', 'DECREE'], releases: [], at: 'T_EVAL' }),
    )
    const reversed = evaluatePauseState(
      inputFor({ causes: ['DECREE', 'FIRM', 'REG'], releases: [], at: 'T_EVAL' }),
    )
    assert.deepEqual(forward, reversed)
  })

  test('release order does not change the answer', () => {
    const forward = evaluatePauseState(
      inputFor({
        causes: ['REG', 'FIRM', 'DECREE'],
        releases: ['REL_REG_BY_REGULATOR', 'REL_FIRM_BY_FIRM'],
        at: 'T_EVAL',
      }),
    )
    const reversed = evaluatePauseState(
      inputFor({
        causes: ['REG', 'FIRM', 'DECREE'],
        releases: ['REL_FIRM_BY_FIRM', 'REL_REG_BY_REGULATOR'],
        at: 'T_EVAL',
      }),
    )
    assert.deepEqual(forward, reversed)
  })

  test('the preimage excludes signature and record_id and nothing else', () => {
    const preimage = suspensionRecordPreimage({
      b: 2,
      a: 1,
      signature: 'deadbeef',
      record_id: 'cafe',
    })
    assert.equal(preimage, '{"a":1,"b":2}')
  })

  test('a resolver that throws fails the record closed rather than crashing the evaluation', () => {
    const state = evaluatePauseState({
      delegationId: vectors.delegation_id,
      causes: [vectors.causes.REG],
      releases: [vectors.releases.REL_REG_BY_REGULATOR],
      atInstant: vectors.clock.T_EVAL,
      resolveReleaseStanding: fixtureStanding,
      resolveVerificationKey: () => {
        throw new Error('resolver down')
      },
    })
    // The cause record cannot be verified either, so nothing is in evidence and nothing is
    // claimed against the artifact.
    assert.equal(state.verdict, 'valid')
    assert.equal(state.reason_code, 'NO_CAUSE_IN_EVIDENCE')
  })

  test('the result and its outstanding set are frozen', () => {
    const state = evaluatePauseState(
      inputFor({ causes: ['REG', 'FIRM'], releases: [], at: 'T_EVAL' }),
    )
    assert.equal(Object.isFrozen(state), true)
    assert.equal(Object.isFrozen(state.outstanding), true)
  })

  test('nothing in this module is reachable from an existing chain result', async () => {
    // The opt-in guarantee, checked rather than asserted in prose: the chain verifier does
    // not import the suspension module.
    const verifySource = readFileSync(
      join(here, '..', '..', 'src', 'v2', 'authority-delegation', 'verify.ts'),
      'utf8',
    )
    assert.equal(verifySource.includes('suspension'), false)
  })
})
