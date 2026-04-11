// Consistency score tests — predictability as a separate primitive.
// Reference: Nanook PDR v2.19 §6.5, gap audit §3 row 21 / §5 rank 6.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  computeConsistencyScore,
  createScopedReputation,
  updateReputationFromResult,
} from '../src/index.js'
import type { ScopedReputation, ReputationObservation } from '../src/index.js'

// ── Helpers ─────────────────────────────────────────────────

/** Build a minimal ScopedReputation with a fabricated ring buffer of
 *  muDelta values. Used to drive computeConsistencyScore deterministically
 *  without going through updateReputationFromResult. */
function repWithDeltas(muDeltas: number[]): ScopedReputation {
  const base = createScopedReputation('principal-1', 'agent-1', 'scope-a')
  const observations: ReputationObservation[] = muDeltas.map((delta, i) => ({
    timestamp: new Date(1_700_000_000_000 + i * 60_000).toISOString(),
    success: delta >= 0,
    evidenceClass: 'standard',
    muDelta: delta,
    sigmaDelta: 0,
  }))
  return { ...base, recentObservations: observations }
}

// ── 1. Degenerate cases ─────────────────────────────────────

describe('computeConsistencyScore — no history', () => {
  it('undefined recentObservations → no_history, score=0', () => {
    const rep = createScopedReputation('p', 'a', 's')
    // createScopedReputation does not populate recentObservations
    assert.equal(rep.recentObservations, undefined)
    const result = computeConsistencyScore(rep)
    assert.equal(result.classification, 'no_history')
    assert.equal(result.score, 0)
    assert.equal(result.stddev, 0)
    assert.equal(result.mean, 0)
    assert.equal(result.observationsInWindow, 0)
  })

  it('empty recentObservations → no_history, score=0', () => {
    const rep: ScopedReputation = {
      ...createScopedReputation('p', 'a', 's'),
      recentObservations: [],
    }
    const result = computeConsistencyScore(rep)
    assert.equal(result.classification, 'no_history')
    assert.equal(result.score, 0)
    assert.equal(result.observationsInWindow, 0)
  })
})

describe('computeConsistencyScore — insufficient data', () => {
  it('1 observation → insufficient_data, score=0.5', () => {
    const rep = repWithDeltas([1.0])
    const result = computeConsistencyScore(rep)
    assert.equal(result.classification, 'insufficient_data')
    assert.equal(result.score, 0.5)
    assert.equal(result.observationsInWindow, 1)
    // stddev of a single value is 0 by construction
    assert.equal(result.stddev, 0)
    assert.equal(result.mean, 1.0)
  })

  it('2 observations → insufficient_data, score=0.5', () => {
    const rep = repWithDeltas([1.0, 2.0])
    const result = computeConsistencyScore(rep)
    assert.equal(result.classification, 'insufficient_data')
    assert.equal(result.score, 0.5)
    assert.equal(result.observationsInWindow, 2)
    // stddev and mean should still be computed diagnostically
    assert.equal(result.mean, 1.5)
    assert.ok(result.stddev > 0)
  })
})

// ── 2. Core classification thresholds ──────────────────────

describe('computeConsistencyScore — classification', () => {
  it('3 identical muDeltas → stddev=0, score=1.0, highly_consistent', () => {
    const rep = repWithDeltas([1.0, 1.0, 1.0])
    const result = computeConsistencyScore(rep)
    assert.equal(result.stddev, 0)
    assert.equal(result.score, 1.0)
    assert.equal(result.classification, 'highly_consistent')
    assert.equal(result.mean, 1.0)
  })

  it('small variance → highly_consistent (stddev < 0.5)', () => {
    // [0.9, 1.0, 1.1] has mean=1.0, variance=(0.01+0+0.01)/3 ≈ 0.00667,
    // stddev ≈ 0.0816
    const rep = repWithDeltas([0.9, 1.0, 1.1])
    const result = computeConsistencyScore(rep)
    assert.ok(result.stddev < 0.5)
    assert.equal(result.classification, 'highly_consistent')
    assert.ok(result.score > 0.5)
  })

  it('medium variance → moderately_consistent (0.5 ≤ stddev < 1.5)', () => {
    // [0, 1, 2] mean=1, variance=(1+0+1)/3=0.667, stddev≈0.816
    const rep = repWithDeltas([0, 1, 2])
    const result = computeConsistencyScore(rep)
    assert.ok(result.stddev >= 0.5 && result.stddev < 1.5)
    assert.equal(result.classification, 'moderately_consistent')
  })

  it('large variance → inconsistent (stddev ≥ 1.5)', () => {
    // [3, -3, 3, -3, 3] mean=0.6, variance≈8.64, stddev≈2.94
    const rep = repWithDeltas([3, -3, 3, -3, 3])
    const result = computeConsistencyScore(rep)
    assert.ok(result.stddev >= 1.5)
    assert.equal(result.classification, 'inconsistent')
    assert.ok(result.score < 0.5)
  })
})

// ── 3. Direction independence ───────────────────────────────

describe('computeConsistencyScore — direction independence', () => {
  it('[-1,-1,-1] and [1,1,1] produce the same score', () => {
    const neg = computeConsistencyScore(repWithDeltas([-1, -1, -1]))
    const pos = computeConsistencyScore(repWithDeltas([1, 1, 1]))
    assert.equal(neg.score, pos.score)
    assert.equal(neg.stddev, pos.stddev)
    assert.equal(neg.classification, pos.classification)
    // But mean still carries the sign for diagnostic visibility
    assert.equal(neg.mean, -1)
    assert.equal(pos.mean, 1)
  })
})

// ── 4. §6.5 over-promiser paradox — the whole point ────────

describe('computeConsistencyScore — §6.5 over-promiser paradox', () => {
  it('over-promiser: [-0.5, -0.5, -0.5, -0.5, -0.5] → highly_consistent, score=1.0', () => {
    // The "consistent bad agent" Nanook describes: chronically fails in
    // the same small way every time. Robustness-style metrics love this
    // agent because variance is zero.
    const overPromiser = computeConsistencyScore(
      repWithDeltas([-0.5, -0.5, -0.5, -0.5, -0.5]),
    )
    assert.equal(overPromiser.stddev, 0)
    assert.equal(overPromiser.score, 1.0)
    assert.equal(overPromiser.classification, 'highly_consistent')
    assert.equal(overPromiser.mean, -0.5)
  })

  it('environment-sensitive: [3, -3, 3, -3, 3] → inconsistent, low score', () => {
    // The "flaky agent" that sometimes crushes the job and sometimes
    // catastrophically fails. Robustness-style metrics punish this agent
    // even though its mean outcome may be positive.
    const envSensitive = computeConsistencyScore(
      repWithDeltas([3, -3, 3, -3, 3]),
    )
    assert.ok(envSensitive.stddev >= 1.5)
    assert.equal(envSensitive.classification, 'inconsistent')
    assert.ok(envSensitive.score < 0.5)
  })

  it('REGRESSION: over-promiser score > environment-sensitive score', () => {
    // This is the §6.5 paradox as an executable invariant. The primitive's
    // entire purpose is to surface this cleanly: a consistently bad agent
    // scores as MORE consistent than an environment-sensitive one, even
    // though the environment-sensitive agent may have better mean outcomes.
    const overPromiser = computeConsistencyScore(
      repWithDeltas([-0.5, -0.5, -0.5, -0.5, -0.5]),
    )
    const envSensitive = computeConsistencyScore(
      repWithDeltas([3, -3, 3, -3, 3]),
    )
    assert.ok(
      overPromiser.score > envSensitive.score,
      `over-promiser (${overPromiser.score}) must score higher than env-sensitive (${envSensitive.score})`,
    )
    // And the mean of env-sensitive is actually positive while the
    // over-promiser's is negative — yet over-promiser is "more consistent."
    assert.ok(envSensitive.mean > 0)
    assert.ok(overPromiser.mean < 0)
  })
})

// ── 5. Window size behavior ─────────────────────────────────

describe('computeConsistencyScore — windowSize', () => {
  it('default windowSize uses all available observations', () => {
    const rep = repWithDeltas([1, 1, 1, 5, 5, 5])
    const result = computeConsistencyScore(rep)
    assert.equal(result.observationsInWindow, 6)
  })

  it('windowSize=3 on a 10-observation buffer uses only the last 3', () => {
    // First 7 are wildly inconsistent, last 3 are identical.
    // If windowing works correctly, score should reflect ONLY the last 3.
    const rep = repWithDeltas([5, -5, 5, -5, 5, -5, 5, 2, 2, 2])
    const result = computeConsistencyScore(rep, 3)
    assert.equal(result.observationsInWindow, 3)
    assert.equal(result.stddev, 0)
    assert.equal(result.score, 1.0)
    assert.equal(result.mean, 2)
    assert.equal(result.classification, 'highly_consistent')
  })

  it('windowSize larger than buffer clamps to buffer length', () => {
    const rep = repWithDeltas([1, 1, 1])
    const result = computeConsistencyScore(rep, 100)
    assert.equal(result.observationsInWindow, 3)
  })

  it('windowSize=1 returns insufficient_data', () => {
    const rep = repWithDeltas([1, 1, 1, 1, 1])
    const result = computeConsistencyScore(rep, 1)
    assert.equal(result.observationsInWindow, 1)
    assert.equal(result.classification, 'insufficient_data')
    assert.equal(result.score, 0.5)
  })
})

// ── 6. Numerical correctness ────────────────────────────────

describe('computeConsistencyScore — numerical correctness', () => {
  it('mean matches arithmetic mean of window', () => {
    const rep = repWithDeltas([2, 4, 6])
    const result = computeConsistencyScore(rep)
    assert.equal(result.mean, 4)
  })

  it('mean is correctly signed for negative values', () => {
    const rep = repWithDeltas([-2, -4, -6])
    const result = computeConsistencyScore(rep)
    assert.equal(result.mean, -4)
  })

  it('stddev matches expected value within float tolerance', () => {
    // [1, 2, 3, 4, 5] mean=3, variance=(4+1+0+1+4)/5=2, stddev=sqrt(2)≈1.4142
    const rep = repWithDeltas([1, 2, 3, 4, 5])
    const result = computeConsistencyScore(rep)
    assert.ok(Math.abs(result.stddev - Math.sqrt(2)) < 1e-9)
    assert.equal(result.mean, 3)
  })

  it('score formula: stddev=0 → 1.0', () => {
    const rep = repWithDeltas([2, 2, 2])
    const result = computeConsistencyScore(rep)
    assert.equal(result.stddev, 0)
    assert.equal(result.score, 1.0)
  })

  it('score formula: stddev=1 → 0.5', () => {
    // Find a sequence with exactly stddev=1. Values [0, 1, 2] give
    // variance=2/3 (≠1). We need population variance of 1.
    // Try [1, 3] — but that's only 2 points. For 3 points we need
    // mean=m, sum((x-m)^2) = 3. E.g. [m-1, m, m+1] gives variance=2/3.
    // Use [m - sqrt(1.5), m, m + sqrt(1.5)] — variance = (1.5+0+1.5)/3 = 1.
    const offset = Math.sqrt(1.5)
    const rep = repWithDeltas([10 - offset, 10, 10 + offset])
    const result = computeConsistencyScore(rep)
    assert.ok(Math.abs(result.stddev - 1) < 1e-9, `stddev was ${result.stddev}`)
    assert.ok(Math.abs(result.score - 0.5) < 1e-9, `score was ${result.score}`)
  })

  it('score is monotonically decreasing in stddev', () => {
    const low = computeConsistencyScore(repWithDeltas([1, 1.1, 0.9]))
    const mid = computeConsistencyScore(repWithDeltas([0, 1, 2]))
    const high = computeConsistencyScore(repWithDeltas([-3, 0, 3]))
    assert.ok(low.score > mid.score)
    assert.ok(mid.score > high.score)
    assert.ok(low.stddev < mid.stddev)
    assert.ok(mid.stddev < high.stddev)
  })
})

// ── 7. Purity ───────────────────────────────────────────────

describe('computeConsistencyScore — purity', () => {
  it('does not mutate the input reputation', () => {
    const rep = repWithDeltas([1, 2, 3, 4, 5])
    const snapshot = JSON.stringify(rep)
    computeConsistencyScore(rep)
    assert.equal(JSON.stringify(rep), snapshot)
  })

  it('does not mutate the recentObservations array', () => {
    const rep = repWithDeltas([1, 2, 3])
    const originalLength = rep.recentObservations!.length
    const originalFirst = rep.recentObservations![0].muDelta
    computeConsistencyScore(rep, 2)
    assert.equal(rep.recentObservations!.length, originalLength)
    assert.equal(rep.recentObservations![0].muDelta, originalFirst)
  })
})

// ── 8. Integration with updateReputationFromResult ─────────

describe('computeConsistencyScore — integration with updateReputationFromResult', () => {
  it('window reflects the actual ring buffer state after several updates', () => {
    let rep = createScopedReputation('p', 'a', 's')
    // Feed 5 standard successes — effective muDelta should be identical
    // for each event (until mu hits the clamp at 100), so consistency
    // should be very high.
    for (let i = 0; i < 5; i++) {
      rep = updateReputationFromResult(rep, true, 'standard')
    }
    const result = computeConsistencyScore(rep)
    assert.equal(result.observationsInWindow, 5)
    // All 5 events are standard success with identical effective muDelta
    // (mu moves from INITIAL_MU far from the clamps), so stddev should be 0.
    assert.equal(result.stddev, 0)
    assert.equal(result.score, 1.0)
    assert.equal(result.classification, 'highly_consistent')
  })

  it('mixing critical success + trivial failure produces high variance', () => {
    let rep = createScopedReputation('p', 'a', 's')
    // Alternate critical success (+3.0) with critical failure (-5.0)
    // to span the full REPUTATION_UPDATES delta range.
    rep = updateReputationFromResult(rep, true, 'critical')
    rep = updateReputationFromResult(rep, false, 'critical')
    rep = updateReputationFromResult(rep, true, 'critical')
    rep = updateReputationFromResult(rep, false, 'critical')
    rep = updateReputationFromResult(rep, true, 'critical')
    const result = computeConsistencyScore(rep)
    assert.equal(result.observationsInWindow, 5)
    // Alternating +3/-5 should produce very high stddev (well past 1.5).
    assert.ok(result.stddev >= 1.5, `stddev was ${result.stddev}`)
    assert.equal(result.classification, 'inconsistent')
  })

  it('a sequence of standard successes then failures produces measurable variance', () => {
    let rep = createScopedReputation('p', 'a', 's')
    for (let i = 0; i < 3; i++) {
      rep = updateReputationFromResult(rep, true, 'standard')
    }
    for (let i = 0; i < 3; i++) {
      rep = updateReputationFromResult(rep, false, 'standard')
    }
    const result = computeConsistencyScore(rep)
    assert.equal(result.observationsInWindow, 6)
    // Six events: three at +1.0, three at -2.0. mean=-0.5.
    // variance = 3*(1.5)^2/6 + 3*(-1.5)^2/6 = (3*2.25 + 3*2.25)/6 = 2.25.
    // stddev = 1.5. Right at the boundary between moderate and inconsistent.
    assert.ok(result.stddev > 1.4 && result.stddev < 1.6)
  })
})
