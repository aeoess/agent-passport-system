// Sliding window drift detection tests for ScopedReputation.
// Phase 2 of Rank 3 from the Nanook PDR v2.19 gap audit (§5).
// Reference: Nanook PDR v2.19 §6.6 (NexusGuard sliding window drift),
// gap audit §3 row 8 / §5 rank 3.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  computeReputationDrift,
  createScopedReputation,
  updateReputationFromResult,
  RECENT_OBSERVATIONS_CAP,
  DEFAULT_DRIFT_WARNING_THRESHOLD,
  DEFAULT_DRIFT_CRITICAL_THRESHOLD,
} from '../src/index.js'
import type {
  ScopedReputation,
  ReputationObservation,
  EvidenceClass,
} from '../src/index.js'

// ── Fixtures ────────────────────────────────────────────────

function makeFreshRep(): ScopedReputation {
  return createScopedReputation('p-drift', 'a-drift', 's-drift')
}

/** Build a reputation with an explicit recentObservations array.
 *  Bypasses updateReputationFromResult for direct control over muDeltas. */
function makeRepWithObservations(opts: {
  mu?: number
  sigma?: number
  recentObservations: ReputationObservation[]
}): ScopedReputation {
  const base = makeFreshRep()
  return {
    ...base,
    mu: opts.mu ?? 50,
    sigma: opts.sigma ?? 10,
    receiptCount: opts.recentObservations.length,
    recentObservations: opts.recentObservations,
  }
}

function obs(muDelta: number, success: boolean = true, evidenceClass: EvidenceClass = 'standard'): ReputationObservation {
  return {
    timestamp: '2026-04-10T00:00:00.000Z',
    success,
    evidenceClass,
    muDelta,
    sigmaDelta: 0,
  }
}

// ── 1. No history available (backward compat) ───────────────

describe('computeReputationDrift — no history available', () => {
  it('fresh reputation with no recentObservations: delta=0, severity=none, alert=null', () => {
    const rep = makeFreshRep()
    assert.equal(rep.recentObservations, undefined, 'fresh rep has no ring buffer')

    const result = computeReputationDrift(rep, 5)
    assert.equal(result.delta, 0)
    assert.equal(result.windowedScore, 0)
    assert.equal(result.cumulativeScore, rep.mu)
    assert.equal(result.observationsInWindow, 0)
    assert.equal(result.windowSize, 5)
    assert.equal(result.alert, null)
  })

  it('reputation with empty recentObservations array: same no-history result', () => {
    const rep = makeRepWithObservations({ recentObservations: [] })
    const result = computeReputationDrift(rep, 5)
    assert.equal(result.delta, 0)
    assert.equal(result.observationsInWindow, 0)
    assert.equal(result.alert, null)
  })
})

// ── 2. Direction: improving / degrading ─────────────────────

describe('computeReputationDrift — direction', () => {
  it('all-positive muDeltas: delta > 0, direction improving', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.5), obs(0.5), obs(0.5)],
    })
    const result = computeReputationDrift(rep, 3)
    assert.equal(result.delta, 1.5)
    assert.equal(result.windowedScore, 1.5)
    assert.equal(result.observationsInWindow, 3)
    assert.ok(result.alert)
    assert.equal(result.alert!.direction, 'improving')
  })

  it('all-negative muDeltas: delta < 0, direction degrading', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(-0.5), obs(-0.5), obs(-0.5)],
    })
    const result = computeReputationDrift(rep, 3)
    assert.equal(result.delta, -1.5)
    assert.equal(result.windowedScore, -1.5)
    assert.ok(result.alert)
    assert.equal(result.alert!.direction, 'degrading')
  })

  it('mixed deltas summing to within threshold: direction stable, severity none', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.05), obs(-0.03), obs(0.02)],
    })
    const result = computeReputationDrift(rep, 3)
    // sum = 0.04, below default warning threshold of 0.15
    assert.ok(Math.abs(result.delta - 0.04) < 1e-9)
    assert.equal(result.alert, null)
  })
})

// ── 3. Threshold boundaries ─────────────────────────────────

describe('computeReputationDrift — threshold boundaries', () => {
  it('exactly at warning threshold (delta = 0.15): severity warning', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.15)],
    })
    const result = computeReputationDrift(rep, 1)
    assert.equal(result.delta, 0.15)
    assert.ok(result.alert)
    assert.equal(result.alert!.severity, 'warning')
    assert.equal(result.alert!.direction, 'stable', 'delta exactly equals threshold so direction is stable, not improving')
  })

  it('exactly at critical threshold (delta = 0.30): severity critical', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.30)],
    })
    const result = computeReputationDrift(rep, 1)
    assert.equal(result.delta, 0.30)
    assert.ok(result.alert)
    assert.equal(result.alert!.severity, 'critical')
  })

  it('just below warning (delta = 0.149): severity none, alert null', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.149)],
    })
    const result = computeReputationDrift(rep, 1)
    assert.equal(result.alert, null)
  })

  it('just above critical (delta = 0.31): severity critical', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.31)],
    })
    const result = computeReputationDrift(rep, 1)
    assert.ok(result.alert)
    assert.equal(result.alert!.severity, 'critical')
  })

  it('negative critical (delta = -0.40): severity critical, direction degrading', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(-0.40)],
    })
    const result = computeReputationDrift(rep, 1)
    assert.ok(result.alert)
    assert.equal(result.alert!.severity, 'critical')
    assert.equal(result.alert!.direction, 'degrading')
  })
})

// ── 4. Severity escalation ──────────────────────────────────

describe('computeReputationDrift — severity escalates with |delta|', () => {
  it('|delta| growth from 0.10 → 0.20 → 0.40 walks through none → warning → critical', () => {
    const r1 = makeRepWithObservations({ recentObservations: [obs(0.10)] })
    const r2 = makeRepWithObservations({ recentObservations: [obs(0.20)] })
    const r3 = makeRepWithObservations({ recentObservations: [obs(0.40)] })

    assert.equal(computeReputationDrift(r1, 1).alert, null)
    assert.equal(computeReputationDrift(r2, 1).alert!.severity, 'warning')
    assert.equal(computeReputationDrift(r3, 1).alert!.severity, 'critical')
  })
})

// ── 5. Window clamping ──────────────────────────────────────

describe('computeReputationDrift — window clamping', () => {
  it('observationsInWindow clamps to recentObservations.length when history is sparse', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.1), obs(0.1)],
    })
    const result = computeReputationDrift(rep, 10)
    assert.equal(result.windowSize, 10)
    assert.equal(result.observationsInWindow, 2, 'only 2 events available')
    assert.equal(result.delta, 0.2)
  })

  it('only the last windowSize events are summed when history is longer than the window', () => {
    const rep = makeRepWithObservations({
      // Five events. Last 3 are -0.5 each (sum -1.5). First 2 are +1.0 each.
      recentObservations: [
        obs(1.0),
        obs(1.0),
        obs(-0.5),
        obs(-0.5),
        obs(-0.5),
      ],
    })
    const result = computeReputationDrift(rep, 3)
    assert.equal(result.observationsInWindow, 3)
    assert.ok(Math.abs(result.delta - (-1.5)) < 1e-9, `expected -1.5, got ${result.delta}`)
    assert.equal(result.alert!.severity, 'critical')
    assert.equal(result.alert!.direction, 'degrading')
  })

  it('windowSize equal to history length uses every event', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.1), obs(0.2), obs(0.3)],
    })
    const result = computeReputationDrift(rep, 3)
    assert.equal(result.observationsInWindow, 3)
    assert.ok(Math.abs(result.delta - 0.6) < 1e-9)
  })
})

// ── 6. Custom thresholds ────────────────────────────────────

describe('computeReputationDrift — custom thresholds', () => {
  it('tighter thresholds (0.05 / 0.10) trip earlier', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.07)],
    })
    // Default thresholds: not even warning (0.07 < 0.15)
    const defaultResult = computeReputationDrift(rep, 1)
    assert.equal(defaultResult.alert, null)

    // Custom tight thresholds: 0.07 >= 0.05, less than 0.10 → warning
    const customResult = computeReputationDrift(rep, 1, {
      warningThreshold: 0.05,
      criticalThreshold: 0.10,
    })
    assert.ok(customResult.alert)
    assert.equal(customResult.alert!.severity, 'warning')
    assert.equal(customResult.alert!.warningThreshold, 0.05)
    assert.equal(customResult.alert!.criticalThreshold, 0.10)
  })

  it('looser thresholds (0.50 / 1.00) suppress alerts that would fire under defaults', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.40)],
    })
    // Default: critical
    assert.equal(computeReputationDrift(rep, 1).alert!.severity, 'critical')
    // Loose: not even warning
    assert.equal(
      computeReputationDrift(rep, 1, { warningThreshold: 0.50, criticalThreshold: 1.00 }).alert,
      null,
    )
  })
})

// ── 7. Default thresholds match NexusGuard (regression lock) ─

describe('computeReputationDrift — default thresholds (NexusGuard AIP v0.5.48)', () => {
  it('exported constants are 0.15 and 0.30', () => {
    assert.equal(DEFAULT_DRIFT_WARNING_THRESHOLD, 0.15)
    assert.equal(DEFAULT_DRIFT_CRITICAL_THRESHOLD, 0.30)
  })

  it('default thresholds in alert match the exported constants', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.20)],
    })
    const result = computeReputationDrift(rep, 1)
    assert.ok(result.alert)
    assert.equal(result.alert!.warningThreshold, 0.15)
    assert.equal(result.alert!.criticalThreshold, 0.30)
  })
})

// ── 8. Invariants ───────────────────────────────────────────

describe('computeReputationDrift — invariants', () => {
  it('alert is null iff severity === none', () => {
    const cases = [
      { delta: 0.0, expectedAlert: false },
      { delta: 0.10, expectedAlert: false },
      { delta: 0.149, expectedAlert: false },
      { delta: 0.15, expectedAlert: true },
      { delta: 0.20, expectedAlert: true },
      { delta: 0.30, expectedAlert: true },
      { delta: 0.40, expectedAlert: true },
      { delta: -0.10, expectedAlert: false },
      { delta: -0.15, expectedAlert: true },
      { delta: -0.30, expectedAlert: true },
    ]
    for (const c of cases) {
      const rep = makeRepWithObservations({ recentObservations: [obs(c.delta)] })
      const result = computeReputationDrift(rep, 1)
      const hasAlert = result.alert !== null
      assert.equal(hasAlert, c.expectedAlert, `delta=${c.delta}: expected alert=${c.expectedAlert}, got ${hasAlert}`)
      if (hasAlert) {
        assert.notEqual(result.alert!.severity, 'none', 'when alert is non-null, severity must not be none')
      }
    }
  })

  it('does not mutate input reputation', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.1), obs(0.2), obs(0.3)],
    })
    const beforeMu = rep.mu
    const beforeSigma = rep.sigma
    const beforeRecentLength = rep.recentObservations!.length
    const beforeRecentRef = rep.recentObservations

    computeReputationDrift(rep, 5)

    assert.equal(rep.mu, beforeMu)
    assert.equal(rep.sigma, beforeSigma)
    assert.equal(rep.recentObservations!.length, beforeRecentLength)
    assert.strictEqual(rep.recentObservations, beforeRecentRef, 'array reference unchanged')
  })
})

// ── 9. Ring buffer end-to-end (Phase 1 + Phase 2) ──────────

describe('updateReputationFromResult ring buffer + computeReputationDrift', () => {
  it('after 40 update calls, recentObservations.length === RECENT_OBSERVATIONS_CAP (FIFO eviction)', () => {
    let rep = makeFreshRep()
    for (let i = 0; i < 40; i++) {
      rep = updateReputationFromResult(rep, true, 'standard', { principalHash: `p${i}` })
    }
    assert.equal(rep.recentObservations!.length, RECENT_OBSERVATIONS_CAP, `expected cap ${RECENT_OBSERVATIONS_CAP}, got ${rep.recentObservations!.length}`)
    assert.equal(RECENT_OBSERVATIONS_CAP, 30, 'sanity: cap default')
  })

  it('after 5 successful updates, drift sum equals (rep.mu - INITIAL_MU) within float tolerance', () => {
    let rep = makeFreshRep()
    const startMu = rep.mu
    for (let i = 0; i < 5; i++) {
      rep = updateReputationFromResult(rep, true, 'standard', { principalHash: `p${i}` })
    }
    const muChange = rep.mu - startMu
    const result = computeReputationDrift(rep, 5)
    assert.equal(result.observationsInWindow, 5)
    // The sum of effective muDeltas equals the actual mu trajectory.
    assert.ok(
      Math.abs(result.delta - muChange) < 1e-9,
      `delta=${result.delta} should equal mu change=${muChange}`,
    )
    // 5 successful 'standard' tasks at +1.0 each = +5.0 mu, way over critical
    assert.ok(result.alert)
    assert.equal(result.alert!.severity, 'critical')
    assert.equal(result.alert!.direction, 'improving')
  })

  it('after 5 failed updates, drift is negative and direction is degrading', () => {
    let rep = makeFreshRep()
    const startMu = rep.mu
    for (let i = 0; i < 5; i++) {
      rep = updateReputationFromResult(rep, false, 'standard', { principalHash: `p${i}` })
    }
    const muChange = rep.mu - startMu
    const result = computeReputationDrift(rep, 5)
    assert.ok(muChange < 0, 'sanity: 5 failures should reduce mu')
    assert.ok(
      Math.abs(result.delta - muChange) < 1e-9,
      `delta=${result.delta} should equal mu change=${muChange}`,
    )
    assert.ok(result.alert)
    assert.equal(result.alert!.direction, 'degrading')
  })

  it('window of 3 only counts the last 3 events from a longer history', () => {
    let rep = makeFreshRep()
    // Three failures, then three successes. Last 3 events are the successes.
    for (let i = 0; i < 3; i++) {
      rep = updateReputationFromResult(rep, false, 'standard', { principalHash: `f${i}` })
    }
    const muAfterFailures = rep.mu
    for (let i = 0; i < 3; i++) {
      rep = updateReputationFromResult(rep, true, 'standard', { principalHash: `s${i}` })
    }
    const recentImprovement = rep.mu - muAfterFailures
    const result = computeReputationDrift(rep, 3)
    assert.equal(result.observationsInWindow, 3)
    assert.ok(
      Math.abs(result.delta - recentImprovement) < 1e-9,
      `windowed delta ${result.delta} should equal recent improvement ${recentImprovement}`,
    )
    assert.ok(result.delta > 0, 'window of last 3 should be improving (the successes)')
  })

  it('mu clamping is reflected in stored muDeltas (boundary case)', () => {
    // Push mu near 100 with successive critical successes, then keep going.
    // The effective muDelta should shrink as mu approaches the clamp.
    let rep = makeFreshRep()
    for (let i = 0; i < 30; i++) {
      rep = updateReputationFromResult(rep, true, 'critical', { principalHash: `p${i}` })
    }
    // mu should have hit 100 (clamp) at some point.
    assert.equal(rep.mu, 100, 'mu should be clamped at 100 after many critical successes')

    // The most recent muDelta should be 0 (no further change possible past clamp).
    const lastObs = rep.recentObservations![rep.recentObservations!.length - 1]
    assert.equal(lastObs.muDelta, 0, 'effective muDelta at the clamp boundary is zero')

    // Drift over the most recent window should reflect the clamped trajectory.
    const result = computeReputationDrift(rep, 5)
    // Sum of last 5 muDeltas should equal actual mu change over those 5 events.
    // Since we're at the clamp, the last 5 muDeltas are all 0 → delta is 0.
    assert.equal(result.delta, 0, 'at the clamp, recent drift is zero')
    assert.equal(result.alert, null)
  })
})
