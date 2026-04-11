// Temporal decay tests for ScopedReputation.
// Motivated by Nanook PDR v2.19 §7.6.1 and gap audit §5 rank 1.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  applyTemporalDecay,
  createScopedReputation,
  MAX_SIGMA, MIN_SIGMA, INITIAL_SIGMA,
  DEFAULT_DRIFT_RATE_PER_DAY, DEFAULT_DECAY_DAYS,
} from '../src/index.js'
import type { ScopedReputation } from '../src/index.js'

const SECONDS_PER_DAY = 86400

// Build a fresh reputation with sigma anchored at MIN_SIGMA so we have headroom
// to grow without immediately hitting the MAX_SIGMA clamp. Override
// lastUpdatedAt to a fixed timestamp so date arithmetic in the function is
// deterministic.
function makeRep(sigma: number = MIN_SIGMA, mu: number = 50): ScopedReputation {
  const rep = createScopedReputation('principal-test', 'agent-test', 'scope-test')
  return {
    ...rep,
    mu,
    sigma,
    lastUpdatedAt: '2026-01-01T00:00:00.000Z',
    receiptCount: 5,
  }
}

describe('applyTemporalDecay — identity at zero elapsed', () => {
  it('returns sigma unchanged when elapsedSeconds = 0', () => {
    const rep = makeRep(3.5)
    const decayed = applyTemporalDecay(rep, 0)
    assert.equal(decayed.sigma, rep.sigma)
  })

  it('does not advance lastUpdatedAt when elapsedSeconds = 0', () => {
    const rep = makeRep()
    const decayed = applyTemporalDecay(rep, 0)
    assert.equal(decayed.lastUpdatedAt, rep.lastUpdatedAt)
  })
})

describe('applyTemporalDecay — monotonic sigma growth', () => {
  it('grows sigma over 1 day at the default rate', () => {
    const rep = makeRep(MIN_SIGMA)
    const decayed = applyTemporalDecay(rep, SECONDS_PER_DAY)
    assert.ok(decayed.sigma > rep.sigma, 'sigma should grow')
    // Default drift rate is (MAX - MIN) / 180 days. One day adds (MAX-MIN)/180.
    const expectedDelta = (MAX_SIGMA - MIN_SIGMA) / DEFAULT_DECAY_DAYS
    assert.ok(
      Math.abs(decayed.sigma - (rep.sigma + expectedDelta)) < 1e-9,
      `sigma delta should be (MAX-MIN)/${DEFAULT_DECAY_DAYS} per day, got ${decayed.sigma - rep.sigma}`
    )
  })

  it('grows monotonically across a sequence of elapsed-time deltas', () => {
    let rep = makeRep(MIN_SIGMA)
    let prev = rep.sigma
    for (let i = 0; i < 10; i++) {
      rep = applyTemporalDecay(rep, SECONDS_PER_DAY)
      assert.ok(rep.sigma > prev, `iteration ${i}: sigma should keep growing`)
      prev = rep.sigma
    }
  })
})

describe('applyTemporalDecay — clamping', () => {
  it('cannot exceed maxSigma even with very large elapsed time', () => {
    const rep = makeRep(MIN_SIGMA)
    // 10 years is way past the 180-day saturation point
    const tenYearsSeconds = 10 * 365 * SECONDS_PER_DAY
    const decayed = applyTemporalDecay(rep, tenYearsSeconds)
    assert.equal(decayed.sigma, MAX_SIGMA)
  })

  it('honors a custom maxSigma override', () => {
    const rep = makeRep(MIN_SIGMA)
    const decayed = applyTemporalDecay(rep, 10 * 365 * SECONDS_PER_DAY, { maxSigma: 10 })
    assert.equal(decayed.sigma, 10)
  })

  it('clamps to MIN_SIGMA from below if a negative drift rate is supplied', () => {
    // Edge case: if a caller deliberately uses a negative driftRatePerDay, the
    // function should still clamp to MIN_SIGMA, not produce sub-1 values.
    const rep = makeRep(2)
    const decayed = applyTemporalDecay(rep, 100 * SECONDS_PER_DAY, { driftRatePerDay: -1 })
    assert.equal(decayed.sigma, MIN_SIGMA)
  })
})

describe('applyTemporalDecay — invariants', () => {
  it('does not change mu', () => {
    const rep = makeRep(MIN_SIGMA, 73.5)
    const decayed = applyTemporalDecay(rep, 30 * SECONDS_PER_DAY)
    assert.equal(decayed.mu, 73.5)
  })

  it('does not change receiptCount', () => {
    const rep = makeRep()
    const decayed = applyTemporalDecay(rep, SECONDS_PER_DAY)
    assert.equal(decayed.receiptCount, rep.receiptCount)
  })

  it('does not change principalId, agentId, scope', () => {
    const rep = makeRep()
    const decayed = applyTemporalDecay(rep, SECONDS_PER_DAY)
    assert.equal(decayed.principalId, rep.principalId)
    assert.equal(decayed.agentId, rep.agentId)
    assert.equal(decayed.scope, rep.scope)
  })

  it('does not mutate the input reputation', () => {
    const rep = makeRep(MIN_SIGMA)
    const beforeSigma = rep.sigma
    const beforeLastUpdated = rep.lastUpdatedAt
    applyTemporalDecay(rep, SECONDS_PER_DAY)
    assert.equal(rep.sigma, beforeSigma, 'input sigma must not be mutated')
    assert.equal(rep.lastUpdatedAt, beforeLastUpdated, 'input lastUpdatedAt must not be mutated')
  })
})

describe('applyTemporalDecay — idempotency', () => {
  it('decay(decay(r, t1), t2) ≈ decay(r, t1+t2) within 1e-9 (no clamp)', () => {
    const rep = makeRep(MIN_SIGMA)
    const t1 = 3 * SECONDS_PER_DAY
    const t2 = 5 * SECONDS_PER_DAY
    const split = applyTemporalDecay(applyTemporalDecay(rep, t1), t2)
    const direct = applyTemporalDecay(rep, t1 + t2)
    assert.ok(
      Math.abs(split.sigma - direct.sigma) < 1e-9,
      `split sigma=${split.sigma} vs direct sigma=${direct.sigma}`
    )
  })

  it('idempotency holds for many small steps versus one big step', () => {
    const rep = makeRep(MIN_SIGMA)
    let stepped = rep
    const stepSeconds = 100
    const stepCount = 50
    for (let i = 0; i < stepCount; i++) {
      stepped = applyTemporalDecay(stepped, stepSeconds)
    }
    const direct = applyTemporalDecay(rep, stepSeconds * stepCount)
    assert.ok(
      Math.abs(stepped.sigma - direct.sigma) < 1e-9,
      `stepped sigma=${stepped.sigma} vs direct sigma=${direct.sigma}, delta=${Math.abs(stepped.sigma - direct.sigma)}`
    )
  })

  it('lastUpdatedAt advances by exactly elapsedSeconds', () => {
    const rep = makeRep()
    const decayed = applyTemporalDecay(rep, 12345)
    const lastMs = new Date(rep.lastUpdatedAt).getTime()
    const newMs = new Date(decayed.lastUpdatedAt).getTime()
    assert.equal(newMs - lastMs, 12345 * 1000)
  })
})

describe('applyTemporalDecay — input validation', () => {
  it('throws on negative elapsedSeconds', () => {
    const rep = makeRep()
    assert.throws(() => applyTemporalDecay(rep, -1), /non-negative/)
  })

  it('throws on NaN elapsedSeconds', () => {
    const rep = makeRep()
    assert.throws(() => applyTemporalDecay(rep, NaN), /finite/)
  })

  it('throws on Infinity elapsedSeconds', () => {
    const rep = makeRep()
    assert.throws(() => applyTemporalDecay(rep, Infinity), /finite/)
  })
})

describe('applyTemporalDecay — DEFAULT_DRIFT_RATE_PER_DAY constant', () => {
  it('is derived as (MAX_SIGMA - MIN_SIGMA) / DEFAULT_DECAY_DAYS', () => {
    assert.equal(DEFAULT_DRIFT_RATE_PER_DAY, (MAX_SIGMA - MIN_SIGMA) / DEFAULT_DECAY_DAYS)
  })

  it('saturates to MAX_SIGMA after DEFAULT_DECAY_DAYS days from MIN_SIGMA start', () => {
    const rep = makeRep(MIN_SIGMA)
    const decayed = applyTemporalDecay(rep, DEFAULT_DECAY_DAYS * SECONDS_PER_DAY)
    // At exactly DEFAULT_DECAY_DAYS the un-clamped value would equal MAX_SIGMA;
    // the clamp returns exactly MAX_SIGMA.
    assert.equal(decayed.sigma, MAX_SIGMA)
  })
})
