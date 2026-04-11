// Confidence breakdown tests for ScopedReputation.
// Motivated by Nanook PDR v2.19 §6.4 / §7.6.1 and gap audit §3 row 17.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  confidenceBreakdown,
  computeConfidence,
  createScopedReputation,
  createEvidenceDiversity,
  updateReputationFromResult,
} from '../src/index.js'
import type { ScopedReputation, EvidenceDiversity } from '../src/index.js'

// Build a reputation with controlled diversity for deterministic tests.
function makeRep(opts: {
  receiptCount?: number
  distinctPrincipals?: number
  distinctEvidenceClasses?: number
  successCount?: number
  failureCount?: number
  firstObservedAt?: string
  lastUpdatedAt?: string
} = {}): ScopedReputation {
  const base = createScopedReputation('p-test', 'a-test', 's-test')
  const diversity: EvidenceDiversity = {
    ...createEvidenceDiversity(),
    distinctPrincipals: opts.distinctPrincipals ?? 0,
    distinctEvidenceClasses: opts.distinctEvidenceClasses ?? 0,
    successCount: opts.successCount ?? 0,
    failureCount: opts.failureCount ?? 0,
  }
  return {
    ...base,
    receiptCount: opts.receiptCount ?? 0,
    evidenceDiversity: diversity,
    firstObservedAt: opts.firstObservedAt,
    lastUpdatedAt: opts.lastUpdatedAt ?? base.lastUpdatedAt,
  }
}

describe('confidenceBreakdown — composite matches computeConfidence', () => {
  // Ten varied inputs covering early-exit cases, mid-range scores, and saturated scores.
  const cases: Array<{ label: string; rep: ScopedReputation }> = [
    { label: 'fresh empty rep (early exit: receiptCount=0)', rep: makeRep() },
    { label: 'no diversity (early exit)', rep: { ...makeRep({ receiptCount: 5 }), evidenceDiversity: undefined } },
    { label: 'receipts but zero success+failure (early exit)', rep: makeRep({ receiptCount: 3 }) },
    { label: 'low volume, single principal, healthy 10% failure', rep: makeRep({
      receiptCount: 10, distinctPrincipals: 1, distinctEvidenceClasses: 2,
      successCount: 9, failureCount: 1,
      firstObservedAt: '2026-01-01T00:00:00.000Z', lastUpdatedAt: '2026-01-15T00:00:00.000Z',
    }) },
    { label: 'mid volume, multi principal, all-success few interactions', rep: makeRep({
      receiptCount: 5, distinctPrincipals: 3, distinctEvidenceClasses: 1,
      successCount: 5, failureCount: 0,
      firstObservedAt: '2026-01-01T00:00:00.000Z', lastUpdatedAt: '2026-01-08T00:00:00.000Z',
    }) },
    { label: 'high volume, max diversity, optimal failure rate', rep: makeRep({
      receiptCount: 100, distinctPrincipals: 8, distinctEvidenceClasses: 4,
      successCount: 90, failureCount: 10,
      firstObservedAt: '2026-01-01T00:00:00.000Z', lastUpdatedAt: '2026-02-01T00:00:00.000Z',
    }) },
    { label: 'high volume, low principal diversity', rep: makeRep({
      receiptCount: 80, distinctPrincipals: 1, distinctEvidenceClasses: 3,
      successCount: 70, failureCount: 10,
      firstObservedAt: '2026-01-01T00:00:00.000Z', lastUpdatedAt: '2026-01-30T00:00:00.000Z',
    }) },
    { label: 'too many failures (>50%) penalized to 0.2', rep: makeRep({
      receiptCount: 20, distinctPrincipals: 4, distinctEvidenceClasses: 2,
      successCount: 8, failureCount: 12,
      firstObservedAt: '2026-01-01T00:00:00.000Z', lastUpdatedAt: '2026-01-20T00:00:00.000Z',
    }) },
    { label: 'no temporal metadata fallback', rep: makeRep({
      receiptCount: 12, distinctPrincipals: 2, distinctEvidenceClasses: 2,
      successCount: 11, failureCount: 1,
    }) },
    { label: 'fully saturated optimal: lots of receipts, principals, classes, healthy', rep: makeRep({
      receiptCount: 150, distinctPrincipals: 10, distinctEvidenceClasses: 4,
      successCount: 140, failureCount: 10,
      firstObservedAt: '2026-01-01T00:00:00.000Z', lastUpdatedAt: '2026-03-01T00:00:00.000Z',
    }) },
  ]

  for (const c of cases) {
    it(c.label, () => {
      const breakdown = confidenceBreakdown(c.rep)
      const direct = computeConfidence(c.rep)
      assert.equal(
        breakdown.composite, direct,
        `composite=${breakdown.composite} should equal computeConfidence=${direct}`
      )
    })
  }
})

describe('confidenceBreakdown — sub-score ranges', () => {
  it('all sub-scores fall in [0, 1] across diverse inputs', () => {
    const inputs: ScopedReputation[] = [
      makeRep(),
      makeRep({ receiptCount: 1, distinctPrincipals: 0, distinctEvidenceClasses: 1, successCount: 1, failureCount: 0 }),
      makeRep({ receiptCount: 50, distinctPrincipals: 5, distinctEvidenceClasses: 4, successCount: 45, failureCount: 5,
        firstObservedAt: '2026-01-01T00:00:00.000Z', lastUpdatedAt: '2026-01-29T00:00:00.000Z' }),
      makeRep({ receiptCount: 1000, distinctPrincipals: 100, distinctEvidenceClasses: 100, successCount: 900, failureCount: 100,
        firstObservedAt: '2026-01-01T00:00:00.000Z', lastUpdatedAt: '2026-06-01T00:00:00.000Z' }),
    ]
    for (const rep of inputs) {
      const b = confidenceBreakdown(rep)
      for (const key of ['volume', 'principal', 'class', 'health', 'temporal'] as const) {
        const v = b[key]
        assert.ok(v >= 0 && v <= 1, `${key}=${v} out of [0,1]`)
      }
      assert.ok(b.composite >= 0 && b.composite <= 1, `composite=${b.composite} out of [0,1]`)
    }
  })
})

describe('confidenceBreakdown — re-weighting reproduces composite', () => {
  // The known weights for computeConfidence are 1/5 each (5-way geometric mean).
  // Therefore: composite = (volume * principal * class * health * temporal)^(1/5),
  // rounded to 3 decimals as in computeConfidence.
  const cases = [
    { receiptCount: 10, distinctPrincipals: 2, distinctEvidenceClasses: 2,
      successCount: 9, failureCount: 1,
      firstObservedAt: '2026-01-01T00:00:00.000Z', lastUpdatedAt: '2026-01-15T00:00:00.000Z' },
    { receiptCount: 50, distinctPrincipals: 5, distinctEvidenceClasses: 3,
      successCount: 45, failureCount: 5,
      firstObservedAt: '2026-01-01T00:00:00.000Z', lastUpdatedAt: '2026-02-01T00:00:00.000Z' },
    { receiptCount: 100, distinctPrincipals: 10, distinctEvidenceClasses: 4,
      successCount: 90, failureCount: 10,
      firstObservedAt: '2026-01-01T00:00:00.000Z', lastUpdatedAt: '2026-03-01T00:00:00.000Z' },
  ]

  for (const c of cases) {
    it(`reproduces composite via geometric mean for receipts=${c.receiptCount}`, () => {
      const rep = makeRep(c)
      const b = confidenceBreakdown(rep)
      const product = b.volume * b.principal * b.class * b.health * b.temporal
      const reconstructed = Math.round(Math.pow(product, 0.2) * 1000) / 1000
      assert.equal(
        reconstructed, b.composite,
        `geometric mean ${reconstructed} should equal composite ${b.composite}`
      )
    })
  }

  it('early-exit case: all-zero sub-scores reproduce composite=0', () => {
    const rep = makeRep() // receiptCount=0 → early exit
    const b = confidenceBreakdown(rep)
    assert.equal(b.composite, 0)
    for (const key of ['volume', 'principal', 'class', 'health', 'temporal'] as const) {
      assert.equal(b[key], 0)
    }
    // Geometric mean of all zeros is 0
    const product = b.volume * b.principal * b.class * b.health * b.temporal
    assert.equal(Math.pow(product, 0.2), 0)
  })
})

describe('confidenceBreakdown — integration with updateReputationFromResult', () => {
  it('breakdown remains consistent after a real reputation update', () => {
    let rep = createScopedReputation('p-int', 'a-int', 's-int')
    rep = updateReputationFromResult(rep, true, 'standard', { principalHash: 'h1', taskType: 't1' })
    rep = updateReputationFromResult(rep, true, 'complex', { principalHash: 'h2', taskType: 't2' })
    rep = updateReputationFromResult(rep, false, 'standard', { principalHash: 'h3', taskType: 't1' })

    const b = confidenceBreakdown(rep)
    const direct = computeConfidence(rep)
    assert.equal(b.composite, direct)
    // After a few updates the volume sub-score should be positive
    assert.ok(b.volume > 0, 'volume should be > 0 after 3 receipts')
    // Three principals → principal score should be 0.2 + 0.2*3 = 0.8
    assert.equal(b.principal, 0.8)
  })
})
