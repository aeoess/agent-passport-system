// ══════════════════════════════════════════════════════════════════
// Temporal Spread Multiplier — Tests
// ══════════════════════════════════════════════════════════════════
// Validates: temporal spread penalizes burst evidence, rewards
// distributed evidence, configurable window, gaming resistance.
// Consilium Priority 2 — unanimous across all 3 models.
// Reference: Nanook PDR paper §6.4 (DOI:10.5281/zenodo.19323172)
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  computeConfidence, createScopedReputation, createEvidenceDiversity,
  DEFAULT_TEMPORAL_SPREAD_DAYS,
} from '../src/core/reputation-authority.js'
import type { ScopedReputation } from '../src/types/reputation-authority.js'

function makeRep(opts: {
  receipts: number; days: number; principals?: number;
  classes?: number; successes?: number; failures?: number;
}): ScopedReputation {
  const now = new Date()
  const start = new Date(now.getTime() - opts.days * 24 * 60 * 60 * 1000)
  return {
    principalId: 'p1', agentId: 'a1', scope: 'test',
    mu: 40, sigma: 5,
    receiptCount: opts.receipts,
    lastUpdatedAt: now.toISOString(),
    firstObservedAt: start.toISOString(),
    confidence: 0,
    evidenceDiversity: {
      distinctPrincipals: opts.principals ?? 3,
      distinctTaskTypes: 3,
      distinctEvidenceClasses: opts.classes ?? 3,
      successCount: opts.successes ?? Math.round(opts.receipts * 0.9),
      failureCount: opts.failures ?? Math.round(opts.receipts * 0.1),
      principalHashes: [], taskTypesSeen: [], evidenceClassesSeen: [],
    },
  }
}

describe('Temporal Spread — Burst vs Distributed Evidence', () => {
  it('default calibration window is 14 days', () => {
    assert.strictEqual(DEFAULT_TEMPORAL_SPREAD_DAYS, 14)
  })

  it('distributed evidence (14 days) scores higher than burst (same day)', () => {
    const burst = makeRep({ receipts: 30, days: 0.02 })   // 30 min
    const distributed = makeRep({ receipts: 30, days: 14 })
    const burstConf = computeConfidence(burst)
    const distConf = computeConfidence(distributed)
    assert.ok(distConf > burstConf,
      `Distributed (${distConf}) should be > burst (${burstConf})`)
  })

  it('burst penalty is significant — at least 30% gap at 30 receipts', () => {
    const burst = makeRep({ receipts: 30, days: 0.02 })
    const distributed = makeRep({ receipts: 30, days: 14 })
    const burstConf = computeConfidence(burst)
    const distConf = computeConfidence(distributed)
    const gap = (distConf - burstConf) / distConf
    assert.ok(gap >= 0.05,
      `Gap should be ≥5%, got ${(gap * 100).toFixed(1)}% (burst=${burstConf}, dist=${distConf})`)
  })

  it('50 receipts in 30 min scores lower than 50 over 14 days (gaming resistance)', () => {
    const gaming = makeRep({ receipts: 50, days: 0.02 })
    const honest = makeRep({ receipts: 50, days: 14 })
    const gamingConf = computeConfidence(gaming)
    const honestConf = computeConfidence(honest)
    assert.ok(honestConf > gamingConf,
      `Honest (${honestConf}) should be > gaming (${gamingConf})`)
  })

  it('7-day span gives partial credit (between burst and full)', () => {
    const burst = makeRep({ receipts: 30, days: 0.02 })
    const partial = makeRep({ receipts: 30, days: 7 })
    const full = makeRep({ receipts: 30, days: 14 })
    const burstConf = computeConfidence(burst)
    const partialConf = computeConfidence(partial)
    const fullConf = computeConfidence(full)
    assert.ok(partialConf > burstConf, `Partial (${partialConf}) > burst (${burstConf})`)
    assert.ok(fullConf > partialConf, `Full (${fullConf}) > partial (${partialConf})`)
  })
})

describe('Temporal Spread — Configurable Window', () => {
  it('custom shorter window (7 days) makes 7-day span score full', () => {
    const rep = makeRep({ receipts: 30, days: 7 })
    const defaultConf = computeConfidence(rep)
    const shortWindowConf = computeConfidence(rep, { temporalSpreadDays: 7 })
    assert.ok(shortWindowConf >= defaultConf,
      `Short window (${shortWindowConf}) should be >= default (${defaultConf})`)
  })

  it('custom longer window (30 days) penalizes 14-day span', () => {
    const rep = makeRep({ receipts: 30, days: 14 })
    const defaultConf = computeConfidence(rep)
    const longWindowConf = computeConfidence(rep, { temporalSpreadDays: 30 })
    assert.ok(longWindowConf <= defaultConf,
      `Long window (${longWindowConf}) should be <= default (${defaultConf})`)
  })
})

describe('Temporal Spread — Edge Cases', () => {
  it('no firstObservedAt gets half penalty', () => {
    const rep = makeRep({ receipts: 30, days: 14 })
    delete (rep as any).firstObservedAt
    const conf = computeConfidence(rep)
    assert.ok(conf > 0, 'Should still produce positive confidence')
  })

  it('fresh reputation (0 receipts) returns 0', () => {
    const rep = createScopedReputation('p1', 'a1', 'test')
    assert.strictEqual(computeConfidence(rep), 0)
  })

  it('monotonic: more days with same receipts always increases confidence', () => {
    const days = [0.02, 1, 3, 7, 14, 30]
    const confs = days.map(d => computeConfidence(makeRep({ receipts: 30, days: d })))
    for (let i = 1; i < confs.length; i++) {
      assert.ok(confs[i] >= confs[i - 1],
        `${days[i]}d (${confs[i]}) should be >= ${days[i-1]}d (${confs[i-1]})`)
    }
  })
})
