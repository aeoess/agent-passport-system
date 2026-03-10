// Reputation-Gated Authority Tests
// Coverage for all exported functions in src/core/reputation-authority.ts
// Addresses the new Layer 9 extension: earned trust gates agent authority.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  DEFAULT_K, MAX_SIGMA, INITIAL_MU, INITIAL_SIGMA, SCARRING_PENALTY,
  DEFAULT_TIERS, DEFAULT_PROMOTION_REQUIREMENTS,
  computeEffectiveScore, createScopedReputation,
  classifyEvidence, resolveAuthorityTier, shouldDemote,
  effectiveAutonomy, effectiveSpendLimit, effectiveDelegationDepth,
  classifyRuntimeChange, sigmaAfterRuntimeChange,
  meetsPromotionRequirements
} from '../src/index.js'

import type {
  TaskClassification, EvidencePortfolio,
  RuntimeProfile, PromotionRequirements
} from '../src/index.js'

// ══════════════════════════════════════
// 1. Bayesian Score
// ══════════════════════════════════════

describe('computeEffectiveScore', () => {
  it('computes mu - k*sigma', () => {
    // mu=80, sigma=5, k=2 → 80-10=70
    assert.equal(computeEffectiveScore(80, 5, 2), 70)
  })

  it('clamps to 0 when sigma is large', () => {
    // mu=25, sigma=25, k=2 → 25-50=-25 → 0
    assert.equal(computeEffectiveScore(25, 25, 2), 0)
  })

  it('clamps to 100', () => {
    assert.equal(computeEffectiveScore(100, 0, 2), 100)
  })

  it('uses default k=2', () => {
    // mu=90, sigma=5 → 90-10=80
    assert.equal(computeEffectiveScore(90, 5), 80)
  })

  it('respects custom k', () => {
    // mu=60, sigma=15, k=1.5 → 60-22.5=37.5
    assert.equal(computeEffectiveScore(60, 15, 1.5), 37.5)
  })
})

describe('createScopedReputation', () => {
  it('creates fresh reputation with correct defaults', () => {
    const rep = createScopedReputation('principal-abc', 'agent-001', 'code_execution')
    assert.equal(rep.principalId, 'principal-abc')
    assert.equal(rep.agentId, 'agent-001')
    assert.equal(rep.scope, 'code_execution')
    assert.equal(rep.mu, INITIAL_MU)
    assert.equal(rep.sigma, INITIAL_SIGMA)
    assert.equal(rep.receiptCount, 0)
    assert.ok(rep.lastUpdatedAt)
  })

  it('fresh agent effective score is 0 (max uncertainty)', () => {
    const rep = createScopedReputation('p', 'a', 's')
    const score = computeEffectiveScore(rep.mu, rep.sigma)
    // mu=25, sigma=25, k=2 → 25-50=-25 → 0
    assert.equal(score, 0)
  })
})

// ══════════════════════════════════════
// 2. Evidence Classification
// ══════════════════════════════════════

describe('classifyEvidence', () => {
  it('trivial: no complexity signals', () => {
    const tc: TaskClassification = {
      stake: 'low', workflowDepth: 'simple',
      externality: 'none', oversightRequired: 'none',
    }
    assert.equal(classifyEvidence(tc), 'trivial')
  })

  it('standard: one signal (medium stake)', () => {
    const tc: TaskClassification = {
      stake: 'medium', workflowDepth: 'simple',
      externality: 'none', oversightRequired: 'none',
    }
    assert.equal(classifyEvidence(tc), 'standard')
  })

  it('standard: one signal (multi-step only)', () => {
    const tc: TaskClassification = {
      stake: 'low', workflowDepth: 'multi-step',
      externality: 'none', oversightRequired: 'none',
    }
    assert.equal(classifyEvidence(tc), 'standard')
  })

  it('complex: two signals (medium stake + multi-step)', () => {
    const tc: TaskClassification = {
      stake: 'medium', workflowDepth: 'multi-step',
      externality: 'none', oversightRequired: 'none',
    }
    assert.equal(classifyEvidence(tc), 'complex')
  })

  it('complex: two signals (review + internal effect)', () => {
    const tc: TaskClassification = {
      stake: 'low', workflowDepth: 'simple',
      externality: 'internal', oversightRequired: 'review',
    }
    assert.equal(classifyEvidence(tc), 'complex')
  })

  it('critical: external-irreversible (short-circuit)', () => {
    const tc: TaskClassification = {
      stake: 'low', workflowDepth: 'simple',
      externality: 'external-irreversible', oversightRequired: 'none',
    }
    assert.equal(classifyEvidence(tc), 'critical')
  })

  it('critical: high stake + human-gated', () => {
    const tc: TaskClassification = {
      stake: 'high', workflowDepth: 'simple',
      externality: 'none', oversightRequired: 'human-gated',
    }
    assert.equal(classifyEvidence(tc), 'critical')
  })
})

// ══════════════════════════════════════
// 3. Tier Resolution + Hysteresis
// ══════════════════════════════════════

describe('resolveAuthorityTier', () => {
  it('score 0 → recruit', () => {
    assert.equal(resolveAuthorityTier(0).tier, 0)
  })
  it('score 30 → operator', () => {
    assert.equal(resolveAuthorityTier(30).tier, 1)
  })
  it('score 60 → specialist', () => {
    assert.equal(resolveAuthorityTier(60).tier, 2)
  })
  it('score 80 → captain', () => {
    assert.equal(resolveAuthorityTier(80).tier, 3)
  })
  it('score 95 → sovereign', () => {
    assert.equal(resolveAuthorityTier(95).tier, 4)
  })
  it('score 79 → specialist (not captain)', () => {
    assert.equal(resolveAuthorityTier(79).tier, 2)
  })

  it('scarring: 1 demotion raises thresholds by 5', () => {
    // Captain normally needs 80. With 1 demotion: 80+5=85.
    // Score 80 → specialist (needs 60+5=65, 80>=65)
    assert.equal(resolveAuthorityTier(80, 1).tier, 2)
    // Score 85 → captain (85 >= 85)
    assert.equal(resolveAuthorityTier(85, 1).tier, 3)
  })

  it('scarring: 2 demotions raise captain threshold to 90', () => {
    assert.equal(resolveAuthorityTier(89, 2).tier, 2) // specialist (60+10=70, 89>=70)
    assert.equal(resolveAuthorityTier(90, 2).tier, 3) // captain (80+10=90, 90>=90)
  })

  it('heavy scarring can make sovereign unreachable', () => {
    // Sovereign needs 95 + 3*5 = 110. Max score is 100.
    assert.equal(resolveAuthorityTier(100, 3).tier, 3) // captain at best
  })
})

describe('shouldDemote', () => {
  it('returns false when score above demoteAt', () => {
    // Captain demoteAt=65, score=70
    assert.equal(shouldDemote(70, 3), false)
  })

  it('returns true when score below demoteAt', () => {
    // Captain demoteAt=65, score=64
    assert.equal(shouldDemote(64, 3), true)
  })

  it('hysteresis: promote at 80 but demote only at 65', () => {
    // Score 70: below captain promote (80) but above captain demote (65)
    assert.equal(shouldDemote(70, 3), false)
  })

  it('returns false for recruit (demoteAt=-1)', () => {
    assert.equal(shouldDemote(0, 0), false)
  })
})

// ══════════════════════════════════════
// 4. Core Invariant: min(delegation, tier)
// ══════════════════════════════════════

describe('effectiveAuthority', () => {
  it('effectiveAutonomy returns the minimum', () => {
    assert.equal(effectiveAutonomy(4, 2), 2) // delegation=4, tier=2 → 2
    assert.equal(effectiveAutonomy(2, 4), 2) // delegation=2, tier=4 → 2
    assert.equal(effectiveAutonomy(3, 3), 3) // equal
  })

  it('effectiveSpendLimit returns the minimum', () => {
    assert.equal(effectiveSpendLimit(1000, 500), 500)
    assert.equal(effectiveSpendLimit(100, 2000), 100)
  })

  it('effectiveDelegationDepth returns the minimum', () => {
    assert.equal(effectiveDelegationDepth(5, 2), 2)
    assert.equal(effectiveDelegationDepth(1, 3), 1)
  })

  it('tier cannot expand delegation authority', () => {
    // Delegation allows autonomy 2 and spend $100.
    // Agent earned tier with autonomy 5 and spend $10000.
    // Effective is still capped at delegation.
    assert.equal(effectiveAutonomy(2, 5), 2)
    assert.equal(effectiveSpendLimit(100, 10000), 100)
  })

  it('delegation cannot expand tier authority', () => {
    // Delegation allows autonomy 5 and spend $10000.
    // Agent only earned tier 1 (autonomy 2, spend $100).
    // Effective is capped at tier.
    assert.equal(effectiveAutonomy(5, 2), 2)
    assert.equal(effectiveSpendLimit(10000, 100), 100)
  })
})

// ══════════════════════════════════════
// 5. Runtime Change Detection
// ══════════════════════════════════════

describe('classifyRuntimeChange', () => {
  const base: RuntimeProfile = {
    modelFamily: 'claude', modelVersion: '4.0',
    provider: 'anthropic', toolsetHash: 'abc', policyProfileHash: 'def',
  }

  it('returns null for identical profiles', () => {
    assert.equal(classifyRuntimeChange(base, { ...base }), null)
  })

  it('architecture: different provider', () => {
    assert.equal(classifyRuntimeChange(base, { ...base, provider: 'openai' }), 'architecture')
  })

  it('architecture: different model family', () => {
    assert.equal(classifyRuntimeChange(base, { ...base, modelFamily: 'gpt' }), 'architecture')
  })

  it('major: different model version', () => {
    assert.equal(classifyRuntimeChange(base, { ...base, modelVersion: '5.0' }), 'major')
  })

  it('minor: only toolset changed', () => {
    assert.equal(classifyRuntimeChange(base, { ...base, toolsetHash: 'xyz' }), 'minor')
  })

  it('minor: only policy changed', () => {
    assert.equal(classifyRuntimeChange(base, { ...base, policyProfileHash: 'new' }), 'minor')
  })
})

describe('sigmaAfterRuntimeChange', () => {
  it('minor: small sigma increase', () => {
    assert.equal(sigmaAfterRuntimeChange(5, 'minor'), 10)
  })

  it('major: sigma resets to 80% of max', () => {
    assert.equal(sigmaAfterRuntimeChange(5, 'major'), 20)
  })

  it('architecture: sigma resets to max', () => {
    assert.equal(sigmaAfterRuntimeChange(5, 'architecture'), MAX_SIGMA)
  })

  it('minor capped at MAX_SIGMA', () => {
    assert.equal(sigmaAfterRuntimeChange(23, 'minor'), MAX_SIGMA)
  })

  it('scenario: model upgrade drops effective score', () => {
    // Sovereign agent: mu=95, sigma=2 → effective=91
    const before = computeEffectiveScore(95, 2)
    assert.ok(before > 80, 'Before upgrade: captain-level')

    // Architecture change resets sigma to 25
    const newSigma = sigmaAfterRuntimeChange(2, 'architecture')
    const after = computeEffectiveScore(95, newSigma)
    assert.ok(after < 50, 'After upgrade: effective score drops dramatically')

    // But mu is preserved, so recovery is fast with few good receipts
    // Simulating: sigma drops to 10 after some receipts
    const recovered = computeEffectiveScore(95, 10)
    assert.ok(recovered >= 70, 'After recovery: back to specialist+ range')
  })
})

// ══════════════════════════════════════
// 6. Promotion Requirements
// ══════════════════════════════════════

describe('meetsPromotionRequirements', () => {
  const goodPortfolio: EvidencePortfolio = {
    scope: 'code_execution',
    totalReceipts: 60,
    classCounts: { trivial: 30, standard: 18, complex: 9, critical: 3 },
    distinctReviewers: 3,
    distinctTaskTypes: 4,
    failureRate: 0.05,
    interventionRate: 0.1,
  }
  // For tier 2 (specialist): minReceipts=50, minStandardPct=0.2, minComplexPct=0.05
  const reqs = DEFAULT_PROMOTION_REQUIREMENTS[2]

  it('passes when all criteria met', () => {
    const result = meetsPromotionRequirements(goodPortfolio, reqs)
    assert.equal(result.eligible, true)
    assert.equal(result.failures.length, 0)
  })

  it('fails on insufficient receipts', () => {
    const result = meetsPromotionRequirements(
      { ...goodPortfolio, totalReceipts: 30 }, reqs
    )
    assert.equal(result.eligible, false)
    assert.ok(result.failures.some(f => f.includes('Receipts')))
  })

  it('fails on low complexity diversity', () => {
    const result = meetsPromotionRequirements(
      { ...goodPortfolio, classCounts: { trivial: 55, standard: 5, complex: 0, critical: 0 } },
      reqs
    )
    // standard+ = 5/60 = 8.3% < 20%, complex+ = 0% < 5%
    assert.equal(result.eligible, false)
    assert.ok(result.failures.some(f => f.includes('Complex+')))
  })

  it('fails on too few reviewers', () => {
    const result = meetsPromotionRequirements(
      { ...goodPortfolio, distinctReviewers: 1 }, reqs
    )
    assert.equal(result.eligible, false)
    assert.ok(result.failures.some(f => f.includes('reviewers')))
  })

  it('fails on high failure rate', () => {
    const result = meetsPromotionRequirements(
      { ...goodPortfolio, failureRate: 0.5 }, reqs
    )
    assert.equal(result.eligible, false)
    assert.ok(result.failures.some(f => f.includes('Failure rate')))
  })

  it('returns all failure reasons simultaneously', () => {
    const badPortfolio: EvidencePortfolio = {
      scope: 'code_execution',
      totalReceipts: 5,
      classCounts: { trivial: 5, standard: 0, complex: 0, critical: 0 },
      distinctReviewers: 0,
      distinctTaskTypes: 1,
      failureRate: 0.8,
      interventionRate: 0.9,
    }
    const result = meetsPromotionRequirements(badPortfolio, reqs)
    assert.equal(result.eligible, false)
    assert.ok(result.failures.length >= 5, `Expected 5+ failures, got ${result.failures.length}`)
  })
})
