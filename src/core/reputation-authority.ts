// ══════════════════════════════════════════════════════════════════
// Reputation-Gated Authority — Core Implementation
// ══════════════════════════════════════════════════════════════════
// Core invariant: effectiveAuthority = min(delegation, tier)
// Reputation is Bayesian: (mu, sigma) per (principal, agent, scope).
// Effective score = mu - k * sigma.
// Tier crossing requires signed promotion review.
// ══════════════════════════════════════════════════════════════════

import type {
  ScopedReputation, AuthorityTier, TierDefinition,
  EvidenceClass, TaskClassification, EvidencePortfolio,
  PromotionRequirements, RuntimeProfile, RuntimeChangeClass,
  DemotionCause, DemotionEvent, TierOrigin
} from '../types/reputation-authority.js'
import type { AutonomyLevel } from '../types/intent.js'

// ── Constants ──

/** Strictness constant for effective score: score = mu - K * sigma */
export const DEFAULT_K = 2

/** Maximum uncertainty value */
export const MAX_SIGMA = 25

/** Initial mu for a new agent (slight benefit of doubt) */
export const INITIAL_MU = 25

/** Initial sigma for a new agent (maximum uncertainty) */
export const INITIAL_SIGMA = MAX_SIGMA

/** Points added to promotion threshold per demotion (cryptographic scarring) */
export const SCARRING_PENALTY = 5

/** Default tier definitions with hysteresis */
export const DEFAULT_TIERS: TierDefinition[] = [
  { tier: 0, name: 'recruit',    promoteAt: 0,  demoteAt: -1,  autonomyLevel: 1 as AutonomyLevel, maxDelegationDepth: 0, maxSpendPerAction: 0 },
  { tier: 1, name: 'operator',   promoteAt: 30, demoteAt: 15,  autonomyLevel: 2 as AutonomyLevel, maxDelegationDepth: 1, maxSpendPerAction: 100 },
  { tier: 2, name: 'specialist', promoteAt: 60, demoteAt: 45,  autonomyLevel: 3 as AutonomyLevel, maxDelegationDepth: 2, maxSpendPerAction: 500 },
  { tier: 3, name: 'captain',    promoteAt: 80, demoteAt: 65,  autonomyLevel: 4 as AutonomyLevel, maxDelegationDepth: 3, maxSpendPerAction: 2000 },
  { tier: 4, name: 'sovereign',  promoteAt: 95, demoteAt: 80,  autonomyLevel: 5 as AutonomyLevel, maxDelegationDepth: 5, maxSpendPerAction: 10000 },
]

// ── Bayesian Score ──

/**
 * Compute effective reputation score from (mu, sigma).
 * Higher sigma (uncertainty) penalizes the score.
 * Result clamped to [0, 100].
 */
export function computeEffectiveScore(
  mu: number,
  sigma: number,
  k: number = DEFAULT_K
): number {
  const raw = mu - k * sigma
  return Math.max(0, Math.min(100, Math.round(raw * 100) / 100))
}

/**
 * Create a fresh reputation state for a new (principal, agent, scope) tuple.
 */
export function createScopedReputation(
  principalId: string,
  agentId: string,
  scope: string
): ScopedReputation {
  return {
    principalId, agentId, scope,
    mu: INITIAL_MU,
    sigma: INITIAL_SIGMA,
    receiptCount: 0,
    lastUpdatedAt: new Date().toISOString(),
  }
}

// ── Evidence Classification ──

/**
 * Deterministic evidence class from delegator-provided task metadata.
 * Classification is based on counting complexity signals across 4 dimensions.
 * The delegator sets TaskClassification BEFORE the agent executes,
 * preventing self-reported complexity gaming.
 */
export function classifyEvidence(tc: TaskClassification): EvidenceClass {
  // Critical: any single critical-level signal
  if (tc.externality === 'external-irreversible') return 'critical'
  if (tc.stake === 'high' && tc.oversightRequired === 'human-gated') return 'critical'

  // Count complexity signals (each dimension can contribute 0 or 1)
  let signals = 0
  if (tc.stake === 'medium' || tc.stake === 'high') signals++
  if (tc.workflowDepth === 'multi-step' || tc.workflowDepth === 'branched') signals++
  if (tc.externality === 'internal' || tc.externality === 'external-reversible') signals++
  if (tc.oversightRequired === 'review' || tc.oversightRequired === 'human-gated') signals++

  // Complex: 2+ signals
  if (signals >= 2) return 'complex'

  // Standard: 1 signal
  if (signals >= 1) return 'standard'

  // Trivial: no signals
  return 'trivial'
}

// ── Tier Resolution ──

/**
 * Resolve the highest tier an agent qualifies for based on effective score.
 * Cryptographic scarring: each past demotion increases the threshold.
 * Returns the TierDefinition the agent is at, NOT the next one.
 */
export function resolveAuthorityTier(
  effectiveScore: number,
  demotionCount: number = 0,
  tiers: TierDefinition[] = DEFAULT_TIERS
): TierDefinition {
  // Sort descending so we find the highest qualifying tier first
  const sorted = [...tiers].sort((a, b) => b.tier - a.tier)

  for (const tier of sorted) {
    // Scarring: each demotion raises the threshold
    const adjustedThreshold = tier.promoteAt + (demotionCount * SCARRING_PENALTY)
    if (effectiveScore >= adjustedThreshold) {
      return tier
    }
  }

  // Fallback to lowest tier (recruit). Should always match since promoteAt=0.
  return sorted[sorted.length - 1]
}

/**
 * Check if an agent should be demoted from their current tier.
 * Uses the demoteAt threshold (lower than promoteAt = hysteresis).
 * Only behavioral demotions increase the scarring counter.
 */
export function shouldDemote(
  effectiveScore: number,
  currentTier: number,
  tiers: TierDefinition[] = DEFAULT_TIERS
): boolean {
  const tierDef = tiers.find(t => t.tier === currentTier)
  if (!tierDef) return false
  return effectiveScore < tierDef.demoteAt
}

// ── Effective Authority (Core Invariant) ──

/**
 * Compute effective autonomy level: min(delegation, tier).
 * Delegation says "you're allowed up to X."
 * Tier says "you've earned up to Y."
 * Neither can independently expand authority.
 */
export function effectiveAutonomy(
  delegationAutonomy: AutonomyLevel,
  tierAutonomy: AutonomyLevel
): AutonomyLevel {
  return Math.min(delegationAutonomy, tierAutonomy) as AutonomyLevel
}

export function effectiveSpendLimit(
  delegationSpend: number,
  tierMaxSpend: number
): number {
  return Math.min(delegationSpend, tierMaxSpend)
}

export function effectiveDelegationDepth(
  delegationMaxDepth: number,
  tierMaxDepth: number
): number {
  return Math.min(delegationMaxDepth, tierMaxDepth)
}

// ── Runtime Change Detection ──

/**
 * Classify the severity of a runtime profile change.
 * Returns null if profiles are identical.
 */
export function classifyRuntimeChange(
  oldProfile: RuntimeProfile,
  newProfile: RuntimeProfile
): RuntimeChangeClass | null {
  // No change
  if (
    oldProfile.provider === newProfile.provider &&
    oldProfile.modelFamily === newProfile.modelFamily &&
    oldProfile.modelVersion === newProfile.modelVersion &&
    oldProfile.toolsetHash === newProfile.toolsetHash &&
    oldProfile.policyProfileHash === newProfile.policyProfileHash
  ) return null

  // Architecture: different provider or model family
  if (oldProfile.provider !== newProfile.provider) return 'architecture'
  if (oldProfile.modelFamily !== newProfile.modelFamily) return 'architecture'

  // Major: different model version within same family
  if (oldProfile.modelVersion !== newProfile.modelVersion) return 'major'

  // Minor: only toolset or policy changed
  return 'minor'
}

/**
 * Compute new sigma after a runtime profile change.
 * Minor: small increase. Major: large reset. Architecture: full reset.
 */
export function sigmaAfterRuntimeChange(
  currentSigma: number,
  changeClass: RuntimeChangeClass
): number {
  switch (changeClass) {
    case 'minor':
      return Math.min(MAX_SIGMA, currentSigma + 5)
    case 'major':
      return MAX_SIGMA * 0.8   // 20
    case 'architecture':
      return MAX_SIGMA         // 25 (full uncertainty)
  }
}

// ── Promotion Eligibility ──

/** Default promotion requirements per tier. Higher tiers need more diverse evidence. */
export const DEFAULT_PROMOTION_REQUIREMENTS: Record<number, PromotionRequirements> = {
  1: { // → Operator
    minReceipts: 10, minStandardPct: 0.1, minComplexPct: 0,
    minDistinctReviewers: 1, minDistinctTaskTypes: 2,
    maxFailureRate: 0.3, maxInterventionRate: 0.5,
    minTimeInCurrentTier: 0,
  },
  2: { // → Specialist
    minReceipts: 50, minStandardPct: 0.2, minComplexPct: 0.05,
    minDistinctReviewers: 2, minDistinctTaskTypes: 3,
    maxFailureRate: 0.15, maxInterventionRate: 0.3,
    minTimeInCurrentTier: 7 * 24 * 60 * 60 * 1000, // 7 days
  },
  3: { // → Captain
    minReceipts: 150, minStandardPct: 0.25, minComplexPct: 0.1,
    minDistinctReviewers: 3, minDistinctTaskTypes: 5,
    maxFailureRate: 0.1, maxInterventionRate: 0.2,
    minTimeInCurrentTier: 14 * 24 * 60 * 60 * 1000, // 14 days
  },
  4: { // → Sovereign
    minReceipts: 500, minStandardPct: 0.3, minComplexPct: 0.15,
    minDistinctReviewers: 5, minDistinctTaskTypes: 8,
    maxFailureRate: 0.05, maxInterventionRate: 0.1,
    minTimeInCurrentTier: 30 * 24 * 60 * 60 * 1000, // 30 days
  },
}

/**
 * Check if an evidence portfolio meets promotion requirements.
 * Returns pass/fail with specific reasons for each failed check.
 */
export function meetsPromotionRequirements(
  portfolio: EvidencePortfolio,
  requirements: PromotionRequirements
): { eligible: boolean; failures: string[] } {
  const failures: string[] = []

  if (portfolio.totalReceipts < requirements.minReceipts) {
    failures.push(`Receipts: ${portfolio.totalReceipts} < ${requirements.minReceipts} required`)
  }

  const total = portfolio.totalReceipts || 1 // avoid division by zero
  const standardPlus = portfolio.classCounts.standard + portfolio.classCounts.complex + portfolio.classCounts.critical
  const complexPlus = portfolio.classCounts.complex + portfolio.classCounts.critical

  if (standardPlus / total < requirements.minStandardPct) {
    failures.push(`Standard+ evidence: ${(standardPlus / total * 100).toFixed(1)}% < ${requirements.minStandardPct * 100}% required`)
  }

  if (complexPlus / total < requirements.minComplexPct) {
    failures.push(`Complex+ evidence: ${(complexPlus / total * 100).toFixed(1)}% < ${requirements.minComplexPct * 100}% required`)
  }

  if (portfolio.distinctReviewers < requirements.minDistinctReviewers) {
    failures.push(`Distinct reviewers: ${portfolio.distinctReviewers} < ${requirements.minDistinctReviewers} required`)
  }

  if (portfolio.distinctTaskTypes < requirements.minDistinctTaskTypes) {
    failures.push(`Distinct task types: ${portfolio.distinctTaskTypes} < ${requirements.minDistinctTaskTypes} required`)
  }

  if (portfolio.failureRate > requirements.maxFailureRate) {
    failures.push(`Failure rate: ${(portfolio.failureRate * 100).toFixed(1)}% > ${requirements.maxFailureRate * 100}% max`)
  }

  if (portfolio.interventionRate > requirements.maxInterventionRate) {
    failures.push(`Intervention rate: ${(portfolio.interventionRate * 100).toFixed(1)}% > ${requirements.maxInterventionRate * 100}% max`)
  }

  return { eligible: failures.length === 0, failures }
}
