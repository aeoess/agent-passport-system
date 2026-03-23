// ══════════════════════════════════════════════════════════════════
// Reputation-Gated Authority — Core Implementation
// ══════════════════════════════════════════════════════════════════
// Core invariant: effectiveAuthority = min(delegation, tier)
// Reputation is Bayesian: (mu, sigma) per (principal, agent, scope).
// Effective score = mu - k * sigma.
// Tier crossing requires signed promotion review.
// ══════════════════════════════════════════════════════════════════

import { randomBytes } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type {
  ScopedReputation, TierDefinition,
  EvidenceClass, TaskClassification, EvidencePortfolio,
  PromotionRequirements, PromotionReview,
  RuntimeProfile, RuntimeChangeClass,
  DemotionCause, DemotionEvent, TierOrigin,
  TierEscalation, TierCheckContext
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


// ══════════════════════════════════════════════════════════════════
// Phase 2: Signed Promotion Reviews, Demotion, Tier Checking

// ══════════════════════════════════════════════════════════════════
// Phase 2: Signed Promotion Reviews, Demotion, Tier Checking
// ══════════════════════════════════════════════════════════════════

// ── Promotion Reviews ──

/**
 * Create a signed promotion review.
 * The reviewer cryptographically commits: "I reviewed this agent's
 * evidence and approve/deny their promotion to tier X."
 *
 * Enforces: reviewer must be Earned (not Fiat), reviewer tier > target tier,
 * no self-promotion.
 */
export function createPromotionReview(opts: {
  agentId: string
  principalId: string
  scope: string
  fromTier: number
  toTier: number
  reviewerId: string
  reviewerTier: number
  reviewerOrigin: TierOrigin
  evidence: EvidencePortfolio
  effectiveScore: number
  verdict: 'promoted' | 'denied'
  reasoning: string
  reviewerPrivateKey: string
  probationDays?: number
}): PromotionReview {
  // Validation: only Earned agents can promote
  if (opts.reviewerOrigin !== 'earned') {
    throw new Error(
      `Reviewer origin is '${opts.reviewerOrigin}' — only 'earned' agents can approve promotions. ` +
      'Fiat and provisional agents lack the operational track record to evaluate others.'
    )
  }

  // Validation: reviewer must be above target tier
  if (opts.reviewerTier <= opts.toTier) {
    throw new Error(
      `Reviewer tier ${opts.reviewerTier} is not above target tier ${opts.toTier}. ` +
      'Agents can only approve promotions to tiers below their own.'
    )
  }

  // Validation: no self-promotion
  if (opts.reviewerId === opts.agentId) {
    throw new Error('Self-promotion is not allowed. A different agent or human must review.')
  }

  const now = new Date()
  const probationEnd = opts.verdict === 'promoted' && opts.probationDays !== 0
    ? new Date(now.getTime() + (opts.probationDays ?? 7) * 24 * 60 * 60 * 1000).toISOString()
    : undefined

  const payload: Omit<PromotionReview, 'signature'> = {
    reviewId: `promo-${randomBytes(8).toString('hex')}`,
    agentId: opts.agentId,
    principalId: opts.principalId,
    scope: opts.scope,
    fromTier: opts.fromTier,
    toTier: opts.toTier,
    reviewerId: opts.reviewerId,
    reviewerTier: opts.reviewerTier,
    reviewerOrigin: opts.reviewerOrigin,
    evidence: opts.evidence,
    effectiveScore: opts.effectiveScore,
    verdict: opts.verdict,
    reasoning: opts.reasoning,
    probationEndsAt: probationEnd,
    timestamp: now.toISOString(),
  }

  const signature = sign(canonicalize(payload), opts.reviewerPrivateKey)
  return { ...payload, signature }
}

/**
 * Validate a promotion review's cryptographic signature and structural rules.
 */
export function validatePromotionReview(
  review: PromotionReview,
  reviewerPublicKey: string
): { valid: boolean; errors: string[] } {
  const errors: string[] = []

  // Structural checks
  if (review.reviewerOrigin !== 'earned') {
    errors.push(`Reviewer origin '${review.reviewerOrigin}' is not 'earned'`)
  }
  if (review.reviewerTier <= review.toTier) {
    errors.push(`Reviewer tier ${review.reviewerTier} not above target tier ${review.toTier}`)
  }
  if (review.reviewerId === review.agentId) {
    errors.push('Self-promotion detected')
  }

  // Cryptographic signature verification
  const { signature, ...payload } = review
  const canonical = canonicalize(payload)
  const sigValid = verify(canonical, signature, reviewerPublicKey)
  if (!sigValid) {
    errors.push('Invalid signature')
  }

  return { valid: errors.length === 0, errors }
}

// ── Demotion ──

/**
 * Create a demotion event. Only behavioral demotions affect reputation.
 * Administrative (policy change, delegation expired) and environmental
 * (upstream revocation) demotions restrict authority but preserve reputation.
 */
export function triggerDemotion(opts: {
  agentId: string
  principalId: string
  scope: string
  currentTier: number
  cause: DemotionCause
  reason: string
}): DemotionEvent {
  const toTier = Math.max(0, opts.currentTier - 1)

  return {
    agentId: opts.agentId,
    principalId: opts.principalId,
    scope: opts.scope,
    fromTier: opts.currentTier,
    toTier,
    cause: opts.cause,
    reason: opts.reason,
    timestamp: new Date().toISOString(),
    affectsReputation: opts.cause === 'behavioral',
  }
}

// ── Tier Authority Check ──

/**
 * Check if an agent's earned tier permits a specific action.
 * Called alongside evaluateIntent() — not inside it (zero blast radius).
 *
 * Returns null if the tier check passes (agent has sufficient earned authority).
 * Returns TierEscalation if the action requires higher tier than earned.
 */
export function checkTierForIntent(opts: {
  tierContext: TierCheckContext
  requestedAutonomy?: AutonomyLevel
  requestedSpend?: number
  requestedDepth?: number
}): TierEscalation | null {
  const tier = opts.tierContext.agentTier
  const score = opts.tierContext.effectiveScore

  // Check autonomy level
  const reqAutonomy = opts.requestedAutonomy ?? 1
  if (tier.autonomyLevel < reqAutonomy) {
    // Find what tier is needed
    const needed = DEFAULT_TIERS.find(t => t.autonomyLevel >= reqAutonomy)
    return {
      currentTier: tier.tier,
      requiredTier: needed?.tier ?? 4,
      effectiveScore: score,
      effectiveAutonomy: tier.autonomyLevel,
      requestedAutonomy: reqAutonomy,
      effectiveSpend: tier.maxSpendPerAction,
      requestedSpend: opts.requestedSpend,
      recommendation: 'needs_promotion',
    }
  }

  // Check spend limit
  if (opts.requestedSpend !== undefined && tier.maxSpendPerAction < opts.requestedSpend) {
    const needed = DEFAULT_TIERS.find(t => t.maxSpendPerAction >= opts.requestedSpend!)
    return {
      currentTier: tier.tier,
      requiredTier: needed?.tier ?? 4,
      effectiveScore: score,
      effectiveAutonomy: tier.autonomyLevel,
      requestedAutonomy: reqAutonomy,
      effectiveSpend: tier.maxSpendPerAction,
      requestedSpend: opts.requestedSpend,
      recommendation: opts.requestedSpend > 2000 ? 'needs_human_approval' : 'needs_promotion',
    }
  }

  // Check delegation depth
  if (opts.requestedDepth !== undefined && tier.maxDelegationDepth < opts.requestedDepth) {
    const needed = DEFAULT_TIERS.find(t => t.maxDelegationDepth >= opts.requestedDepth!)
    return {
      currentTier: tier.tier,
      requiredTier: needed?.tier ?? 4,
      effectiveScore: score,
      effectiveAutonomy: tier.autonomyLevel,
      requestedAutonomy: reqAutonomy,
      effectiveSpend: tier.maxSpendPerAction,
      recommendation: 'needs_promotion',
    }
  }

  // All checks passed
  return null
}

/**
 * Advisory soft precheck before intent creation.
 * Returns warnings but does NOT block the agent.
 * The agent can still create the intent — this is for ergonomics only.
 */
export function advisoryTierPrecheck(opts: {
  tierContext: TierCheckContext
  requestedAutonomy?: AutonomyLevel
  requestedSpend?: number
}): string[] {
  const warnings: string[] = []
  const tier = opts.tierContext.agentTier

  if (opts.requestedAutonomy && tier.autonomyLevel < opts.requestedAutonomy) {
    warnings.push(
      `Advisory: requested autonomy ${opts.requestedAutonomy} exceeds earned tier ` +
      `${tier.name} (max ${tier.autonomyLevel}). Intent will likely be denied.`
    )
  }

  if (opts.requestedSpend && tier.maxSpendPerAction < opts.requestedSpend) {
    warnings.push(
      `Advisory: requested spend $${opts.requestedSpend} exceeds tier ` +
      `${tier.name} limit ($${tier.maxSpendPerAction}).`
    )
  }

  return warnings
}

// ── Reputation Updates ──

/** Mu/sigma adjustments per evidence class and outcome */
const REPUTATION_UPDATES: Record<EvidenceClass, {
  successMu: number; successSigma: number;
  failureMu: number; failureSigma: number;
}> = {
  trivial:  { successMu: 0.5, successSigma: -0.3,  failureMu: -1.0, failureSigma: 0.5 },
  standard: { successMu: 1.0, successSigma: -0.5,  failureMu: -2.0, failureSigma: 1.0 },
  complex:  { successMu: 2.0, successSigma: -0.8,  failureMu: -3.0, failureSigma: 1.5 },
  critical: { successMu: 3.0, successSigma: -1.0,  failureMu: -5.0, failureSigma: 2.0 },
}

/** Minimum sigma — we never have perfect certainty */
const MIN_SIGMA = 1

/**
 * Update reputation (mu, sigma) from an action result.
 * Success → mu increases, sigma decreases (more confident of capability).
 * Failure → mu decreases, sigma increases (less confident).
 * Higher evidence class → larger updates (complex tasks are more informative).
 */
export function updateReputationFromResult(
  rep: ScopedReputation,
  success: boolean,
  evidenceClass: EvidenceClass
): ScopedReputation {
  const updates = REPUTATION_UPDATES[evidenceClass]

  const muDelta = success ? updates.successMu : updates.failureMu
  const sigmaDelta = success ? updates.successSigma : updates.failureSigma

  const newMu = Math.max(0, Math.min(100, rep.mu + muDelta))
  const newSigma = Math.max(MIN_SIGMA, Math.min(MAX_SIGMA, rep.sigma + sigmaDelta))

  return {
    ...rep,
    mu: Math.round(newMu * 100) / 100,
    sigma: Math.round(newSigma * 100) / 100,
    receiptCount: rep.receiptCount + 1,
    lastUpdatedAt: new Date().toISOString(),
  }
}
