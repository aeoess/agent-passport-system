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
  EvidenceClass, TaskClassification, EvidencePortfolio, EvidenceDiversity,
  PromotionRequirements, PromotionReview,
  RuntimeProfile, RuntimeChangeClass,
  DemotionCause, DemotionEvent, TierOrigin,
  TierEscalation, TierCheckContext,
  ReputationObservation,
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

/** Maximum number of evidence events retained in the ScopedReputation
 *  recentObservations ring buffer (FIFO eviction).
 *
 *  Default is 30. Rationale: NexusGuard's PDR sliding window analysis in
 *  Nanook PDR v2.19 §6.6 finds that window sizes 5-30 cover the full
 *  detection sensitivity range (5 catches drift in 5 events with
 *  alert-fatigue risk; 30 dilutes brief degradation episodes but produces
 *  stable signal). 30 is the upper end of that range, which means the
 *  ring buffer holds enough history to support every window size the
 *  paper explores without storing more than necessary. Memory cost per
 *  reputation: ~30 × 5 fields ≈ 150 small primitives, negligible.
 *
 *  Reference: Nanook PDR v2.19 §6.6, gap audit §3 row 8 / §5 rank 3. */
export const RECENT_OBSERVATIONS_CAP = 30

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
    evidenceDiversity: createEvidenceDiversity(),
    confidence: 0,
    firstObservedAt: undefined,
  }
}

/**
 * Create empty evidence diversity metadata.
 */
export function createEvidenceDiversity(): EvidenceDiversity {
  return {
    distinctPrincipals: 0,
    distinctTaskTypes: 0,
    distinctEvidenceClasses: 0,
    successCount: 0,
    failureCount: 0,
    principalHashes: [],
    taskTypesSeen: [],
    evidenceClassesSeen: [],
  }
}

/** Default temporal spread calibration window in days.
 *  Configurable per deployment. Nanook's empirical data suggests
 *  window ≥ 5 observations achieves reliable drift detection.
 *  14 days is a conservative default for most agent deployments. */
export const DEFAULT_TEMPORAL_SPREAD_DAYS = 14

/**
 * Compute confidence (0-1) from evidence diversity, volume, and temporal spread.
 *
 * Confidence is the product of five sub-scores:
 *   1. Volume: log-scaled receipt count (saturates around 100 receipts)
 *   2. Diversity of principals: more distinct principals = harder to sybil
 *   3. Diversity of evidence classes: not all trivial tasks
 *   4. Success/failure balance: some failures are HEALTHIER than 100% success
 *      (100% success with few interactions is suspicious)
 *   5. Temporal spread: evidence clustered in a short window is penalized
 *      (prevents gaming through burst submissions — Nanook PDR paper §6.4)
 *
 * Each sub-score is [0, 1]. Final confidence = geometric mean (5th root).
 * This means ALL dimensions must be non-zero for meaningful confidence.
 */
export function computeConfidence(
  rep: ScopedReputation,
  opts?: { temporalSpreadDays?: number },
): number {
  const diversity = rep.evidenceDiversity
  if (!diversity || rep.receiptCount === 0) return 0

  // Volume: log-scaled, saturates around 100 receipts
  // log2(1+n) / log2(101) → 0 at n=0, ~1.0 at n=100
  const volumeScore = Math.min(1, Math.log2(1 + rep.receiptCount) / Math.log2(101))

  // Principal diversity: how many distinct principals?
  // 1 principal = 0.2 (minimum), 5+ principals = 1.0
  const principalScore = Math.min(1, 0.2 + 0.2 * diversity.distinctPrincipals)

  // Evidence class diversity: how many distinct classes?
  // 1 class = 0.25, 4 classes = 1.0
  const classScore = Math.min(1, diversity.distinctEvidenceClasses * 0.25)

  // Healthy failure rate: 0% failures with few receipts is suspicious.
  // Optimal is 5-15% failure rate (realistic). 0% or >50% both penalized.
  const total = diversity.successCount + diversity.failureCount
  if (total === 0) return 0
  const failRate = diversity.failureCount / total
  let healthScore: number
  if (failRate === 0 && total < 20) {
    healthScore = 0.5  // suspicious: no failures yet with few interactions
  } else if (failRate >= 0.05 && failRate <= 0.15) {
    healthScore = 1.0  // healthy range
  } else if (failRate > 0.5) {
    healthScore = 0.2  // too many failures
  } else {
    healthScore = 0.7  // acceptable
  }

  // Geometric mean: all dimensions must contribute
  // Temporal spread: penalize evidence clustered in short windows
  // Formula: 0.5 + 0.5 × min(span_days / calibration_window, 1.0)
  // Floor of 0.5 means burst evidence still counts (half weight), not zero
  const spreadDays = opts?.temporalSpreadDays ?? DEFAULT_TEMPORAL_SPREAD_DAYS
  let temporalScore = 1.0
  if (rep.firstObservedAt && rep.lastUpdatedAt) {
    const firstMs = new Date(rep.firstObservedAt).getTime()
    const lastMs = new Date(rep.lastUpdatedAt).getTime()
    const spanDays = Math.max(0, (lastMs - firstMs) / (1000 * 60 * 60 * 24))
    const coverage = Math.min(spanDays / spreadDays, 1.0)
    temporalScore = 0.5 + 0.5 * coverage
  } else if (rep.receiptCount > 0) {
    // Has evidence but no temporal metadata — default to half penalty
    temporalScore = 0.5
  }

  const raw = Math.pow(volumeScore * principalScore * classScore * healthScore * temporalScore, 0.2)
  return Math.round(raw * 1000) / 1000
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
export const MIN_SIGMA = 1

/**
 * Update reputation (mu, sigma) from an action result.
 * Success → mu increases, sigma decreases (more confident of capability).
 * Failure → mu decreases, sigma increases (less confident).
 * Higher evidence class → larger updates (complex tasks are more informative).
 */
export function updateReputationFromResult(
  rep: ScopedReputation,
  success: boolean,
  evidenceClass: EvidenceClass,
  /** Optional diversity metadata — pass to enable sybil-resistant confidence scoring */
  diversityUpdate?: { principalHash?: string; taskType?: string }
): ScopedReputation {
  const updates = REPUTATION_UPDATES[evidenceClass]

  const muDelta = success ? updates.successMu : updates.failureMu
  const sigmaDelta = success ? updates.successSigma : updates.failureSigma

  const newMu = Math.max(0, Math.min(100, rep.mu + muDelta))
  const newSigma = Math.max(MIN_SIGMA, Math.min(MAX_SIGMA, rep.sigma + sigmaDelta))

  // Update evidence diversity if tracking is active
  let diversity = rep.evidenceDiversity ? { ...rep.evidenceDiversity } : createEvidenceDiversity()
  diversity = { ...diversity,
    principalHashes: [...diversity.principalHashes],
    taskTypesSeen: [...diversity.taskTypesSeen],
    evidenceClassesSeen: [...diversity.evidenceClassesSeen],
  }

  if (success) diversity.successCount++
  else diversity.failureCount++

  if (!diversity.evidenceClassesSeen.includes(evidenceClass)) {
    diversity.evidenceClassesSeen.push(evidenceClass)
    diversity.distinctEvidenceClasses = diversity.evidenceClassesSeen.length
  }

  if (diversityUpdate?.principalHash && !diversity.principalHashes.includes(diversityUpdate.principalHash)) {
    diversity.principalHashes.push(diversityUpdate.principalHash)
    diversity.distinctPrincipals = diversity.principalHashes.length
  }

  if (diversityUpdate?.taskType && !diversity.taskTypesSeen.includes(diversityUpdate.taskType)) {
    diversity.taskTypesSeen.push(diversityUpdate.taskType)
    diversity.distinctTaskTypes = diversity.taskTypesSeen.length
  }

  const roundedMu = Math.round(newMu * 100) / 100
  const roundedSigma = Math.round(newSigma * 100) / 100

  // Effective deltas: what actually changed on mu/sigma after rounding and
  // clamping. Store these (not the raw REPUTATION_UPDATES table values) so
  // that drift calculations summing recent muDeltas match the actual mu
  // trajectory at boundary cases (mu near 0 or 100, sigma at MIN/MAX).
  const effectiveMuDelta = roundedMu - rep.mu
  const effectiveSigmaDelta = roundedSigma - rep.sigma
  const observationTimestamp = new Date().toISOString()

  // Append to the recent-observations ring buffer with FIFO eviction at
  // RECENT_OBSERVATIONS_CAP. Spread to avoid mutating the input array.
  const prevRecent = rep.recentObservations ?? []
  const observation: ReputationObservation = {
    timestamp: observationTimestamp,
    success,
    evidenceClass,
    muDelta: effectiveMuDelta,
    sigmaDelta: effectiveSigmaDelta,
  }
  let nextRecent = [...prevRecent, observation]
  if (nextRecent.length > RECENT_OBSERVATIONS_CAP) {
    nextRecent = nextRecent.slice(nextRecent.length - RECENT_OBSERVATIONS_CAP)
  }

  const updated: ScopedReputation = {
    ...rep,
    mu: roundedMu,
    sigma: roundedSigma,
    receiptCount: rep.receiptCount + 1,
    lastUpdatedAt: observationTimestamp,
    evidenceDiversity: diversity,
    recentObservations: nextRecent,
  }
  updated.confidence = computeConfidence(updated)
  return updated
}

// ══════════════════════════════════════
// Temporal Decay
// Motivated by Nanook PDR v2.19 §7.6.1: the paper attributes a linear sigma
// drift adapter to AEOESS (the first-order Euler discretization of Bhardwaj's
// Riemannian Langevin diffusion). This function makes that claim concrete in
// SDK code so callers can compute "what is this agent's reputation right now
// if no new evidence arrived" without re-running the full update pipeline.
// ══════════════════════════════════════

/** How many days of inactivity it takes for sigma to drift from MIN_SIGMA to
 *  MAX_SIGMA at the default rate. 180 days is a deliberate round number: it
 *  matches the typical employee-review cadence and is long enough that an
 *  agent operating weekly never reaches max uncertainty from inactivity alone. */
export const DEFAULT_DECAY_DAYS = 180

/** Default drift rate per day, derived so that sigma traverses the full
 *  [MIN_SIGMA, MAX_SIGMA] range in DEFAULT_DECAY_DAYS. Linear, not exponential —
 *  the function is the discrete first-order step of a continuous diffusion. */
export const DEFAULT_DRIFT_RATE_PER_DAY = (MAX_SIGMA - MIN_SIGMA) / DEFAULT_DECAY_DAYS

const SECONDS_PER_DAY = 86400

/**
 * Apply temporal decay to a reputation by growing sigma linearly with elapsed
 * time. Pure function — does not mutate input.
 *
 * Semantics:
 *   - sigma += driftRatePerDay * (elapsedSeconds / 86400), clamped to
 *     [MIN_SIGMA, maxSigma]
 *   - mu is unchanged. Decay is uncertainty growth, not capability change.
 *   - lastUpdatedAt is advanced by elapsedSeconds. The function does NOT
 *     consult the system clock; elapsedSeconds is the authoritative delta.
 *   - receiptCount is unchanged. Decay does not consume evidence.
 *   - Idempotent: applyTemporalDecay(applyTemporalDecay(r, t1), t2) equals
 *     applyTemporalDecay(r, t1 + t2) within floating-point tolerance, as long
 *     as no clamp is reached in the intermediate step.
 *
 * @param rep             Source reputation. Not mutated.
 * @param elapsedSeconds  Non-negative seconds of elapsed time to apply.
 * @param opts.maxSigma   Override the max sigma ceiling (default MAX_SIGMA = 25).
 * @param opts.driftRatePerDay  Override the drift rate (default 24/180/day).
 *
 * Reference: Nanook PDR v2.19 §7.6.1, gap audit §5 rank 1.
 */
export function applyTemporalDecay(
  rep: ScopedReputation,
  elapsedSeconds: number,
  opts?: { maxSigma?: number; driftRatePerDay?: number }
): ScopedReputation {
  if (typeof elapsedSeconds !== 'number' || !Number.isFinite(elapsedSeconds)) {
    throw new Error('applyTemporalDecay: elapsedSeconds must be a finite number')
  }
  if (elapsedSeconds < 0) {
    throw new Error('applyTemporalDecay: elapsedSeconds must be non-negative')
  }

  const maxSigma = opts?.maxSigma ?? MAX_SIGMA
  const driftRatePerDay = opts?.driftRatePerDay ?? DEFAULT_DRIFT_RATE_PER_DAY

  const elapsedDays = elapsedSeconds / SECONDS_PER_DAY
  const sigmaDelta = driftRatePerDay * elapsedDays
  // Clamp to [MIN_SIGMA, maxSigma]. No rounding — idempotency requires full precision.
  const newSigma = Math.min(maxSigma, Math.max(MIN_SIGMA, rep.sigma + sigmaDelta))

  // Advance lastUpdatedAt by elapsedSeconds without consulting wall clock.
  const lastMs = new Date(rep.lastUpdatedAt).getTime()
  const newLastUpdatedAt = new Date(lastMs + elapsedSeconds * 1000).toISOString()

  return {
    ...rep,
    sigma: newSigma,
    lastUpdatedAt: newLastUpdatedAt,
  }
}

// ══════════════════════════════════════
// Confidence Breakdown
// Motivated by Nanook PDR v2.19 §6.4 / §7.6.1 and gap audit §3 row 17.
// computeConfidence() returns a single 0-1 number computed as the geometric
// mean of five sub-scores. Callers that want to inspect or re-weight the
// dimensions had to recompute the math themselves. This exposes the same
// five sub-scores plus the composite, with composite guaranteed equal to
// computeConfidence(rep) by construction.
// ══════════════════════════════════════

export interface ConfidenceBreakdown {
  /** Receipt-volume sub-score: log2(1+n) / log2(101). Range [0, 1]. */
  volume: number
  /** Distinct-principals sub-score: 0.2 + 0.2 * distinctPrincipals. Range [0, 1]. */
  principal: number
  /** Distinct-evidence-classes sub-score: 0.25 * distinctEvidenceClasses. Range [0, 1]. */
  class: number
  /** Failure-rate health sub-score. 1.0 in healthy 5-15% band, 0.2 above 50%, 0.5 if all-success and few interactions, 0.7 otherwise. */
  health: number
  /** Temporal-spread sub-score: 0.5 + 0.5 * min(spanDays/spreadDays, 1). Floor 0.5. */
  temporal: number
  /** Composite confidence equal to computeConfidence(rep). The 5-way geometric
   *  mean of the sub-scores above (with rounding to 3 decimals as in computeConfidence). */
  composite: number
}

/**
 * Decompose computeConfidence(rep) into its five named sub-scores.
 *
 * The composite field is guaranteed equal to computeConfidence(rep) by
 * construction. The sub-scores reproduce the same internal calculation
 * computeConfidence performs, exposing them for inspection and re-weighting.
 *
 * In the early-exit cases where computeConfidence returns 0 (no diversity,
 * zero receipts, or zero success+failure events), all sub-scores are reported
 * as 0 so that any geometric or weighted mean over them also yields 0,
 * preserving the "re-weighting reproduces composite" invariant.
 *
 * Reference: Nanook PDR v2.19 §6.4, gap audit §3 row 17.
 */
export function confidenceBreakdown(rep: ScopedReputation): ConfidenceBreakdown {
  const composite = computeConfidence(rep)

  const diversity = rep.evidenceDiversity
  if (!diversity || rep.receiptCount === 0) {
    return { volume: 0, principal: 0, class: 0, health: 0, temporal: 0, composite }
  }
  const total = diversity.successCount + diversity.failureCount
  if (total === 0) {
    return { volume: 0, principal: 0, class: 0, health: 0, temporal: 0, composite }
  }

  // Mirror the exact formulas from computeConfidence (above).
  const volume = Math.min(1, Math.log2(1 + rep.receiptCount) / Math.log2(101))
  const principal = Math.min(1, 0.2 + 0.2 * diversity.distinctPrincipals)
  const cls = Math.min(1, diversity.distinctEvidenceClasses * 0.25)

  const failRate = diversity.failureCount / total
  let health: number
  if (failRate === 0 && total < 20) {
    health = 0.5
  } else if (failRate >= 0.05 && failRate <= 0.15) {
    health = 1.0
  } else if (failRate > 0.5) {
    health = 0.2
  } else {
    health = 0.7
  }

  let temporal = 1.0
  if (rep.firstObservedAt && rep.lastUpdatedAt) {
    const firstMs = new Date(rep.firstObservedAt).getTime()
    const lastMs = new Date(rep.lastUpdatedAt).getTime()
    const spanDays = Math.max(0, (lastMs - firstMs) / (1000 * 60 * 60 * 24))
    const coverage = Math.min(spanDays / DEFAULT_TEMPORAL_SPREAD_DAYS, 1.0)
    temporal = 0.5 + 0.5 * coverage
  } else if (rep.receiptCount > 0) {
    temporal = 0.5
  }

  return { volume, principal, class: cls, health, temporal, composite }
}

// ══════════════════════════════════════
// Sliding Window Drift Detection
// Reference: Nanook PDR v2.19 §6.6, gap audit §3 row 8 / §5 rank 3.
//
// Rests on the recentObservations ring buffer added to ScopedReputation in
// the same change set. The cumulative score is rep.mu (the running Bayesian
// aggregate). The windowed score reflects what the agent's recent behavior
// has done to mu — specifically, the sum of effective muDeltas across the
// last N observations. delta = sum(recent muDeltas) is signed: positive
// means recent events pushed mu up (improving), negative means down
// (degrading).
//
// This is the honest version of the function. An earlier draft tried to
// approximate windowing from cumulative-only state (mu, sigma, receiptCount,
// successCount, failureCount) and found that no such approximation actually
// measures recent drift — every formula either returned delta=0 or relabeled
// a non-windowed statistic as windowed. The ring buffer makes it real.
// ══════════════════════════════════════

/** Severity-graded drift alert. Null when severity === 'none'.
 *
 *  Default thresholds (0.15 warning / 0.30 critical) match NexusGuard AIP
 *  v0.5.48 — the implementation Nanook PDR v2.19 §6.6 references — for
 *  cross-system interop. They are NOT scientifically calibrated. Callers
 *  should override for their own deployments based on the variance profile
 *  of their fleet. */
export interface DriftAlert {
  severity: 'none' | 'warning' | 'critical'
  /** Signed delta. Positive = improving, negative = degrading. Same units as mu (0-100). */
  delta: number
  warningThreshold: number
  criticalThreshold: number
  direction: 'improving' | 'degrading' | 'stable'
  /** Short, actionable recommendation tied to severity + direction. */
  recommendation: string
}

/** Result of computeReputationDrift. The cumulative side is the running mu;
 *  the windowed side is the sum of effective muDeltas across the last N
 *  observations from the ring buffer. delta = windowedScore - cumulativeScore
 *  in this framing simplifies to "sum of recent muDeltas" with sign preserved. */
export interface ReputationDrift {
  /** Current cumulative mu (the running Bayesian aggregate). */
  cumulativeScore: number
  /** Sum of effective muDeltas across the last `observationsInWindow` events.
   *  This is what recent behavior has contributed to mu. NOT a "what mu would
   *  be in isolation" projection — it is the contribution of the window to
   *  the current mu. The drift signal is the magnitude and sign of this
   *  contribution. */
  windowedScore: number
  /** Signed: windowedScore - 0 = windowedScore. Positive = recent events
   *  pushed mu up; negative = recent events pushed mu down. */
  delta: number
  /** The window size requested by the caller. */
  windowSize: number
  /** Actual number of observations the function used (= min(windowSize,
   *  recentObservations.length)). Less than windowSize when history is sparse. */
  observationsInWindow: number
  /** Null when severity === 'none', otherwise the full alert. */
  alert: DriftAlert | null
}

/** Default thresholds matching NexusGuard AIP v0.5.48 (Nanook PDR v2.19 §6.6).
 *  Exposed as public constants so callers can override consistently. */
export const DEFAULT_DRIFT_WARNING_THRESHOLD = 0.15
export const DEFAULT_DRIFT_CRITICAL_THRESHOLD = 0.30

/**
 * Compute sliding window drift on a ScopedReputation by reading the
 * recentObservations ring buffer and summing effective muDeltas across
 * the last `windowSize` events.
 *
 * Backward compatibility: when `rep.recentObservations` is undefined or
 * empty, the function returns a "no history available" early result with
 * delta=0, severity=none, and alert=null. This means reputations created
 * before the ring buffer was added (or reputations that have never been
 * fed through updateReputationFromResult) read as "stable" rather than
 * throwing. Callers can detect the no-history case by checking
 * `observationsInWindow === 0`.
 *
 * Default thresholds (0.15 / 0.30) match NexusGuard AIP v0.5.48 for
 * interop with the implementation Nanook PDR v2.19 §6.6 references.
 * Override per deployment based on the variance profile of your fleet —
 * these defaults are interop-friendly, not scientifically calibrated.
 *
 * @param rep         Source reputation. Not mutated.
 * @param windowSize  Maximum number of recent events to consider.
 * @param opts.warningThreshold   Override the warning threshold (default 0.15).
 * @param opts.criticalThreshold  Override the critical threshold (default 0.30).
 *
 * Reference: Nanook PDR v2.19 §6.6, gap audit §3 row 8 / §5 rank 3.
 */
export function computeReputationDrift(
  rep: ScopedReputation,
  windowSize: number,
  opts?: {
    warningThreshold?: number
    criticalThreshold?: number
  },
): ReputationDrift {
  const warningThreshold = opts?.warningThreshold ?? DEFAULT_DRIFT_WARNING_THRESHOLD
  const criticalThreshold = opts?.criticalThreshold ?? DEFAULT_DRIFT_CRITICAL_THRESHOLD
  const cumulativeScore = rep.mu

  // Backward-compat early return: no history available.
  const recent = rep.recentObservations
  if (!recent || recent.length === 0) {
    return {
      cumulativeScore,
      windowedScore: 0,
      delta: 0,
      windowSize,
      observationsInWindow: 0,
      alert: null,
    }
  }

  // Take the last min(windowSize, recent.length) entries. The ring buffer
  // is ordered oldest-to-newest, so slice from the tail.
  const observationsInWindow = Math.min(windowSize, recent.length)
  const windowSlice = recent.slice(recent.length - observationsInWindow)

  // delta = sum of effective muDeltas across the window.
  // Positive: recent events pushed mu up (improving).
  // Negative: recent events pushed mu down (degrading).
  const delta = windowSlice.reduce((acc, obs) => acc + obs.muDelta, 0)
  const windowedScore = delta

  const absDelta = Math.abs(delta)
  let severity: 'none' | 'warning' | 'critical'
  if (absDelta >= criticalThreshold) severity = 'critical'
  else if (absDelta >= warningThreshold) severity = 'warning'
  else severity = 'none'

  let direction: 'improving' | 'degrading' | 'stable'
  if (delta > warningThreshold) direction = 'improving'
  else if (delta < -warningThreshold) direction = 'degrading'
  else direction = 'stable'

  let alert: DriftAlert | null = null
  if (severity !== 'none') {
    alert = {
      severity,
      delta,
      warningThreshold,
      criticalThreshold,
      direction,
      recommendation: buildDriftRecommendation(severity, direction),
    }
  }

  return {
    cumulativeScore,
    windowedScore,
    delta,
    windowSize,
    observationsInWindow,
    alert,
  }
}

/** Static recommendation text per severity + direction combination.
 *  Short, actionable, deployment-neutral. Caller-facing copy. */
function buildDriftRecommendation(
  severity: 'warning' | 'critical',
  direction: 'improving' | 'degrading' | 'stable',
): string {
  if (direction === 'improving') {
    return severity === 'critical'
      ? 'Recent reputation gain is large. Consider whether the rapid improvement is real evidence or a small-window artifact before promoting authority.'
      : 'Recent reputation gain is meaningful. Continue monitoring; promotion may be appropriate after window stabilizes.'
  }
  if (direction === 'degrading') {
    return severity === 'critical'
      ? 'Recent reputation loss is severe. Restrict authority and investigate root cause before allowing further high-stakes actions.'
      : 'Recent reputation loss is meaningful. Watch the next several events; consider narrowing scope if the trend continues.'
  }
  // direction === 'stable' but severity !== 'none' is unreachable in
  // practice because severity comes from |delta| and direction from sign-vs-
  // threshold; if |delta| crosses warningThreshold then |delta| > warning
  // threshold and direction is non-stable. Defensive default for type safety.
  return 'Reputation drift crossed alert threshold without a clear directional signal. Review recent events.'
}
