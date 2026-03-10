// ══════════════════════════════════════════════════════════════════
// Reputation-Gated Authority — Type Definitions
// ══════════════════════════════════════════════════════════════════
// Connects Layer 1 reputation to Layer 5 autonomy through earned
// trust, promotion reviews, and automatic containment.
// Core invariant: effectiveAuthority = min(delegation, tier)
// ══════════════════════════════════════════════════════════════════

import type { AutonomyLevel } from './intent.js'

// ── Bayesian Reputation ──

/**
 * Reputation state per (principal, agent, scope) tuple.
 * Uses Bayesian (mu, sigma) model inspired by TrueSkill.
 * mu = estimated capability, sigma = uncertainty.
 * Effective score = mu - k * sigma.
 */
export interface ScopedReputation {
  principalId: string
  agentId: string
  scope: string
  mu: number               // Estimated capability (0-100)
  sigma: number            // Uncertainty (0-50, higher = less certain)
  receiptCount: number     // Total receipts in this scope
  lastUpdatedAt: string
}

// ── Authority Tiers ──

/** How a tier was granted. Only 'earned' agents can promote others. */
export type TierOrigin = 'fiat' | 'earned' | 'provisional'

export interface AuthorityTier {
  tier: number              // 0-4
  name: string              // human-readable label
  origin: TierOrigin
  autonomyLevel: AutonomyLevel
  maxDelegationDepth: number
  maxSpendPerAction: number
  promotedAt?: string       // when this tier was granted
  demotionCount: number     // cryptographic scarring counter
}

/**
 * Default tier definitions. Deployments can customize thresholds.
 * Promotion threshold increases by (demotionCount * SCARRING_PENALTY).
 */
export interface TierDefinition {
  tier: number
  name: string
  promoteAt: number         // effective score threshold to be eligible
  demoteAt: number          // effective score threshold to trigger demotion
  autonomyLevel: AutonomyLevel
  maxDelegationDepth: number
  maxSpendPerAction: number
}

// ── Evidence Classification ──

/** Evidence class for a completed action. Determined by delegator/reviewer, never self-reported. */
export type EvidenceClass = 'trivial' | 'standard' | 'complex' | 'critical'

/**
 * Metadata attached to a task by the DELEGATOR (not the executor).
 * This prevents agents from self-reporting complexity to game promotions.
 */
export interface TaskClassification {
  stake: 'low' | 'medium' | 'high'
  workflowDepth: 'simple' | 'multi-step' | 'branched'
  externality: 'none' | 'internal' | 'external-reversible' | 'external-irreversible'
  oversightRequired: 'none' | 'review' | 'human-gated'
}

/**
 * Evidence portfolio required for promotion.
 * Minimum diversity constraints prevent farming.
 */
export interface EvidencePortfolio {
  scope: string
  totalReceipts: number
  classCounts: Record<EvidenceClass, number>
  distinctReviewers: number
  distinctTaskTypes: number
  failureRate: number           // 0-1
  interventionRate: number      // 0-1 (policy narrowing or escalation)
}

// ── Runtime Profile (Model Change Detection) ──

export interface RuntimeProfile {
  modelFamily: string         // 'claude' | 'gpt' | 'gemini' | etc.
  modelVersion: string        // '4.0' | '3.5-sonnet' | etc.
  provider: string            // 'anthropic' | 'openai' | 'google' | etc.
  toolsetHash: string         // SHA-256 of sorted tool names
  policyProfileHash: string   // SHA-256 of system prompt / policy config
}

export type RuntimeChangeClass = 'minor' | 'major' | 'architecture'

// ── Demotion ──

export type DemotionCause = 'behavioral' | 'administrative' | 'environmental'

export interface DemotionEvent {
  agentId: string
  principalId: string
  scope: string
  fromTier: number
  toTier: number
  cause: DemotionCause
  reason: string
  timestamp: string
  affectsReputation: boolean   // only behavioral = true
}

// ── Promotion ──

export interface PromotionRequirements {
  minReceipts: number
  minStandardPct: number        // 0-1: minimum % of standard+ evidence
  minComplexPct: number         // 0-1: minimum % of complex+ evidence
  minDistinctReviewers: number
  minDistinctTaskTypes: number
  maxFailureRate: number        // 0-1: maximum allowed failure rate
  maxInterventionRate: number   // 0-1: maximum policy intervention rate
  minTimeInCurrentTier: number  // milliseconds
}

export interface PromotionReview {
  reviewId: string
  agentId: string
  principalId: string
  scope: string
  fromTier: number
  toTier: number
  reviewerId: string
  reviewerTier: number
  reviewerOrigin: TierOrigin
  evidence: EvidencePortfolio
  effectiveScore: number        // mu - k*sigma at time of review
  verdict: 'promoted' | 'denied'
  reasoning: string
  probationEndsAt?: string      // if promoted, probation expiry
  timestamp: string
  signature: string             // Ed25519 signed by reviewer
}
