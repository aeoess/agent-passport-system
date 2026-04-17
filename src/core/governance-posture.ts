// ══════════════════════════════════════════════════════════════════
// Governance Posture — Tier definitions + constraint primitives
// ══════════════════════════════════════════════════════════════════
// Consilium Priority 5 — Gemini's framing:
//   "behavioral failures update a governance posture tier,
//    posture tier changes what the gateway allows by default,
//    identity stays intact."
//
// SDK retains pure tier types, default constraint shapes, scope checks,
// and tier ordering helpers. The downgrade/upgrade STATE MACHINE
// (createInitialPosture, recordBehavioralFailure, recordBehavioralSuccess,
// upgradePosture, plus DEFAULT_DOWNGRADE_POLICY) MOVED to
// @aeoess/gateway src/sdk-migrated/core/posture-state.ts on 2026-04-17.
// Posture state tracking is gateway product policy — the SDK only
// describes the tiers and what they constrain.
// ══════════════════════════════════════════════════════════════════

/** Governance posture tiers — ordered from most to least trusted.
 *  Each tier defines default constraints that override delegation grants. */
export type PostureTier = 'full_trust' | 'standard' | 'cautious' | 'restricted' | 'quarantine'

/** Posture tier ordering — lower number = more restrictive */
const TIER_ORDER: Record<PostureTier, number> = {
  quarantine: 0,
  restricted: 1,
  cautious: 2,
  standard: 3,
  full_trust: 4,
}

/** Default constraints applied per posture tier */
export interface PostureConstraints {
  /** Maximum spend per action (null = delegation limit applies) */
  maxSpendPerAction?: number | null
  /** Maximum delegation depth allowed */
  maxDelegationDepth?: number
  /** Scopes explicitly blocked at this posture */
  blockedScopes?: string[]
  /** Whether irreversible actions are allowed */
  allowIrreversible?: boolean
  /** Whether escalation grants are honored */
  allowEscalation?: boolean
  /** Minimum fidelity score required */
  minFidelityScore?: number
}

/** Default constraints for each posture tier */
export const DEFAULT_POSTURE_CONSTRAINTS: Record<PostureTier, PostureConstraints> = {
  full_trust: {
    maxSpendPerAction: null,
    maxDelegationDepth: 5,
    allowIrreversible: true,
    allowEscalation: true,
    minFidelityScore: 0.3,
  },
  standard: {
    maxSpendPerAction: null,
    maxDelegationDepth: 3,
    allowIrreversible: true,
    allowEscalation: true,
    minFidelityScore: 0.5,
  },
  cautious: {
    maxSpendPerAction: 100,
    maxDelegationDepth: 2,
    blockedScopes: ['commerce:checkout'],
    allowIrreversible: false,
    allowEscalation: true,
    minFidelityScore: 0.6,
  },
  restricted: {
    maxSpendPerAction: 10,
    maxDelegationDepth: 1,
    blockedScopes: ['commerce:checkout', 'data:write', 'admin'],
    allowIrreversible: false,
    allowEscalation: false,
    minFidelityScore: 0.8,
  },
  quarantine: {
    maxSpendPerAction: 0,
    maxDelegationDepth: 0,
    blockedScopes: ['*'],
    allowIrreversible: false,
    allowEscalation: false,
    minFidelityScore: 1.0,
  },
}

/** Agent's governance posture state. The SDK only defines the shape;
 *  the state machine that mutates it lives in the gateway. */
export interface GovernancePosture {
  /** Current posture tier */
  tier: PostureTier
  /** When this posture was last changed */
  changedAt: string
  /** Who changed it — 'system' for auto-downgrade, principal DID for manual */
  changedBy: string
  /** Consecutive behavioral failure count (resets on success) */
  consecutiveFailures: number
  /** Total behavioral failures since last posture change */
  failuresSinceChange: number
  /** History of posture changes (audit trail) */
  history: PostureChange[]
}

export interface PostureChange {
  from: PostureTier
  to: PostureTier
  reason: string
  changedBy: string
  changedAt: string
}

/** Downgrade thresholds — how many consecutive failures trigger each level.
 *  Default policy values live in the gateway alongside the state machine. */
export interface PostureDowngradePolicy {
  /** Consecutive failures to go from full_trust → standard */
  fullToStandard: number
  /** Consecutive failures to go from standard → cautious */
  standardToCautious: number
  /** Consecutive failures to go from cautious → restricted */
  cautiousToRestricted: number
  /** Consecutive failures to go from restricted → quarantine */
  restrictedToQuarantine: number
}

// ── Pure constraint helpers ──

/** Get the constraints for a given posture tier */
export function getPostureConstraints(
  tier: PostureTier,
  custom?: Partial<Record<PostureTier, Partial<PostureConstraints>>>,
): PostureConstraints {
  const base = DEFAULT_POSTURE_CONSTRAINTS[tier]
  const override = custom?.[tier]
  if (!override) return base
  return { ...base, ...override }
}

/** Check if a scope is blocked at the current posture tier */
export function isScopeBlocked(tier: PostureTier, scope: string): boolean {
  const constraints = DEFAULT_POSTURE_CONSTRAINTS[tier]
  if (!constraints.blockedScopes) return false
  if (constraints.blockedScopes.includes('*')) return true
  return constraints.blockedScopes.some(blocked =>
    scope === blocked || scope.startsWith(blocked + ':'))
}

/** Compare two posture tiers. Returns negative if a < b, 0 if equal, positive if a > b */
export function comparePostureTiers(a: PostureTier, b: PostureTier): number {
  return TIER_ORDER[a] - TIER_ORDER[b]
}

// ── Removed state-machine stubs ──

const MIGRATED_MSG =
  'governance-posture state machine moved to @aeoess/gateway ' +
  'src/sdk-migrated/core/posture-state.ts (2026-04-17). ' +
  'SDK keeps tier types, DEFAULT_POSTURE_CONSTRAINTS, getPostureConstraints, ' +
  'isScopeBlocked, comparePostureTiers.'

// Stubs preserve original signatures so consumers continue to typecheck;
// calling them at runtime throws.

export function createInitialPosture(_tier?: PostureTier): GovernancePosture {
  throw new Error(MIGRATED_MSG)
}
export function recordBehavioralFailure(
  _posture: GovernancePosture, _reason: string, _policy?: PostureDowngradePolicy,
): GovernancePosture {
  throw new Error(MIGRATED_MSG)
}
export function recordBehavioralSuccess(_posture: GovernancePosture): GovernancePosture {
  throw new Error(MIGRATED_MSG)
}
export function upgradePosture(
  _posture: GovernancePosture, _principalDid: string, _reason: string,
): GovernancePosture {
  throw new Error(MIGRATED_MSG)
}
