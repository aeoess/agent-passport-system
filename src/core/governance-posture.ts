// ══════════════════════════════════════════════════════════════════
// Governance Posture — Behavioral failures → structural consequences
// ══════════════════════════════════════════════════════════════════
// Consilium Priority 5 — Gemini's framing:
//   "behavioral failures update a governance posture tier,
//    posture tier changes what the gateway allows by default,
//    identity stays intact."
//
// Claude: "ratchet + human review to restore"
// GPT: "one-directional monotonic narrowing"
//
// Decision: Posture tiers with hysteresis. Downgrade is automatic
// after sustained failures. Upgrade requires human principal action.
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

/** Agent's governance posture state */
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

/** Downgrade thresholds — how many consecutive failures trigger each level */
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

export const DEFAULT_DOWNGRADE_POLICY: PostureDowngradePolicy = {
  fullToStandard: 3,
  standardToCautious: 5,
  cautiousToRestricted: 3,
  restrictedToQuarantine: 2,
}

/** Create initial posture for a newly registered agent */
export function createInitialPosture(tier: PostureTier = 'standard'): GovernancePosture {
  return {
    tier,
    changedAt: new Date().toISOString(),
    changedBy: 'system',
    consecutiveFailures: 0,
    failuresSinceChange: 0,
    history: [],
  }
}

/** Record a behavioral failure and check if downgrade is needed.
 *  Returns updated posture (may be downgraded). */
export function recordBehavioralFailure(
  posture: GovernancePosture,
  reason: string,
  policy: PostureDowngradePolicy = DEFAULT_DOWNGRADE_POLICY,
): GovernancePosture {
  const updated = { ...posture }
  updated.consecutiveFailures++
  updated.failuresSinceChange++

  // Check if downgrade threshold reached for current tier
  const threshold = getDowngradeThreshold(posture.tier, policy)
  if (threshold !== null && updated.consecutiveFailures >= threshold) {
    const nextTier = getNextLowerTier(posture.tier)
    if (nextTier) {
      const change: PostureChange = {
        from: posture.tier, to: nextTier,
        reason: `Auto-downgrade: ${updated.consecutiveFailures} consecutive failures. ${reason}`,
        changedBy: 'system', changedAt: new Date().toISOString(),
      }
      updated.tier = nextTier
      updated.changedAt = change.changedAt
      updated.changedBy = 'system'
      updated.consecutiveFailures = 0
      updated.failuresSinceChange = 0
      updated.history = [...posture.history, change]
    }
  }
  return updated
}

/** Record a behavioral success — resets consecutive failure counter */
export function recordBehavioralSuccess(posture: GovernancePosture): GovernancePosture {
  return { ...posture, consecutiveFailures: 0 }
}

/** Manually upgrade posture — REQUIRES human principal action.
 *  Cannot skip tiers (must go one step at a time).
 *  Trust is easy to lose and hard to rebuild. */
export function upgradePosture(
  posture: GovernancePosture,
  principalDid: string,
  reason: string,
): GovernancePosture {
  const nextTier = getNextHigherTier(posture.tier)
  if (!nextTier) return posture // already at full_trust

  const change: PostureChange = {
    from: posture.tier, to: nextTier,
    reason: `Manual upgrade by ${principalDid}: ${reason}`,
    changedBy: principalDid, changedAt: new Date().toISOString(),
  }

  return {
    ...posture,
    tier: nextTier,
    changedAt: change.changedAt,
    changedBy: principalDid,
    consecutiveFailures: 0,
    failuresSinceChange: 0,
    history: [...posture.history, change],
  }
}

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

// ── Internal helpers ──

const TIER_SEQUENCE: PostureTier[] = ['quarantine', 'restricted', 'cautious', 'standard', 'full_trust']

function getNextLowerTier(tier: PostureTier): PostureTier | null {
  const idx = TIER_SEQUENCE.indexOf(tier)
  return idx > 0 ? TIER_SEQUENCE[idx - 1] : null
}

function getNextHigherTier(tier: PostureTier): PostureTier | null {
  const idx = TIER_SEQUENCE.indexOf(tier)
  return idx < TIER_SEQUENCE.length - 1 ? TIER_SEQUENCE[idx + 1] : null
}

function getDowngradeThreshold(
  tier: PostureTier,
  policy: PostureDowngradePolicy,
): number | null {
  switch (tier) {
    case 'full_trust': return policy.fullToStandard
    case 'standard': return policy.standardToCautious
    case 'cautious': return policy.cautiousToRestricted
    case 'restricted': return policy.restrictedToQuarantine
    case 'quarantine': return null // can't go lower
  }
}
