// ══════════════════════════════════════════════════════════════════
// Decision Equivalence — Implementation
// ══════════════════════════════════════════════════════════════════
// Canonical boundary profiles, static compatibility, projection-based
// comparison. No runtime negotiation. Consilium decision: 2026-03-24.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalize } from './canonical.js'
import type {
  BoundaryProfile, ProfileCompatibility, ProfileComparisonResult,
  DecisionEquivalence, DecisionComparisonResult,
  ProfileTaggedDecision, ThresholdDistance,
} from '../types/decision-equivalence.js'

// ═══════════════════════════════════════
// Canonical Boundary Profiles (Registry)
// ═══════════════════════════════════════

export const CANONICAL_PROFILES: Record<string, BoundaryProfile> = {
  'aps:commerce:preflight': {
    name: 'aps:commerce:preflight',
    version: '1.0',
    decisionType: 'commerce_authorization',
    fields: ['agentId', 'delegationId', 'merchantOrigin', 'intentName', 'amount', 'currency'],
    description: 'Commerce preflight authorization. Two systems using this profile agree on what constitutes the same purchase decision.',
  },
  'aps:data:access': {
    name: 'aps:data:access',
    version: '1.0',
    decisionType: 'data_access_authorization',
    fields: ['agentId', 'delegationId', 'sourceId', 'termsVersion', 'accessType'],
    description: 'Data access authorization. Two systems using this profile agree on what constitutes the same data access decision.',
  },
  'aps:delegation:evaluate': {
    name: 'aps:delegation:evaluate',
    version: '1.0',
    decisionType: 'delegation_policy_evaluation',
    fields: ['agentId', 'delegationId', 'scopeRequired', 'action.type', 'action.target'],
    description: 'Delegation policy evaluation. Two systems using this profile agree on what constitutes the same policy decision.',
  },
  'aps:settlement:contribution': {
    name: 'aps:settlement:contribution',
    version: '1.0',
    decisionType: 'contribution_weight_computation',
    fields: ['sourceId', 'agentId', 'termsVersion', 'accessCount', 'period'],
    description: 'Settlement contribution weight. Two systems using this profile agree on what constitutes the same contribution calculation.',
  },
}

/**
 * Resolve a profile by name. Returns the canonical profile or undefined.
 */
export function resolveProfile(name: string): BoundaryProfile | undefined {
  return CANONICAL_PROFILES[name]
}

/**
 * Register a custom boundary profile.
 * Custom profiles must be namespaced (contain ':').
 */
export function registerProfile(profile: BoundaryProfile): void {
  if (!profile.name.includes(':')) {
    throw new Error('Profile names must be namespaced (e.g. "vendor:type:subtype")')
  }
  CANONICAL_PROFILES[profile.name] = profile
}

// ═══════════════════════════════════════
// Profile Compatibility (static lookup)
// ═══════════════════════════════════════

/**
 * Compare two boundary profiles to determine compatibility.
 * This is a static analysis — no runtime negotiation.
 */
export function compareProfiles(a: BoundaryProfile, b: BoundaryProfile): ProfileComparisonResult {
  const setA = new Set(a.fields)
  const setB = new Set(b.fields)

  const shared = a.fields.filter(f => setB.has(f))
  const onlyInA = a.fields.filter(f => !setB.has(f))
  const onlyInB = b.fields.filter(f => !setA.has(f))

  let compatibility: ProfileCompatibility
  if (onlyInA.length === 0 && onlyInB.length === 0) {
    compatibility = 'identical'
  } else if (onlyInA.length === 0) {
    compatibility = 'subset'  // A ⊂ B
  } else if (onlyInB.length === 0) {
    compatibility = 'superset'  // A ⊃ B
  } else if (shared.length > 0) {
    compatibility = 'overlapping'
  } else {
    compatibility = 'disjoint'
  }

  return { compatibility, sharedFields: shared, onlyInA, onlyInB }
}

// ═══════════════════════════════════════
// Content Hash for Profile Fields
// ═══════════════════════════════════════

/**
 * Extract a nested field value from an object using dot-notation path.
 * e.g. getField({ action: { type: 'code' } }, 'action.type') → 'code'
 */
function getField(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split('.')
  let current: unknown = obj
  for (const part of parts) {
    if (current == null || typeof current !== 'object') return undefined
    current = (current as Record<string, unknown>)[part]
  }
  return current
}

/**
 * Project a decision's fields to a specific field set and hash.
 */
function projectAndHash(fields: Record<string, unknown>, fieldSet: string[]): string {
  const projected: Record<string, unknown> = {}
  for (const f of fieldSet.sort()) {
    projected[f] = getField(fields, f)
  }
  const canonical = canonicalize(projected)
  return createHash('sha256').update(canonical).digest('hex')
}

// ═══════════════════════════════════════
// Decision Comparison
// ═══════════════════════════════════════

/**
 * Compare two profile-tagged decisions for equivalence.
 *
 * - Same profile, same hash → equivalent
 * - Same profile, different hash → divergent
 * - Overlapping profiles → project to intersection, compare
 * - Disjoint profiles → incomparable
 *
 * No runtime negotiation. Static projection.
 */
export function compareDecisions(
  a: ProfileTaggedDecision,
  b: ProfileTaggedDecision
): DecisionComparisonResult {
  const profileA = resolveProfile(a.profileName)
  const profileB = resolveProfile(b.profileName)

  if (!profileA || !profileB) {
    return {
      equivalence: 'incomparable',
      profileA: a.profileName,
      profileB: b.profileName,
      profileCompatibility: 'disjoint',
    }
  }

  const comparison = compareProfiles(profileA, profileB)

  // Disjoint profiles → no basis for comparison
  if (comparison.compatibility === 'disjoint') {
    return {
      equivalence: 'incomparable',
      profileA: a.profileName,
      profileB: b.profileName,
      profileCompatibility: 'disjoint',
    }
  }

  // Identical profiles → direct hash comparison
  if (comparison.compatibility === 'identical') {
    const hashA = projectAndHash(a.fields, profileA.fields)
    const hashB = projectAndHash(b.fields, profileB.fields)
    return {
      equivalence: hashA === hashB ? 'equivalent' : 'divergent',
      profileA: a.profileName,
      profileB: b.profileName,
      profileCompatibility: 'identical',
      agreedFields: hashA === hashB ? profileA.fields : undefined,
      divergentFields: hashA !== hashB ? findDivergentFields(a.fields, b.fields, profileA.fields) : undefined,
    }
  }

  // Overlapping/superset/subset → project to intersection, compare
  const sharedFields = comparison.sharedFields
  const projHashA = projectAndHash(a.fields, sharedFields)
  const projHashB = projectAndHash(b.fields, sharedFields)

  const matchOnIntersection = projHashA === projHashB

  return {
    equivalence: matchOnIntersection ? 'equivalent_on_intersection' : 'divergent_on_intersection',
    profileA: a.profileName,
    profileB: b.profileName,
    profileCompatibility: comparison.compatibility,
    agreedFields: matchOnIntersection ? sharedFields : undefined,
    divergentFields: matchOnIntersection ? undefined : findDivergentFields(a.fields, b.fields, sharedFields),
    projectedHashA: projHashA,
    projectedHashB: projHashB,
  }
}

/**
 * Find which fields in a field set have different values between two decisions.
 */
function findDivergentFields(
  fieldsA: Record<string, unknown>,
  fieldsB: Record<string, unknown>,
  fieldSet: string[]
): string[] {
  return fieldSet.filter(f => {
    const valA = getField(fieldsA, f)
    const valB = getField(fieldsB, f)
    return canonicalize(valA) !== canonicalize(valB)
  })
}

// ═══════════════════════════════════════
// Threshold Distance (metadata, not resolution)
// ═══════════════════════════════════════

/**
 * Compute the threshold distance for a metric.
 * This records proximity to a decision boundary — the protocol
 * exposes this, it does NOT resolve divergent thresholds.
 */
export function computeThresholdDistance(
  metric: string,
  actual: number,
  threshold: number
): ThresholdDistance {
  return {
    metric,
    threshold,
    actual,
    distance: Math.abs(actual - threshold),
    side: actual >= threshold ? 'above' : 'below',
  }
}

/**
 * Tag a decision with a boundary profile.
 * Extracts the profile's field set from the raw decision fields
 * and computes the content hash over those fields.
 */
export function tagDecisionWithProfile(
  profileName: string,
  fields: Record<string, unknown>,
  thresholdDistances?: ThresholdDistance[]
): ProfileTaggedDecision {
  const profile = resolveProfile(profileName)
  if (!profile) throw new Error(`Unknown boundary profile: ${profileName}`)

  const hash = projectAndHash(fields, profile.fields)

  return {
    profileName,
    contentHash: {
      algorithm: 'sha256',
      hash,
      canonicalForm: 'canonical_json_sorted_keys',
      identityBoundary: profile.fields,
    },
    fields,
    thresholdDistances,
  }
}

// ═══════════════════════════════════════
// Decision Identity (the invariant layer)
// ═══════════════════════════════════════
// Per xsa520 (2026-03-24): the invariant must exist PRIOR to
// boundary profiles, negotiation, or commitment declarations.
// A decision is the same decision across systems iff its
// canonical question hash matches. Two-layer architecture:
//   Layer 1: Question hash — WHAT is being decided (the invariant)
//   Layer 2: Evaluation hash — HOW each system answered (may diverge)

/**
 * Compute the decision question hash — the cross-system invariant.
 * This hashes only the QUESTION being asked, not the answer.
 * Two systems asking the same question produce the same hash
 * regardless of how they evaluate it.
 */
export function computeDecisionQuestionHash(
  fields: Record<string, unknown>,
  profileName: string
): string {
  const profile = resolveProfile(profileName)
  if (!profile) throw new Error(`Unknown profile: ${profileName}`)
  return projectAndHash(fields, profile.fields)
}

/**
 * Check if two decisions are asking the same question.
 * This is the minimal invariant — true means the decisions
 * are about the same thing, regardless of evaluation outcome.
 */
export function isSameDecisionQuestion(
  a: ProfileTaggedDecision,
  b: ProfileTaggedDecision
): boolean {
  if (a.profileName !== b.profileName) return false
  const profile = resolveProfile(a.profileName)
  if (!profile) return false
  const hashA = projectAndHash(a.fields, profile.fields)
  const hashB = projectAndHash(b.fields, profile.fields)
  return hashA === hashB
}
