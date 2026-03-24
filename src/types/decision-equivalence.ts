// ══════════════════════════════════════════════════════════════════
// Decision Equivalence — Canonical Boundary Profiles + Comparison
// ══════════════════════════════════════════════════════════════════
// Consilium decision (Claude + GPT + human, 2026-03-24):
//   - Boundary profiles as registry, not negotiation protocol
//   - Static compatibility function, not runtime handshake
//   - Projection-based comparison for overlapping profiles
//   - thresholdDistance as metadata, not resolution
//   - Threshold semantics out of scope (engine property)
// ══════════════════════════════════════════════════════════════════

import type { ContentHash } from './decision-semantics.js'

// ── Canonical Boundary Profiles ──
// Named configurations defining which fields constitute "same decision"
// for a given decision type. Systems using the same profile produce
// comparable hashes. Different profiles = explicitly incomparable
// unless projected to intersection.

export interface BoundaryProfile {
  /** Profile name, namespaced. e.g. 'aps:commerce:preflight' */
  name: string
  /** Semantic version of the profile */
  version: string
  /** Decision type this profile applies to */
  decisionType: string
  /** Sorted array of field paths that define decision identity */
  fields: string[]
  /** Optional description */
  description?: string
}

// ── Profile Compatibility ──

export type ProfileCompatibility =
  | 'identical'      // same fields in same order
  | 'superset'       // A contains all of B's fields plus more
  | 'subset'         // A is contained within B's fields
  | 'overlapping'    // partial intersection, neither contains the other
  | 'disjoint'       // no shared fields

export interface ProfileComparisonResult {
  compatibility: ProfileCompatibility
  sharedFields: string[]
  onlyInA: string[]
  onlyInB: string[]
}

// ── Decision Comparison ──

export type DecisionEquivalence =
  | 'equivalent'              // same profile, same hash
  | 'equivalent_on_intersection'  // different profiles, matching on shared fields
  | 'divergent'               // same profile, different hash
  | 'divergent_on_intersection'   // different profiles, divergent even on shared fields
  | 'incomparable'            // disjoint profiles, no basis for comparison

export interface DecisionComparisonResult {
  equivalence: DecisionEquivalence
  profileA: string
  profileB: string
  profileCompatibility: ProfileCompatibility
  /** Fields where the decisions agree (only populated for overlapping/identical) */
  agreedFields?: string[]
  /** Fields where the decisions diverge */
  divergentFields?: string[]
  /** If projected to intersection: hash of A on shared fields */
  projectedHashA?: string
  /** If projected to intersection: hash of B on shared fields */
  projectedHashB?: string
}

// ── Threshold Distance (metadata, not resolution) ──
// Records how close an evaluation was to its decision boundary.
// The protocol exposes this; it does NOT resolve divergent thresholds.

export interface ThresholdDistance {
  /** The metric being evaluated (e.g. 'risk_score', 'reputation_mu') */
  metric: string
  /** The threshold value that determines the boundary */
  threshold: number
  /** The actual computed value */
  actual: number
  /** Absolute distance from threshold: |actual - threshold| */
  distance: number
  /** Which side of the threshold: 'above' | 'below' */
  side: 'above' | 'below'
}

// ── Profile-Tagged Decision ──
// A decision artifact annotated with its boundary profile.
// This is what systems exchange for cross-system comparison.

export interface ProfileTaggedDecision {
  /** The boundary profile used */
  profileName: string
  /** Content hash computed using the profile's field set */
  contentHash: ContentHash
  /** The raw decision fields (superset of profile fields) */
  fields: Record<string, unknown>
  /** Optional threshold distances for boundary-adjacent decisions */
  thresholdDistances?: ThresholdDistance[]
}
