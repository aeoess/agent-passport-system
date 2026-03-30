// ══════════════════════════════════════════════════════════════════
// Data Narrowing Invariant — Data Can Only Narrow Authority
// ══════════════════════════════════════════════════════════════════
// GPT's "Context-Bypass Attack" (consilium March 2026):
// An agent reads a data source containing authority-widening
// instructions. The gateway must ensure data inputs can ONLY narrow
// the ConstraintVector, never widen it.
//
// Same as monotonic narrowing for delegation — monotonic narrowing
// for data influence. Only signed delegations from a higher-tier
// principal can widen authority.
// ══════════════════════════════════════════════════════════════════

import type { ConstraintFacet, ConstraintStatus } from '../types/gateway.js'

/** A facet evaluation snapshot — facet name + its status */
export interface FacetSnapshot {
  facet: ConstraintFacet
  status: ConstraintStatus
}

/** Result of a narrowing check */
export interface NarrowingCheckResult {
  valid: boolean
  /** Facets where data attempted to widen authority */
  violations: Array<{
    facet: ConstraintFacet
    before: ConstraintStatus
    after: ConstraintStatus
    message: string
  }>
}

/** Status ordering for monotonic narrowing check.
 *  Lower number = more restrictive. Authority can only move DOWN. */
const STATUS_ORDER: Record<ConstraintStatus, number> = {
  'fail': 0,
  'unknown': 1,
  'not_applicable': 2,
  'pass': 3,
}

/** Assert that data influence only narrows authority.
 *  Compares constraint evaluations BEFORE and AFTER data is considered.
 *  Any facet that moves from a more restrictive status to a more
 *  permissive one is a violation — data attempted to widen authority.
 *
 *  @param before - Facet evaluations before data influence
 *  @param after  - Facet evaluations after data influence
 *  @returns NarrowingCheckResult with any violations */
export function assertDataNarrowsOnly(
  before: FacetSnapshot[],
  after: FacetSnapshot[],
): NarrowingCheckResult {
  const violations: NarrowingCheckResult['violations'] = []

  const beforeMap = new Map(before.map(f => [f.facet, f.status]))

  for (const a of after) {
    const beforeStatus = beforeMap.get(a.facet)
    if (beforeStatus === undefined) continue // new facet, no comparison

    const beforeOrder = STATUS_ORDER[beforeStatus]
    const afterOrder = STATUS_ORDER[a.status]

    // If after is MORE permissive (higher order) than before → violation
    if (afterOrder > beforeOrder) {
      violations.push({
        facet: a.facet,
        before: beforeStatus,
        after: a.status,
        message: `Data attempted to widen ${a.facet}: ${beforeStatus} → ${a.status}`,
      })
    }
  }

  return { valid: violations.length === 0, violations }
}

/** Apply data-sourced constraint modifications safely.
 *  Only allows narrowing (making more restrictive).
 *  Returns the narrowed snapshots with any widening attempts rejected.
 *
 *  Use case: a data source declares "this data requires scope:read_only"
 *  → the constraint is narrowed. But if data declares "grant scope:admin"
 *  → the widening is rejected and the original constraint stands. */
export function applyDataConstraints(
  current: FacetSnapshot[],
  dataInfluence: FacetSnapshot[],
): { result: FacetSnapshot[]; rejected: NarrowingCheckResult['violations'] } {
  const currentMap = new Map(current.map(f => [f.facet, f]))
  const result: FacetSnapshot[] = [...current]
  const rejected: NarrowingCheckResult['violations'] = []

  for (const influence of dataInfluence) {
    const existing = currentMap.get(influence.facet)
    if (!existing) {
      // New facet from data — only accept if restrictive (fail or unknown)
      if (STATUS_ORDER[influence.status] <= STATUS_ORDER['unknown']) {
        result.push(influence)
      }
      continue
    }

    const existingOrder = STATUS_ORDER[existing.status]
    const influenceOrder = STATUS_ORDER[influence.status]

    if (influenceOrder <= existingOrder) {
      // More restrictive or equal — allowed (narrowing)
      const idx = result.findIndex(f => f.facet === influence.facet)
      if (idx >= 0) result[idx] = influence
    } else {
      // Less restrictive — rejected (widening attempt)
      rejected.push({
        facet: influence.facet,
        before: existing.status,
        after: influence.status,
        message: `Rejected: data tried to widen ${influence.facet} from ${existing.status} to ${influence.status}`,
      })
    }
  }

  return { result, rejected }
}

/** Check if a status transition is valid narrowing (same or more restrictive) */
export function isValidNarrowing(before: ConstraintStatus, after: ConstraintStatus): boolean {
  return STATUS_ORDER[after] <= STATUS_ORDER[before]
}

/** The status ordering: fail < unknown < not_applicable < pass.
 *  Exported for test vectors and cross-language verification. */
export const NARROWING_ORDER = STATUS_ORDER
