// ══════════════════════════════════════════════════════════════════
// Denial Domains — Operator-Facing Constraint Grouping
// ══════════════════════════════════════════════════════════════════
// The ConstraintVector has 15 facets. That's correct for the machine.
// For humans it's unusable. This module groups facets into 5 domains
// and provides a primary + contributing denial format.
//
// Consilium Priority 4 — unanimous that 15 facets need grouping.
// Claude: "primary denial reason + count"
// GPT: "4 master tiers"
// Gemini: "5 operator-facing domains"
// Decision: 5 domains + primary-with-context pattern.
// ══════════════════════════════════════════════════════════════════

import type { ConstraintFacet, ConstraintFailure, ConstraintVector } from '../types/gateway.js'

/** Five operator-facing denial domains.
 *  Each groups 2-4 ConstraintVector facets. */
export type DenialDomain =
  | 'identity_trust'       // identity, reputation, fidelity
  | 'authority_scope'      // scope, reversibility, escalation, revocation
  | 'economic'             // spend, data (data access = economic: who pays for data usage)
  | 'temporal_integrity'   // time, replay, governance, cross_chain
  | 'safety_values'        // values (the dispute overlay lives here conceptually)

/** Facet → domain mapping. Deterministic, no ambiguity. */
const FACET_DOMAIN: Record<ConstraintFacet, DenialDomain> = {
  identity:       'identity_trust',
  reputation:     'identity_trust',
  fidelity:       'identity_trust',
  scope:          'authority_scope',
  reversibility:  'authority_scope',
  escalation:     'authority_scope',
  revocation:     'authority_scope',
  spend:          'economic',
  data:           'economic',
  time:           'temporal_integrity',
  replay:         'temporal_integrity',
  governance:     'temporal_integrity',
  cross_chain:    'temporal_integrity',
  values:         'safety_values',
}

/** Human-readable domain labels */
const DOMAIN_LABELS: Record<DenialDomain, string> = {
  identity_trust:     'Identity & Trust',
  authority_scope:    'Authority & Scope',
  economic:           'Economic Controls',
  temporal_integrity: 'Temporal & Integrity',
  safety_values:      'Safety & Values',
}

/** Structured denial summary for operators and dashboards.
 *  Primary reason + contributing factors + remediation hint. */
export interface DenialSummary {
  /** The single most important reason the action was denied */
  primary: {
    domain: DenialDomain
    domainLabel: string
    facet: ConstraintFacet
    code: string
    message: string
  }
  /** Additional failures beyond the primary */
  contributing: Array<{
    domain: DenialDomain
    facet: ConstraintFacet
    code: string
  }>
  /** Total number of failed facets */
  totalFailures: number
  /** The nearest condition that would have satisfied the primary failure */
  nearestSatisfiable?: string
  /** One-line remediation hint */
  remediationHint?: string
}

/** Get the denial domain for a constraint facet */
export function getDomain(facet: ConstraintFacet): DenialDomain {
  return FACET_DOMAIN[facet]
}

/** Get the human-readable label for a domain */
export function getDomainLabel(domain: DenialDomain): string {
  return DOMAIN_LABELS[domain]
}

/** Evaluation order: cheapest checks first.
 *  Gateway should evaluate in this order for deny-fast optimization.
 *  This also determines which failure is "primary" — first to fail wins. */
export const EVALUATION_ORDER: ConstraintFacet[] = [
  'replay',        // O(1) set lookup
  'time',          // O(1) date comparison
  'revocation',    // O(1) revocation check
  'identity',      // O(1) signature verify
  'scope',         // O(n) scope matching
  'spend',         // O(1) budget check
  'reputation',    // O(1) tier lookup
  'reversibility', // O(1) classification
  'escalation',    // O(1) grant check
  'cross_chain',   // O(1) taint check
  'governance',    // O(1) version check
  'data',          // O(n) data terms check
  'values',        // O(n) values floor eval
  'fidelity',      // O(1) attestation check
]

/** Create a structured denial summary from constraint failures.
 *  The primary failure is the FIRST in evaluation order (cheapest check
 *  that failed), which is also the most actionable for the operator. */
export function summarizeDenial(failures: ConstraintFailure[]): DenialSummary | null {
  if (failures.length === 0) return null

  // Sort failures by evaluation order to find primary
  const sorted = [...failures].sort((a, b) => {
    const aIdx = EVALUATION_ORDER.indexOf(a.facet)
    const bIdx = EVALUATION_ORDER.indexOf(b.facet)
    return (aIdx === -1 ? 999 : aIdx) - (bIdx === -1 ? 999 : bIdx)
  })

  const primary = sorted[0]
  const contributing = sorted.slice(1).map(f => ({
    domain: getDomain(f.facet),
    facet: f.facet,
    code: f.code,
  }))

  return {
    primary: {
      domain: getDomain(primary.facet),
      domainLabel: getDomainLabel(getDomain(primary.facet)),
      facet: primary.facet,
      code: primary.code,
      message: primary.message,
    },
    contributing,
    totalFailures: failures.length,
    nearestSatisfiable: computeNearestSatisfiable(primary),
    remediationHint: computeRemediationHint(primary),
  }
}

/** Compute the nearest condition that would satisfy the primary failure */
function computeNearestSatisfiable(failure: ConstraintFailure): string | undefined {
  switch (failure.facet) {
    case 'time':
      return 'Renew delegation with a later expiry'
    case 'spend':
      if (failure.limit !== undefined && failure.actual !== undefined) {
        return `Increase spend limit to at least ${failure.actual} (current: ${failure.limit})`
      }
      return 'Increase delegation spend limit'
    case 'scope':
      return `Add required scope to delegation: ${failure.code}`
    case 'reputation':
      return 'Accumulate more positive evidence to reach required tier'
    case 'revocation':
      return 'Obtain a new delegation from the principal'
    case 'identity':
      return 'Re-register with a valid passport and attestation'
    case 'fidelity':
      return 'Pass a fidelity probe to update attestation'
    case 'data':
      return 'Ensure data source terms permit the requested access'
    case 'replay':
      return 'Use a unique requestId for each tool call'
    default:
      return undefined
  }
}

/** One-line remediation hint based on the failure domain */
function computeRemediationHint(failure: ConstraintFailure): string {
  const domain = getDomain(failure.facet)
  switch (domain) {
    case 'identity_trust':
      return 'Verify agent identity or improve trust score through diverse positive interactions'
    case 'authority_scope':
      return 'Request a delegation with broader scope or appropriate escalation grants'
    case 'economic':
      return 'Check spend limits and data access terms in the delegation'
    case 'temporal_integrity':
      return 'Ensure delegation is current and request IDs are unique'
    case 'safety_values':
      return 'Review the action against the values floor constraints'
  }
}

/** Group failures by domain for dashboard display */
export function groupByDomain(failures: ConstraintFailure[]): Record<DenialDomain, ConstraintFailure[]> {
  const groups: Record<DenialDomain, ConstraintFailure[]> = {
    identity_trust: [], authority_scope: [], economic: [],
    temporal_integrity: [], safety_values: [],
  }
  for (const f of failures) {
    groups[getDomain(f.facet)].push(f)
  }
  return groups
}
