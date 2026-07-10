// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
/**
 * @fileoverview Reconcile audience binding with the existing cross_chain
 * confused-deputy constraint.
 *
 * Audience binding and cross_chain are complementary, not competing:
 *
 *   - cross_chain (src/types/cross-chain.ts, FACET 'cross_chain') stops
 *     authority from principal X being COMBINED into a destination governed by
 *     principal Y unless a CrossChainPermit authorizes it. It is a DATA-FLOW
 *     restriction evaluated over a taint set.
 *
 *   - audience (FACET 'audience') stops a proof minted for recipient A from
 *     being PRESENTED to recipient B. It is a PROOF-PRESENTATION restriction
 *     evaluated over a recipient-identifier set.
 *
 * A single attempted misuse can trip both: presenting A's proof at B (audience
 * mismatch) while also crossing a data-flow boundary (cross_chain block). The
 * reconciliation rule below makes sure the relying party emits ONE primary
 * denial, not two contradictory ones, and never a contradiction (one facet
 * 'pass' while the other 'fail' for the SAME recipient mismatch).
 *
 * This module emits denials in the canonical ConstraintFailure shape
 * (src/types/gateway.ts) using the 'audience' facet. It does NOT invent a
 * parallel error type and does NOT re-implement cross_chain evaluation; it
 * consumes a cross_chain result the caller already computed.
 */

import type { ConstraintFailure, ConstraintStatus } from '../../types/gateway.js'
import type { AudienceCheckResult } from './types.js'

/**
 * Map an audience check result to the four-valued ConstraintStatus. The
 * AudienceStatus is already lattice-aligned, so this is a direct projection;
 * it exists so callers do not depend on the two enums being string-identical.
 */
export function audienceToConstraintStatus(result: AudienceCheckResult): ConstraintStatus {
  switch (result.status) {
    case 'pass':
      return 'pass'
    case 'fail':
      return 'fail'
    case 'not_applicable':
      return 'not_applicable'
    case 'unknown':
      return 'unknown'
  }
}

/**
 * Build a canonical ConstraintFailure for a failed audience check, using the
 * 'audience' facet. Returns null when the check did not fail (a non-failure
 * never produces a ConstraintFailure, matching the gateway convention that
 * failures-only populate ConstraintVector.failures).
 *
 * Audience failures are HARD and NOT retryable: a relying party cannot retry
 * its way into being a named recipient. The reason code becomes the failure
 * `code` so it is machine-readable.
 */
export function audienceFailure(result: AudienceCheckResult): ConstraintFailure | null {
  if (result.status !== 'fail') return null
  return {
    facet: 'audience',
    status: 'fail',
    code: result.reason,
    severity: 'hard',
    retryable: false,
    ...(result.checkedAgainst !== undefined ? { actual: result.checkedAgainst } : {}),
    ...(result.recipients !== undefined ? { limit: result.recipients.join(',') } : {}),
    message: result.message,
  }
}

/**
 * The outcome of reconciling an audience check with a cross_chain evaluation.
 */
export interface AudienceCrossChainReconciliation {
  /**
   * The single set of constraint failures the relying party should surface.
   * At most one audience failure and at most one cross_chain failure, with the
   * primary called out. Never contains a contradictory pair (a 'pass' next to
   * a 'fail' for the same mismatch).
   */
  failures: ConstraintFailure[]
  /**
   * The primary failure: the one that would block even if the other passed.
   * Audience is checked at proof presentation (cheaper, earlier) and is the
   * primary when both fail, matching the EVALUATION_ORDER intuition that the
   * presentation-layer check fronts the data-flow check.
   */
  primary?: ConstraintFailure
  /** True when both facets failed (a deliberately scoped-and-routed misuse). */
  bothFailed: boolean
  /** True when the two facets agree (no contradiction). */
  consistent: boolean
}

/**
 * Reconcile an audience check with an already-computed cross_chain failure (if
 * any). The cross_chain failure, when present, MUST already be in the
 * canonical ConstraintFailure shape with facet 'cross_chain'.
 *
 * Rules:
 *   1. No double-deny on the SAME facet: only one audience failure is emitted.
 *   2. No contradiction: the two facets describe different boundaries, so an
 *      audience 'pass' alongside a cross_chain 'fail' (or vice versa) is
 *      CONSISTENT, not contradictory; both are reported and the cross_chain
 *      one is primary. A contradiction would be the same boundary yielding
 *      both pass and fail, which this shape cannot produce.
 *   3. When both fail, audience is primary (presentation layer fronts the
 *      data-flow layer) but both failures are preserved for the audit trail.
 */
export function reconcileAudienceWithCrossChain(
  audienceResult: AudienceCheckResult,
  crossChainFailure: ConstraintFailure | null,
): AudienceCrossChainReconciliation {
  if (crossChainFailure !== null && crossChainFailure.facet !== 'cross_chain') {
    throw new Error(
      `reconcile expects a cross_chain ConstraintFailure, got facet '${crossChainFailure.facet}'`,
    )
  }

  const audFailure = audienceFailure(audienceResult)
  const failures: ConstraintFailure[] = []
  if (audFailure !== null) failures.push(audFailure)
  if (crossChainFailure !== null) failures.push(crossChainFailure)

  const bothFailed = audFailure !== null && crossChainFailure !== null

  // The two facets evaluate different boundaries, so they cannot contradict in
  // the logical sense; any combination of statuses is internally consistent.
  // We surface them as a single deduplicated set with one primary.
  const consistent = true

  let primary: ConstraintFailure | undefined
  if (audFailure !== null) {
    primary = audFailure
  } else if (crossChainFailure !== null) {
    primary = crossChainFailure
  }

  return { failures, primary, bothFailed, consistent }
}
