// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
/**
 * @fileoverview Bilateral pair reconciliation types (FREEZE-VWE F2).
 *
 * A bilateral receipt exists as two copies, one held by each party. Both
 * parties signed the same canonical body, so honest copies are identical.
 * Reconciliation takes the relying party's copy plus the counterparty's copy
 * (or its absence) and emits a reason-coded verdict in the same string-union
 * style as AudienceReason (src/v2/audience-binding/types.ts).
 *
 * The five mismatch classes are frozen (FREEZE-VWE F2, SCHEMAS-DRAFT 3a).
 * They exist ONLY in the pair verdict: no new ConstraintFacet is introduced
 * (the facet count is a public claim). wrong_audience may additionally emit
 * the existing 'audience' ConstraintFailure via audienceFailure.
 *
 * PRECONDITION: reconciliation compares two copies structurally. It does NOT
 * re-verify signatures; callers run verifyBilateralReceipt on each copy first
 * and only reconcile copies whose signatures verified. The detectors are
 * defined over individually valid copies (SCHEMAS-DRAFT 3a).
 */

import type { AudienceCheckResult } from '../audience-binding/types.js'
import type { ConstraintFailure } from '../../types/gateway.js'

/** The five frozen mismatch classes (FREEZE-VWE F2). */
export type BilateralMismatchReason =
  | 'payload_changed'      // both copies valid but outcome.requestHash/responseHash differ
  | 'recipient_changed'    // two validly signed copies naming different servingAgentId
  | 'wrong_audience'       // an audience direction check failed (memo invariant)
  | 'unilateral_success'   // success claimed on one side; counterparty absent or says failure
  | 'action_ref_mismatch'  // present action_refs disagree (slot or caller-supplied)

/**
 * Relying-party policy for pair reconciliation. Never read from a receipt.
 */
export interface BilateralPairPolicy {
  /**
   * The relying party's own recipient identifier. Per the audience memo:
   * APS-native parties use the agent DID; JWT/JWKS counterparties use
   * 'jwks-kid:' + the stable JWKS kid.
   */
  selfRecipientId: string
  /** When true, an audience-unbound copy fails the audience direction checks. */
  requireAudience?: boolean
  /**
   * Caller-supplied expected action_ref, serving legacy pairing for receipts
   * minted before the F1 slot existed (FREEZE-VWE F1). Compared with
   * actionRefsMatch against any copy that carries the slot.
   */
  expectedActionRef?: string
  /**
   * Optional explicit counterparty recipient identifier for the reverse
   * audience direction (local copy must name the counterparty). When omitted,
   * the counterparty identifier is derived from the local copy's agent ids
   * (the APS-native DID convention); for jwks-kid counterparties the derived
   * form does not exist, so supply this field and the direction is otherwise
   * reported 'unknown', never silently passed.
   */
  counterpartyRecipientId?: string
}

/**
 * The audience evaluation trace, one entry per direction of the memo
 * invariant: the counterparty's copy must name self; the local copy must name
 * the counterparty. Entries are absent when the direction could not run
 * (no counterparty copy; no counterparty identifier).
 */
export interface BilateralPairAudienceTrace {
  /** checkAudience(counterparty copy, {recipientId: selfRecipientId, requireAudience}) */
  counterpartyCopyToSelf?: AudienceCheckResult
  /** checkAudience(local copy, {recipientId: counterparty identifier, requireAudience}) */
  localCopyToCounterparty?: AudienceCheckResult
}

/** The reconciliation verdict (FREEZE-VWE F2). */
export interface BilateralPairVerdict {
  /**
   * 'reconciled'  : counterparty copy present, no mismatch class detected.
   * 'mismatch'    : counterparty copy present, one or more classes detected.
   * 'unilateral'  : no counterparty copy was supplied; mismatches may still
   *                 carry unilateral_success, wrong_audience, or
   *                 action_ref_mismatch findings computable from one copy.
   */
  status: 'reconciled' | 'mismatch' | 'unilateral'
  /** Detected classes, deduplicated, in detection order. */
  mismatches: BilateralMismatchReason[]
  /** One human-readable line per detected class (logs, never parsed). */
  detail: Partial<Record<BilateralMismatchReason, string>>
  /** Per-direction audience results backing any wrong_audience finding. */
  audience: BilateralPairAudienceTrace
  /**
   * Canonical ConstraintFailures for failed audience checks, built ONLY via
   * the existing audienceFailure (facet 'audience'). The other four classes
   * exist only in this verdict and emit no ConstraintFailure this sprint
   * (FREEZE-VWE F2: no new ConstraintFacet).
   */
  constraintFailures: ConstraintFailure[]
}
