// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
/**
 * @fileoverview reconcileBilateralPair: compare the two parties' copies of a
 * bilateral receipt and emit a reason-coded verdict (FREEZE-VWE F2).
 *
 * ── PROOF BOX ──────────────────────────────────────────────────────────────
 * What a 'reconciled' verdict PROVES, given the precondition that both copies
 * individually passed verifyBilateralReceipt:
 *   The two parties hold copies that agree on the request/response hashes,
 *   the serving agent, the success claim, and (when present) the action_ref,
 *   and each copy's audience binding names the other side per the memo
 *   invariant.
 *
 * What it does NOT prove:
 *   - It does NOT re-verify signatures; run verifyBilateralReceipt first.
 *   - It does NOT prove the interaction happened; it proves the copies agree.
 *   - It is NOT a gateway decision. The verdict feeds a relying party's own
 *     policy; only the audience facet emits a ConstraintFailure, via the
 *     existing audienceFailure builder.
 * ───────────────────────────────────────────────────────────────────────────
 *
 * Detectors per SCHEMAS-DRAFT 3a, classes frozen by FREEZE-VWE F2.
 * Audience directions per AUDIENCE-BINDING-MEMO decision 4: the counterparty
 * receipt's aud must contain the requester (self) identifier; the
 * requester-side receipt's aud must contain the counterparty identifier.
 */

import { checkAudience } from '../audience-binding/verify.js'
import { audienceFailure } from '../audience-binding/reconcile.js'
import { actionRefsMatch } from '../../core/action-ref.js'
import type { BilateralReceipt } from '../../types/bilateral-receipt.js'
import type { ConstraintFailure } from '../../types/gateway.js'
import type {
  BilateralMismatchReason,
  BilateralPairAudienceTrace,
  BilateralPairPolicy,
  BilateralPairVerdict,
} from './types.js'

/**
 * Derive the counterparty's recipient identifier from the local copy under
 * the APS-native convention (agent DIDs are the recipient identifiers). When
 * selfRecipientId matches neither agent id (e.g. the jwks-kid convention),
 * returns null and the caller reports the direction as not evaluable rather
 * than guessing.
 */
function deriveCounterpartyId(local: BilateralReceipt, selfRecipientId: string): string | null {
  if (selfRecipientId === local.requestingAgentId) return local.servingAgentId
  if (selfRecipientId === local.servingAgentId) return local.requestingAgentId
  return null
}

/**
 * Reconcile the relying party's copy of a bilateral receipt with the
 * counterparty's copy (or its absence). See the fileoverview for the proof
 * box and the precondition (signatures already verified per copy).
 */
export function reconcileBilateralPair(
  local: BilateralReceipt,
  counterparty: BilateralReceipt | null,
  policy: BilateralPairPolicy,
): BilateralPairVerdict {
  const mismatches: BilateralMismatchReason[] = []
  const detail: BilateralPairVerdict['detail'] = {}
  const audience: BilateralPairAudienceTrace = {}
  const constraintFailures: ConstraintFailure[] = []

  const push = (reason: BilateralMismatchReason, line: string): void => {
    if (!mismatches.includes(reason)) mismatches.push(reason)
    if (detail[reason] === undefined) detail[reason] = line
  }

  // ── wrong_audience: both directions of the memo invariant ──
  // Direction 1: the counterparty's copy must name self among its recipients.
  if (counterparty !== null) {
    const d1 = checkAudience(counterparty, {
      recipientId: policy.selfRecipientId,
      requireAudience: policy.requireAudience,
    })
    audience.counterpartyCopyToSelf = d1
    if (d1.status === 'fail') {
      push('wrong_audience', `counterparty copy does not admit self (${d1.reason})`)
      const failure = audienceFailure(d1)
      if (failure !== null) constraintFailures.push(failure)
    }
  }

  // Direction 2: the local copy must name the counterparty among its
  // recipients. The identifier comes from policy when supplied, else from the
  // APS-native agent-DID convention; when neither resolves the direction is
  // simply not evaluable (no silent pass, no invented failure).
  const counterpartyId =
    policy.counterpartyRecipientId ?? deriveCounterpartyId(local, policy.selfRecipientId)
  if (counterpartyId !== null) {
    const d2 = checkAudience(local, {
      recipientId: counterpartyId,
      requireAudience: policy.requireAudience,
    })
    audience.localCopyToCounterparty = d2
    if (d2.status === 'fail') {
      push('wrong_audience', `local copy does not admit the counterparty (${d2.reason})`)
      const failure = audienceFailure(d2)
      if (failure !== null) constraintFailures.push(failure)
    }
  }

  // ── action_ref_mismatch: every pair of PRESENT refs must match ──
  // Absence never mismatches: the slot is additive (F1) and expectedActionRef
  // exists precisely so legacy slot-free receipts can still be paired.
  const presentRefs: string[] = []
  if (local.action_ref !== undefined) presentRefs.push(local.action_ref)
  if (counterparty !== null && counterparty.action_ref !== undefined) {
    presentRefs.push(counterparty.action_ref)
  }
  if (policy.expectedActionRef !== undefined) presentRefs.push(policy.expectedActionRef)
  if (presentRefs.length >= 2) {
    const first = presentRefs[0]
    if (!presentRefs.every((r) => actionRefsMatch(first, r))) {
      push('action_ref_mismatch', 'present action_ref values disagree across copies/policy')
    }
  }

  // ── pairwise detectors (need both copies) ──
  if (counterparty !== null) {
    if (
      local.outcome.requestHash !== counterparty.outcome.requestHash ||
      local.outcome.responseHash !== counterparty.outcome.responseHash
    ) {
      push('payload_changed', 'outcome.requestHash/responseHash differ between copies')
    }

    if (local.servingAgentId !== counterparty.servingAgentId) {
      push('recipient_changed', 'copies name different servingAgentId (re-mint)')
    }

    const localSuccess = local.outcome.status === 'success'
    const cpSuccess = counterparty.outcome.status === 'success'
    if (localSuccess !== cpSuccess) {
      push('unilateral_success', 'one copy claims success, the other does not')
    }
  } else if (local.outcome.status === 'success') {
    // One-sided success with no counterparty copy at all.
    push('unilateral_success', 'local copy claims success with no counterparty copy')
  }

  const status: BilateralPairVerdict['status'] =
    counterparty === null ? 'unilateral' : mismatches.length === 0 ? 'reconciled' : 'mismatch'

  return { status, mismatches, detail, audience, constraintFailures }
}
