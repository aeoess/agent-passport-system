// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { computeReceiptIdV1, validateReceiptV1 } from './receipt.js'
import type { Hex64, ReceiptV1 } from './types.js'

/** The state of the predecessor axis for one receipt.
 *
 *  `not_applicable` is reserved for a record whose stage has no predecessor rule here, and
 *  `indeterminate` for the axis that could not be established because no predecessor was
 *  supplied. Neither is a pass: section 5.6 lines 1227-1228 forbid collapsing either into
 *  valid, and this result type keeps them apart rather than folding both into a boolean.
 */
export type ReceiptPredecessorStatusV1 = 'valid' | 'invalid' | 'indeterminate' | 'not_applicable'

/** This SDK's own vocabulary. The draft names states and reasons, not code strings, so a
 *  code here is not a protocol claim. */
export type ReceiptPredecessorFailureV1 =
  | 'predecessor_not_supplied'
  | 'predecessor_malformed'
  | 'predecessor_not_policy_decision'
  | 'prev_absent'
  | 'predecessor_receipt_id_mismatch'
  | 'decision_ref_absent'
  | 'decision_ref_mismatch'

export interface ReceiptPredecessorVerificationV1 {
  /** True only when status is valid. */
  bound: boolean
  status: ReceiptPredecessorStatusV1
  /** The single reason this axis is not valid, or null when it is. One code, not a
   *  cascade: the checks short-circuit, so the code names the first thing that actually
   *  failed rather than everything downstream of it. */
  failure: ReceiptPredecessorFailureV1 | null
  /** Human-readable detail for `failure`, or null. Not a protocol claim. */
  detail: string | null
  /** The predecessor's receipt_id as recomputed from its own body, or null where the
   *  recomputation was never reached. Reporting the claimed field here would defeat the
   *  point of the check below. */
  recomputed_predecessor_receipt_id: Hex64 | null
}

const result = (
  status: ReceiptPredecessorStatusV1,
  failure: ReceiptPredecessorFailureV1 | null,
  detail: string | null,
  recomputed: Hex64 | null = null,
): ReceiptPredecessorVerificationV1 => ({
  bound: status === 'valid',
  status,
  failure,
  detail,
  recomputed_predecessor_receipt_id: recomputed,
})

/**
 * Bind an action-result record to the policy-decision record it follows.
 *
 * WHAT THE DRAFT SAYS, AND WHAT IT DOES NOT. Section 5.3.3 lines 1104-1105 STATES that for
 * an action-result record "prev is the consumed policy-decision receipt_id, and decision_ref
 * MUST equal that decision's decision_ref". The prev sentence is declarative and carries no
 * BCP 14 keyword (section 1.1 lines 175-179 interpret those keywords only where they appear
 * in all capitals); the decision_ref equality does carry MUST. Section 5.6 line 1219 lists
 * "validate prev and stage transitions" among a verifier's checks, also without a keyword.
 * So THIS CHECK IS OPT-IN HARDENING. It is not a draft-03 conformance fix, and draft-03 does
 * not require a verifier to perform it. A caller that never supplies a predecessor sees no
 * change in any other result this SDK produces.
 *
 * Why it is worth having anyway: prev is a bare digest inside a signed body, so a record can
 * name a predecessor that the verifier never obtains. Without this check, an action-result
 * attesting to a dispatch can be presented alongside any policy-decision record at all, and
 * nothing establishes that the decision in hand is the one the result claims to follow.
 *
 * SCOPE. Action-result records only. The policy-decision to action-intent link of section
 * 5.3.2 line 1072 ("prev is the receipt_id of the action-intent record") is deliberately
 * OUT OF SCOPE here: it is a separate pairing with its own operand and its own expected
 * predecessor type, and nothing in this function generalises to it. A record of any other
 * receipt_type returns `not_applicable`, which is not a pass.
 *
 * The checks, in order, each with its own code:
 *
 *   1. `not_applicable`  the receipt is not an aps:action-result:v1 record, so no rule
 *      this function knows applies to it.
 *   2. `predecessor_not_supplied`  the predecessor is undefined or null. The axis is NOT
 *      ESTABLISHED, which is `indeterminate` and never valid. A verifier that does not hold
 *      the predecessor has checked nothing here, and saying otherwise in either direction
 *      would be the collapse section 5.6 line 1227 forbids.
 *   3. `predecessor_malformed`  the predecessor is not a structurally valid ReceiptV1 under
 *      validateReceiptV1. An artifact that is not a receipt cannot be the receipt this one
 *      names.
 *   4. `predecessor_not_policy_decision`  the predecessor's receipt_type is not
 *      aps:policy-decision:v1. Line 1104 names the consumed policy decision specifically, so
 *      an action-intent record presented in that slot is refused rather than silently
 *      accepted because its digest happens to match.
 *   5. `prev_absent`  the action-result carries no prev to compare. The stage layer already
 *      reports this as RESULT_PREV_MISSING; this function reports it rather than throwing,
 *      because it is reachable when the primitive is called on its own.
 *   6. `predecessor_receipt_id_mismatch`  the predecessor's receipt_id, RECOMPUTED from its
 *      body with computeReceiptIdV1, does not equal receipt.prev. The recomputation is the
 *      whole point: receipt_id is excluded from its own preimage (lines 1003-1009), so the
 *      claimed field is an unauthenticated label that anyone can rewrite to whatever prev
 *      names, and comparing prev against that field would bind a receipt to a body it never
 *      committed to. The claimed field is never consulted.
 *   7. `decision_ref_absent`  the action-result carries no decision_ref, so the equality at
 *      line 1105 has no left operand. The stage layer reports this as
 *      RESULT_DECISION_REF_MISSING.
 *   8. `decision_ref_mismatch`  section 5.3.3 line 1105, "decision_ref MUST equal that
 *      decision's decision_ref". Compared as strings; both are already constrained to 64
 *      lowercase hexadecimal characters by validateReceiptV1, so there is no normalisation
 *      step that could make two different values compare equal.
 *
 * WHAT THIS DOES NOT ESTABLISH. It does not verify the predecessor's signatures, does not
 * resolve any signing key, and does not run the predecessor's own section 5.3 stage rules
 * beyond reading its receipt_type. A `valid` result here says the two records are linked by
 * digest and agree on decision_ref, and says nothing about whether the predecessor is
 * itself a record anyone should trust. CALLERS VERIFY THE PREDECESSOR SEPARATELY, with
 * verifyReceiptV1 or verifyReceiptWithDecisionV1, and a caller that skips that has bound
 * this receipt to an unverified artifact. It also does not enforce the single-use and
 * freshness obligations of lines 1093-1099: whether that decision had already been consumed
 * is enforcement-boundary state, not a property of these two artifacts.
 */
export function verifyReceiptPredecessorV1(
  receipt: ReceiptV1,
  predecessor?: ReceiptV1 | null,
): ReceiptPredecessorVerificationV1 {
  // Read through an unknown-shaped view: this primitive is exported, so it can be handed a
  // receipt that never passed validateReceiptV1, and a direct field access on a non-object
  // would throw where a defined result is required.
  const record = receipt as unknown as Record<string, unknown> | null
  const receiptType = typeof record === 'object' && record !== null && !Array.isArray(record)
    ? record.receipt_type
    : undefined
  if (receiptType !== 'aps:action-result:v1') {
    return result('not_applicable', null, null)
  }

  if (predecessor === undefined || predecessor === null) {
    return result('indeterminate', 'predecessor_not_supplied', 'no predecessor receipt was supplied, so the prev binding was not established')
  }

  try {
    validateReceiptV1(predecessor)
  } catch (err) {
    return result('invalid', 'predecessor_malformed', err instanceof Error ? err.message : String(err))
  }

  if (predecessor.receipt_type !== 'aps:policy-decision:v1') {
    return result('invalid', 'predecessor_not_policy_decision',
      `predecessor receipt_type is ${predecessor.receipt_type}, not aps:policy-decision:v1`)
  }

  if (typeof receipt.prev !== 'string') {
    return result('invalid', 'prev_absent', 'the action-result record carries no prev to compare')
  }

  const recomputed = computeReceiptIdV1(predecessor)
  if (recomputed !== receipt.prev) {
    return result('invalid', 'predecessor_receipt_id_mismatch',
      `prev ${receipt.prev} does not name the predecessor, whose body recomputes to ${recomputed}`, recomputed)
  }

  if (typeof receipt.decision_ref !== 'string') {
    return result('invalid', 'decision_ref_absent', 'the action-result record carries no decision_ref to compare', recomputed)
  }

  if (predecessor.decision_ref !== receipt.decision_ref) {
    return result('invalid', 'decision_ref_mismatch',
      `decision_ref ${receipt.decision_ref} does not equal the predecessor decision_ref ${String(predecessor.decision_ref)}`, recomputed)
  }

  return result('valid', null, null, recomputed)
}
