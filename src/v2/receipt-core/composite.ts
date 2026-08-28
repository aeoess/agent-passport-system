// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { buildDecisionRefV1 } from './decision-ref.js'
import { isExactUtcMilliseconds, verifyReceiptV1 } from './receipt.js'
import type { ReceiptVerificationV1 } from './receipt.js'
import type { CoreDecisionOutputV1, JsonValue, ReceiptV1 } from './types.js'

/** The decision material a verifier must hold to bind a decision to a receipt.
 *
 *  Why the decision OUTPUT alone is not enough, since that is the obvious
 *  expectation: receipt.decision_ref is a digest over the whole
 *  DecisionRefInputV1, which is the action reference plus the four component
 *  digests. The output contributes only one of those components. Supplying just
 *  the output would make the binding check unimplementable, and an unbindable
 *  operand is exactly the substitution hole this verifier exists to close.
 *
 *  action_ref is deliberately absent: it is taken from the receipt, so a
 *  decision built for a different action cannot bind, and the caller cannot
 *  quietly supply an action_ref that disagrees with the receipt it is checking.
 */
export interface DecisionEvidenceV1 {
  authority_state: JsonValue
  policy_input: JsonValue
  decision_context: JsonValue
  decision_output: CoreDecisionOutputV1
}

/** Per-stage outcome of the composite verification.
 *
 *  Stages run in order and short-circuit: a stage that does not run leaves its
 *  flag false and contributes no error code, so the errors array names the first
 *  thing that actually failed rather than a cascade.
 */
export interface ReceiptWithDecisionVerificationV1 {
  valid: boolean
  receipt: ReceiptVerificationV1
  decision_ref_present: boolean
  decision_ref_bound: boolean
  temporal_relation_valid: boolean
  errors: string[]
}

/**
 * Verify a receipt together with the decision it references.
 *
 * Receipt verification establishes the integrity and semantics represented by the
 * receipt. It does not authorize dispatch, consume receipt_id, enforce single-use,
 * recheck revocation or time at dispatch, or reserve spend. Those obligations belong to
 * the enforcement boundary.
 *
 * Four stages, each with its own error code:
 *
 *   1. `receipt_invalid`  structural and cryptographic verification, delegated
 *      unchanged to verifyReceiptV1. The full sub-result is returned under
 *      `receipt` so the caller keeps the per-signature detail.
 *   2. `decision_ref_absent`  decision_ref is OPTIONAL on ReceiptV1, so a receipt
 *      that carries none cannot be checked against a decision. Passing a decision
 *      for such a receipt is an error, never a pass: silently succeeding would
 *      report a relation that was never examined.
 *   3. `decision_ref_mismatch`  the reference binding. The decision digest is
 *      recomputed through buildDecisionRefV1, the same builder that produced it,
 *      including the normalize-before-hash step, and must equal
 *      receipt.decision_ref exactly. Without this a receipt for decision A could
 *      be checked against an unrelated decision B chosen for its convenient
 *      valid_until.
 *   4. `valid_until_not_after_issued_at`  the temporal relation, checked only
 *      once the operands are known to belong together. Both timestamps are
 *      validated as exact UTC milliseconds and then compared as instants, never
 *      as strings.
 *
 * The binding check runs BEFORE the temporal one on purpose. A temporal result
 * computed over an unbound pair is not evidence about this receipt at all.
 */
export function verifyReceiptWithDecisionV1(
  receipt: ReceiptV1,
  decision: DecisionEvidenceV1,
  resolveKey: (signer: string, keyId: string, issuedAt: string) => string | undefined,
): ReceiptWithDecisionVerificationV1 {
  const errors: string[] = []
  const base = (receiptResult: ReceiptVerificationV1): ReceiptWithDecisionVerificationV1 => ({
    valid: false,
    receipt: receiptResult,
    decision_ref_present: false,
    decision_ref_bound: false,
    temporal_relation_valid: false,
    errors,
  })

  // Stage 1: structural and cryptographic, unchanged.
  const receiptResult = verifyReceiptV1(receipt, resolveKey)
  if (!receiptResult.valid) {
    errors.push('receipt_invalid', ...receiptResult.errors)
    return base(receiptResult)
  }

  // Stage 2: the reference must be there to be bound.
  if (typeof receipt.decision_ref !== 'string') {
    errors.push('decision_ref_absent')
    return base(receiptResult)
  }

  // Stage 3: reference binding, through the builder rather than a reimplementation.
  let recomputed: string
  try {
    recomputed = buildDecisionRefV1({
      action_ref: receipt.action_ref,
      authority_state: decision.authority_state,
      policy_input: decision.policy_input,
      decision_context: decision.decision_context,
      decision_output: decision.decision_output,
    }).decision_ref
  } catch (err) {
    errors.push('decision_input_invalid', err instanceof Error ? err.message : String(err))
    return { ...base(receiptResult), decision_ref_present: true }
  }
  if (recomputed !== receipt.decision_ref) {
    errors.push('decision_ref_mismatch')
    return { ...base(receiptResult), decision_ref_present: true }
  }

  // Stage 4: temporal relation, on operands now known to belong together.
  const validUntil = decision.decision_output.valid_until
  if (validUntil === null) {
    // A deny decision carries no validity window, so there is no instant that
    // could be later than issued_at. Named separately from the ordering failure
    // because the cause and the fix differ.
    errors.push('valid_until_absent')
    return { ...base(receiptResult), decision_ref_present: true, decision_ref_bound: true }
  }
  if (!isExactUtcMilliseconds(receipt.issued_at) || !isExactUtcMilliseconds(validUntil)) {
    errors.push('timestamp_invalid')
    return { ...base(receiptResult), decision_ref_present: true, decision_ref_bound: true }
  }
  if (!(Date.parse(validUntil) > Date.parse(receipt.issued_at))) {
    errors.push('valid_until_not_after_issued_at')
    return { ...base(receiptResult), decision_ref_present: true, decision_ref_bound: true }
  }

  return {
    valid: true,
    receipt: receiptResult,
    decision_ref_present: true,
    decision_ref_bound: true,
    temporal_relation_valid: true,
    errors,
  }
}
