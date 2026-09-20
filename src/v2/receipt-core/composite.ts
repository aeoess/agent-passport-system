// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { buildDecisionRefV1 } from './decision-ref.js'
import { strictJCS } from './jcs.js'
import { isExactUtcMilliseconds, isLaterUtcMillisecond, verifyReceiptV1 } from './receipt.js'
import type { ReceiptVerificationStatusV1, ReceiptVerificationV1 } from './receipt.js'
import { validateReceiptStageV1 } from './stage.js'
import type { ReceiptStageOptionsV1, ReceiptStageResultV1 } from './stage.js'
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
  /** Section 5.6 lines 1225-1228. Invalid dominates: a structural failure anywhere makes
   *  the composite invalid. Otherwise an unsupported or indeterminate sub-result carries
   *  through, so a caller cannot read a valid composite out of an axis that was never
   *  established. */
  status: ReceiptVerificationStatusV1
  receipt: ReceiptVerificationV1
  /** The section 5.3 stage result for this record, which decides which cross-document
   *  checks below apply at all. */
  stage: ReceiptStageResultV1
  decision_ref_present: boolean
  decision_ref_bound: boolean
  /** For a policy-decision record, whether receipt.result is byte-identical under JCS to
   *  the decision_output supplied. Section 5.4 lines 1183-1184 define decision_output as
   *  the exact CoreDecisionOutputV1 carried in the policy-decision receipt, so a decision
   *  whose output differs from the receipt's own result is not the decision this receipt
   *  carries, however well its digest binds. `not_applicable` for the other stages. */
  decision_output_bound: boolean | 'not_applicable'
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
 * Six stages, each with its own error code:
 *
 *   1. `receipt_invalid`  structural and cryptographic verification, delegated
 *      unchanged to verifyReceiptV1. The full sub-result is returned under
 *      `receipt` so the caller keeps the per-signature detail. A sub-result that is
 *      unsupported or indeterminate rather than invalid carries its own status through,
 *      so an unresolvable signing key does not come back as a composite failure.
 *   2. `stage_invalid`  the section 5.3 rules for this record's own receipt_type,
 *      delegated to validateReceiptStageV1. Which of the checks below apply is decided
 *      here and never by the caller.
 *   3. `decision_ref_absent`  decision_ref is conditional on ReceiptV1, so a receipt
 *      that carries none cannot be checked against a decision. Passing a decision
 *      for such a receipt is an error, never a pass: silently succeeding would
 *      report a relation that was never examined.
 *   4. `decision_ref_mismatch`  the reference binding. The decision digest is
 *      recomputed through buildDecisionRefV1, the same builder that produced it,
 *      including the normalize-before-hash step, and must equal
 *      receipt.decision_ref exactly. Without this a receipt for decision A could
 *      be checked against an unrelated decision B chosen for its convenient
 *      valid_until.
 *   5. `decision_output_mismatch`  for a policy-decision record, receipt.result must be
 *      the exact CoreDecisionOutputV1 the decision carries (section 5.4 lines 1183-1184),
 *      compared as canonical bytes. The digest binding alone did not establish this: the
 *      decision_ref commits to a digest of the output, and nothing compared that output
 *      with the result the receipt itself carries and signs.
 *   6. `valid_until_not_after_issued_at`  the temporal relation, checked only
 *      once the operands are known to belong together. Both timestamps are
 *      validated as exact UTC milliseconds and then compared as instants, never
 *      as strings. A deny decision carries a null valid_until by rule (line 1090), so
 *      there is no window to compare and its absence is not a failure. Reporting one
 *      made every correct deny decision fail this verifier.
 *
 * The binding checks run BEFORE the temporal one on purpose. A temporal result
 * computed over an unbound pair is not evidence about this receipt at all.
 */
export function verifyReceiptWithDecisionV1(
  receipt: ReceiptV1,
  decision: DecisionEvidenceV1,
  resolveKey: (signer: string, keyId: string, issuedAt: string) => string | undefined,
  options: ReceiptStageOptionsV1 = {},
): ReceiptWithDecisionVerificationV1 {
  const errors: string[] = []
  const notRun: ReceiptStageResultV1 = {
    status: 'invalid', receipt_type: null, stage: null, boundary_identity: 'not_applicable', failures: [],
  }
  const base = (
    receiptResult: ReceiptVerificationV1,
    status: ReceiptVerificationStatusV1,
    stage: ReceiptStageResultV1,
  ): ReceiptWithDecisionVerificationV1 => ({
    valid: false,
    status,
    receipt: receiptResult,
    stage,
    decision_ref_present: false,
    decision_ref_bound: false,
    decision_output_bound: 'not_applicable',
    temporal_relation_valid: false,
    errors,
  })

  // A sub-result that is not valid is named for what it is. Calling an indeterminate
  // receipt "receipt_invalid" would tell a caller the record was wrong when the verifier
  // could not establish one of its axes, which is the collapse section 5.6 line 1227
  // forbids, just pointed the other way.
  const code = (prefix: string, status: ReceiptVerificationStatusV1): string =>
    `${prefix}_${status === 'valid' ? 'valid' : status}`

  // Stage 1: structural and cryptographic, unchanged.
  const receiptResult = verifyReceiptV1(receipt, resolveKey)
  if (!receiptResult.valid) {
    errors.push(code('receipt', receiptResult.status), ...receiptResult.errors)
    return base(receiptResult, receiptResult.status, notRun)
  }

  // Stage 2: the rules of this record's own stage.
  const stage = validateReceiptStageV1(receipt, options)
  if (stage.status !== 'valid') {
    errors.push(code('stage', stage.status), ...stage.failures.map(f => f.code))
    return base(receiptResult, stage.status, stage)
  }

  // Stage 3: the reference must be there to be bound.
  if (typeof receipt.decision_ref !== 'string') {
    errors.push('decision_ref_absent')
    return base(receiptResult, 'invalid', stage)
  }

  // Stage 4: reference binding, through the builder rather than a reimplementation.
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
    return { ...base(receiptResult, 'invalid', stage), decision_ref_present: true }
  }
  if (recomputed !== receipt.decision_ref) {
    errors.push('decision_ref_mismatch')
    return { ...base(receiptResult, 'invalid', stage), decision_ref_present: true }
  }

  const bound = {
    ...base(receiptResult, 'invalid', stage),
    decision_ref_present: true,
    decision_ref_bound: true,
  }

  // Stage 5: for a policy-decision record, the decision's output is the result this
  // receipt carries. Canonical bytes, so member order cannot make two different objects
  // compare equal or two equal objects compare different.
  const isPolicyDecision = stage.stage === 'policy-decision'
  if (isPolicyDecision) {
    if (strictJCS(receipt.result) !== strictJCS(decision.decision_output as unknown as JsonValue)) {
      errors.push('decision_output_mismatch')
      return { ...bound, decision_output_bound: false }
    }
  }
  const decisionOutputBound: boolean | 'not_applicable' = isPolicyDecision ? true : 'not_applicable'

  // Stage 6: temporal relation, on operands now known to belong together.
  const validUntil = decision.decision_output.valid_until
  if (validUntil === null) {
    // A deny decision carries no validity window by rule, so there is no instant that
    // could be later than issued_at and nothing here has failed. Whether a deny may be
    // consumed as an approval is the caller's rule at line 1098, not a property of this
    // pair of artifacts.
    return {
      ...bound,
      decision_output_bound: decisionOutputBound,
      temporal_relation_valid: true,
      valid: true,
      status: 'valid',
    }
  }
  if (!isExactUtcMilliseconds(receipt.issued_at) || !isExactUtcMilliseconds(validUntil)) {
    errors.push('timestamp_invalid')
    return { ...bound, decision_output_bound: decisionOutputBound }
  }
  // The comparison is against the issued_at of the record that carries the window. For a
  // policy-decision record that is its own issued_at, which is what line 1091 fixes. For an
  // action-result record the window belongs to the decision it follows, and the draft
  // states no relation between that window and the result's own issuance time, so none is
  // invented: the check applies to the decision stage only.
  if (isPolicyDecision && !isLaterUtcMillisecond(validUntil, receipt.issued_at)) {
    errors.push('valid_until_not_after_issued_at')
    return { ...bound, decision_output_bound: decisionOutputBound }
  }

  return {
    valid: true,
    status: 'valid',
    receipt: receiptResult,
    stage,
    decision_ref_present: true,
    decision_ref_bound: true,
    decision_output_bound: decisionOutputBound,
    temporal_relation_valid: true,
    errors,
  }
}
