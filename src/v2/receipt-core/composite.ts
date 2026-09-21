// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { buildDecisionRefV1, validateCoreDecisionOutputV1 } from './decision-ref.js'
import { strictJCS } from './jcs.js'
import { verifyReceiptPredecessorV1 } from './predecessor.js'
import { isExactUtcMilliseconds, isLaterUtcMillisecond, verifyReceiptV1 } from './receipt.js'
import type { ReceiptVerificationStatusV1, ReceiptVerificationV1 } from './receipt.js'
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

/** The stage options this composite accepts, plus the predecessor record.
 *
 *  `predecessor` is added here rather than on ReceiptStageOptionsV1 on purpose: the stage
 *  layer judges one record against its own section 5.3 rules and holds no second artifact,
 *  so a predecessor there would be an input nothing reads. Every existing field is
 *  unchanged and is still forwarded to verifyReceiptV1 as before.
 */
export interface ReceiptWithDecisionOptionsV1 extends ReceiptStageOptionsV1 {
  /** The policy-decision record this receipt's prev names, when the caller holds it.
   *
   *  OPTIONAL, and omitting it is the default. Absent, the predecessor axis is reported
   *  `not_checked` and the composite's valid, status and errors are exactly what they were
   *  before this option existed. Supplying null is the same as omitting it: nothing was
   *  supplied, so nothing is checked. See verifyReceiptPredecessorV1 for what supplying it
   *  does and does not establish, including that its signatures are NOT verified here. */
  predecessor?: ReceiptV1 | null
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
  /** `not_applicable` on the stages where the comparison is deliberately not made: the
   *  window belongs to the decision, and the draft states no relation between it and the
   *  issuance time of a later record. Reporting true there said a check had passed that
   *  never ran, which is the same overstatement in the other direction. */
  temporal_relation_valid: boolean | 'not_applicable'
  /** The section 5.3.3 prev binding for an action-result record, run only when the caller
   *  supplies `options.predecessor`. OPT-IN HARDENING, not a draft-03 conformance check:
   *  draft-03 states the prev linkage without a BCP 14 keyword, so it does not require a
   *  verifier to make this comparison.
   *
   *  `not_checked` where no predecessor was supplied, which is the default and leaves every
   *  other field exactly as it was before this axis existed. `not_applicable` where a
   *  predecessor was supplied for a record that is not an action-result. `false` makes the
   *  composite invalid under the error code `predecessor_not_bound`. Reporting false for
   *  the unsupplied case would say a link had been refused when nothing was compared. */
  predecessor_bound: boolean | 'not_checked' | 'not_applicable'
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
 *   6. `predecessor_not_bound`  OPTIONAL and off by default. Only when the caller supplies
 *      `options.predecessor`, the section 5.3.3 prev binding for an action-result record,
 *      delegated unchanged to verifyReceiptPredecessorV1. This is OPT-IN HARDENING: the
 *      draft STATES that prev is the consumed policy-decision receipt_id (lines 1104-1105)
 *      and lists prev validation among a verifier's checks (line 1219) without a BCP 14
 *      keyword on either, so it is not required of a verifier and is not enabled unless
 *      asked for. With the option absent, `predecessor_bound` is `not_checked` and this
 *      function's valid, status and errors are byte-identical to what they were before the
 *      option existed. The predecessor's own signatures are NOT verified here; a caller
 *      that wants them checked runs this verifier over the predecessor as well.
 *   7. `valid_until_not_after_issued_at`  the temporal relation, checked only
 *      once the operands are known to belong together. Both timestamps are
 *      validated as exact UTC milliseconds and then compared as instants, never
 *      as strings. A deny decision carries a null valid_until by rule (line 1090), so
 *      there is no window to compare and its absence is not a failure. Reporting one
 *      made every correct deny decision fail this verifier.
 *
 * The binding checks run BEFORE the temporal one on purpose. A temporal result
 * computed over an unbound pair is not evidence about this receipt at all. The predecessor
 * check is a binding check, so it sits with the others and ahead of the temporal one for
 * the same reason.
 */
export function verifyReceiptWithDecisionV1(
  receipt: ReceiptV1,
  decision: DecisionEvidenceV1,
  resolveKey: (signer: string, keyId: string, issuedAt: string) => string | undefined,
  options: ReceiptWithDecisionOptionsV1 = {},
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
    predecessor_bound: 'not_checked',
    errors,
  })

  // A sub-result that is not valid is named for what it is. Calling an indeterminate
  // receipt "receipt_invalid" would tell a caller the record was wrong when the verifier
  // could not establish one of its axes, which is the collapse section 5.6 line 1227
  // forbids, just pointed the other way.
  const code = (prefix: string, status: ReceiptVerificationStatusV1): string =>
    `${prefix}_${status === 'valid' ? 'valid' : status}`

  // Stages 1 and 2 together: structural, cryptographic and the section 5.3 rules for this
  // record's own receipt_type. verifyReceiptV1 runs the stage dispatch itself and returns
  // its result, so the two are not evaluated twice and cannot disagree.
  const receiptResult = verifyReceiptV1(receipt, resolveKey, options)
  const stage = receiptResult.stage === 'not_checked' ? notRun : receiptResult.stage
  if (!receiptResult.valid) {
    errors.push(code('receipt', receiptResult.status), ...receiptResult.errors)
    return base(receiptResult, receiptResult.status, stage)
  }

  // Stage 3: the reference must be there to be bound.
  if (typeof receipt.decision_ref !== 'string') {
    errors.push('decision_ref_absent')
    return base(receiptResult, 'invalid', stage)
  }

  // Stage 4: reference binding, through the builder rather than a reimplementation.
  //
  // The supplied output is validated exactly as received first. buildDecisionRefV1
  // normalizes before hashing, which is right for an issuer building a value it is about
  // to sign and wrong here: it would let ["b","a","a"] bind to the digest of ["a","b"],
  // so a component this SDK's own verifier rejects would still match. Draft lines 1145 to
  // 1147 compute each component reference over the EXACT value evaluated, and lines 1183
  // to 1184 say decision_output is the exact object the receipt carries.
  let recomputed: string
  try {
    validateCoreDecisionOutputV1(decision.decision_output as unknown as JsonValue)
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

  // Stage 6: the section 5.3.3 prev binding, only when the caller supplied a predecessor.
  // A null predecessor is treated exactly as an omitted one: nothing was supplied, so
  // nothing is compared and the axis stays not_checked rather than reporting a refusal.
  // The primitive's own indeterminate state is unreachable from here for that reason; a
  // caller that wants it calls verifyReceiptPredecessorV1 directly.
  let predecessorBound: boolean | 'not_checked' | 'not_applicable' = 'not_checked'
  if (options.predecessor !== undefined && options.predecessor !== null) {
    const predecessorResult = verifyReceiptPredecessorV1(receipt, options.predecessor)
    predecessorBound = predecessorResult.status === 'not_applicable' ? 'not_applicable' : predecessorResult.bound
    if (predecessorBound === false) {
      errors.push('predecessor_not_bound')
      // The primitive's own code, so a caller reading the errors learns which of the
      // section 5.3.3 comparisons refused the pair rather than only that one did.
      if (predecessorResult.failure !== null) errors.push(predecessorResult.failure)
      return { ...bound, decision_output_bound: decisionOutputBound, predecessor_bound: false }
    }
  }

  // Stage 7: temporal relation, on operands now known to belong together.
  const validUntil = decision.decision_output.valid_until
  if (validUntil === null) {
    // A deny decision carries no validity window by rule, so there is no instant that
    // could be later than issued_at and nothing here has failed. Whether a deny may be
    // consumed as an approval is the caller's rule at line 1098, not a property of this
    // pair of artifacts.
    return {
      ...bound,
      decision_output_bound: decisionOutputBound,
      predecessor_bound: predecessorBound,
      temporal_relation_valid: isPolicyDecision ? true : 'not_applicable',
      valid: true,
      status: 'valid',
    }
  }
  if (!isExactUtcMilliseconds(receipt.issued_at) || !isExactUtcMilliseconds(validUntil)) {
    errors.push('timestamp_invalid')
    return { ...bound, decision_output_bound: decisionOutputBound, predecessor_bound: predecessorBound }
  }
  // The comparison is against the issued_at of the record that carries the window. For a
  // policy-decision record that is its own issued_at, which is what line 1091 fixes. For an
  // action-result record the window belongs to the decision it follows, and the draft
  // states no relation between that window and the result's own issuance time, so none is
  // invented: the check applies to the decision stage only.
  if (isPolicyDecision && !isLaterUtcMillisecond(validUntil, receipt.issued_at)) {
    errors.push('valid_until_not_after_issued_at')
    return { ...bound, decision_output_bound: decisionOutputBound, predecessor_bound: predecessorBound }
  }

  return {
    valid: true,
    status: 'valid',
    receipt: receiptResult,
    stage,
    decision_ref_present: true,
    decision_ref_bound: true,
    decision_output_bound: decisionOutputBound,
    temporal_relation_valid: isPolicyDecision ? true : 'not_applicable',
    predecessor_bound: predecessorBound,
    errors,
  }
}
