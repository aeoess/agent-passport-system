// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { validateCoreDecisionOutputV1 } from './decision-ref.js'
import { isExactUtcMilliseconds, validateReceiptV1 } from './receipt.js'
import type { JsonValue, ReceiptV1 } from './types.js'

const HEX64 = /^[0-9a-f]{64}$/

export const RECEIPT_STAGE_TYPES_V1 = {
  'aps:action-intent:v1': 'action-intent',
  'aps:policy-decision:v1': 'policy-decision',
  'aps:action-result:v1': 'action-result',
} as const

export type ReceiptStageV1 = (typeof RECEIPT_STAGE_TYPES_V1)[keyof typeof RECEIPT_STAGE_TYPES_V1]

/** draft-pidlisnyi-aps-03 section 3.3 line 588 and section 5.6 lines 1225-1228: a
 *  verification result is one of valid, invalid, indeterminate or unsupported, and a
 *  caller MUST NOT collapse indeterminate or unsupported into valid. */
export type ReceiptStageStatusV1 = 'valid' | 'invalid' | 'indeterminate' | 'unsupported'

/** The enforcement-boundary identity axis of section 5.3.2 line 1072 and section 5.3.3
 *  line 1104, kept separate from the structural result as section 5.6 lines 1223-1225
 *  requires. `not_established` means no expected identity was supplied, which is
 *  indeterminate and never valid; it is not evidence that the issuer was the boundary. */
export type BoundaryIdentityResultV1 = 'verified' | 'mismatch' | 'not_established' | 'not_applicable'

export interface ReceiptStageFailureV1 {
  code: string
  detail: string
}

export interface ReceiptStageResultV1 {
  status: ReceiptStageStatusV1
  receipt_type: string | null
  stage: ReceiptStageV1 | null
  boundary_identity: BoundaryIdentityResultV1
  failures: ReceiptStageFailureV1[]
}

export interface ReceiptStageOptionsV1 {
  /** The stage the caller believes it is looking at. The stage is always taken from
   *  receipt.receipt_type; supplying this only adds the check that the two agree. */
  expectedReceiptType?: string
  /** The expected enforcement-boundary identity, supplied as verifier trust input for the
   *  policy-decision and action-result stages. Absent means that axis is indeterminate. */
  boundaryIdentity?: string
}

/**
 * Section 5.3 stage rules for a ReceiptV1, dispatched on receipt.receipt_type.
 *
 * The caller never selects the stage: the type in the record decides which rules apply, and
 * `expectedReceiptType` only adds the check that the caller's belief matches the record.
 * This runs after the closed envelope check of section 5.1 and never loosens it; a receipt
 * that fails validateReceiptV1 is invalid here for that reason alone.
 *
 * What each status means here:
 *   unsupported  the envelope profile is not "aps-receipt-v1", or receipt_type is not one
 *                of the three stages of section 5.3. Section 5.6 line 1226 makes an unknown
 *                required profile unsupported. An unrecognised stage is reported
 *                unsupported and never valid, and its body is not judged against a stage
 *                schema it may not belong to.
 *   invalid      a structural or stage rule of section 5.1 or 5.3 fails, including a wrong
 *                result.profile for a stage that is recognised: those result objects are
 *                closed.
 *   indeterminate  every rule that could be checked passed, and an axis could not be
 *                established. Today that is the enforcement-boundary identity when the
 *                caller supplied none.
 *   valid        every rule this function can check on a single record passed.
 *
 * What this function does NOT establish, so that a caller cannot read more into a valid
 * result than it carries: it does not recompute action_ref from an independently supplied
 * action, does not bind delegation_ref to a leaf delegation_id (it checks the structural
 * form only, per the ruling recorded for that question), does not recompute decision_ref
 * from decision components, does not resolve prev against the receipt it names, and does
 * not enforce the approval obligations of lines 1093-1099, which are enforcement-boundary
 * state rather than properties of one record. Those are the section 5.6 composition points.
 *
 * The failure codes are this SDK's own vocabulary. The draft names states and reasons, not
 * code strings, so a code is not a protocol claim.
 */
export function validateReceiptStageV1(
  receipt: ReceiptV1,
  options: ReceiptStageOptionsV1 = {},
): ReceiptStageResultV1 {
  const failures: ReceiptStageFailureV1[] = []
  const fail = (code: string, detail: string): void => { failures.push({ code, detail }) }
  const record = receipt as unknown as Record<string, unknown>
  const receiptType = typeof record?.receipt_type === 'string' ? record.receipt_type : null

  const result = (status: ReceiptStageStatusV1, stage: ReceiptStageV1 | null, boundary: BoundaryIdentityResultV1): ReceiptStageResultV1 =>
    ({ status, receipt_type: receiptType, stage, boundary_identity: boundary, failures })

  if (typeof receipt !== 'object' || receipt === null || Array.isArray(receipt)) {
    fail('SCHEMA_INVALID', 'ReceiptV1: not a JSON object')
    return result('invalid', null, 'not_applicable')
  }

  // The envelope profile is read before the closed schema runs. An artifact under another
  // envelope profile is unsupported (section 5.6 line 1226) and is not judged against the
  // aps-receipt-v1 schema, which is not its schema.
  if (typeof record.profile !== 'string') {
    fail('SCHEMA_INVALID', 'ReceiptV1: profile must be a string')
    return result('invalid', null, 'not_applicable')
  }
  if (record.profile !== 'aps-receipt-v1') {
    fail('UNSUPPORTED_PROFILE', `ReceiptV1: envelope profile ${record.profile} is not aps-receipt-v1`)
    return result('unsupported', null, 'not_applicable')
  }

  try {
    validateReceiptV1(receipt)
  } catch (err) {
    fail('SCHEMA_INVALID', err instanceof Error ? err.message : String(err))
    return result('invalid', null, 'not_applicable')
  }

  if (options.expectedReceiptType !== undefined && options.expectedReceiptType !== receipt.receipt_type) {
    // The caller asked for one stage and this record names another. The mismatch is the
    // failure, whether or not the record is a valid instance of its own stage.
    fail('STAGE_MISMATCH', `expected receipt_type ${options.expectedReceiptType}, record carries ${receipt.receipt_type}`)
    return result('invalid', null, 'not_applicable')
  }

  const stage = RECEIPT_STAGE_TYPES_V1[receipt.receipt_type as keyof typeof RECEIPT_STAGE_TYPES_V1]
  if (stage === undefined) {
    fail('UNSUPPORTED_RECEIPT_TYPE', `receipt_type ${receipt.receipt_type} is not a stage defined in section 5.3`)
    return result('unsupported', null, 'not_applicable')
  }

  if (stage === 'action-intent') {
    checkActionIntent(receipt, fail)
    return result(failures.length === 0 ? 'valid' : 'invalid', stage, 'not_applicable')
  }

  if (stage === 'policy-decision') checkPolicyDecision(receipt, fail)
  else checkActionResult(receipt, fail)

  // Boundary identity, section 5.3.2 line 1072 and 5.3.3 line 1104, as ruled: the expected
  // identity is verifier trust input; a mismatch is invalid; no supplied identity leaves the
  // axis indeterminate. There is no rule here that issuer differs from subject_agent, and
  // none that an action-result issuer equals the issuer of the decision it follows: the
  // draft states neither, and both were rejected when proposed.
  let boundary: BoundaryIdentityResultV1
  if (options.boundaryIdentity === undefined) {
    boundary = 'not_established'
  } else if (options.boundaryIdentity === receipt.issuer) {
    boundary = 'verified'
  } else {
    boundary = 'mismatch'
    fail('BOUNDARY_IDENTITY_MISMATCH', `issuer ${receipt.issuer} is not the supplied enforcement boundary identity`)
  }

  if (failures.length > 0) return result('invalid', stage, boundary)
  if (boundary === 'not_established') return result('indeterminate', stage, boundary)
  return result('valid', stage, boundary)
}

type Fail = (code: string, detail: string) => void

/** Section 5.3.1, lines 1052-1058. */
function checkActionIntent(receipt: ReceiptV1, fail: Fail): void {
  if (receipt.issuer !== receipt.subject_agent) {
    fail('INTENT_ISSUER_NOT_ACTING_AGENT', 'issuer and subject_agent must both be the acting agent')
  }
  if (receipt.prev !== undefined) fail('INTENT_PREV_PRESENT', 'prev must be absent from an action-intent record')
  if (receipt.decision_ref !== undefined) {
    fail('INTENT_DECISION_REF_PRESENT', 'decision_ref must be absent from an action-intent record')
  }
  const expected = { profile: 'aps-action-intent-result-v1', status: 'declared' }
  const keys = Object.keys(receipt.result)
  if (receipt.result.profile !== expected.profile) {
    fail('INTENT_RESULT_PROFILE', `result.profile must be ${expected.profile}`)
  } else if (keys.length !== 2 || !keys.includes('status') || receipt.result.status !== expected.status) {
    fail('INTENT_RESULT_INVALID', 'result must contain exactly profile aps-action-intent-result-v1 and status declared')
  }
  // The signature that binds the intent is the acting agent's. Section 5.1 line 999 already
  // requires a signature from issuer, and for this stage issuer is the acting agent, so the
  // envelope check and this stage rule together give line 1056.
}

/** Section 5.3.2, lines 1069-1099, and the conditional members at lines 984-988. */
function checkPolicyDecision(receipt: ReceiptV1, fail: Fail): void {
  if (receipt.prev === undefined) fail('DECISION_PREV_MISSING', 'prev is required for a policy-decision record')
  if (receipt.decision_ref === undefined) {
    fail('DECISION_REF_MISSING', 'decision_ref is required for a policy-decision record')
  }
  let output
  try {
    output = validateCoreDecisionOutputV1(receipt.result as unknown as JsonValue)
  } catch (err) {
    fail('DECISION_RESULT_INVALID', err instanceof Error ? err.message : String(err))
    return
  }
  // Line 1091: valid_until is later than issued_at for permit or narrow. The comparison is
  // against this record's own issued_at, which is the decision's issuance time. Both values
  // are already known to be exact UTC milliseconds, and they are compared as instants.
  if (output.verdict !== 'deny') {
    const validUntil = output.valid_until as string
    if (!isExactUtcMilliseconds(validUntil) || !(Date.parse(validUntil) > Date.parse(receipt.issued_at))) {
      fail('DECISION_VALID_UNTIL_NOT_AFTER_ISSUED_AT', `valid_until ${validUntil} is not later than issued_at ${receipt.issued_at}`)
    }
  }
}

/** Section 5.3.3, lines 1101-1133, and the conditional members at lines 984-988. */
function checkActionResult(receipt: ReceiptV1, fail: Fail): void {
  if (receipt.prev === undefined) fail('RESULT_PREV_MISSING', 'prev is required for an action-result record')
  if (receipt.decision_ref === undefined) {
    fail('RESULT_DECISION_REF_MISSING', 'decision_ref is required for an action-result record')
  }
  const result = receipt.result
  const keys = Object.keys(result).sort()
  if (result.profile !== 'aps-action-result-v1') {
    fail('RESULT_PROFILE', 'result.profile must be aps-action-result-v1')
    return
  }
  if (keys.length !== 4 || keys.join(',') !== 'effect_ref,error_code,profile,status') {
    fail('RESULT_MEMBERS', 'result must contain exactly profile, status, effect_ref and error_code')
    return
  }
  const { status, effect_ref: effectRef, error_code: errorCode } = result
  if (status !== 'succeeded' && status !== 'failed' && status !== 'unknown') {
    fail('RESULT_STATUS', 'status must be succeeded, failed or unknown')
    return
  }
  if (effectRef !== null && (typeof effectRef !== 'string' || !HEX64.test(effectRef))) {
    fail('RESULT_EFFECT_REF', 'effect_ref must be null or 64 lowercase hexadecimal characters')
    return
  }
  if (status === 'succeeded') {
    // Line 1125: for succeeded, effect_ref is REQUIRED and error_code is null.
    if (effectRef === null) fail('RESULT_EFFECT_REF_REQUIRED', 'effect_ref is required when status is succeeded')
    if (errorCode !== null) fail('RESULT_ERROR_CODE_PRESENT', 'error_code must be null when status is succeeded')
    return
  }
  if (status === 'failed') {
    // Line 1126: for failed, error_code is a non-empty stable identifier. Stability is not
    // machine-checkable and is not claimed; the non-empty string is.
    if (typeof errorCode !== 'string' || errorCode === '') {
      fail('RESULT_ERROR_CODE_REQUIRED', 'error_code must be a non-empty string when status is failed')
    }
    return
  }
  // Line 1128: for unknown, both are null.
  if (effectRef !== null || errorCode !== null) {
    fail('RESULT_UNKNOWN_NOT_NULL', 'effect_ref and error_code must both be null when status is unknown')
  }
}
