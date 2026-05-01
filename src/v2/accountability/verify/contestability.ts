// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// ContestabilityReceipt — verification
// ══════════════════════════════════════════════════════════════════
// Failure modes:
//   INVALID_CLAIM_TYPE          — claim_type is not 'aps:contestability:v1'
//   MISSING_CONTESTANT_IDENTITY — contestant has neither did nor pseudonym_hash
//   INVALID_STANDING_BASIS      — outside the closed taxonomy
//   INVALID_REMEDY              — outside the closed taxonomy
//   INVALID_CONTEST_STATUS      — outside the closed taxonomy (response only)
//   RECEIPT_ID_MISMATCH         — receipt_id does not equal sha256(JCS(filing form))
//   SIGNATURE_INVALID           — outer (contestant) signature does not verify
//   CONTROLLER_SIGNATURE_INVALID — response_signature does not verify
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { verify } from '../../../crypto/keys.js'
import type {
  ContestabilityReceipt,
  ContestabilityControllerResponse,
  ContestStatus,
  RequestedRemedy,
  StandingBasis,
} from '../types/contestability.js'

export type ContestabilityReceiptVerifyReason =
  | 'INVALID_CLAIM_TYPE'
  | 'MISSING_CONTESTANT_IDENTITY'
  | 'INVALID_STANDING_BASIS'
  | 'INVALID_REMEDY'
  | 'INVALID_CONTEST_STATUS'
  | 'RECEIPT_ID_MISMATCH'
  | 'SIGNATURE_INVALID'
  | 'CONTROLLER_SIGNATURE_INVALID'

export interface ContestabilityReceiptVerifyResult {
  valid: boolean
  reason?: ContestabilityReceiptVerifyReason
}

const VALID_STANDING: readonly StandingBasis[] = [
  'data_subject',
  'third_party',
  'regulator',
  'court',
  'internal_audit',
  'insurer',
  'principal',
]

const VALID_REMEDY: readonly RequestedRemedy[] = [
  'rollback',
  'review',
  'explanation',
  'compensation',
  'erasure',
  'modification',
]

const VALID_STATUS: readonly ContestStatus[] = [
  'filed',
  'under_review',
  'upheld',
  'rejected',
  'remedied',
  'expired',
  'abandoned',
]

/** Strip controller_response to recover the receipt as the contestant
 *  originally signed it. */
function withoutControllerResponse(receipt: ContestabilityReceipt): ContestabilityReceipt {
  const { controller_response: _ignored, ...rest } = receipt
  return rest as ContestabilityReceipt
}

export function verifyContestabilityReceipt(
  receipt: ContestabilityReceipt,
): ContestabilityReceiptVerifyResult {
  if (receipt.claim_type !== 'aps:contestability:v1') {
    return { valid: false, reason: 'INVALID_CLAIM_TYPE' }
  }

  const hasDid =
    receipt.contestant.did !== undefined && receipt.contestant.did !== ''
  const hasPseudo =
    receipt.contestant.pseudonym_hash !== undefined &&
    receipt.contestant.pseudonym_hash !== ''
  if (!hasDid && !hasPseudo) {
    return { valid: false, reason: 'MISSING_CONTESTANT_IDENTITY' }
  }

  if (!VALID_STANDING.includes(receipt.contestant.standing_basis)) {
    return { valid: false, reason: 'INVALID_STANDING_BASIS' }
  }
  if (!VALID_REMEDY.includes(receipt.requested_remedy)) {
    return { valid: false, reason: 'INVALID_REMEDY' }
  }
  if (
    receipt.controller_response !== undefined &&
    !VALID_STATUS.includes(receipt.controller_response.status)
  ) {
    return { valid: false, reason: 'INVALID_CONTEST_STATUS' }
  }

  // Re-derive receipt_id over the filing form: empty receipt_id, empty
  // signature, no controller_response.
  const filingDraft = withoutControllerResponse({
    ...receipt,
    receipt_id: '',
    signature: '',
  })
  const expectedReceiptId = createHash('sha256')
    .update(canonicalizeJCS(filingDraft), 'utf8')
    .digest('hex')
  if (receipt.receipt_id !== expectedReceiptId) {
    return { valid: false, reason: 'RECEIPT_ID_MISMATCH' }
  }

  // Verify outer (contestant) signature over the filing form with
  // populated receipt_id and empty signature.
  const sigDraft = withoutControllerResponse({ ...receipt, signature: '' })
  const outerOk = verify(canonicalizeJCS(sigDraft), receipt.signature, receipt.signer_did)
  if (!outerOk) {
    return { valid: false, reason: 'SIGNATURE_INVALID' }
  }

  // Verify controller response signature, if present.
  if (receipt.controller_response !== undefined) {
    const respDraft: ContestabilityControllerResponse = {
      ...receipt.controller_response,
      response_signature: '',
    }
    const fullDraft: ContestabilityReceipt = {
      ...receipt,
      controller_response: respDraft,
    }
    const respOk = verify(
      canonicalizeJCS(fullDraft),
      receipt.controller_response.response_signature,
      receipt.controller_response.responder_did,
    )
    if (!respOk) {
      return { valid: false, reason: 'CONTROLLER_SIGNATURE_INVALID' }
    }
  }

  return { valid: true }
}
