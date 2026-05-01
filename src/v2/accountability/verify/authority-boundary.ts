// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// AuthorityBoundaryReceipt — verification
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { verify } from '../../../crypto/keys.js'
import type { AuthorityBoundaryReceipt } from '../types/authority-boundary.js'

export type AuthorityBoundaryReceiptVerifyReason =
  | 'INVALID_CLAIM_TYPE'
  | 'RECEIPT_ID_MISMATCH'
  | 'SIGNATURE_INVALID'

export interface AuthorityBoundaryReceiptVerifyResult {
  valid: boolean
  reason?: AuthorityBoundaryReceiptVerifyReason
}

export function verifyAuthorityBoundaryReceipt(
  receipt: AuthorityBoundaryReceipt,
): AuthorityBoundaryReceiptVerifyResult {
  if (receipt.claim_type !== 'aps:authority_boundary:v1') {
    return { valid: false, reason: 'INVALID_CLAIM_TYPE' }
  }

  const draftForId: AuthorityBoundaryReceipt = { ...receipt, receipt_id: '', signature: '' }
  const expectedReceiptId = createHash('sha256')
    .update(canonicalizeJCS(draftForId), 'utf8')
    .digest('hex')
  if (receipt.receipt_id !== expectedReceiptId) {
    return { valid: false, reason: 'RECEIPT_ID_MISMATCH' }
  }

  const draftForSig: AuthorityBoundaryReceipt = { ...receipt, signature: '' }
  const ok = verify(canonicalizeJCS(draftForSig), receipt.signature, receipt.signer_did)
  if (!ok) {
    return { valid: false, reason: 'SIGNATURE_INVALID' }
  }

  return { valid: true }
}
