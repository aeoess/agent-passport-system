// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// ActionReceipt — verification
// ══════════════════════════════════════════════════════════════════
// Three failure modes:
//   INVALID_CLAIM_TYPE  — receipt is not aps:action:v1
//   RECEIPT_ID_MISMATCH — receipt_id does not equal sha256(JCS(empty-id form))
//   SIGNATURE_INVALID   — Ed25519 signature does not verify under signer_did
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { verify } from '../../../crypto/keys.js'
import type { ActionReceipt } from '../types/action.js'

export type ActionReceiptVerifyReason =
  | 'INVALID_CLAIM_TYPE'
  | 'RECEIPT_ID_MISMATCH'
  | 'SIGNATURE_INVALID'

export interface ActionReceiptVerifyResult {
  valid: boolean
  reason?: ActionReceiptVerifyReason
}

export function verifyActionReceipt(receipt: ActionReceipt): ActionReceiptVerifyResult {
  if (receipt.claim_type !== 'aps:action:v1') {
    return { valid: false, reason: 'INVALID_CLAIM_TYPE' }
  }

  // Re-derive receipt_id over the empty-id, empty-signature form.
  const draftForId: ActionReceipt = { ...receipt, receipt_id: '', signature: '' }
  const expectedReceiptId = createHash('sha256')
    .update(canonicalizeJCS(draftForId), 'utf8')
    .digest('hex')
  if (receipt.receipt_id !== expectedReceiptId) {
    return { valid: false, reason: 'RECEIPT_ID_MISMATCH' }
  }

  // Verify signature over the populated-id, empty-signature form.
  const draftForSig: ActionReceipt = { ...receipt, signature: '' }
  const ok = verify(canonicalizeJCS(draftForSig), receipt.signature, receipt.signer_did)
  if (!ok) {
    return { valid: false, reason: 'SIGNATURE_INVALID' }
  }

  return { valid: true }
}
