// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// CustodyReceipt — verification
// ══════════════════════════════════════════════════════════════════
// Five failure modes:
//   INVALID_CLAIM_TYPE   — claim_type is not 'aps:custody:v1'
//   INVALID_EVENT_TYPE   — event_type is outside the closed taxonomy
//   INVALID_PURPOSE      — purpose is outside the closed taxonomy
//   RECEIPT_ID_MISMATCH  — receipt_id does not equal sha256(JCS(empty-id form))
//   SIGNATURE_INVALID    — Ed25519 signature does not verify under signer_did
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { verify } from '../../../crypto/keys.js'
import type {
  CustodyReceipt,
  CustodyEventType,
  CustodyPurpose,
} from '../types/custody.js'

export type CustodyReceiptVerifyReason =
  | 'INVALID_CLAIM_TYPE'
  | 'INVALID_EVENT_TYPE'
  | 'INVALID_PURPOSE'
  | 'RECEIPT_ID_MISMATCH'
  | 'SIGNATURE_INVALID'

export interface CustodyReceiptVerifyResult {
  valid: boolean
  reason?: CustodyReceiptVerifyReason
}

const VALID_EVENT_TYPES: readonly CustodyEventType[] = [
  'created',
  'sealed',
  'transferred',
  'disclosed',
  'redacted',
  'erased',
  'expired',
  'verified',
]

const VALID_PURPOSES: readonly CustodyPurpose[] = [
  'internal_audit',
  'regulator_disclosure',
  'subject_access',
  'litigation_discovery',
  'vendor_handoff',
  'archival',
  'incident_response',
]

export function verifyCustodyReceipt(receipt: CustodyReceipt): CustodyReceiptVerifyResult {
  if (receipt.claim_type !== 'aps:custody:v1') {
    return { valid: false, reason: 'INVALID_CLAIM_TYPE' }
  }
  if (!VALID_EVENT_TYPES.includes(receipt.event_type)) {
    return { valid: false, reason: 'INVALID_EVENT_TYPE' }
  }
  if (!VALID_PURPOSES.includes(receipt.purpose)) {
    return { valid: false, reason: 'INVALID_PURPOSE' }
  }

  const draftForId: CustodyReceipt = { ...receipt, receipt_id: '', signature: '' }
  const expectedReceiptId = createHash('sha256')
    .update(canonicalizeJCS(draftForId), 'utf8')
    .digest('hex')
  if (receipt.receipt_id !== expectedReceiptId) {
    return { valid: false, reason: 'RECEIPT_ID_MISMATCH' }
  }

  const draftForSig: CustodyReceipt = { ...receipt, signature: '' }
  const ok = verify(canonicalizeJCS(draftForSig), receipt.signature, receipt.signer_did)
  if (!ok) {
    return { valid: false, reason: 'SIGNATURE_INVALID' }
  }

  return { valid: true }
}
