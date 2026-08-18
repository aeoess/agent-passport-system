// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// APSBundle — verification
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { isRecord } from '../../../core/is-record.js'
import { verify as edVerifyHex } from '../../../crypto/keys.js'
import type { APSBundle } from '../types/bundle.js'

export type APSBundleVerifyReason =
  | 'INVALID_CLAIM_TYPE'
  | 'INVALID_MERKLE_ROOT'
  | 'INVALID_RECEIPT_COUNT'
  | 'RECEIPT_ID_MISMATCH'
  | 'SIGNATURE_INVALID'

export interface APSBundleVerifyResult {
  valid: boolean
  reason?: APSBundleVerifyReason
}

function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf-8').digest('hex')
}

export function verifyAPSBundle(bundle: APSBundle): APSBundleVerifyResult {
  // Null / undefined / non-object rejects as a wrong claim type rather than
  // throwing on the property access below.
  if (!isRecord(bundle)) {
    return { valid: false, reason: 'INVALID_CLAIM_TYPE' }
  }
  if (bundle.claim_type !== 'aps:bundle:v1') {
    return { valid: false, reason: 'INVALID_CLAIM_TYPE' }
  }
  if (typeof bundle.merkle_root !== 'string' || bundle.merkle_root.length !== 64) {
    return { valid: false, reason: 'INVALID_MERKLE_ROOT' }
  }
  if (!Number.isInteger(bundle.receipt_count) || bundle.receipt_count < 0) {
    return { valid: false, reason: 'INVALID_RECEIPT_COUNT' }
  }

  // explicit null: keeps the shipped preimage bytes (#101); omission would change signatures
  const idCheck = sha256Hex(canonicalizeJCS({ ...bundle, receipt_id: '', signature: null }))
  if (idCheck !== bundle.receipt_id) {
    return { valid: false, reason: 'RECEIPT_ID_MISMATCH' }
  }

  // explicit null: keeps the shipped preimage bytes (#101); omission would change signatures
  const sigPayload = canonicalizeJCS({ ...bundle, signature: null })
  if (!edVerifyHex(sigPayload, bundle.signature, bundle.signer_did)) {
    return { valid: false, reason: 'SIGNATURE_INVALID' }
  }

  return { valid: true }
}
