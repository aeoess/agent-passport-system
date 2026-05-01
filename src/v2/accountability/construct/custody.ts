// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// CustodyReceipt — construction
// ══════════════════════════════════════════════════════════════════
// receipt_id is sha256 hex of JCS(receipt with empty receipt_id and
// empty signature). signature is Ed25519 over JCS(receipt with computed
// receipt_id and empty signature) — i.e. the signature covers the
// receipt_id, so any post-signing receipt_id tampering breaks the sig.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { sign, publicKeyFromPrivate } from '../../../crypto/keys.js'
import type { CustodyReceipt } from '../types/custody.js'

export type CreateCustodyReceiptInput = Omit<
  CustodyReceipt,
  'receipt_id' | 'signature' | 'signer_did' | 'timestamp' | 'claim_type'
> & {
  /** Optional override; defaults to new Date().toISOString(). */
  timestamp?: string
}

export function createCustodyReceipt(
  input: CreateCustodyReceiptInput,
  custodianPrivateKey: string,
): CustodyReceipt {
  const signer_did = publicKeyFromPrivate(custodianPrivateKey)
  const timestamp = input.timestamp ?? new Date().toISOString()

  const draft: CustodyReceipt = {
    claim_type: 'aps:custody:v1',
    receipt_id: '',
    timestamp,
    signer_did,
    scope_of_claim: input.scope_of_claim,
    custodian_did: input.custodian_did,
    event_type: input.event_type,
    subject_receipt_batch: input.subject_receipt_batch,
    ...(input.previous_custody_id !== undefined
      ? { previous_custody_id: input.previous_custody_id }
      : {}),
    ...(input.next_custodian_did !== undefined
      ? { next_custodian_did: input.next_custodian_did }
      : {}),
    purpose: input.purpose,
    signature: '',
  }

  const receipt_id = createHash('sha256')
    .update(canonicalizeJCS(draft), 'utf8')
    .digest('hex')

  const signed: CustodyReceipt = { ...draft, receipt_id }
  const signature = sign(canonicalizeJCS(signed), custodianPrivateKey)

  return { ...signed, signature }
}
