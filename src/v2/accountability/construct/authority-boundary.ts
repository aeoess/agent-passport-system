// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// AuthorityBoundaryReceipt — construction
// ══════════════════════════════════════════════════════════════════
// Same id-then-signature ordering as ActionReceipt: receipt_id covers
// the empty-id form, signature covers the populated-id form.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { sign, publicKeyFromPrivate } from '../../../crypto/keys.js'
import type { AuthorityBoundaryReceipt } from '../types/authority-boundary.js'

export type CreateAuthorityBoundaryReceiptInput = Omit<
  AuthorityBoundaryReceipt,
  'receipt_id' | 'signature' | 'signer_did' | 'timestamp' | 'claim_type'
> & {
  /** Optional override; defaults to new Date().toISOString(). */
  timestamp?: string
}

export function createAuthorityBoundaryReceipt(
  input: CreateAuthorityBoundaryReceiptInput,
  evaluatorPrivateKey: string,
): AuthorityBoundaryReceipt {
  const signer_did = publicKeyFromPrivate(evaluatorPrivateKey)
  const timestamp = input.timestamp ?? new Date().toISOString()

  const draft: AuthorityBoundaryReceipt = {
    claim_type: 'aps:authority_boundary:v1',
    receipt_id: '',
    timestamp,
    signer_did,
    scope_of_claim: input.scope_of_claim,
    action_id: input.action_id,
    evaluator_did: input.evaluator_did,
    delegation_chain_root: input.delegation_chain_root,
    result: input.result,
    ...(input.result_detail !== undefined ? { result_detail: input.result_detail } : {}),
    signature: '',
  }

  const receiptIdBytes = canonicalizeJCS(draft)
  const receipt_id = createHash('sha256').update(receiptIdBytes, 'utf8').digest('hex')

  const signed: AuthorityBoundaryReceipt = { ...draft, receipt_id }
  const signatureInput = canonicalizeJCS(signed)
  const signature = sign(signatureInput, evaluatorPrivateKey)

  return { ...signed, signature }
}
