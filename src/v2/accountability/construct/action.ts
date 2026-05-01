// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// ActionReceipt — construction
// ══════════════════════════════════════════════════════════════════
// receipt_id is the sha256 hex of JCS(receipt with empty receipt_id and
// empty signature). signature is Ed25519 over JCS(receipt with computed
// receipt_id and empty signature) — i.e. the signature covers the
// receipt_id, so any post-signing receipt_id tampering breaks the sig.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { sign, publicKeyFromPrivate } from '../../../crypto/keys.js'
import type { ActionReceipt } from '../types/action.js'

export type CreateActionReceiptInput = Omit<
  ActionReceipt,
  'receipt_id' | 'signature' | 'signer_did' | 'timestamp' | 'claim_type'
> & {
  /** Optional override; defaults to new Date().toISOString(). */
  timestamp?: string
}

export function createActionReceipt(
  input: CreateActionReceiptInput,
  signerPrivateKey: string,
): ActionReceipt {
  const signer_did = publicKeyFromPrivate(signerPrivateKey)
  const timestamp = input.timestamp ?? new Date().toISOString()

  // Pre-signature draft: receipt_id and signature both empty.
  const draft: ActionReceipt = {
    claim_type: 'aps:action:v1',
    receipt_id: '',
    timestamp,
    signer_did,
    scope_of_claim: input.scope_of_claim,
    agent_did: input.agent_did,
    delegation_chain_root: input.delegation_chain_root,
    ...(input.intent_ref !== undefined ? { intent_ref: input.intent_ref } : {}),
    ...(input.policy_ref !== undefined ? { policy_ref: input.policy_ref } : {}),
    action: input.action,
    side_effect_classes: input.side_effect_classes,
    ...(input.transparency_log_inclusion !== undefined
      ? { transparency_log_inclusion: input.transparency_log_inclusion }
      : {}),
    ...(input.rfc3161_timestamp !== undefined
      ? { rfc3161_timestamp: input.rfc3161_timestamp }
      : {}),
    signature: '',
  }

  // receipt_id = sha256(JCS(draft with empty receipt_id and empty signature))
  const receiptIdBytes = canonicalizeJCS(draft)
  const receipt_id = createHash('sha256').update(receiptIdBytes, 'utf8').digest('hex')

  // signature = Ed25519(JCS(draft with computed receipt_id and empty signature))
  const signed: ActionReceipt = { ...draft, receipt_id }
  const signatureInput = canonicalizeJCS(signed)
  const signature = sign(signatureInput, signerPrivateKey)

  return { ...signed, signature }
}
