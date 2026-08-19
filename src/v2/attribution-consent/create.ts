// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Attribution Consent — construct + sign (citer-side)

import { createHash } from 'node:crypto'
import { sign } from '../../crypto/keys.js'
import { canonicalize, canonicalizeForWrite } from '../../core/canonical.js'
import type { HybridTimestamp } from '../../types/time.js'
import type {
  AgentDID,
  AttributionReceipt,
  ContextID,
  PrincipalDID,
} from './types.js'

/** The canonical unsigned core of a receipt. Both citer and cited principal
 *  sign exactly this payload, and the receipt id is sha256(core). */
type ReceiptCoreInput = AttributionReceipt | Omit<AttributionReceipt,
  'id' | 'citer_signature' | 'cited_principal_signature'>

function receiptCoreImpl(receipt: ReceiptCoreInput, canon: (v: unknown) => string): string {
  return canon({
    version: receipt.version,
    citer: receipt.citer,
    citer_public_key: receipt.citer_public_key,
    cited_principal: receipt.cited_principal,
    cited_principal_public_key: receipt.cited_principal_public_key,
    citation_content: receipt.citation_content,
    binding_context: receipt.binding_context,
    created_at: receipt.created_at,
    expires_at: receipt.expires_at,
  })
}

export function receiptCore(receipt: ReceiptCoreInput): string {
  return receiptCoreImpl(receipt, canonicalize)
}

/** Write-boundary twin of receiptCore().
 *
 *  Shares one implementation body with receiptCore() so the two can never drift apart
 *  on the field list. Emits the same bytes for every value it accepts; the only
 *  difference is that an integer-valued number outside the interoperable IEEE 754
 *  range is refused instead of serialized. Use at signing and new-write boundaries
 *  ONLY: receiptCore() stays unrestricted so an artifact signed before this rule keeps
 *  verifying. */
export function receiptCoreForWrite(receipt: ReceiptCoreInput): string {
  return receiptCoreImpl(receipt, canonicalizeForWrite)
}

export interface CreateAttributionReceiptParams {
  citer: AgentDID
  citer_public_key: string
  citer_private_key: string
  cited_principal: PrincipalDID
  cited_principal_public_key: string
  citation_content: string
  binding_context: ContextID
  created_at: HybridTimestamp
  expires_at: HybridTimestamp
}

/** Build an AttributionReceipt signed by the citer. The cited principal's
 *  consent signature is still absent — verifyAttributionConsent() will
 *  reject this receipt until signAttributionConsent() runs. */
export function createAttributionReceipt(
  params: CreateAttributionReceiptParams,
): AttributionReceipt {
  if (!params.citation_content || typeof params.citation_content !== 'string') {
    throw new Error('createAttributionReceipt: citation_content must be a non-empty string')
  }
  if (!params.binding_context) {
    throw new Error('createAttributionReceipt: binding_context is required')
  }

  const unsigned = {
    version: '1.0' as const,
    citer: params.citer,
    citer_public_key: params.citer_public_key,
    cited_principal: params.cited_principal,
    cited_principal_public_key: params.cited_principal_public_key,
    citation_content: params.citation_content,
    binding_context: params.binding_context,
    created_at: params.created_at,
    expires_at: params.expires_at,
  }

  const core = receiptCoreForWrite(unsigned)
  const id = createHash('sha256').update(core).digest('hex')
  const citer_signature = sign(core, params.citer_private_key)

  return {
    id,
    ...unsigned,
    citer_signature,
  }
}
