// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Attribution Consent — verify + artifact-citation gate

import { createHash } from 'node:crypto'
import { verify } from '../../crypto/keys.js'
import { compareTimestamps, createHybridTimestamp } from '../../core/time.js'
import { receiptCore } from './create.js'
import type {
  AttributionConsentResult,
  AttributionReceipt,
  CitingArtifact,
} from './types.js'

function fail(reason: string): AttributionConsentResult {
  return { valid: false, reason }
}

/** Verify an AttributionReceipt end-to-end:
 *   - id matches the canonical core hash
 *   - citer_signature verifies against citer_public_key
 *   - cited_principal_signature present and verifies against cited_principal_public_key
 *   - receipt not expired (wall-clock comparison)
 *   - created_at is not after expires_at
 *
 *  The optional `now` HybridTimestamp lets callers pin the evaluation
 *  moment (tests, replayed audits). Defaults to a freshly issued stamp
 *  on a synthetic 'verifier' gateway. */
export function verifyAttributionConsent(
  receipt: AttributionReceipt,
  now?: { wallClockEarliest: number; wallClockLatest: number; logicalTime: number; gatewayId: string },
): AttributionConsentResult {
  const core = receiptCore(receipt)
  const expectedId = createHash('sha256').update(core).digest('hex')
  if (expectedId !== receipt.id) return fail('receipt id does not match canonical core — tampered')

  try {
    if (!verify(core, receipt.citer_signature, receipt.citer_public_key)) {
      return fail('citer signature invalid')
    }
  } catch {
    return fail('citer signature invalid')
  }

  if (!receipt.cited_principal_signature) return fail('no consent signature')

  try {
    if (!verify(core, receipt.cited_principal_signature, receipt.cited_principal_public_key)) {
      return fail('cited principal consent signature invalid')
    }
  } catch {
    return fail('cited principal consent signature invalid')
  }

  // Bounds sanity: expires_at must not precede created_at.
  const createdVsExpires = compareTimestamps(receipt.created_at, receipt.expires_at)
  if (createdVsExpires === 'definitely_after') {
    return fail('expires_at precedes created_at')
  }

  const current = now ?? createHybridTimestamp('attribution-verifier')
  // Expired when the earliest possible 'now' is definitively after the
  // latest possible expiry — conservative bound.
  if (current.wallClockEarliest > receipt.expires_at.wallClockLatest) {
    return fail('expired')
  }
  // Not-yet-valid: created strictly in the future of the latest 'now'.
  if (current.wallClockLatest < receipt.created_at.wallClockEarliest) {
    return fail('not yet valid')
  }

  return { valid: true }
}

/** Gate an artifact's citations. Each artifact.citations[] entry must
 *  have a matching receipt (by id) whose content + principal match the
 *  referenced citation, which verifies end-to-end, and whose
 *  binding_context matches the artifact's binding context id.
 *
 *  Replay protection: a single receipt id may appear at most once in
 *  artifact.citations — reusing a receipt for two different citation
 *  slots is rejected. */
export function checkArtifactCitations(
  artifact: CitingArtifact,
  receipts: AttributionReceipt[],
  opts?: { binding_context?: string; now?: Parameters<typeof verifyAttributionConsent>[1] },
): AttributionConsentResult {
  const citations = artifact.citations ?? []
  if (citations.length === 0) return { valid: true }

  const byId = new Map<string, AttributionReceipt>()
  for (const r of receipts) byId.set(r.id, r)

  const seen = new Set<string>()
  for (const c of citations) {
    if (seen.has(c.receipt_id)) {
      return fail(`replay: receipt ${c.receipt_id} cited more than once in this artifact`)
    }
    seen.add(c.receipt_id)

    const r = byId.get(c.receipt_id)
    if (!r) return fail(`no receipt provided for citation ${c.receipt_id}`)

    if (r.citation_content !== c.citation_content) {
      return fail(`citation content mismatch for receipt ${c.receipt_id}`)
    }
    if (r.cited_principal !== c.cited_principal) {
      return fail(`cited principal mismatch for receipt ${c.receipt_id}`)
    }
    if (opts?.binding_context && r.binding_context !== opts.binding_context) {
      return fail(`receipt ${c.receipt_id} is scoped to a different binding context`)
    }

    const v = verifyAttributionConsent(r, opts?.now)
    if (!v.valid) return fail(`receipt ${c.receipt_id} invalid: ${v.reason}`)
  }

  return { valid: true }
}
