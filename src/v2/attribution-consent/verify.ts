// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Attribution Consent — verify + artifact-citation gate

import { createHash } from 'node:crypto'
import { verify } from '../../crypto/keys.js'
import { bindVerificationMethod } from '../../core/vc-proof.js'
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

/**
 * Bind a named party to the key sitting beside it, or say why it could not be.
 *
 * The receipt names each party twice, as a DID and as a key, and the
 * signatures are checked against the keys the receipt carries. Without this,
 * the principal whose consent is being proved supplies the key that proves it.
 *
 * Uses `bindVerificationMethod` from the credential surfaces and nothing else,
 * including its canonicality round-trip, so one signer cannot hold two
 * identities. A DID that commits to no key cannot be bound without a DID
 * document, and this SDK resolves none here, so it is refused rather than
 * assumed. The `keyAuthority` vocabulary is the one those surfaces already
 * use: `unresolved` for a method that is not self-certifying, `rejected` for
 * one that commits to a different key. Neither is an acceptance.
 */
function bindingFailure(
  party: 'citer' | 'cited_principal',
  did: unknown,
  publicKey: unknown,
): string | null {
  if (typeof publicKey !== 'string' || publicKey.length === 0) {
    return `${party}_public_key missing`
  }
  const binding = bindVerificationMethod(did, did)
  if (binding.keyAuthority !== 'verified') {
    return `${party} binding ${binding.keyAuthority}: ${binding.reason}`
  }
  if (binding.publicKey !== publicKey) {
    return (
      `${party} binding rejected: the DID commits to a different key than the ` +
      `${party}_public_key beside it`
    )
  }
  return null
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

  // Whose key. Each party's DID must commit to the key beside it, before any
  // signature made with that key is allowed to mean anything.
  const citerProblem = bindingFailure('citer', receipt.citer, receipt.citer_public_key)
  if (citerProblem !== null) return fail(citerProblem)
  const citedProblem = bindingFailure(
    'cited_principal', receipt.cited_principal, receipt.cited_principal_public_key,
  )
  if (citedProblem !== null) return fail(citedProblem)

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
