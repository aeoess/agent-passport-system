// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// APSBundle — construction
// ══════════════════════════════════════════════════════════════════
// merkle_root is computed over receipt_ids sorted lexicographically,
// hashed leaf-wise, then folded pairwise. Odd-length layers duplicate
// the trailing leaf. Empty bundles use sha256('') as the sentinel.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { sign, publicKeyFromPrivate } from '../../../crypto/keys.js'
import type { APSBundle, BundledReceiptRef } from '../types/bundle.js'
import type { ScopeOfClaim } from '../types/base.js'

function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf-8').digest('hex')
}

/** Balanced binary Merkle tree over sorted receipt ids.
 *  Empty input returns sha256('') as the canonical sentinel.
 *  Odd-length layers duplicate the trailing element. */
export function computeMerkleRoot(receiptIds: string[]): string {
  if (receiptIds.length === 0) {
    return sha256Hex('')
  }
  const sorted = [...receiptIds].sort()
  let layer = sorted.map(id => sha256Hex(id))
  while (layer.length > 1) {
    const next: string[] = []
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i]!
      const right = i + 1 < layer.length ? layer[i + 1]! : layer[i]!
      next.push(sha256Hex(left + right))
    }
    layer = next
  }
  return layer[0]!
}

export interface CreateAPSBundleInput {
  bundler_did: string
  period_start: string
  period_end: string
  subject_scope?: string[]
  receipts: BundledReceiptRef[]
  profile_conformance: string[]
  scope_of_claim: ScopeOfClaim
  /** Optional override; defaults to new Date().toISOString(). */
  timestamp?: string
}

export function createAPSBundle(
  input: CreateAPSBundleInput,
  bundlerPrivateKey: string,
): APSBundle {
  const timestamp = input.timestamp ?? new Date().toISOString()
  const signer_did = publicKeyFromPrivate(bundlerPrivateKey)
  const merkle_root = computeMerkleRoot(input.receipts.map(r => r.receipt_id))
  const receipt_count = input.receipts.length

  // Skeleton: receipt_id and signature both empty placeholders. Optional
  // fields (subject_scope) are conditionally spread so the canonical bytes
  // match what JSON.stringify will produce when the fixture is reloaded.
  const skeleton: APSBundle = {
    claim_type: 'aps:bundle:v1',
    receipt_id: '',
    timestamp,
    signer_did,
    scope_of_claim: input.scope_of_claim,
    bundler_did: input.bundler_did,
    period_start: input.period_start,
    period_end: input.period_end,
    ...(input.subject_scope !== undefined ? { subject_scope: input.subject_scope } : {}),
    merkle_root,
    receipt_count,
    profile_conformance: input.profile_conformance,
    signature: '',
  }

  const receipt_id = sha256Hex(canonicalizeJCS({ ...skeleton, signature: undefined }))
  const withId: APSBundle = { ...skeleton, receipt_id }
  const signature = sign(canonicalizeJCS({ ...withId, signature: undefined }), bundlerPrivateKey)

  return { ...withId, signature }
}
