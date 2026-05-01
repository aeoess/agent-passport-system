// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// APSBundle — signed aggregation envelope over a set of receipts
// ══════════════════════════════════════════════════════════════════
// Spec: specs/full-accountability-mvp.md
// A bundler signs a Merkle-rooted commitment over a batch of receipt
// ids in a closed time window. Survives cryptographic erasure of the
// underlying content: merkle_root and receipt_count remain verifiable
// even when the leaves are destroyed.
// ══════════════════════════════════════════════════════════════════

import type { AccountabilityReceiptBase } from './base.js'

export interface APSBundle extends AccountabilityReceiptBase {
  claim_type: 'aps:bundle:v1'
  bundler_did: string
  /** ISO 8601 UTC ms + Z, inclusive. */
  period_start: string
  /** ISO 8601 UTC ms + Z, exclusive. */
  period_end: string
  /** Optional list of subject DIDs covered. */
  subject_scope?: string[]
  /** sha256 hex of balanced binary tree over sorted receipt_ids. */
  merkle_root: string
  /** Exact count of bundled receipts. */
  receipt_count: number
  /** e.g. ['aps:profile/mva-v1']. */
  profile_conformance: string[]
}

/** Lightweight reference for tree construction. */
export interface BundledReceiptRef {
  receipt_id: string
  claim_type: string
}
