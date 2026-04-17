// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Settlement — type surface (Build C)
// ══════════════════════════════════════════════════════════════════
// Spec: BUILD-C-SETTLEMENT-PIPELINE.md. Four signed SettlementAxisIndex
// objects compose into one SettlementRecord per settlement period. No
// payment semantics — this is evidence, not money. The gateway's economic
// conversion (weight → currency) is out of scope.
// ══════════════════════════════════════════════════════════════════

import type { AttributionAxisTag } from '../attribution-primitive/types.js'

/** Half-open settlement period. `t0` is inclusive, `t1` is exclusive.
 *  I-C5 / property test #7: receipt timestamped exactly at `t0` is
 *  included; receipt at `t1` is excluded. Both are canonical ISO-8601 UTC
 *  with millisecond precision and trailing Z. */
export interface SettlementPeriod {
  t0: string
  t1: string
  /** Gateway-scoped identifier. Two records from the same gateway MUST NOT
   *  share a `period_id` (I-C1). Opaque to verifiers. */
  period_id: string
}

/** Per-contributor aggregate on a single axis. `merkle_leaf_hash` is
 *  sha256(canonicalize({contributor_did, total_weight, contribution_count}))
 *  as lowercase hex — the leaf that participates in `axis_merkle_root`. */
export interface SettlementContributor {
  contributor_did: string
  /** Sum of this contributor's weights across every receipt in the period.
   *  Canonical 6-digit decimal string. Fractional part can exceed 1.0 —
   *  the per-axis total equals total_actions, not 1.0. */
  total_weight: string
  /** Number of input AttributionPrimitives in which this contributor
   *  appears on this axis (I-C3). */
  contribution_count: number
  /** Hex sha256 of the canonicalized leaf body. Included for fast lookup;
   *  verifiers MUST recompute from the leaf body, not trust this value. */
  merkle_leaf_hash: string
}

/** Residual-bucket aggregate on an axis (§4.1 / I-C6). Pooled contributors
 *  are committed via a merkle_root over the pooled list so individual
 *  pooled members can prove inclusion at settlement time without the axis
 *  enumerating them. */
export interface SettlementResidualBucket {
  residual_id: 'residual:D' | 'residual:P' | 'residual:C'
  /** Sum of pooled pre-threshold weights across the period. Canonical
   *  6-digit decimal string. */
  total_pooled_weight: string
  count_of_pooled_contributors: number
  /** Hex sha256 Merkle commitment over the pooled list (I-C6) —
   *  lex-sorted by DID. */
  pooled_contributors_hash: string
}

/** One axis worth of settlement data. Balanced binary Merkle tree over
 *  contributor leaves (plus residual leaf, if any) → `axis_merkle_root`.
 *  Contributors are lex-sorted by DID so the tree is deterministic. */
export interface SettlementAxisIndex {
  axis: AttributionAxisTag
  period: SettlementPeriod
  /** Count of input receipts that contributed to this axis (may be < the
   *  SettlementRecord.total_input_count when some axes are empty per
   *  receipt). */
  total_actions: number
  contributors: SettlementContributor[]
  residual_bucket: SettlementResidualBucket | null
  /** Root of the balanced binary Merkle tree over contributor leaves
   *  (plus the residual-bucket leaf if non-null). Empty-axis convention:
   *  sha256 of the empty-list canonicalization (I-C5). */
  axis_merkle_root: string
}

/** Top-level settlement record §"The settlement record". Signed by the
 *  gateway over canonicalize(record minus signature). */
export interface SettlementRecord {
  schema: 'aps.settlement.v1'
  period: SettlementPeriod
  gateway_did: string
  axes: {
    D: SettlementAxisIndex
    P: SettlementAxisIndex
    G: SettlementAxisIndex
    C: SettlementAxisIndex
  }
  /** Hex sha256 Merkle commitment over the sorted action_ref list of the
   *  input primitives — verifiers can challenge the gateway to reveal the
   *  input set and recompute (S5). */
  input_receipts_hash: string
  total_input_count: number
  issued_at: string
  signature: string
}

/** Per-axis body returned by the contributor-query endpoint. Only the
 *  axes where the contributor has a share are populated. */
export interface ContributorQueryAxisBody {
  total_weight: string
  contribution_count: number
  /** Merkle path to prove inclusion of the contributor's leaf in
   *  `axis_root`. Root-to-leaf order NOT required — the verifier walks
   *  the path using the leaf index bitmap, which is carried implicitly
   *  by a `leaf_index` field so a verifier can reconstruct balanced-tree
   *  pairing. */
  leaf_index: number
  merkle_path: string[]
  axis_root: string
}

/** §"The contributor query" response. A contributor can verify this
 *  without trusting the gateway beyond the JWKS signature check.
 *
 *  Judgment call (spec §"The contributor query" is ambiguous): we embed
 *  the full signed SettlementRecord so the verifier can (a) check the
 *  gateway signature end-to-end without a second round trip and (b) see
 *  that the axis_roots used in per_axis paths are the same ones the
 *  signature binds. Spec v0.1 only shows `settlement_record_hash` — we
 *  include both for forward compatibility. */
export interface ContributorQueryResponse {
  settlement_record: SettlementRecord
  settlement_record_hash: string
  contributor_did: string
  per_axis: {
    D?: ContributorQueryAxisBody
    P?: ContributorQueryAxisBody
    G?: ContributorQueryAxisBody
    C?: ContributorQueryAxisBody
  }
  /** Advisory URL. Verifiers SHOULD use their own out-of-band JWKS; this
   *  is purely informational and not part of the signed material. */
  gateway_jwks?: string
}

/** Standard reason codes for settlement verification failures. Callers
 *  branch on these — do not compare against strings from other modules. */
export type SettlementVerifyReason =
  | 'MALFORMED'
  | 'SIGNATURE_INVALID'
  | 'MERKLE_ROOT_MISMATCH'
  | 'CONSERVATION_VIOLATION'
  | 'RESIDUAL_BUCKET_MISMATCH'
  | 'INPUT_RECEIPTS_HASH_MISMATCH'
  | 'RECEIPT_OUT_OF_PERIOD'
  | 'RECEIPT_SIGNATURE_INVALID'
  | 'PERIOD_MALFORMED'

export type SettlementVerifyResult =
  | { valid: true }
  | { valid: false; reason: SettlementVerifyReason; detail?: string }
