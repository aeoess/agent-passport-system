// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Primitive — type surface for the unified four-axis receipt
// ══════════════════════════════════════════════════════════════════
// Spec: ATTRIBUTION-PRIMITIVE-v1.1.md. One signed object per action with
// four axis projections (D, P, G, C). Each projection verifies independently;
// any two projections cross-verify by shared action_ref + merkle_root +
// signature. See §1.2, §2.2, §2.3.
//
// NAMING: The type is AttributionPrimitive (not AttributionReceipt) because
// src/v2/attribution-consent already owns that name for a different primitive.
// ══════════════════════════════════════════════════════════════════

/** Four axis discriminators from §1.2. */
export type AttributionAxisTag = 'D' | 'P' | 'G' | 'C'

/** A single data-source contribution. §1.2 (D). */
export interface DataAxisEntry {
  /** DID of the registered data source whose content influenced the output. */
  source_did: string
  /** Fractional attribution weight in [0, 1]. Decimal string, 6 digits after
   *  the decimal point, no scientific notation. Spec §2.5 "Numeric representation". */
  contribution_weight: string
  /** Hex sha256 of the underlying AccessReceipt this contribution composes over. */
  access_receipt_hash: string
}

/** A single protocol-module evaluation entry. §1.2 (P). */
export interface ProtocolAxisEntry {
  module_id: string
  module_version: string
  evaluation_outcome: string
  evaluation_receipt_hash: string
  /** Optional post-decay weight surfaced for axis P when value-audit decay
   *  is applied by the issuer. §4.2 "Integration with the primitive". Decimal
   *  string, 6 digits after the decimal point. */
  weight?: string
}

/** A single delegation-chain hop. §1.2 (G). Ordered root-to-leaf by depth. */
export interface GovernanceAxisEntry {
  delegation_id: string
  signer_did: string
  scope_hash: string
  /** 0 = root principal, increasing monotonically toward the acting agent. */
  depth: number
}

/** A single compute-provider entry. §1.2 (C). */
export interface ComputeAxisEntry {
  provider_did: string
  /** Fractional compute share in [0, 1]. Decimal string, 6-digit precision. */
  compute_share: string
  hardware_attestation_hash: string
}

/** Pooled sub-threshold contributors per §4.1. A residual bucket occupies
 *  one slot in its axis and participates in distribution as a single entity.
 *  The pooled_contributors_hash is a Merkle commitment over the pooled list
 *  so individual pooled contributors can prove inclusion without the axis
 *  content enumerating them. */
export interface ResidualBucket {
  /** Axis-scoped identifier: "residual:D" | "residual:P" | "residual:C".
   *  Governance axis is not pooled; see spec §4.1 / §1.2. */
  residual_id: 'residual:D' | 'residual:P' | 'residual:C'
  /** Sum of pre-threshold weights for the pooled contributors. Decimal string. */
  total_pooled_weight: string
  count_of_pooled_contributors: number
  /** Hex sha256 Merkle root over the lexicographically-sorted pooled list. */
  pooled_contributors_hash: string
}

/** Entry on a poolable axis (D, P, C): either an explicit contributor or the
 *  residual bucket. Only one residual bucket is permitted per axis. */
export type DataAxisItem = DataAxisEntry | ResidualBucket
export type ProtocolAxisItem = ProtocolAxisEntry | ResidualBucket
export type ComputeAxisItem = ComputeAxisEntry | ResidualBucket

/** The four-axis tuple from §1.2. Governance is ordered, not sorted. */
export interface AttributionAxes {
  D: DataAxisItem[]
  P: ProtocolAxisItem[]
  G: GovernanceAxisEntry[]
  C: ComputeAxisItem[]
}

/** The unified primitive. §1.2 tuple form. */
export interface AttributionPrimitive {
  /** Hex sha256. Derived from canonical(action tuple). §1.2. */
  action_ref: string
  /** Full axis content. Projections omit three of the four. */
  axes: AttributionAxes
  /** Hex sha256 of the four-leaf balanced Merkle tree. §2.1. */
  merkle_root: string
  /** Issuer DID (gateway or agent). */
  issuer: string
  /** ISO-8601 UTC, millisecond precision, trailing Z. §2.5. */
  timestamp: string
  /** Ed25519 hex signature over canonical(envelope). §2.3. */
  signature: string
}

/** Action identity tuple used to derive action_ref. Kept as an object so the
 *  canonicalizer walks it unambiguously and satisfies A1 (injectivity) by
 *  construction. §1.2 mixes two notations for action_ref; we adopt the
 *  canonical-tuple form from Theorem 1 in §3.4 because it is provably
 *  injective under the APS schema, not reliant on string concatenation
 *  being self-delimiting. */
export interface AttributionAction {
  agentId: string
  actionType: string
  /** Action parameters. Opaque JSON — canonicalizer handles sorting. */
  params: Record<string, unknown>
  /** Anti-replay nonce. Production callers should use a UUID or similar. */
  nonce: string
}

/** A single-axis projection. §2.2. */
export interface AttributionProjection {
  action_ref: string
  axis_tag: AttributionAxisTag
  /** The axis content for this projection's axis. Typed loosely because
   *  callers dispatch on axis_tag. */
  axis_data: unknown
  /** Two sibling hashes reconstructing the root via §2.3's tag-dispatch.
   *  [sibling_leaf_within_pair, sibling_internal_node]. */
  merkle_path: [string, string]
  merkle_root: string
  issuer: string
  timestamp: string
  signature: string
}

/** Outcome of verify_projection. §2.6. */
export type AttributionVerifyResult =
  | { valid: true }
  | {
      valid: false
      reason:
        | 'INVALID_AXIS_TAG'
        | 'MERKLE_MISMATCH'
        | 'SIGNATURE_INVALID'
        | 'MALFORMED'
    }

/** Outcome of check_same_receipt. §2.4. */
export type AttributionConsistencyResult =
  | { same_receipt: true }
  | {
      same_receipt: false
      reason:
        | 'DIFFERENT_ACTIONS'
        | 'DIFFERENT_RECEIPTS'
        | 'DIFFERENT_SIGNATURES'
        | 'METADATA_MISMATCH'
    }

/** Canonical envelope that Ed25519 signs. §2.3. Exposed so downstream
 *  tooling (verifiers, test vectors, audit pipelines) can reproduce the
 *  exact bytes without reimplementing field selection. */
export interface AttributionEnvelope {
  action_ref: string
  merkle_root: string
  issuer: string
  timestamp: string
}
