// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Weights — type surface (Build B)
// ══════════════════════════════════════════════════════════════════
// Spec: BUILD-B-FRACTIONAL-WEIGHTS.md. These types feed the D and C
// axes of the Build A primitive; computed weights are emitted as
// DataAxisEntry[] / ComputeAxisEntry[] so constructAttributionPrimitive
// consumes them without format translation.
// ══════════════════════════════════════════════════════════════════

import type { DataAxisEntry, ComputeAxisEntry } from '../attribution-primitive/types.js'

/** The four roles from the Build B spec (§ "Role weight"). Locked for v0.1
 *  per the spec's Open Questions — custom roles open in v0.2. */
export type AttributionRole =
  | 'primary_source'
  | 'supporting_evidence'
  | 'context_only'
  | 'background_retrieval'

export const ATTRIBUTION_ROLES: ReadonlyArray<AttributionRole> = [
  'primary_source',
  'supporting_evidence',
  'context_only',
  'background_retrieval',
]

/** Per-source record that feeds computeDataAxisWeights. One entry per
 *  AccessReceipt pulled into the action's context. */
export interface AccessReceiptWithRole {
  /** DID of the registered data source. Surfaced through to the emitted
   *  DataAxisEntry.source_did. */
  source_did: string
  /** Hex sha256 of the underlying AccessReceipt. Passed through to the
   *  emitted DataAxisEntry.access_receipt_hash unchanged. */
  access_receipt_hash: string
  /** How the source was used. See AttributionRole. */
  role: AttributionRole
  /** ISO-8601 UTC with millisecond precision + Z. When the source content
   *  was produced (the spec's t_source). Used for recency decay. */
  timestamp: string
  /** Content length in tokens. Non-negative integer. The spec's len(). */
  content_length: number
}

/** Per-provider record that feeds computeComputeAxisWeights. */
export interface InferenceBillingRecord {
  /** DID of the compute provider. Surfaced through to the emitted
   *  ComputeAxisEntry.provider_did. */
  provider_did: string
  /** Hex sha256 of the hardware attestation. Passed through unchanged. */
  hardware_attestation_hash: string
  /** Prompt (input) tokens computed by this provider for this action. */
  prompt_tokens: number
  /** Completion (output) tokens computed by this provider for this action. */
  completion_tokens: number
}

/** Tunable parameters for the weight formulas. Defaults live in
 *  DEFAULT_WEIGHT_PROFILE. Profile-hash binding (I-B6) means two issuers
 *  with different profiles produce incompatible receipts. */
export interface WeightProfile {
  /** Monotonically increasing version string. Included in the hash so a
   *  re-tuned profile is distinct from the prior version even if every
   *  numeric parameter is the same. */
  version: string
  role_weights: {
    primary_source: number
    supporting_evidence: number
    context_only: number
    background_retrieval: number
  }
  recency: {
    /** Floor on the decay factor. A source older than several half-lives
     *  still contributes at least this much. */
    min_recency: number
    /** Decay rate. ln(2) ≈ 0.693 gives a half-life of τ days. */
    lambda: number
    /** Decay time constant in days. */
    tau_days: number
  }
  length: {
    /** Reference length (tokens) at which content_length_weight = 1.0. */
    reference_length: number
  }
  compute: {
    /** How many input tokens an output token costs. 3.0 reflects current
     *  provider economics; versioned with the profile. */
    completion_multiplier: number
  }
}

/** Options for computeDataAxisWeights. Action-level parameters that apply
 *  to the whole vector, not per-source. */
export interface ComputeDataAxisOptions {
  /** ISO-8601 UTC ms when the action ran (the spec's t_action). Required
   *  for recency decay. */
  action_timestamp: string
  /** Override the default profile. */
  profile?: WeightProfile
}

/** Options for computeComputeAxisWeights. */
export interface ComputeComputeAxisOptions {
  /** Override the default profile. */
  profile?: WeightProfile
}

/** Result of validateWeightProfile. */
export interface ValidationResult {
  valid: boolean
  errors: string[]
}

/** Re-exported from Build A for convenience so callers don't need two
 *  imports. The functions in this module emit these exact shapes. */
export type { DataAxisEntry, ComputeAxisEntry }
