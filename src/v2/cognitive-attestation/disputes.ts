// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Cognitive Attestation — dispute primitives (typed shapes only)
// ══════════════════════════════════════════════════════════════════
// Paper: "Cognitive Attestation" — Zenodo DOI 10.5281/zenodo.19646276, §5
//
// The SDK ships the dispute VOCABULARY, not the workflow. Dispute
// submission, resolution, scheduling, rate-limiting, and governance
// annotations are product intelligence and live in the private gateway.
// ══════════════════════════════════════════════════════════════════

// ──────────────────────────────────────────────────────────────────
// Computational disputes — resolved by replay (Stage 3).
// ──────────────────────────────────────────────────────────────────

/**
 * The envelope claimed a feature activation that differs from replay by
 * more than `epsilon_applied`.
 */
export interface ThresholdDispute {
  kind: 'threshold'
  feature_id: number
  attested_value: number
  claimed_value: number
  delta: number
  epsilon_applied: number
}

/**
 * A feature active in replay was not present in the envelope's reported
 * activations. Reason distinguishes the aggregation-policy mechanism that
 * excluded it.
 */
export interface ExclusionDispute {
  kind: 'exclusion'
  feature_id: number
  claimed_activation: number
  reason: 'missing_from_top_k' | 'below_threshold' | 'allowlist_violation'
}

export type ComputationalDispute = ThresholdDispute | ExclusionDispute

// ──────────────────────────────────────────────────────────────────
// Interpretive disputes — governance annotations, no replay applies.
// ──────────────────────────────────────────────────────────────────

/**
 * Claim that the dictionary's feature decomposition is inadequate to
 * describe the attested behavior. Resolved by governance, not math.
 */
export interface DecompositionAdequacyDispute {
  kind: 'decomposition_adequacy'
  claim: string
  /** IPFS CIDs, Zenodo DOIs, gateway artifact IDs, etc. SDK does not interpret. */
  evidence_refs: string[]
  annotator_did: string
}

/**
 * Claim that a feature's conventional label misrepresents the concept it
 * detects in the attested context. Resolved by governance annotation.
 */
export interface FacetedReinterpretationDispute {
  kind: 'faceted_reinterpretation'
  feature_id: number
  original_label: string | null
  proposed_reinterpretation: string
  evidence_refs: string[]
  annotator_did: string
}

export type InterpretiveDispute =
  | DecompositionAdequacyDispute
  | FacetedReinterpretationDispute

export type Dispute = ComputationalDispute | InterpretiveDispute
