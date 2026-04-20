// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Cognitive Attestation — TypeScript types mirroring the normative schema
// ══════════════════════════════════════════════════════════════════
// Source of truth: papers/paper-4/poc/schema/cognitive_attestation.schema.json
// Paper: "Cognitive Attestation" — Zenodo DOI 10.5281/zenodo.19646276
//
// Every nullable field in the JSON schema is expressed as `T | null` here so
// that JCS canonicalization preserves null (RFC 8785 requirement, and the
// cross-language compatibility contract with the Python reference impl).
// ══════════════════════════════════════════════════════════════════

export type Precision = 'fp32' | 'fp16' | 'bf16' | 'int8'

export type AttachmentPoint = 'residual_stream' | 'attention_output' | 'mlp_output'

export type SAEType = 'standard' | 'topk' | 'jumprelu' | 'gated' | 'batchtopk'

export type ActivationStatistic = 'max' | 'mean' | 'sum' | 'integral' | 'last'

export type CompletenessClaim = 'top_k_only' | 'all_above_threshold' | 'dictionary_exhaustive'

export type TiebreakerRule = 'lowest_feature_id' | 'highest_feature_id'

export type SignerRole = 'agent' | 'operator' | 'provider' | 'third_party_attester'

export interface ExecutionEnvironment {
  /** e.g. `nvidia/hopper/h100-sxm5` or `apple-silicon/m-series/m3-max` */
  hardware_family: string
  precision: Precision
  /** `library@version` format, e.g. `vllm@0.6.3`. */
  inference_engine: string
  deterministic_mode: boolean
}

export interface ModelRef {
  model_id: string
  /** sha256 hex, 64 lowercase chars. */
  model_version_hash: string
  /** sha256 hex, 64 lowercase chars. */
  tokenizer_version_hash: string
  inference_provider: string | null
  execution_environment: ExecutionEnvironment
}

export interface DictionaryRef {
  dictionary_id: string
  /** sha256 hex, 64 lowercase chars. */
  dictionary_version_hash: string
  /** sha256 hex, 64 lowercase chars, or null. */
  training_corpus_hash: string | null
  layer_index: number
  attachment_point: AttachmentPoint
  sae_type: SAEType
}

export interface TokenRange {
  /** sha256 of uint32-big-endian token IDs from BOS through end-of-range, no separators. */
  absolute_sequence_hash: string
  /** sha256 of tokens preceding the attested range, or null. NOT a KV-cache hash. */
  prior_state_hash: string | null
  start_token_index: number
  end_token_index: number
  token_count: number
}

export interface FeatureActivation {
  feature_id: number
  feature_label: string | null
  activation_statistic: ActivationStatistic
  activation_value: number
  tokens_active: number
}

/**
 * Aggregation policy. Note: `attestation_epsilon` and `required_signer_roles`
 * are REQUIRED per the normative schema. The Python reference's smoke test
 * omitted them — this TS type makes that omission a compile error.
 */
export interface AggregationPolicy {
  top_k: number | null
  threshold: number | null
  /** Governance-relevant "effectively zero" threshold. Must be > 0. */
  attestation_epsilon: number
  /** sha256 hex of the allowlist, or null. */
  feature_allowlist_hash: string | null
  completeness_claim: CompletenessClaim
  tiebreaker_rule: TiebreakerRule
  /** At least one role. Verifiers MUST confirm every listed role is signed by someone. */
  required_signer_roles: SignerRole[]
}

export interface Signature {
  signer_did: string
  signer_role: SignerRole
  /** base64-encoded Ed25519 signature over JCS-canonicalized payload with signatures=[] elided. */
  signature: string
}

export interface CognitiveAttestation {
  spec_version: '1.0'
  model_ref: ModelRef
  dictionary_ref: DictionaryRef
  token_range: TokenRange
  feature_activations: FeatureActivation[]
  aggregation_policy: AggregationPolicy
  signatures: Signature[]
  /** ISO 8601 UTC timestamp. */
  attestation_timestamp: string
}

/** Input to `buildAttestation`. Flat shape matches the Python reference. */
export interface BuildAttestationInput {
  // model_ref
  model_id: string
  model_version_hash: string
  tokenizer_version_hash: string
  inference_provider: string | null
  hardware_family: string
  precision: Precision
  inference_engine: string
  deterministic_mode: boolean
  // dictionary_ref
  dictionary_id: string
  dictionary_version_hash: string
  training_corpus_hash: string | null
  layer_index: number
  attachment_point: AttachmentPoint
  sae_type: SAEType
  // token_range
  absolute_sequence_hash: string
  prior_state_hash: string | null
  start_token_index: number
  end_token_index: number
  token_count: number
  // aggregation
  feature_activations: FeatureActivation[]
  aggregation_policy: AggregationPolicy
  /** Override for deterministic fixtures. Defaults to `new Date().toISOString()`. */
  timestamp?: string
}
