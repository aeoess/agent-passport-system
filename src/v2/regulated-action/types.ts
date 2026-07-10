// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// APS Regulated Action Profile v0. Principle: Reconciled Action Attestation.
//
// Public primitive. Profile types per RAPV0-FROZEN-CONTRACT.md section A. A regulated
// action (class rank >= 3) reaches finality only when a pre-committed intent reconciles
// against two anchors OUTSIDE the operator trust domain: the IdP authority (EMA/ID-JAG)
// and the resource system of record. The verifier counts trust DOMAINS, not signatures.
//
// This module ships the receipt shape, the VerificationContext, and the disposition
// vocabulary. The deterministic verifier is in ./verify.ts. Product intelligence
// (reconciliation engine, chokepoint, BAN, transparency service, completeness layer)
// is NOT here; it is the private gateway. judgment_correctness is always not_claimed.

export const REGULATED_ACTION_PROFILE = 'aps-regulated-action-v0' as const

// Rank map. action_class is SET BY GATEWAY POLICY, never the agent. Compare via this
// map, never enum order. Rank >= 3 is "regulated" for the finality gate.
export const ACTION_CLASS_RANK = {
  read: 0,
  internal_write: 1,
  external_message: 2,
  financial_movement: 3,
  regulated_decision: 4,
  irreversible_action: 5,
} as const
export type ActionClass = keyof typeof ACTION_CLASS_RANK

// Domain-separation tags. Each signature signs a canonical subobject prefixed by its tag,
// never the whole mutable receipt.
export const RAPV0_TAG = {
  actor: 'APS-RAPV0-ACTOR',
  intent: 'APS-RAPV0-INTENT',
  policy: 'APS-RAPV0-POLICY',
  resource: 'APS-RAPV0-RESOURCE-CONFIRMATION',
  authority: 'APS-RAPV0-AUTHORITY',
  lifecycle: 'APS-RAPV0-LIFECYCLE',
} as const

export interface SignatureBlock {
  alg: string
  key_id: string
  sig: string
}

// EXTERNAL domain #1. authority_ref is a SINGLE scalar anchor in v0 (no array, no reserved
// multi-anchor fields; a future profile version adds any multi-anchor shape). The verifier
// validates assertion_sig against the VerificationContext IdP keyset, never a live fetch.
export interface AuthorityRef {
  type: 'id_jag' | 'ema'
  issuer: string
  subject: string
  audience: string
  scope_hash: string
  issued_at: string
  expires_at: string
  assertion_hash: string
  jti: string
  // The IdP signature over the canonical authority assertion. Section A lists the authority
  // fields but not this inline signature; section B's authority_ok requires "the authority_ref
  // signature validates vs the IdP keyset", so the implementation carries it here. This is the
  // single anchor's own signature, not multi-anchor widening (item 3). See HANDOFF DEVIATIONS.
  assertion_sig: string
}

// OPERATOR domain. intent_hash = canonical digest over {action_class, scope,
// authority_ref.assertion_hash, decision_basis_commitment.root_hash, expected_effect_hash}.
export interface IntentCommitment {
  created_before_execution: true
  intent_hash: string
  expected_effect_hash: string
  gateway_nonce: string
  timestamp_ms: number
  scope: string
  signature: string
}

// FIXED enum subset. The type system makes raw chain-of-thought UNREPRESENTABLE:
// leaves_schema is constrained to this union and raw_chain_of_thought_included is the
// literal false. There is no field that can carry raw reasoning text.
export type DecisionBasisLeaf =
  | 'input_artifact_hashes'
  | 'policy_version_hash'
  | 'tool_call_refs'
  | 'risk_flags'
  | 'approval_state'
  | 'model_runtime_context_summary_hash'
  | 'uncertainty_band'
  | 'resource_correlation_ref'

export interface DecisionBasisCommitment {
  root_hash: string
  leaves_schema: DecisionBasisLeaf[]
  raw_chain_of_thought_included: false
}

export interface GatewayPolicyDecision {
  policy_version_hash: string
  decision: 'allow' | 'deny' | 'hold'
  action_class_assigned: ActionClass
  signer: string
  signature: string
}

export type ResourceConfirmationType =
  | 'native_resource_signed'
  | 'boundary_attested'
  | 'boundary_attested_weak'
  | 'channel_authenticated'
  | 'manual_reconciliation'
  | 'missing'

export type RealizedEffectProvenance = 'ban_derived' | 'echoed'

// EXTERNAL domain #2 iff the BAN independence contract holds. realized_effect_hash MUST be
// BAN-derived from the resource's committed transaction record; an echoed provenance fails
// independence. The signing key's REGISTRATION must be outside operator control.
export interface ResourceConfirmationRef {
  type: ResourceConfirmationType
  resource_transaction_id: string
  correlation_id: string
  gateway_nonce_echo: string
  realized_effect_hash: string
  realized_effect_provenance: RealizedEffectProvenance
  status: string
  timestamp_ms: number
  signer_key_id: string
  signature: string
}

export interface TransparencyRef {
  type: 'scitt' | 'enterprise_merkle_log'
  log_id: string
  inclusion_proof: InclusionStep[]
  anchored_at_state: string
  tree_size: number
  leaf_hash: string
}

export interface InclusionStep {
  dir: 'L' | 'R'
  hash: string
}

export interface RegulatedActionReceiptV0 {
  profile: typeof REGULATED_ACTION_PROFILE
  receipt_id: string
  action_class: ActionClass
  actor_signature: SignatureBlock
  aps_delegation_ref?: string
  authority_ref?: AuthorityRef
  intent_commitment?: IntentCommitment
  decision_basis_commitment?: DecisionBasisCommitment
  gateway_policy_decision?: GatewayPolicyDecision
  resource_confirmation_ref?: ResourceConfirmationRef
  transparency_ref?: TransparencyRef
  // trust_domain_map and verifier_disposition are COMPUTED by the verifier, never trusted
  // from the receipt, so they are not fields on the input receipt type.
}

// ── VerificationContext: everything the pure verifier needs, supplied by the caller. ──
// The verifier does NOT fetch the network, read the wall clock, or hold replay state.
export interface RegisteredResourceKey {
  publicKey: string
  // true if this key was registered into the trust store by the operator/gateway. A
  // gateway-registered key is NOT independent and cannot establish external domain #2.
  registered_by_operator: boolean
}

export interface VerificationContext {
  // EXTERNAL IdP keyset (issuer -> ed25519 public key hex), the IdP historical/transparency
  // keyset, never an operator-anchored copy.
  idp_keyset: Record<string, string>
  // Optional operator-anchored copy of an IdP key (issuer -> pubkey). Validating only against
  // this yields authority_weak_basis, NOT an external domain (per D2).
  operator_anchored_idp_copy?: Record<string, string>
  // Resource confirmation keys (signer_key_id -> {publicKey, registered_by_operator}).
  registered_resource_keys: Record<string, RegisteredResourceKey>
  // Operator-domain keys (key_id -> {publicKey, identity}) for actor/intent/policy signatures.
  // crypto_ok uses publicKey; separation_ok requires every operator key to map to the ONE
  // registered operator identity (operator_identity_id).
  operator_domain_registry: Record<string, { publicKey: string; identity: string }>
  operator_identity_id: string
  // key_id the gateway used to sign intent_commitment when no policy decision is present
  // (intent_commitment carries no inline key_id in the frozen shape). When a policy decision
  // is present, intent is verified against gateway_policy_decision.signer.
  gateway_key_id?: string
  // Transparency log roots (log_id -> root hash) for inclusion-proof verification.
  registered_log_roots: Record<string, string>
  // RESERVED, NOT applied by the v0 verifier. Temporal ordering is a caller-supplied boolean
  // (anchor_orders_intent_before_resource) and authority freshness uses exact compares
  // (issued_at <= reserved_ts, expires_at >= submitted_ts), so v0 applies no skew tolerance.
  // Kept for forward compatibility; a future profile version may apply it. Optional.
  allowed_clock_skew_ms?: number
  // Anchor and submission timestamps supplied by the caller (no clock read here).
  reserved_ts: number
  submitted_ts: number
  max_authority_execution_window_ms: number
  // Per-class required field names for the regulator_grade_for_class tier.
  per_class_required_fields?: Partial<Record<ActionClass, string[]>>
  // Completeness layer (private gateway) shows a matching resource event for this
  // correlation_id. Used only for the `executed` predicate; default false.
  completeness_match?: boolean
  // True if the anchored intent precedes the resource event in log/state ordering. The
  // caller (gateway) supplies the ordering result; the verifier never reads a clock for it.
  anchor_orders_intent_before_resource?: boolean
  // Non-equivocation status of the transparency log. Defaults to anchor_present (the frozen
  // "noneq_ok = anchor_present" equivalence). Modeled as a distinct input so the regulator_grade
  // noneq_ok conjunct is non-vacuous; set false to model a log that admits equivocation.
  non_equivocation_ok?: boolean
}

// ── Disposition vocabulary ──
export type Disposition =
  | 'void'
  | 'void_policy_violation'
  | 'void_temporal_violation'
  | 'void_reconciliation_mismatch'
  | 'resource_unbound'
  | 'authority_invalid'
  | 'self_attested'
  | 'regulator_grade_for_class'
  | 'reconciled'
  | 'intent_precommitted'
  | 'authority_bound'
  | 'incomplete_for_class'

export type IncompleteReason =
  | 'policy_denied_no_execution'
  | 'missing_authority'
  | 'missing_transparency_anchor'
  | 'execution_unconfirmed'

export type AuthorityBasis = 'external_idp' | 'operator_anchored_copy_weak'

export interface TrustDomainSeparation {
  computed_domains: number
  idp_counts: boolean
  resource_counts: boolean
  operator_identity: string
  separation_ok: boolean
}

export interface RegulatedVerifyResult {
  profile: typeof REGULATED_ACTION_PROFILE
  disposition: Disposition
  incomplete_reason?: IncompleteReason
  // Every terminal condition (guards 1-7) that held, most-dangerous-first; first match wins
  // for `disposition` but every signal is recorded here so a second alarm is never hidden.
  violations: Disposition[]
  missing_evidence: string[]
  trust_domain_separation: TrustDomainSeparation
  authority_basis?: AuthorityBasis
  // Replay/jti/nonce uniqueness is computed by the PRIVATE gateway, never the public
  // verifier. Always not_evaluated here.
  authority_replay: 'not_evaluated' | 'pass' | 'fail'
  // The single locked claim: we never certify the correctness of a discretionary judgment.
  judgment_correctness: 'not_claimed'
}
