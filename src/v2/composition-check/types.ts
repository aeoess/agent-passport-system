// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// APS Composition Check Receipt v0. Principle: carry the ANCHOR, not the verdict.
//
// A chain of individually rule-legal delegations can compose to a globally-unsafe
// target that per-hop monotonic narrowing cannot detect. DETECTION of such hazards
// is product intelligence and lives in the PRIVATE gateway. This module ships ONLY
// the public carrier: a signed receipt an external attestor produces to say "I ran
// these named policy profiles over this exact (chain, action, context) and these were
// the per-check results", plus a stateless verifier that checks the ANCHOR (signature,
// binding, freshness, well-formedness, attestor trust) and SURFACES independence.
//
// The SDK has NO policy grammar, NO evaluator, NO ontology of what "unsafe" means, and
// emits NO aggregate "safe" boolean. A per-check result of "pass" means only "the named
// attestor reported pass for the named profile over the bound context", never "globally
// safe". policy_profile_ids and checks_run are OPAQUE identifiers; the SDK never
// interprets them beyond string identity.
//
// Mirrors RAP-v0's resource_confirmation_ref: the gateway/attestor PRODUCES, the SDK
// VERIFIES the signature. Independence is corroborated from the trust context, never
// the receipt's self-declaration, exactly as RAP gates its strong claim on domains>=2.

export const COMPOSITION_CHECK_PROFILE = 'aps-composition-check-v0' as const

// Domain-separation tag. The single signature signs `${TAG}.${JCS(receipt-without-signature)}`.
export const COMPOSITION_CHECK_TAG = 'APS-COMPCHECK-V0' as const

// SMALL FIXED ENUM. There is deliberately no 'safe'/'unsafe' member: a per-check result
// is the attestor's finding for one named check, never a global verdict.
export type CompositionCheckResult = 'pass' | 'fail' | 'indeterminate' | 'not_checked'
export const COMPOSITION_CHECK_RESULTS: readonly CompositionCheckResult[] = [
  'pass',
  'fail',
  'indeterminate',
  'not_checked',
] as const

// Independence of the attestor's trust domain.
//   gateway_self           operator-signed, ONE trust domain, WEAK.
//   independent_registered key registered outside the operator's reach, a genuine SECOND
//                          anchor, STRONG, but ONLY when the trust context confirms the
//                          registration. A self-declared 'independent_registered' the
//                          context does not back is NOT treated as a second anchor.
export type AttestorIndependenceClass = 'gateway_self' | 'independent_registered'
export const ATTESTOR_INDEPENDENCE_CLASSES: readonly AttestorIndependenceClass[] = [
  'gateway_self',
  'independent_registered',
] as const

export interface CompositionCheckReceipt {
  profile: typeof COMPOSITION_CHECK_PROFILE
  receipt_id: string
  // Bind the receipt to the EXACT delegation chain / action / context it covers.
  chain_hash: string
  action_ref: string
  context_hash: string
  // OPAQUE identifiers (with versions) of the policy profiles checked and the checks run,
  // e.g. "sanctions-routing-v3". NOT policy contents, NOT a grammar. The SDK never
  // interprets these beyond string identity.
  policy_profile_ids: string[]
  checks_run: string[]
  // One result per check, from the fixed enum, positionally aligned with checks_run.
  // There is NO aggregate result and no "safe" field.
  result_per_check: CompositionCheckResult[]
  attestor_key_id: string
  attestor_independence_class: AttestorIndependenceClass
  issued_at: string   // ISO 8601
  expires_at: string  // ISO 8601
  // ed25519 over `${COMPOSITION_CHECK_TAG}.${JCS(receipt-without-signature)}`.
  signature: string
}

// Trust-store entry for an attestor key, supplied by the caller. registered_by_operator
// === false is what makes an 'independent_registered' attestation a genuine second anchor.
export interface RegisteredAttestorKey {
  publicKey: string
  registered_by_operator: boolean
  // The OPAQUE policy_profile_ids this attestor is recognized to attest. The verifier
  // requires every profile in the receipt to be covered here (string identity only).
  profiles: string[]
}

// Everything the pure verifier needs, supplied by the caller. The verifier reads no clock
// and does no network: now_ms and the expected bindings are inputs.
export interface CompositionCheckVerificationContext {
  // attestor_key_id -> trust entry. A key absent here cannot be trusted and its signature
  // cannot be checked (no public key available).
  trusted_attestors: Record<string, RegisteredAttestorKey>
  // The (chain, action, context) the CALLER is asking about. The receipt must bind to these.
  expected_chain_hash: string
  expected_action_ref: string
  expected_context_hash: string
  // Verification time in epoch ms, supplied by the caller (the verifier reads no clock).
  now_ms: number
}

export interface CompositionCheckVerifyResult {
  profile: typeof COMPOSITION_CHECK_PROFILE
  // The signed reference is authentic (signature valid under a trusted attestor key),
  // bound to the expected (chain, action, context), fresh, well-formed, and from an
  // attestor trusted for the named profiles. This is an ANCHOR verdict, NOT a
  // composition-safety verdict. There is deliberately no 'safe' field: downstream decides
  // whether the named profiles plus the independence class are sufficient for its risk.
  anchor_verified: boolean
  // Every anchor check that FAILED (e.g. 'signature', 'chain_binding', 'expired',
  // 'result_enum', 'attestor_not_trusted'). Empty iff anchor_verified.
  violations: string[]
  // Surfaced facts (echoed from the receipt) so downstream can decide sufficiency. These
  // are reported, never aggregated into a verdict.
  policy_profile_ids: string[]
  checks_run: string[]
  result_per_check: CompositionCheckResult[]
  attestor_key_id: string
  // The class AS CLAIMED in the receipt.
  attestor_independence_class: AttestorIndependenceClass
  // CORROBORATED against the trust context AND gated on anchor_verified: true ONLY when the
  // receipt anchor-verifies AND claims 'independent_registered' AND the context registers the
  // key as registered_by_operator === false. gateway_self is always false (one trust domain,
  // weak); a self-declared strong class the context does not back is false; and an
  // independent attestor whose receipt fails the anchor (expired, tampered, mis-bound) is
  // false too, so a consumer reading this flag alone is never misled. Downgraded, never
  // upgraded. Mirrors RAP gating its strong claim on domains>=2. The raw claimed class is
  // still available in attestor_independence_class.
  independence_is_second_anchor: boolean
  issued_at: string
  expires_at: string
}
