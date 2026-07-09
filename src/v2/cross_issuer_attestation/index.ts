// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// cross_issuer_attestation signal_type (v0.1): public surface
// ══════════════════════════════════════════════════════════════════
// Vocabulary primitive proposed as matrix v2 candidate C-II-4. A
// corresponding vocabulary entry will land as a separate PR to
// agent-governance-vocabulary after the SDK side is reviewed.
//
// Scope (v0.1):
//   - Bundle of references to N constituent attestation envelopes
//     from potentially N different issuers and N different
//     signal_types.
//   - Composer-signed envelope: Ed25519 over JCS-canonical form with
//     the signature field emptied during signing, then attached.
//   - Verify of the composer signature only. Constituent verification
//     is the downstream consumer's responsibility.
//   - Runtime type guard.
//
// Out of scope (v0.2 or deferred):
//   - Verifier-side resolution of constituent envelopes; consumer
//     fetches them out-of-band.
//   - Trust scoring across issuers.
//   - Federation policy (which issuer combinations are allowed).
//   - Cross-protocol composition (AIIF, AP2, x402); separate
//     boundary question.
//   - Composer reputation.
//   - Privacy posture for sensitive bundles.
//   - Bundle-level revocation propagation.
// ══════════════════════════════════════════════════════════════════

export { signCrossIssuerAttestation, canonicalizeForSignature } from './envelope.js'
export { verifyCrossIssuerAttestation } from './verify.js'
export {
  isCrossIssuerAttestation,
  isConstituentReference,
  isIso8601Timestamp,
  COMPOSITION_PURPOSE_MAX_LENGTH,
} from './types.js'

export type {
  CrossIssuerAttestationSignalType,
  CrossIssuerAttestationEnvelope,
  UnsignedCrossIssuerAttestationEnvelope,
  ConstituentReference,
  CrossIssuerAttestationVerifyResult,
  CrossIssuerAttestationVerifyReason,
} from './types.js'
