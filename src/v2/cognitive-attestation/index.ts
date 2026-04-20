// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Cognitive Attestation — public surface
// ══════════════════════════════════════════════════════════════════
// Paper: "Cognitive Attestation — signed declarations of feature-level
//        model computation for accountable AI"
// Zenodo DOI: 10.5281/zenodo.19646276
// Normative schema: papers/paper-4/poc/schema/cognitive_attestation.schema.json
//
// SDK scope: envelope construction, JCS canonicalization, Ed25519 signing,
//            Stage 1 (cryptographic) verification, Stage 2 (registry)
//            interface, Stage 3 (replay) stub, typed dispute primitives.
//
// Out of scope for the SDK: dispute resolution, re-verification scheduling,
//                           cross-tenant correlation, transparency-log
//                           publishing, bulk compliance reports. All of
//                           those are product intelligence and live in
//                           the private `@aeoess/gateway` module.
// ══════════════════════════════════════════════════════════════════

// Envelope + types
export type {
  CognitiveAttestation,
  ModelRef,
  DictionaryRef,
  TokenRange,
  FeatureActivation,
  AggregationPolicy,
  Signature,
  SignerRole,
  ExecutionEnvironment,
  Precision,
  AttachmentPoint,
  SAEType,
  ActivationStatistic,
  CompletenessClaim,
  TiebreakerRule,
  BuildAttestationInput,
} from './types.js'

export {
  buildAttestation,
  canonicalizeAttestation,
  signAttestation,
  cognitiveAttestationDigest,
  sortFeatureActivations,
  validateAttestationShape,
} from './envelope.js'

// Three-stage verification
export {
  verifySignature,
  verifyRequiredSignerRoles,
  verifyAgainstRegistry,
  verifyByReplay,
} from './verify.js'
export type {
  RequiredRoleCoverage,
  RegistryResolver,
  RegistryVerificationResult,
  ReplayBackend,
  ReplayVerificationResult,
} from './verify.js'

// Typed dispute primitives (no resolution logic)
export type {
  ThresholdDispute,
  ExclusionDispute,
  ComputationalDispute,
  DecompositionAdequacyDispute,
  FacetedReinterpretationDispute,
  InterpretiveDispute,
  Dispute,
} from './disputes.js'
