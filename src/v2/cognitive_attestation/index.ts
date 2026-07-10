// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// cognitive_attestation signal_type (v0.1): public surface
// ══════════════════════════════════════════════════════════════════
// Vocabulary primitive declared at aeoess/agent-governance-vocabulary
// PR #104 (signal_types.cognitive_attestation, status:proposed). This
// module is the AEOESS reference implementation submitted as the first
// of the two implementations CONTRIBUTING.md requires before the
// status can promote.
//
// Scope (v0.1):
//   - Three determinability classes: precondition_set, candidate_set,
//     decision_path.
//   - Envelope construction, JCS canonicalization, Ed25519 signing,
//     signature verification.
//   - Runtime type guard.
//
// Out of scope (v0.2 or deferred per PR #104 notes):
//   - pre_commit_chain class.
//   - (F, Ω, D) structural support in the signed envelope.
//   - Reduction-map syntax.
//   - Truth-of-claim verifier; downstream consumer responsibility.
//   - Privacy posture (selective disclosure, ZK over reductions).
// ══════════════════════════════════════════════════════════════════

export { signCognitiveAttestation, canonicalizeForSignature } from './envelope.js'
export { verifyCognitiveAttestation } from './verify.js'
export {
  isCognitiveAttestation,
  isPreconditionSetPayload,
  isCandidateSetPayload,
  isDecisionPathPayload,
} from './types.js'

export type {
  CognitiveAttestationSignalType,
  CognitiveAttestationClass,
  CognitiveAttestationEnvelope,
  PreconditionSetEnvelope,
  CandidateSetEnvelope,
  DecisionPathEnvelope,
  UnsignedCognitiveAttestationEnvelope,
  UnsignedPreconditionSetEnvelope,
  UnsignedCandidateSetEnvelope,
  UnsignedDecisionPathEnvelope,
  PreconditionSetPayload,
  CandidateSetPayload,
  EvaluatedCandidate,
  DecisionPathPayload,
  CognitiveAttestationVerifyResult,
  CognitiveAttestationVerifyReason,
} from './types.js'
