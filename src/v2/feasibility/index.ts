// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// @aeoess feasibility. proof_ref helpers plus feasibility IR compiler.
// ══════════════════════════════════════════════════════════════════════
//
// Two protocol primitives, both additive and both solver-free:
//
//   1. proof_ref helpers (proof-ref.ts)
//      Name an external soundness proof by content hash on a PolicyReceipt
//      without committing to any cross-system proof format.
//
//   2. feasibility IR compiler (ir.ts + compiler.ts)
//      Compile a policy + delegation envelope into a deterministic IR and an
//      SMT-LIB string. The compiler emits the obligation. Nothing solves it;
//      no solver dependency is introduced this round.
//
// See README.md in this directory for the full proof box.
// ══════════════════════════════════════════════════════════════════════

// proof_ref
export {
  PROOF_REF_ALGORITHM,
  buildProofRef,
  validateProofRef,
  proofRefMatchesArtifact,
  proofRefScopeNote,
} from './proof-ref.js'
export type {
  ProofRef,
  ProofRefHashAlgorithm,
  BuildProofRefParams,
  ProofRefValidationError,
  ProofRefValidationResult,
} from './proof-ref.js'

// feasibility IR
export type {
  FeasibilityIR,
  IRVariable,
  IRConstraint,
  IRConstraintKind,
  IRSort,
} from './ir.js'
export {
  FEASIBILITY_IR_VERSION,
  FEASIBILITY_LOGIC,
  compileFeasibility,
  emitSmtLib,
  compileToSmtLib,
} from './compiler.js'
export type {
  FeasibilityPolicyInput,
  FeasibilityDelegationInput,
  CompileFeasibilityInput,
} from './compiler.js'
