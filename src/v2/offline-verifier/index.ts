// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Offline verifier - public surface
// ══════════════════════════════════════════════════════════════════
// A zero-network APS verify path. It composes the existing crypto-layer
// receipt verifier with the promoted context-layer verifier and emits the
// W2-A1 Evidence Descriptor. No fetch, no DID resolution, no CRL, no
// transparency-log lookup: every input is supplied by the caller, which
// is what makes it air-gappable.
// ══════════════════════════════════════════════════════════════════

// Zero-network verify path.
export {
  verifyOffline,
  type OfflineVerifyOptions,
  type OfflineVerifyResult,
  type OfflineVerifyVerdict,
  type OfflineDescriptorInputs,
} from './verify.js'

// Context-layer verifier (promoted to shippable SDK surface).
export {
  verifyReceiptContext,
  CRYPTO_LAYER_REASONS,
  type RejectReason,
  type ReceiptContext,
  type ContextVerifyResult,
} from './context.js'

// Interim descriptor builder. At W2-A1 merge, this re-exports A1's
// buildEvidenceDescriptor; the EvidenceDescriptor shape is unchanged.
export { buildDescriptor } from './descriptor.js'

// Descriptor interface contract (consumed from W2-A1 at merge).
export type {
  BuildDescriptorInput,
  EvidenceDescriptor,
  SignerClaim,
  WitnessObservationFact,
  CheckedSignature,
  IndependenceRelation,
  SignerNode,
  SignerGraph,
  DescriptorBuilder,
} from './descriptor-interface.js'

// Framework-agnostic relying-party gate. The Express/Fastify adapters in
// examples/aps-relying-party-middleware wrap evaluateRequest/runGate.
export {
  evaluateRequest,
  runGate,
  type GateDecision,
  type GateDenyReason,
  type GateOptions,
  type GateRequestLike,
  type GateResponseLike,
} from './middleware.js'

// Conformance runner (canonicalization vectors). The CLI
// (scripts/aps-conformance.mjs) and the CI workflow wrap it.
export {
  runCanonicalizationConformance,
  checkCanonicalizationVector,
  summarize,
  type ConformanceCheck,
  type ConformanceRunnerResult,
} from './conformance-runner.js'
