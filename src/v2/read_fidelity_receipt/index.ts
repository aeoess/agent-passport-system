// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// read_fidelity_receipt (v2): public surface
// ══════════════════════════════════════════════════════════════════
// A signed record of a sampled readback challenge over perceived
// content. It proves sampled readback fidelity at the stated n under
// the declared sampling assumptions; it does not prove every byte was
// read correctly, does not prove perception or comprehension, does
// not prove which channel was used, and carries no normative pass
// threshold. Pure functions: no I/O, no clock, no randomness. See
// README.md for the record shape, the seed derivation, and the
// verification order.
// ══════════════════════════════════════════════════════════════════

export {
  deriveSeed,
  sampleSpans,
  commitSpans,
  scoreResponses,
} from './sampler.js'

export {
  canonicalNoSig,
  createReadFidelityReceipt,
  verifyReadFidelityReceipt,
  verifyAgainstSource,
  verifyResponses,
} from './receipt.js'

export type {
  ReadFidelityReceipt,
  ReadFidelityReceiptType,
  ReadFidelityChallenge,
  ReadFidelitySamplingAlgorithm,
  ReadFidelityScoringMethod,
  ReadFidelityVerificationMethod,
  CreateReadFidelityReceiptInput,
  SampledSpan,
  ScoreResponsesResult,
  ReadFidelityVerifyReason,
  ReadFidelityVerifyResult,
  VerifyAgainstSourceResult,
  VerifyResponsesResult,
} from './types.js'
