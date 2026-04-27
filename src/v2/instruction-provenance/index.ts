// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// InstructionProvenanceReceipt — public barrel
// ══════════════════════════════════════════════════════════════════
// Spec: ~/aeoess_web/specs/INSTRUCTION-PROVENANCE-RECEIPT-DRAFT-v0.2.md
// Tier scope this version: 'self-asserted' only.
// ══════════════════════════════════════════════════════════════════

export { createInstructionProvenanceReceipt, IPRConstructionError, signEd25519 } from './envelope.js'
export { verifyInstructionProvenanceReceipt, verifyActionTimeContextRoot, matchesAnyPattern } from './verify.js'
export {
  IPRPathError,
  canonicalizePath,
  canonicalizeEnvelope,
  computeContextRoot,
  sortInstructionFiles,
  sha256Hex,
} from './canonicalize.js'

export type {
  AttestationTier,
  FilesystemMode,
  InstructionRole,
  InstructionFile,
  InstructionProvenanceReceipt,
  InstructionProvenanceReceiptBoundTo,
  CanonicalizationResult,
  VerificationResult,
  CreateIPRInput,
  VerifyIPRInput,
  ActionTimeContextRootInput,
} from './types.js'
