// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// CPA v0.1: public surface
// ══════════════════════════════════════════════════════════════════
// Context Provenance Attestation: the general partitioned-Merkle
// context-basis commitment. See TREE-SHAPE.md for the frozen tree shape.
// ══════════════════════════════════════════════════════════════════

// Types and the channel constant.
export {
  CHANNEL_ORDER,
  type ContextChannel,
  type DisclosureMode,
  type ContextItem,
  type ContextProfile,
  type CpaPartition,
  type ContextProvenanceAttestation,
  type UnsignedCPA,
  type CpaReasonCode,
  type CpaVerifyResult,
  type InclusionProof,
  type InclusionStep,
} from './types.js'

// Producer + content address + mutual-binding helpers.
export {
  buildCPA,
  computeCpaRef,
  carryCpaRef,
  bindCpaRefToReceipt,
  type BuildCpaInput,
} from './cpa.js'

// Verifier (offline, fail-closed).
export {
  verifyCPA,
  type CpaReceipt,
  type CpaVerifyOptions,
} from './verify.js'

// Merkle helpers and domain-tag constants (needed by tests and tooling).
export {
  LEAF_TAG,
  NODE_TAG,
  SIGN_TAG,
  leafHash,
  nodeHash,
  leafPreimage,
  type LeafPreimage,
  buildPartitionRoot,
  buildPartitionRootBytes,
  buildInclusionProof,
  verifyInclusionProof,
  buildTopRoot,
  buildTopRootBytes,
  emptyTreeRoot,
  bytesToHex,
  hexToBytes,
} from './merkle.js'
