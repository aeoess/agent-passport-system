// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// memory_provenance signal_type (v0.1): public surface
// ══════════════════════════════════════════════════════════════════
// Matrix v2 candidate C-II-2 (Memory provenance attestation envelope).
// OWASP ASI06 (memory and context poisoning) names a signed provenance
// envelope as the missing primitive that traces each memory entry back
// to a trusted source under a declared transformation. MINJA (95%+
// attack success in published research) and MemoryGraft motivate the
// envelope.
//
// Scope (v0.1):
//   - Envelope shape: signal_type, memory_ref, source sub-object,
//     ingester_id, ingested_at, signature.
//   - JCS canonicalization, Ed25519 signing, signature verification.
//   - Runtime type guard.
//
// Out of scope (v0.2 or deferred):
//   - Verifying source content against source_ref. Consumer carries it.
//   - Verifying that reduction_map_ref names a registered transformation.
//   - Poisoning detection across multiple memory entries.
//   - Cross-tenant memory correlation.
//   - Aggregate memory analytics.
//   - Memory lifecycle (expiry, eviction, re-ingestion).
//   - Privacy posture for sensitive memory contents.
//   - Full (F, Omega, D) reduction-map carrying in the envelope.
// ══════════════════════════════════════════════════════════════════

export { signMemoryProvenance, canonicalizeForSignature } from './envelope.js'
export { verifyMemoryProvenance } from './verify.js'
export {
  isMemoryProvenance,
  isMemoryProvenanceSource,
  isIso8601,
} from './types.js'

export type {
  MemoryProvenanceSignalType,
  MemoryProvenanceSource,
  MemoryProvenanceEnvelope,
  UnsignedMemoryProvenanceEnvelope,
  MemoryProvenanceVerifyResult,
  MemoryProvenanceVerifyReason,
} from './types.js'
