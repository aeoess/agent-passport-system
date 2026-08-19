// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// memory_provenance signal_type (v0.1): envelope helpers
// ══════════════════════════════════════════════════════════════════
// Signs the JCS-canonical form of the envelope with the signature field
// emptied, then attaches the resulting signature. Mirrors the pattern
// used by v2/cognitive_attestation, v2/payment-rails, and
// v2/instruction-provenance: canonical form is the source of truth,
// the wire object is the canonical bytes plus the signature.
//
// Signing key is the ingester_id key, not the source.issuer_id key.
// The envelope attests to a memory commit event by the agent that owns
// the memory, not by the original source issuer.
// ══════════════════════════════════════════════════════════════════

import { canonicalizeJCS, canonicalizeJCSForWrite } from '../../core/canonical-jcs.js'
import { sign, publicKeyFromPrivate } from '../../crypto/keys.js'

import type {
  MemoryProvenanceEnvelope,
  UnsignedMemoryProvenanceEnvelope,
} from './types.js'

/**
 * Canonicalize an envelope for signing. The signature field is set to
 * the empty string before serialization so signing and verification
 * agree on the bytes-under-signature without either side rebuilding the
 * envelope from a partial shape.
 */
export function canonicalizeForSignature(
  envelope: UnsignedMemoryProvenanceEnvelope | MemoryProvenanceEnvelope,
): string {
  const draft = { ...envelope, signature: '' }
  return canonicalizeJCS(draft)
}

/** Write-boundary twin of canonicalizeForSignature().
 *
 *  Emits the same bytes as canonicalizeForSignature() for every value it accepts. The only difference
 *  is that an integer-valued number outside the interoperable IEEE 754 range is
 *  refused instead of serialized. Use at signing and new-write boundaries ONLY:
 *  canonicalizeForSignature() stays unrestricted so an artifact signed before this rule keeps
 *  verifying. */
export function canonicalizeForSignatureForWrite(
  envelope: UnsignedMemoryProvenanceEnvelope | MemoryProvenanceEnvelope,
): string {
  const draft = { ...envelope, signature: '' }
  return canonicalizeJCSForWrite(draft)
}

/**
 * Sign an unsigned envelope with an Ed25519 private key (hex). Derives
 * the public key from the private key and writes it into ingester_id on
 * the returned envelope; this guarantees that the embedded ingester_id
 * matches the signing key, which the verifier checks against.
 *
 * If the caller provides their own ingester_id on the input, this
 * helper still derives the public key from the private key and
 * overwrites the field, because a divergence between the embedded
 * ingester_id and the signing key is always a bug.
 */
export function signMemoryProvenance(
  privateKeyHex: string,
  unsigned: UnsignedMemoryProvenanceEnvelope,
): MemoryProvenanceEnvelope {
  const ingester_id = publicKeyFromPrivate(privateKeyHex)
  const withDerivedKey: UnsignedMemoryProvenanceEnvelope = { ...unsigned, ingester_id }
  const bytes = canonicalizeForSignatureForWrite(withDerivedKey)
  const signature = sign(bytes, privateKeyHex)
  return { ...withDerivedKey, signature }
}
