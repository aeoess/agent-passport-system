// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// cognitive_attestation signal_type (v0.1): envelope helpers
// ══════════════════════════════════════════════════════════════════
// Signs the JCS-canonical form of the envelope with the signature field
// emptied, then attaches the resulting signature. Mirrors the pattern
// used by v2/payment-rails and v2/instruction-provenance: canonical form
// is the source of truth, the wire object is the canonical bytes plus
// signature.
// ══════════════════════════════════════════════════════════════════

import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import { sign, publicKeyFromPrivate } from '../../crypto/keys.js'

import type {
  CognitiveAttestationEnvelope,
  UnsignedCognitiveAttestationEnvelope,
} from './types.js'

/**
 * Canonicalize an envelope for signing. The signature field is set to the
 * empty string before serialization so that signing and verification
 * agree on the bytes-under-signature without either side rebuilding the
 * envelope from a partial shape.
 */
export function canonicalizeForSignature(
  envelope: UnsignedCognitiveAttestationEnvelope | CognitiveAttestationEnvelope,
): string {
  const draft = { ...envelope, signature: '' }
  return canonicalizeJCS(draft)
}

/**
 * Sign an unsigned envelope with an Ed25519 private key (hex). Derives
 * the public key from the private key and writes it into `agent_id` on
 * the returned envelope; this guarantees that the embedded `agent_id`
 * matches the signing key, which the verifier checks against.
 *
 * If the caller provides their own `agent_id` on the input, this helper
 * still derives the public key from the private key and overwrites the
 * field, because a divergence between the embedded agent_id and the
 * signing key is always a bug. Use `publicKeyFromPrivate` upstream if a
 * pre-flight check is needed.
 */
export function signCognitiveAttestation<T extends UnsignedCognitiveAttestationEnvelope>(
  privateKeyHex: string,
  unsigned: T,
): T & { readonly signature: string; readonly agent_id: string } {
  const agent_id = publicKeyFromPrivate(privateKeyHex)
  const withDerivedKey = { ...unsigned, agent_id }
  const bytes = canonicalizeForSignature(withDerivedKey as UnsignedCognitiveAttestationEnvelope)
  const signature = sign(bytes, privateKeyHex)
  return { ...withDerivedKey, signature } as T & { readonly signature: string; readonly agent_id: string }
}
