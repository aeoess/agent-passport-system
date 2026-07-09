// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// behavioral_drift_window signal_type (v0.1): envelope helpers
// ══════════════════════════════════════════════════════════════════
// Signs the JCS-canonical form of the envelope with the signature field
// emptied, then attaches the resulting signature. Mirrors the pattern
// used by v2/cognitive_attestation and v2/payment-rails: canonical form
// is the source of truth, the wire object is the canonical bytes plus
// signature.
//
// The signer is the observer (observer_id). subject_agent_id is the
// agent whose behavior is being summarized and is signature-irrelevant
// from a key-verification standpoint; the verifier checks the signature
// against observer_id. For self-attestation the two coincide.
// ══════════════════════════════════════════════════════════════════

import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import { sign, publicKeyFromPrivate } from '../../crypto/keys.js'

import type {
  BehavioralDriftWindowEnvelope,
  UnsignedBehavioralDriftWindowEnvelope,
} from './types.js'

/**
 * Canonicalize an envelope for signing. The signature field is set to the
 * empty string before serialization so that signing and verification
 * agree on the bytes-under-signature without either side rebuilding the
 * envelope from a partial shape.
 */
export function canonicalizeForSignature(
  envelope: UnsignedBehavioralDriftWindowEnvelope | BehavioralDriftWindowEnvelope,
): string {
  const draft = { ...envelope, signature: '' }
  return canonicalizeJCS(draft)
}

/**
 * Sign an unsigned envelope with the observer's Ed25519 private key
 * (hex). Derives the public key from the private key and writes it into
 * `observer_id` on the returned envelope; this guarantees that the
 * embedded `observer_id` matches the signing key, which the verifier
 * checks against.
 *
 * If the caller provides their own `observer_id` on the input, this
 * helper still derives the public key from the private key and
 * overwrites the field, because a divergence between the embedded
 * observer_id and the signing key is always a bug. The `subject_agent_id`
 * field is passed through unchanged; for self-attestation, the caller
 * sets subject_agent_id to the same value as the derived observer_id.
 */
export function signBehavioralDriftWindow(
  privateKeyHex: string,
  unsigned: UnsignedBehavioralDriftWindowEnvelope,
): BehavioralDriftWindowEnvelope {
  const observer_id = publicKeyFromPrivate(privateKeyHex)
  const withDerivedKey: UnsignedBehavioralDriftWindowEnvelope = { ...unsigned, observer_id }
  const bytes = canonicalizeForSignature(withDerivedKey)
  const signature = sign(bytes, privateKeyHex)
  return { ...withDerivedKey, signature }
}
