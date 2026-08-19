// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// cross_issuer_attestation signal_type (v0.1): envelope helpers
// ══════════════════════════════════════════════════════════════════
// Signs the JCS-canonical form of the envelope with the signature
// field emptied, then attaches the resulting signature. Mirrors the
// pattern used by v2/cognitive_attestation and v2/payment-rails: the
// canonical bytes are the source of truth, the wire object is those
// bytes plus the composer signature.
// ══════════════════════════════════════════════════════════════════

import { canonicalizeJCS, canonicalizeJCSForWrite } from '../../core/canonical-jcs.js'
import { sign, publicKeyFromPrivate } from '../../crypto/keys.js'

import type {
  CrossIssuerAttestationEnvelope,
  UnsignedCrossIssuerAttestationEnvelope,
} from './types.js'

/**
 * Canonicalize an envelope for signing. The signature field is set to
 * the empty string before serialization so that signing and
 * verification agree on the bytes-under-signature without either side
 * having to reconstruct the envelope from a partial shape.
 */
export function canonicalizeForSignature(
  envelope: UnsignedCrossIssuerAttestationEnvelope | CrossIssuerAttestationEnvelope,
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
  envelope: UnsignedCrossIssuerAttestationEnvelope | CrossIssuerAttestationEnvelope,
): string {
  const draft = { ...envelope, signature: '' }
  return canonicalizeJCSForWrite(draft)
}

/**
 * Sign an unsigned envelope with the composer's Ed25519 private key
 * (hex). Derives the public key from the private key and writes it
 * into `composer_id` on the returned envelope. This guarantees that
 * the embedded composer_id matches the signing key, which the verifier
 * checks against; divergence between the two is always a bug, so a
 * caller-supplied composer_id is overwritten here. Use
 * `publicKeyFromPrivate` upstream if a pre-flight check is needed.
 */
export function signCrossIssuerAttestation<T extends UnsignedCrossIssuerAttestationEnvelope>(
  privateKeyHex: string,
  unsigned: T,
): T & { readonly signature: string; readonly composer_id: string } {
  const composer_id = publicKeyFromPrivate(privateKeyHex)
  const withDerivedKey = { ...unsigned, composer_id }
  const bytes = canonicalizeForSignatureForWrite(withDerivedKey as UnsignedCrossIssuerAttestationEnvelope)
  const signature = sign(bytes, privateKeyHex)
  return { ...withDerivedKey, signature } as T & { readonly signature: string; readonly composer_id: string }
}
