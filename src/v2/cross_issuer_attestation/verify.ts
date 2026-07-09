// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// cross_issuer_attestation signal_type (v0.1): verification
// ══════════════════════════════════════════════════════════════════
// Verifies the composer's Ed25519 signature on a cross_issuer
// attestation envelope against composer_id. Does NOT verify the
// constituent envelopes themselves; the downstream consumer fetches
// each constituent by hash and verifies it separately. This module
// only checks that the composer committed to the exact bundle of
// references named in `constituents` at `composed_at`.
// ══════════════════════════════════════════════════════════════════

import { verify as edVerify } from '../../crypto/keys.js'

import { canonicalizeForSignature } from './envelope.js'
import {
  COMPOSITION_PURPOSE_MAX_LENGTH,
  HEX_PUBKEY,
  HEX_SIGNATURE,
  HEX_DIGEST,
  isConstituentReference,
  isIso8601Timestamp,
} from './types.js'
import type {
  CrossIssuerAttestationEnvelope,
  CrossIssuerAttestationVerifyResult,
} from './types.js'

/**
 * Verify the composer's Ed25519 signature on an envelope. Returns
 * `{ valid: true }` only when every shape and format check passes AND
 * the signature verifies against `envelope.composer_id`. A failure
 * carries a `reason` naming the specific failure mode; reason codes
 * are listed on `CrossIssuerAttestationVerifyReason` in types.ts.
 *
 * The function accepts `unknown` and narrows internally, so a
 * malformed input does not throw; it returns a structured failure
 * instead. Evaluation order is: top-level shape, composer_id format,
 * timestamp formats, purpose length, constituents non-empty,
 * per-constituent shape, hash uniqueness, then signature.
 */
export function verifyCrossIssuerAttestation(
  envelope: unknown,
): CrossIssuerAttestationVerifyResult {
  if (typeof envelope !== 'object' || envelope === null) {
    return { valid: false, reason: 'SHAPE_INVALID' }
  }
  const e = envelope as Record<string, unknown>

  if (e.signal_type !== 'cross_issuer_attestation') {
    return { valid: false, reason: 'SHAPE_INVALID' }
  }
  if (typeof e.composer_id !== 'string') {
    return { valid: false, reason: 'SHAPE_INVALID' }
  }
  if (!HEX_PUBKEY.test(e.composer_id)) {
    return { valid: false, reason: 'COMPOSER_ID_INVALID_FORMAT' }
  }
  if (typeof e.signature !== 'string' || !HEX_SIGNATURE.test(e.signature)) {
    return { valid: false, reason: 'SHAPE_INVALID' }
  }
  if (typeof e.composed_at !== 'string') {
    return { valid: false, reason: 'SHAPE_INVALID' }
  }
  if (!isIso8601Timestamp(e.composed_at)) {
    return { valid: false, reason: 'TIMESTAMP_FORMAT_INVALID' }
  }
  if (typeof e.composition_purpose !== 'string') {
    return { valid: false, reason: 'SHAPE_INVALID' }
  }
  if (e.composition_purpose.length > COMPOSITION_PURPOSE_MAX_LENGTH) {
    return { valid: false, reason: 'COMPOSITION_PURPOSE_TOO_LONG' }
  }
  if (!Array.isArray(e.constituents)) {
    return { valid: false, reason: 'SHAPE_INVALID' }
  }
  if (e.constituents.length === 0) {
    return { valid: false, reason: 'CONSTITUENTS_EMPTY' }
  }

  const seenHashes = new Set<string>()
  for (const item of e.constituents) {
    // Distinguish a timestamp-only failure from other shape failures
    // so the verifier can surface a precise reason code.
    if (typeof item === 'object' && item !== null) {
      const c = item as Record<string, unknown>
      if (
        typeof c.envelope_hash === 'string' && HEX_DIGEST.test(c.envelope_hash) &&
        typeof c.issuer_id === 'string' && HEX_PUBKEY.test(c.issuer_id) &&
        typeof c.signal_type === 'string' && c.signal_type.length > 0 &&
        typeof c.issued_at === 'string' && !isIso8601Timestamp(c.issued_at)
      ) {
        return { valid: false, reason: 'TIMESTAMP_FORMAT_INVALID' }
      }
    }
    if (!isConstituentReference(item)) {
      return { valid: false, reason: 'CONSTITUENT_SHAPE_INVALID' }
    }
    if (seenHashes.has(item.envelope_hash)) {
      return { valid: false, reason: 'CONSTITUENT_HASH_DUPLICATE' }
    }
    seenHashes.add(item.envelope_hash)
  }

  const bytes = canonicalizeForSignature(envelope as CrossIssuerAttestationEnvelope)
  const ok = edVerify(bytes, e.signature, e.composer_id)
  if (!ok) {
    return { valid: false, reason: 'SIGNATURE_INVALID' }
  }
  return { valid: true }
}
