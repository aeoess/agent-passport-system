// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// cross_issuer_attestation signal_type (v0.1): TypeScript types
// ══════════════════════════════════════════════════════════════════
// Vocabulary primitive: signal_types.cross_issuer_attestation (matrix
// v2 candidate C-II-4). A corresponding vocabulary entry will land as a
// separate PR to agent-governance-vocabulary after the SDK side is
// reviewed.
//
// What the primitive composes: references to N independent APS
// attestation envelopes, potentially from N different issuers with N
// different signal_types, into one composer-signed envelope. The
// composition has its own integrity (the composer signature on the set
// of references). The constituent integrities are separate: each
// constituent envelope is signed by its own issuer and the downstream
// consumer verifies each constituent independently against its hash.
//
// What this attests:
//   - The composer (composer_id) committed to this exact bundle of
//     constituent references at composed_at.
//   - Tampering with any constituent reference (changing a hash,
//     swapping an issuer, reordering the array) invalidates the
//     composer signature.
//
// What this does NOT attest:
//   - That the constituent envelopes themselves are valid (downstream
//     consumer responsibility; consumer must verify each constituent).
//   - That the constituent issuers trust each other.
//   - That the composition satisfies any federation policy.
//
// Not cross-protocol composition: that is a separate AIIF boundary
// question. This is cross-issuer composition strictly inside the APS
// attestation envelope family.
// ══════════════════════════════════════════════════════════════════

/**
 * Literal tag for envelope discrimination at the wire level.
 */
export type CrossIssuerAttestationSignalType = 'cross_issuer_attestation'

/**
 * Reference to a single constituent attestation envelope. The hash
 * identifies the constituent bytes; the issuer_id, signal_type, and
 * issued_at fields are convenience metadata copied from the constituent
 * for indexing and quick filtering. The composer signature binds the
 * composer to this exact tuple; tampering with any field invalidates
 * the signature.
 */
export interface ConstituentReference {
  /** sha256 hex (64 lowercase chars) of the JCS-canonical bytes of the constituent envelope. */
  readonly envelope_hash: string
  /** Ed25519 public key of the constituent's original issuer, lowercase hex (64 chars). */
  readonly issuer_id: string
  /** signal_type literal carried by the constituent envelope (e.g. cognitive_attestation, memory_provenance). */
  readonly signal_type: string
  /** ISO 8601 timestamp copied from the constituent envelope at composition time. */
  readonly issued_at: string
}

/**
 * The composed envelope. Signed by composer_id over the JCS-canonical
 * form of the envelope with `signature` emptied to the empty string,
 * then re-attached. The composer is a distinct identity from any
 * constituent issuer; a composer that is also an issuer of a
 * constituent is allowed but not required.
 */
export interface CrossIssuerAttestationEnvelope {
  readonly signal_type: CrossIssuerAttestationSignalType
  /** Ed25519 public key of the composing agent, lowercase hex (64 chars). */
  readonly composer_id: string
  /** ISO 8601 timestamp at which the composer committed to this bundle. */
  readonly composed_at: string
  /** Bundle of constituent references. At least one required; envelope_hash values must be unique. */
  readonly constituents: readonly ConstituentReference[]
  /** Free-form purpose string, length 0 to 280 chars inclusive. */
  readonly composition_purpose: string
  /** Ed25519 signature over JCS-canonical envelope-sans-signature, lowercase hex (128 chars). */
  readonly signature: string
}

/**
 * Unsigned envelope shape: identical to the signed envelope minus the
 * signature field. The signing helper accepts this and returns a fully
 * populated envelope.
 */
export type UnsignedCrossIssuerAttestationEnvelope = Omit<CrossIssuerAttestationEnvelope, 'signature'>

/**
 * Verifier reason codes. Listed in order of evaluation:
 *   - SHAPE_INVALID: top-level structure is missing required fields or
 *     a required field has the wrong primitive type, including signature
 *     format failures.
 *   - COMPOSER_ID_INVALID_FORMAT: composer_id is not 64 lowercase hex chars.
 *   - TIMESTAMP_FORMAT_INVALID: composed_at or any constituent issued_at
 *     does not parse as ISO 8601.
 *   - COMPOSITION_PURPOSE_TOO_LONG: composition_purpose > 280 chars.
 *   - CONSTITUENTS_EMPTY: constituents array is empty.
 *   - CONSTITUENT_SHAPE_INVALID: a constituent has wrong field types or
 *     malformed envelope_hash, issuer_id, or signal_type.
 *   - CONSTITUENT_HASH_DUPLICATE: two constituents share the same envelope_hash.
 *   - SIGNATURE_INVALID: Ed25519 verification failed against composer_id.
 */
export type CrossIssuerAttestationVerifyReason =
  | 'SHAPE_INVALID'
  | 'COMPOSER_ID_INVALID_FORMAT'
  | 'TIMESTAMP_FORMAT_INVALID'
  | 'COMPOSITION_PURPOSE_TOO_LONG'
  | 'CONSTITUENTS_EMPTY'
  | 'CONSTITUENT_SHAPE_INVALID'
  | 'CONSTITUENT_HASH_DUPLICATE'
  | 'SIGNATURE_INVALID'

export interface CrossIssuerAttestationVerifyResult {
  readonly valid: boolean
  readonly reason?: CrossIssuerAttestationVerifyReason
}

const HEX_PUBKEY = /^[0-9a-f]{64}$/
const HEX_SIGNATURE = /^[0-9a-f]{128}$/
const HEX_DIGEST = /^[0-9a-f]{64}$/
const ISO_8601 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/

/** Maximum length of composition_purpose, in characters. */
export const COMPOSITION_PURPOSE_MAX_LENGTH = 280

/**
 * Returns true when `value` is a syntactically valid ISO 8601 timestamp
 * of the form YYYY-MM-DDTHH:MM:SS(.fff)?(Z|±HH:MM). The check is both
 * regex-strict and Date.parse-finite, so partial or near-miss forms
 * accepted by lax parsers are rejected here.
 */
export function isIso8601Timestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false
  if (!ISO_8601.test(value)) return false
  const parsed = Date.parse(value)
  return Number.isFinite(parsed)
}

/**
 * Runtime type guard. Returns true when `value` is structurally a
 * signed cross_issuer_attestation envelope. Does NOT verify the
 * signature; use `verifyCrossIssuerAttestation` for that. Length and
 * format invariants checked:
 *   - signal_type literal matches.
 *   - composer_id, signature are lowercase hex of the expected length.
 *   - composed_at parses as ISO 8601.
 *   - composition_purpose is a string of length ≤ 280.
 *   - constituents is a non-empty array; each entry has a 64-hex
 *     envelope_hash, 64-hex issuer_id, non-empty signal_type string,
 *     and ISO 8601 issued_at.
 *   - envelope_hash values are unique across constituents.
 */
export function isCrossIssuerAttestation(
  value: unknown,
): value is CrossIssuerAttestationEnvelope {
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  if (v.signal_type !== 'cross_issuer_attestation') return false
  if (typeof v.composer_id !== 'string' || !HEX_PUBKEY.test(v.composer_id)) return false
  if (typeof v.signature !== 'string' || !HEX_SIGNATURE.test(v.signature)) return false
  if (!isIso8601Timestamp(v.composed_at)) return false
  if (typeof v.composition_purpose !== 'string') return false
  if (v.composition_purpose.length > COMPOSITION_PURPOSE_MAX_LENGTH) return false
  if (!Array.isArray(v.constituents) || v.constituents.length === 0) return false
  const seenHashes = new Set<string>()
  for (const item of v.constituents) {
    if (!isConstituentReference(item)) return false
    if (seenHashes.has(item.envelope_hash)) return false
    seenHashes.add(item.envelope_hash)
  }
  return true
}

/**
 * Runtime shape check for a single constituent reference. The
 * envelope_hash and issuer_id are 64-hex lowercase; signal_type is a
 * non-empty string; issued_at is ISO 8601.
 */
export function isConstituentReference(value: unknown): value is ConstituentReference {
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  if (typeof v.envelope_hash !== 'string' || !HEX_DIGEST.test(v.envelope_hash)) return false
  if (typeof v.issuer_id !== 'string' || !HEX_PUBKEY.test(v.issuer_id)) return false
  if (typeof v.signal_type !== 'string' || v.signal_type.length === 0) return false
  if (!isIso8601Timestamp(v.issued_at)) return false
  return true
}

export { HEX_PUBKEY, HEX_SIGNATURE, HEX_DIGEST, ISO_8601 }
