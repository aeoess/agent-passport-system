// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// memory_provenance signal_type (v0.1): verification
// ══════════════════════════════════════════════════════════════════
// Verifies the Ed25519 signature on a memory_provenance envelope
// against the ingester_id embedded in the envelope. Does NOT verify
// the truth of the memory content, that the source_ref actually
// matches any real source bytes, or that the reduction_map_ref names
// a registered transformation. Those checks belong to downstream
// consumers per the v0.1 scope.
// ══════════════════════════════════════════════════════════════════

import { verify as edVerify } from '../../crypto/keys.js'

import { canonicalizeForSignature } from './envelope.js'
import { isIso8601 } from './types.js'
import type {
  MemoryProvenanceEnvelope,
  MemoryProvenanceVerifyResult,
} from './types.js'

const HEX_KEY = /^[0-9a-f]{64}$/
const HEX_SIGNATURE = /^[0-9a-f]{128}$/
const HEX_DIGEST = /^[0-9a-f]{64}$/

/**
 * Verify the Ed25519 signature on a memory_provenance envelope.
 * Returns `{ valid: true }` only when every shape check passes AND the
 * signature verifies against envelope.ingester_id. A failure carries a
 * reason naming the specific shape or cryptographic failure.
 *
 * Accepts unknown and narrows internally so a malformed input does not
 * throw; returns a structured failure instead. Reason codes are listed
 * in types.ts on MemoryProvenanceVerifyResult.
 *
 * Check order is deliberate: top-level shape and memory_ref first,
 * then ingester_id format, then timestamps, then source structure,
 * then source_ref format, then signature format, then crypto. This
 * matches the order specified for v0.1 reason codes and keeps the
 * shape errors deterministic against malformed inputs.
 */
export function verifyMemoryProvenance(envelope: unknown): MemoryProvenanceVerifyResult {
  if (typeof envelope !== 'object' || envelope === null) {
    return { valid: false, reason: 'SHAPE_INVALID' }
  }
  const e = envelope as Record<string, unknown>

  if (e.signal_type !== 'memory_provenance') {
    return { valid: false, reason: 'SHAPE_INVALID' }
  }
  if (typeof e.memory_ref !== 'string' || !HEX_DIGEST.test(e.memory_ref)) {
    return { valid: false, reason: 'SHAPE_INVALID' }
  }
  if (typeof e.ingester_id !== 'string' || !HEX_KEY.test(e.ingester_id)) {
    return { valid: false, reason: 'INGESTER_ID_INVALID_FORMAT' }
  }
  if (!isIso8601(e.ingested_at)) {
    return { valid: false, reason: 'TIMESTAMP_FORMAT_INVALID' }
  }

  if (typeof e.source !== 'object' || e.source === null) {
    return { valid: false, reason: 'MISSING_SOURCE_FIELDS' }
  }
  const s = e.source as Record<string, unknown>

  if (typeof s.issuer_id !== 'string' || !HEX_KEY.test(s.issuer_id)) {
    return { valid: false, reason: 'MISSING_SOURCE_FIELDS' }
  }
  if (!isIso8601(s.issued_at)) {
    return { valid: false, reason: 'TIMESTAMP_FORMAT_INVALID' }
  }
  if (typeof s.source_ref !== 'string' || !HEX_DIGEST.test(s.source_ref)) {
    return { valid: false, reason: 'SOURCE_HASH_INVALID_FORMAT' }
  }
  if (typeof s.reduction_map_ref !== 'string' || s.reduction_map_ref.length === 0) {
    return { valid: false, reason: 'MISSING_SOURCE_FIELDS' }
  }

  if (typeof e.signature !== 'string' || !HEX_SIGNATURE.test(e.signature)) {
    return { valid: false, reason: 'SIGNATURE_INVALID' }
  }

  const bytes = canonicalizeForSignature(envelope as MemoryProvenanceEnvelope)
  const ok = edVerify(bytes, e.signature, e.ingester_id)
  if (!ok) {
    return { valid: false, reason: 'SIGNATURE_INVALID' }
  }
  return { valid: true }
}
