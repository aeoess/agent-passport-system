// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// memory_provenance signal_type (v0.1): TypeScript types
// ══════════════════════════════════════════════════════════════════
// Substrate for matrix v2 candidate C-II-2 (Memory provenance
// attestation envelope). OWASP ASI06 names a signed provenance envelope
// for memory entries as a missing primitive; MINJA and MemoryGraft
// research motivate it.
//
// What the primitive attests: where a memory entry came from, when it
// was ingested, and under which transformation. It does NOT detect
// poisoning. The truth of the memory content and the integrity of the
// reduction_map_ref are downstream consumer responsibilities.
//
// source_ref is the sha256 hex of the ORIGINAL source content before
// transformation. memory_ref is the sha256 hex of the memory entry
// AFTER transformation. reduction_map_ref names the transformation that
// was applied; future versions will carry a full (F, Omega, D) reduction
// map structure in this slot.
// ══════════════════════════════════════════════════════════════════

/**
 * Literal tag for envelope discrimination at the wire level.
 */
export type MemoryProvenanceSignalType = 'memory_provenance'

/**
 * The source sub-object inside a memory_provenance envelope. Identifies
 * who issued the original source content, when it was issued, the hash
 * of the source bytes (pre-transformation), and a reference to the
 * transformation spec that was applied before storing in memory.
 *
 * Invariants:
 *   - issuer_id is Ed25519 public key as 64 lowercase hex chars.
 *   - issued_at is an ISO 8601 timestamp string.
 *   - source_ref is sha256 hex (64 lowercase chars) of the original
 *     source content bytes.
 *   - reduction_map_ref is a non-empty string identifier or URL
 *     pointing at the transformation spec. v0.1 does not constrain its
 *     syntax; v0.2 will likely tighten this.
 */
export interface MemoryProvenanceSource {
  readonly issuer_id: string
  readonly issued_at: string
  readonly source_ref: string
  readonly reduction_map_ref: string
}

/**
 * Signed memory_provenance envelope.
 *
 * Invariants:
 *   - signal_type is the literal 'memory_provenance'.
 *   - memory_ref is sha256 hex (64 lowercase chars) of the memory entry
 *     AFTER any transformation declared by source.reduction_map_ref.
 *   - source carries the four MemoryProvenanceSource fields. All four
 *     are required.
 *   - ingester_id is the Ed25519 public key (64 lowercase hex chars) of
 *     the agent that committed this entry to memory. It MUST match the
 *     key used to produce the signature.
 *   - ingested_at is the ISO 8601 timestamp at which the agent
 *     committed the memory entry.
 *   - signature is the Ed25519 signature over the JCS-canonical form of
 *     the envelope with the signature field set to the empty string.
 *     128 lowercase hex chars when present.
 */
export interface MemoryProvenanceEnvelope {
  readonly signal_type: MemoryProvenanceSignalType
  readonly memory_ref: string
  readonly source: MemoryProvenanceSource
  readonly ingester_id: string
  readonly ingested_at: string
  readonly signature: string
}

/**
 * Unsigned envelope shape. Same fields as MemoryProvenanceEnvelope
 * minus the signature; signMemoryProvenance accepts this and returns a
 * fully populated envelope.
 */
export type UnsignedMemoryProvenanceEnvelope = Omit<MemoryProvenanceEnvelope, 'signature'>

/**
 * Result of verifying an envelope.
 *
 * Reason codes:
 *   - SHAPE_INVALID: signal_type missing or wrong, memory_ref missing
 *     or not 64 lowercase hex chars, top-level object missing.
 *   - INGESTER_ID_INVALID_FORMAT: ingester_id missing or not 64
 *     lowercase hex chars.
 *   - TIMESTAMP_FORMAT_INVALID: ingested_at or source.issued_at not a
 *     parseable ISO 8601 string.
 *   - MISSING_SOURCE_FIELDS: source not an object, or source.issuer_id,
 *     source.reduction_map_ref missing or malformed in non-timestamp
 *     non-hash ways.
 *   - SOURCE_HASH_INVALID_FORMAT: source.source_ref missing or not 64
 *     lowercase hex chars.
 *   - SIGNATURE_INVALID: signature field missing, malformed, or Ed25519
 *     verification fails against ingester_id.
 */
export interface MemoryProvenanceVerifyResult {
  readonly valid: boolean
  readonly reason?: MemoryProvenanceVerifyReason
}

export type MemoryProvenanceVerifyReason =
  | 'SHAPE_INVALID'
  | 'INGESTER_ID_INVALID_FORMAT'
  | 'SIGNATURE_INVALID'
  | 'MISSING_SOURCE_FIELDS'
  | 'TIMESTAMP_FORMAT_INVALID'
  | 'SOURCE_HASH_INVALID_FORMAT'

const HEX_KEY = /^[0-9a-f]{64}$/
const HEX_SIGNATURE = /^[0-9a-f]{128}$/
const HEX_DIGEST = /^[0-9a-f]{64}$/

// ISO 8601 date-time with required time portion. Accepts second
// precision, optional fractional seconds, and either 'Z' or a numeric
// offset. The regex is the gate; Date.parse is the second gate so that
// invalid days like 2026-02-30 still fail.
const ISO_8601 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/

/**
 * Returns true when value is a syntactically well-formed ISO 8601
 * timestamp string. Checks the lexical form and that Date.parse yields
 * a finite value, which together reject malformed dates such as
 * impossible months or days.
 */
export function isIso8601(value: unknown): value is string {
  if (typeof value !== 'string') return false
  if (!ISO_8601.test(value)) return false
  const ms = Date.parse(value)
  return Number.isFinite(ms)
}

/**
 * Validates the source sub-object shape. Does NOT check that source_ref
 * matches any actual content; the consumer carries that.
 */
export function isMemoryProvenanceSource(value: unknown): value is MemoryProvenanceSource {
  if (typeof value !== 'object' || value === null) return false
  const s = value as Record<string, unknown>
  if (typeof s.issuer_id !== 'string' || !HEX_KEY.test(s.issuer_id)) return false
  if (!isIso8601(s.issued_at)) return false
  if (typeof s.source_ref !== 'string' || !HEX_DIGEST.test(s.source_ref)) return false
  if (typeof s.reduction_map_ref !== 'string' || s.reduction_map_ref.length === 0) return false
  return true
}

/**
 * Runtime type guard. Returns true when value is structurally a signed
 * memory_provenance envelope. Does NOT verify the signature; use
 * verifyMemoryProvenance for that.
 *
 * Invariants checked:
 *   - signal_type literal matches.
 *   - memory_ref is 64 lowercase hex chars.
 *   - source has all four required fields with valid shapes.
 *   - ingester_id is 64 lowercase hex chars.
 *   - ingested_at is a valid ISO 8601 timestamp string.
 *   - signature is 128 lowercase hex chars.
 */
export function isMemoryProvenance(value: unknown): value is MemoryProvenanceEnvelope {
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  if (v.signal_type !== 'memory_provenance') return false
  if (typeof v.memory_ref !== 'string' || !HEX_DIGEST.test(v.memory_ref)) return false
  if (!isMemoryProvenanceSource(v.source)) return false
  if (typeof v.ingester_id !== 'string' || !HEX_KEY.test(v.ingester_id)) return false
  if (!isIso8601(v.ingested_at)) return false
  if (typeof v.signature !== 'string' || !HEX_SIGNATURE.test(v.signature)) return false
  return true
}
