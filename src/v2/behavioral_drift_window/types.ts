// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// behavioral_drift_window signal_type (v0.1): TypeScript types
// ══════════════════════════════════════════════════════════════════
// Time-axis extension of single-event behavioral attestations such as
// cognitive_attestation. One envelope bundles N constituent envelope
// hashes for the same subject agent across [window_start, window_end]
// plus summary metrics computed across that window.
//
// What this primitive attests to: the observer (identified by
// observer_id) committed to a specific summary of subject_agent_id's
// behavior over the declared window at the moment of signing. It does
// NOT attest:
//   - That the constituent envelopes are themselves valid (downstream
//     verifies each).
//   - That the metrics are computed correctly (downstream may recompute
//     from constituents).
//   - Whether the drift is significant, malicious, or benign (downstream
//     policy decision).
//
// observer_id MAY equal subject_agent_id (self-attestation, audit-trail
// use case) or MAY differ (third-party monitoring use case). Both shapes
// are valid; the signature is always verified against observer_id.
//
// v0.1 surface: bundle of constituent hashes, decision_count,
// class_distribution over the three v0.1 cognitive_attestation classes,
// optional confidence summary, optional baseline comparison.
//
// v0.2 deferred: SDK-side recomputation of metrics from constituents,
// time-series API, hierarchical/composite drift envelopes, threshold
// policy.
// ══════════════════════════════════════════════════════════════════

/**
 * Literal tag for envelope discrimination at the wire level.
 */
export type BehavioralDriftWindowSignalType = 'behavioral_drift_window'

/**
 * Counts of constituent envelopes per cognitive_attestation v0.1 class.
 * Sum of values MUST equal {@link BehavioralDriftWindowMetrics.decision_count}.
 * Counts are non-negative integers.
 */
export interface ClassDistribution {
  readonly precondition_set: number
  readonly candidate_set: number
  readonly decision_path: number
}

/**
 * Summary metrics computed across the window. v0.1 trusts caller-supplied
 * numbers and only validates shape and pairing invariants; downstream
 * consumers in possession of the constituent envelopes may recompute
 * these and check the observer's honesty.
 *
 * Invariants enforced at verify:
 *   - decision_count is a non-negative integer.
 *   - class_distribution values are non-negative integers that sum to
 *     decision_count.
 *   - confidence_mean and confidence_stddev are both present or both
 *     absent; when present, mean is in [0, 1] and stddev is non-negative.
 *   - baseline_ref and divergence_score are both present or both absent.
 */
export interface BehavioralDriftWindowMetrics {
  readonly decision_count: number
  readonly class_distribution: ClassDistribution
  readonly confidence_mean?: number
  readonly confidence_stddev?: number
  readonly baseline_ref?: string
  readonly divergence_score?: number
}

/**
 * Signed behavioral_drift_window envelope. The signature is Ed25519 over
 * the JCS-canonical form of this envelope with the signature field
 * emptied (RFC 8785). The signature is verified against observer_id's
 * public key; subject_agent_id is informational from the signature's
 * point of view.
 */
export interface BehavioralDriftWindowEnvelope {
  readonly signal_type: BehavioralDriftWindowSignalType
  /** Ed25519 public key of the agent whose behavior is summarized, lowercase hex (64 chars). */
  readonly subject_agent_id: string
  /** Ed25519 public key of the issuing agent, lowercase hex (64 chars). MAY equal subject_agent_id. */
  readonly observer_id: string
  /** ISO 8601 timestamp marking the window's start (inclusive). */
  readonly window_start: string
  /** ISO 8601 timestamp marking the window's end (exclusive or inclusive is consumer policy; MUST be strictly greater than window_start). */
  readonly window_end: string
  /**
   * sha256 hex (64 lowercase chars) of each constituent envelope's
   * canonical bytes, in caller-chosen order. Order IS part of the
   * canonical form per JCS array spec; reordering changes the canonical
   * bytes and invalidates the signature. Hashes MUST be unique. Empty
   * array is valid and records absence of activity in the window.
   */
  readonly constituent_attestations: readonly string[]
  readonly metrics: BehavioralDriftWindowMetrics
  /** Ed25519 signature by observer_id's private key, lowercase hex (128 chars). Empty during signing. */
  readonly signature: string
}

/**
 * Unsigned envelope shape: same fields as the signed envelope, minus the
 * signature. The signing helper accepts this and returns a fully populated
 * envelope.
 */
export type UnsignedBehavioralDriftWindowEnvelope = Omit<BehavioralDriftWindowEnvelope, 'signature'>

/**
 * Result of verifying an envelope. `valid: false` carries a `reason`
 * naming the specific failure mode. Reasons:
 *   - SHAPE_INVALID: envelope is not a structurally well-formed
 *     behavioral_drift_window envelope (missing or wrong-typed fields).
 *   - OBSERVER_ID_INVALID_FORMAT: observer_id is not 64 lowercase hex chars.
 *   - SUBJECT_AGENT_ID_INVALID_FORMAT: subject_agent_id is not 64 lowercase hex chars.
 *   - WINDOW_INVALID: window_end is not strictly greater than window_start.
 *   - TIMESTAMP_FORMAT_INVALID: window_start or window_end is not a parseable ISO 8601 timestamp.
 *   - CONSTITUENT_HASH_DUPLICATE: constituent_attestations contains a repeated hash.
 *   - METRICS_INCONSISTENT: decision_count does not match constituent count, or class_distribution values do not sum to decision_count.
 *   - CONFIDENCE_RANGE_INVALID: confidence_mean / confidence_stddev pairing or range invariant violated.
 *   - BASELINE_PAIRING_INVALID: baseline_ref / divergence_score pairing invariant violated.
 *   - SIGNATURE_INVALID: Ed25519 verification failed against observer_id.
 */
export interface BehavioralDriftWindowVerifyResult {
  readonly valid: boolean
  readonly reason?: BehavioralDriftWindowVerifyReason
}

export type BehavioralDriftWindowVerifyReason =
  | 'SHAPE_INVALID'
  | 'OBSERVER_ID_INVALID_FORMAT'
  | 'SUBJECT_AGENT_ID_INVALID_FORMAT'
  | 'WINDOW_INVALID'
  | 'TIMESTAMP_FORMAT_INVALID'
  | 'CONSTITUENT_HASH_DUPLICATE'
  | 'METRICS_INCONSISTENT'
  | 'CONFIDENCE_RANGE_INVALID'
  | 'BASELINE_PAIRING_INVALID'
  | 'SIGNATURE_INVALID'

const HEX_KEY = /^[0-9a-f]{64}$/
const HEX_SIGNATURE = /^[0-9a-f]{128}$/
const HEX_DIGEST = /^[0-9a-f]{64}$/

function isNonNegativeInteger(n: unknown): n is number {
  return typeof n === 'number' && Number.isFinite(n) && Number.isInteger(n) && n >= 0
}

/**
 * Parse an ISO 8601 timestamp. Returns the millisecond epoch on success
 * or NaN on failure. Native Date.parse accepts ISO 8601 plus some
 * non-ISO forms; we tighten by requiring the input to round-trip through
 * toISOString-style detection (presence of a date and either a 'T' or
 * 'Z' anchor). This is a shape check, not a normalization step.
 */
export function parseIso8601(value: unknown): number {
  if (typeof value !== 'string' || value.length === 0) return NaN
  // Cheap structural sniff: must contain a digit and either a 'T', '-', or 'Z'
  // and start with a 4-digit year.
  if (!/^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?$/.test(value)) {
    return NaN
  }
  const t = Date.parse(value)
  return Number.isFinite(t) ? t : NaN
}

/**
 * Runtime type guard. Returns true when `value` is structurally a signed
 * behavioral_drift_window envelope at the field-presence and type-tag
 * level. Does NOT verify cross-field invariants (e.g. metrics consistency)
 * or signature validity; use {@link verifyBehavioralDriftWindow} for that.
 *
 * Invariants checked:
 *   - signal_type literal matches.
 *   - observer_id, subject_agent_id are 64 lowercase hex chars.
 *   - signature is 128 lowercase hex chars.
 *   - window_start, window_end are strings.
 *   - constituent_attestations is an array of 64-hex strings.
 *   - metrics has decision_count (non-negative integer) and
 *     class_distribution with three non-negative integer fields.
 *   - confidence_mean / confidence_stddev, when present, are finite numbers.
 *   - baseline_ref, when present, is a 64-hex string; divergence_score,
 *     when present, is a finite number.
 */
export function isBehavioralDriftWindow(value: unknown): value is BehavioralDriftWindowEnvelope {
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  if (v.signal_type !== 'behavioral_drift_window') return false
  if (typeof v.subject_agent_id !== 'string' || !HEX_KEY.test(v.subject_agent_id)) return false
  if (typeof v.observer_id !== 'string' || !HEX_KEY.test(v.observer_id)) return false
  if (typeof v.window_start !== 'string') return false
  if (typeof v.window_end !== 'string') return false
  if (typeof v.signature !== 'string' || !HEX_SIGNATURE.test(v.signature)) return false
  if (!Array.isArray(v.constituent_attestations)) return false
  for (const h of v.constituent_attestations) {
    if (typeof h !== 'string' || !HEX_DIGEST.test(h)) return false
  }
  if (!isBehavioralDriftWindowMetrics(v.metrics)) return false
  return true
}

/**
 * Validate the {@link BehavioralDriftWindowMetrics} shape. Field-presence
 * and per-field type only; cross-field invariants (sum, pairing, range)
 * are enforced by the verifier.
 */
export function isBehavioralDriftWindowMetrics(value: unknown): value is BehavioralDriftWindowMetrics {
  if (typeof value !== 'object' || value === null) return false
  const m = value as Record<string, unknown>
  if (!isNonNegativeInteger(m.decision_count)) return false
  if (typeof m.class_distribution !== 'object' || m.class_distribution === null) return false
  const d = m.class_distribution as Record<string, unknown>
  if (!isNonNegativeInteger(d.precondition_set)) return false
  if (!isNonNegativeInteger(d.candidate_set)) return false
  if (!isNonNegativeInteger(d.decision_path)) return false
  if ('confidence_mean' in m && m.confidence_mean !== undefined) {
    if (typeof m.confidence_mean !== 'number' || !Number.isFinite(m.confidence_mean)) return false
  }
  if ('confidence_stddev' in m && m.confidence_stddev !== undefined) {
    if (typeof m.confidence_stddev !== 'number' || !Number.isFinite(m.confidence_stddev)) return false
  }
  if ('baseline_ref' in m && m.baseline_ref !== undefined) {
    if (typeof m.baseline_ref !== 'string' || !HEX_DIGEST.test(m.baseline_ref)) return false
  }
  if ('divergence_score' in m && m.divergence_score !== undefined) {
    if (typeof m.divergence_score !== 'number' || !Number.isFinite(m.divergence_score)) return false
  }
  return true
}

/**
 * Sum of {@link ClassDistribution} values. Used by the verifier to check
 * that decision_count matches the breakdown.
 */
export function classDistributionSum(d: ClassDistribution): number {
  return d.precondition_set + d.candidate_set + d.decision_path
}
