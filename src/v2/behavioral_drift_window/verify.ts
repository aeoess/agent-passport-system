// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// behavioral_drift_window signal_type (v0.1): verification
// ══════════════════════════════════════════════════════════════════
// Verifies the Ed25519 signature on a behavioral_drift_window envelope
// against the observer_id embedded in the envelope, plus structural and
// cross-field invariants on metrics, constituent hash uniqueness, window
// ordering, and optional-field pairing.
//
// What this verifier does NOT do:
//   - Check that constituent envelopes themselves verify.
//   - Recompute class_distribution from constituents.
//   - Recompute confidence_mean / confidence_stddev from constituents.
//   - Evaluate divergence_score against any threshold.
// All of the above are downstream consumer responsibility per v0.1 scope.
// ══════════════════════════════════════════════════════════════════

import { verify as edVerify } from '../../crypto/keys.js'

import { canonicalizeForSignature } from './envelope.js'
import {
  classDistributionSum,
  isBehavioralDriftWindow,
  parseIso8601,
} from './types.js'
import type {
  BehavioralDriftWindowEnvelope,
  BehavioralDriftWindowVerifyResult,
} from './types.js'

const HEX_KEY = /^[0-9a-f]{64}$/

/**
 * Verify the Ed25519 signature on an envelope plus structural and
 * cross-field invariants. Returns `{ valid: true }` only when every
 * check passes AND the signature verifies against `envelope.observer_id`.
 * A failure carries a `reason` naming the specific shape, invariant, or
 * cryptographic failure. Reason codes are listed in `types.ts` on
 * {@link BehavioralDriftWindowVerifyResult}.
 *
 * Order of checks is fixed: shape first, then field-format and
 * cross-field invariants, then signature. Earlier failures short-circuit
 * later ones so the reason code identifies the most-upstream cause.
 */
export function verifyBehavioralDriftWindow(
  envelope: unknown,
): BehavioralDriftWindowVerifyResult {
  if (!isBehavioralDriftWindow(envelope)) {
    // Distinguish key-format failures from generic shape failures when
    // the only thing wrong is an ID format. This keeps reason codes
    // useful to a caller debugging an integration.
    if (typeof envelope === 'object' && envelope !== null) {
      const e = envelope as Record<string, unknown>
      if (e.signal_type === 'behavioral_drift_window') {
        if (typeof e.observer_id === 'string' && !HEX_KEY.test(e.observer_id)) {
          return { valid: false, reason: 'OBSERVER_ID_INVALID_FORMAT' }
        }
        if (typeof e.subject_agent_id === 'string' && !HEX_KEY.test(e.subject_agent_id)) {
          return { valid: false, reason: 'SUBJECT_AGENT_ID_INVALID_FORMAT' }
        }
      }
    }
    return { valid: false, reason: 'SHAPE_INVALID' }
  }

  const e = envelope

  const startMs = parseIso8601(e.window_start)
  const endMs = parseIso8601(e.window_end)
  if (Number.isNaN(startMs) || Number.isNaN(endMs)) {
    return { valid: false, reason: 'TIMESTAMP_FORMAT_INVALID' }
  }
  if (!(endMs > startMs)) {
    return { valid: false, reason: 'WINDOW_INVALID' }
  }

  const seen = new Set<string>()
  for (const h of e.constituent_attestations) {
    if (seen.has(h)) {
      return { valid: false, reason: 'CONSTITUENT_HASH_DUPLICATE' }
    }
    seen.add(h)
  }

  if (e.metrics.decision_count !== e.constituent_attestations.length) {
    return { valid: false, reason: 'METRICS_INCONSISTENT' }
  }
  if (classDistributionSum(e.metrics.class_distribution) !== e.metrics.decision_count) {
    return { valid: false, reason: 'METRICS_INCONSISTENT' }
  }

  const hasMean = e.metrics.confidence_mean !== undefined
  const hasStddev = e.metrics.confidence_stddev !== undefined
  if (hasMean !== hasStddev) {
    return { valid: false, reason: 'CONFIDENCE_RANGE_INVALID' }
  }
  if (hasMean) {
    const mean = e.metrics.confidence_mean as number
    const stddev = e.metrics.confidence_stddev as number
    if (mean < 0 || mean > 1) {
      return { valid: false, reason: 'CONFIDENCE_RANGE_INVALID' }
    }
    if (stddev < 0) {
      return { valid: false, reason: 'CONFIDENCE_RANGE_INVALID' }
    }
  }

  const hasBaseline = e.metrics.baseline_ref !== undefined
  const hasDivergence = e.metrics.divergence_score !== undefined
  if (hasBaseline !== hasDivergence) {
    return { valid: false, reason: 'BASELINE_PAIRING_INVALID' }
  }

  const bytes = canonicalizeForSignature(e as BehavioralDriftWindowEnvelope)
  const ok = edVerify(bytes, e.signature, e.observer_id)
  if (!ok) {
    return { valid: false, reason: 'SIGNATURE_INVALID' }
  }
  return { valid: true }
}
