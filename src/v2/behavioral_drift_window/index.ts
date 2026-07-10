// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// behavioral_drift_window signal_type (v0.1): public surface
// ══════════════════════════════════════════════════════════════════
// Matrix v2 candidate C-II-5 (Long-horizon attestation envelope drift
// detection). Aggregates references to N single-event behavioral
// attestation envelopes for the same subject agent across a declared
// time window and records longitudinal summary metrics. RECORDS
// evidence of drift; does NOT detect malicious drift (downstream
// consumer responsibility).
//
// Scope (v0.1):
//   - Envelope construction, JCS canonicalization, Ed25519 signing,
//     signature verification.
//   - Structural and cross-field invariants on metrics, constituent
//     hash uniqueness, window ordering, and optional-field pairing.
//   - Runtime type guard.
//
// Out of scope (v0.2 or deferred):
//   - Computing metrics from constituents inside the SDK.
//   - Verifying constituent envelopes.
//   - Drift threshold policy.
//   - Time-series API or windowed aggregation tooling.
//   - Multi-window composition or hierarchical drift envelopes.
//   - Privacy posture for sensitive metric ranges.
// ══════════════════════════════════════════════════════════════════

export { signBehavioralDriftWindow, canonicalizeForSignature } from './envelope.js'
export { verifyBehavioralDriftWindow } from './verify.js'
export {
  isBehavioralDriftWindow,
  isBehavioralDriftWindowMetrics,
  classDistributionSum,
  parseIso8601,
} from './types.js'

export type {
  BehavioralDriftWindowSignalType,
  BehavioralDriftWindowEnvelope,
  UnsignedBehavioralDriftWindowEnvelope,
  BehavioralDriftWindowMetrics,
  ClassDistribution,
  BehavioralDriftWindowVerifyResult,
  BehavioralDriftWindowVerifyReason,
} from './types.js'
