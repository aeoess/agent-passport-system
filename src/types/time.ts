// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Time — Hybrid Logical Clocks + NTP Uncertainty Bounds
// ══════════════════════════════════════════════════════════════════
// Consilium Q1 resolution: Hybrid Logical Clocks (Kulkarni et al. 2014)
// with NTP uncertainty bounds. Replaces 9 ad-hoc TTL patterns with
// unified temporal semantics.
//
// Key insight: wall clocks lie. NTP gives a range, not a point.
// HybridTimestamp captures both causal ordering (logical time) and
// real-world bounds (wall clock range). Gateway-stamped, not agent-stamped.
//
// Evaluation rules:
//   EscrowHold expires when t_earliest > expiresAt
//   Receipt valid when t_latest < delegation_expiry
//   (Conservative: use worst-case bound for each decision)
// ══════════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════════
// Hybrid Timestamp
// ══════════════════════════════════════════════════════════════════

/** A timestamp that captures both causal ordering and wall-clock uncertainty.
 *  Gateway-issued — agents cannot forge these. The gateway is the time authority. */
export interface HybridTimestamp {
  /** Monotonically increasing causal counter (Lamport clock component).
   *  Guarantees causal ordering: if A happened-before B, A.logicalTime < B.logicalTime */
  logicalTime: number
  /** Unix epoch ms — lower bound of wall clock (NTP time - drift bound).
   *  The earliest this event could have occurred in real time. */
  wallClockEarliest: number
  /** Unix epoch ms — upper bound of wall clock (NTP time + drift bound).
   *  The latest this event could have occurred in real time. */
  wallClockLatest: number
  /** Gateway that issued this timestamp. Different gateways have
   *  independent logical clocks — cross-gateway comparison uses wall clock bounds. */
  gatewayId: string
}

// ══════════════════════════════════════════════════════════════════
// Temporal Bound
// ══════════════════════════════════════════════════════════════════

/** Pairs a hybrid timestamp of issuance with a hard TTL expiry.
 *  Used on all time-bounded artifacts: escrows, delegations, attestations. */
export interface TemporalBound {
  /** When this artifact was issued (hybrid timestamp) */
  issuedAt: HybridTimestamp
  /** Absolute Unix epoch ms — hard TTL. Artifact invalid after this. */
  expiresAt: number
}

// ══════════════════════════════════════════════════════════════════
// Temporal Rights — Unified Time Semantics
// ══════════════════════════════════════════════════════════════════

/** Unified temporal governance for all governance artifacts.
 *  Replaces 9 ad-hoc TTL fields scattered across different types
 *  with a single coherent temporal model.
 *
 *  Example lifecycle:
 *    effectiveAt → validFrom → observedAt → validUntil → challengeUntil → graceUntil
 *                                                          ↑ supersededAt (if replaced) */
export interface TemporalRights {
  /** ISO datetime — start of validity window */
  validFrom: string
  /** ISO datetime — end of validity window */
  validUntil: string
  /** ISO datetime — window for challenges (dispute, appeal).
   *  After this, no new disputes can be filed against this artifact. */
  challengeUntil?: string
  /** ISO datetime — grace period after expiry.
   *  Artifact is expired but existing operations can still complete. */
  graceUntil?: string
  /** ISO datetime — when this artifact was replaced by a newer version.
   *  Set when a superseding artifact is created. */
  supersededAt?: string
  /** ISO datetime — when policy/amendment takes effect.
   *  Can be in the future (scheduled activation). */
  effectiveAt?: string
  /** ISO datetime — when this event was first observed/recorded.
   *  May differ from effectiveAt for retroactive recordings. */
  observedAt?: string
}

// ══════════════════════════════════════════════════════════════════
// Temporal Comparison Semantics
// ══════════════════════════════════════════════════════════════════

/** Result of comparing two hybrid timestamps. Because wall clocks have
 *  uncertainty bounds, comparison can be definite or uncertain. */
export type TemporalOrdering =
  | 'definitely_before'   // A.wallClockLatest < B.wallClockEarliest
  | 'definitely_after'    // A.wallClockEarliest > B.wallClockLatest
  | 'concurrent'          // wall clock ranges overlap — use logical time
  | 'causally_before'     // concurrent but A.logicalTime < B.logicalTime (same gateway)
  | 'causally_after'      // concurrent but A.logicalTime > B.logicalTime (same gateway)
  | 'incomparable'        // concurrent, different gateways, cannot determine order

/** Result of checking whether an artifact is temporally valid. */
export interface TemporalValidation {
  /** Whether the artifact is currently within its validity window */
  valid: boolean
  /** Whether the artifact is in its grace period (expired but grace active) */
  inGracePeriod: boolean
  /** Whether the artifact has been superseded */
  superseded: boolean
  /** Whether the challenge window is still open */
  challengeWindowOpen: boolean
  /** Whether the artifact's effective date has been reached */
  effective: boolean
  errors: string[]
}

// ══════════════════════════════════════════════════════════════════
// Session Boundary
// ══════════════════════════════════════════════════════════════════
// HLC-gap-derived session segmentation. Reference: Nanook PDR v2.19 §7.6.3,
// gap audit §3 row 14 / row 29 / §5 rank 5. The paper credits APS with
// "HLC gap detection as session boundary" as a deployable pattern; this
// type is the wire format the extractSessions() utility produces.

/** A contiguous run of HybridTimestamps that belong to the same session.
 *  Sessions are derived from a time-ordered stamp sequence by detecting
 *  wall-clock gaps that exceed a configurable threshold (default 5 min). */
export interface SessionBoundary {
  /** The first timestamp of this session. */
  start: HybridTimestamp
  /** The last timestamp of this session. */
  end: HybridTimestamp
  /** Number of timestamps in this session (inclusive of start and end). */
  eventCount: number
  /** Gap in milliseconds from the previous session's end to this
   *  session's start. Zero for the first session in the sequence. */
  gapFromPreviousMs: number
}
