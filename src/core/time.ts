// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Time — Hybrid Logical Clock Operations
// ══════════════════════════════════════════════════════════════════
// Pure functions for creating, comparing, and validating timestamps.
// Consilium Q1: Hybrid Logical Clocks + NTP uncertainty bounds.
// ══════════════════════════════════════════════════════════════════

import type {
  HybridTimestamp, TemporalBound, TemporalRights,
  TemporalOrdering, TemporalValidation, SessionBoundary,
} from '../types/time.js'

// ══════════════════════════════════════
// CREATE TIMESTAMPS
// ══════════════════════════════════════

/** Default NTP drift bound in milliseconds. Conservative estimate. */
export const DEFAULT_NTP_DRIFT_MS = 50

/** Default wall-clock gap threshold for session boundary extraction.
 *  Five minutes. Reference: Nanook PDR v2.19 §7.6.3 attributes
 *  "HLC gap as session boundary" to APS as a deployable pattern;
 *  five minutes is the round number that survives both natural
 *  conversation pauses and brief network glitches without
 *  fragmenting a single session. Override per deployment for
 *  shorter (high-frequency probing) or longer (batch jobs) cadences. */
export const DEFAULT_SESSION_GAP_MS = 300_000

/** Module-scope logical clock counter retained for backward compatibility
 *  with existing callers (v2 modules, rome-phase2 tests) that don't pass
 *  an explicit logicalTime. New code should use createHybridTimestampAt
 *  or the gateway's LogicalClock — see
 *  @aeoess/gateway src/sdk-migrated/core/logical-clock.ts. */
let logicalCounter = 0

/** Create a hybrid timestamp. Gateway-issued — captures both
 *  causal ordering and wall-clock uncertainty.
 *
 *  When `logicalTime` is provided the call is fully pure. When omitted,
 *  the SDK module counter is incremented for backward compatibility. */
export function createHybridTimestamp(
  gatewayId: string,
  driftMs: number = DEFAULT_NTP_DRIFT_MS,
  logicalTime?: number,
): HybridTimestamp {
  const lt = logicalTime ?? ++logicalCounter
  const now = Date.now()
  return {
    logicalTime: lt,
    wallClockEarliest: now - driftMs,
    wallClockLatest: now + driftMs,
    gatewayId,
  }
}

/** Pure stateless variant. Caller supplies the logical time explicitly,
 *  letting it manage its own counter (per-gateway, per-process, or
 *  per-tenant). The SDK module counter is not touched. */
export function createHybridTimestampAt(
  gatewayId: string,
  logicalTime: number,
  driftMs: number = DEFAULT_NTP_DRIFT_MS,
): HybridTimestamp {
  const now = Date.now()
  return {
    logicalTime,
    wallClockEarliest: now - driftMs,
    wallClockLatest: now + driftMs,
    gatewayId,
  }
}

/** Create a temporal bound: hybrid timestamp + hard TTL. */
export function createTemporalBound(
  gatewayId: string,
  ttlMs: number,
  driftMs: number = DEFAULT_NTP_DRIFT_MS,
): TemporalBound {
  return {
    issuedAt: createHybridTimestamp(gatewayId, driftMs),
    expiresAt: Date.now() + ttlMs,
  }
}

// ══════════════════════════════════════
// COMPARE TIMESTAMPS
// ══════════════════════════════════════

/** Compare two hybrid timestamps. Returns the ordering relationship.
 *  Conservative: uses wall clock bounds for definite ordering,
 *  falls back to logical time for same-gateway concurrent events. */
export function compareTimestamps(a: HybridTimestamp, b: HybridTimestamp): TemporalOrdering {
  // Definite ordering: wall clock ranges don't overlap
  if (a.wallClockLatest < b.wallClockEarliest) return 'definitely_before'
  if (a.wallClockEarliest > b.wallClockLatest) return 'definitely_after'

  // Ranges overlap — concurrent in wall clock terms
  if (a.gatewayId === b.gatewayId) {
    // Same gateway: logical time provides causal ordering
    if (a.logicalTime < b.logicalTime) return 'causally_before'
    if (a.logicalTime > b.logicalTime) return 'causally_after'
    return 'concurrent' // same logical time (shouldn't happen in practice)
  }

  // Different gateways, overlapping ranges: cannot determine order
  return 'incomparable'
}

/** Check if a temporal bound has expired (conservative: earliest > expiresAt). */
export function isTemporalBoundExpired(bound: TemporalBound, nowEarliest?: number): boolean {
  const earliest = nowEarliest ?? (Date.now() - DEFAULT_NTP_DRIFT_MS)
  return earliest > bound.expiresAt
}

// ══════════════════════════════════════
// VALIDATE TEMPORAL RIGHTS
// ══════════════════════════════════════

/** Validate a TemporalRights object against the current time.
 *  Returns a full validation result with status for each temporal aspect. */
export function validateTemporalRights(rights: TemporalRights, now?: Date): TemporalValidation {
  const current = now ?? new Date()
  const errors: string[] = []

  const validFrom = new Date(rights.validFrom)
  const validUntil = new Date(rights.validUntil)
  const effective = rights.effectiveAt ? current >= new Date(rights.effectiveAt) : true
  const valid = current >= validFrom && current <= validUntil && effective

  const inGracePeriod = !valid && rights.graceUntil
    ? current <= new Date(rights.graceUntil) : false
  const superseded = rights.supersededAt
    ? current >= new Date(rights.supersededAt) : false
  const challengeWindowOpen = rights.challengeUntil
    ? current <= new Date(rights.challengeUntil) : false

  if (!valid && !inGracePeriod) errors.push('Outside validity window')
  if (superseded) errors.push('Superseded by newer version')
  if (!effective) errors.push('Effective date not yet reached')

  return {
    valid: valid && !superseded,
    inGracePeriod,
    superseded,
    challengeWindowOpen,
    effective,
    errors,
  }
}

/** Reset the logical counter (for testing only). */
export function resetLogicalCounter(): void {
  logicalCounter = 0
}

// ══════════════════════════════════════════════════════════════════
// SESSION BOUNDARY EXTRACTION
// ══════════════════════════════════════════════════════════════════
// Reference: Nanook PDR v2.19 §7.6.3 attributes "HLC gap detection as
// session boundary" to APS as a deployable pattern. APS produces HLC
// timestamps via createHybridTimestamp but did not previously derive
// session boundaries from them. This utility makes the paper's
// citation accurate. Gap audit §3 row 14 / row 29 / §5 rank 5.
//
// Design notes:
// - Pure function. No clock reads. No mutation of input.
// - The input array is treated as a time-ordered sequence. The function
//   does NOT sort. Sorting HLC stamps is ambiguous (concurrent and
//   incomparable orderings exist; see TemporalOrdering). The caller has
//   more context than this function and is responsible for ordering.
// - The wall-clock gap is computed CONSERVATIVELY:
//     gap = next.wallClockEarliest - current.wallClockLatest
//   Using the latest point of the earlier stamp and the earliest point
//   of the later stamp accounts for NTP drift bounds. A negative gap
//   means the wall-clock ranges overlap, which means the two events
//   could plausibly have occurred at nearly the same wall-clock time
//   even if their logical ordering differs — that is NOT a session
//   boundary regardless of how the logical clocks ordered them.
// - Boundary semantics: gap > threshold (strictly greater than). A gap
//   exactly equal to the threshold does NOT split sessions. Documented
//   in JSDoc and locked by a regression test.
// ══════════════════════════════════════════════════════════════════

/** Extract session boundaries from a time-ordered sequence of hybrid
 *  timestamps by detecting wall-clock gaps that exceed a threshold.
 *
 *  The input array MUST be in chronological order. The function does not
 *  sort it because sorting HLC stamps across gateways is ambiguous; the
 *  caller is the one with enough context to order them.
 *
 *  Gap semantics: the wall-clock gap between two consecutive stamps is
 *  computed conservatively as
 *    gap = next.wallClockEarliest - current.wallClockLatest
 *  which means stamps with overlapping wall-clock ranges produce a
 *  negative gap and are never treated as a session boundary, even when
 *  their logical-time ordering differs. A boundary fires when
 *    gap > opts.gapThresholdMs
 *  strictly. A gap exactly equal to the threshold keeps both stamps in
 *  the same session.
 *
 *  Edge cases:
 *    - Empty input: returns an empty array.
 *    - Single stamp: returns one session with start === end === that stamp,
 *      eventCount = 1, gapFromPreviousMs = 0.
 *    - All stamps within threshold: one session covering the full range.
 *    - All stamps spaced beyond threshold: N sessions, eventCount = 1 each.
 *
 *  Reference: Nanook PDR v2.19 §7.6.3, gap audit §3 row 14 / row 29 / §5 rank 5.
 *
 *  @param stamps  Chronologically ordered HybridTimestamp sequence.
 *  @param opts.gapThresholdMs  Threshold in ms (default DEFAULT_SESSION_GAP_MS).
 *  @returns Array of SessionBoundary in input order, one per detected session.
 */
export function extractSessions(
  stamps: HybridTimestamp[],
  opts?: { gapThresholdMs?: number },
): SessionBoundary[] {
  const threshold = opts?.gapThresholdMs ?? DEFAULT_SESSION_GAP_MS

  if (stamps.length === 0) return []

  const sessions: SessionBoundary[] = []
  // Walk the sequence accumulating into the current session until a gap
  // exceeds the threshold, then close the session and open a new one.
  let sessionStartIndex = 0
  let previousSessionEnd: HybridTimestamp | null = null

  for (let i = 1; i < stamps.length; i++) {
    const prev = stamps[i - 1]
    const curr = stamps[i]
    const gap = curr.wallClockEarliest - prev.wallClockLatest

    if (gap > threshold) {
      // Close the current session at i-1.
      const start = stamps[sessionStartIndex]
      const end = prev
      const eventCount = i - sessionStartIndex
      const gapFromPreviousMs = previousSessionEnd === null
        ? 0
        : start.wallClockEarliest - previousSessionEnd.wallClockLatest
      sessions.push({ start, end, eventCount, gapFromPreviousMs })
      previousSessionEnd = end
      sessionStartIndex = i
    }
  }

  // Close the trailing session covering [sessionStartIndex .. stamps.length - 1].
  {
    const start = stamps[sessionStartIndex]
    const end = stamps[stamps.length - 1]
    const eventCount = stamps.length - sessionStartIndex
    const gapFromPreviousMs = previousSessionEnd === null
      ? 0
      : start.wallClockEarliest - previousSessionEnd.wallClockLatest
    sessions.push({ start, end, eventCount, gapFromPreviousMs })
  }

  return sessions
}
