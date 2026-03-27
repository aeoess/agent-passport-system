// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Time — Hybrid Logical Clock Operations
// ══════════════════════════════════════════════════════════════════
// Pure functions for creating, comparing, and validating timestamps.
// Consilium Q1: Hybrid Logical Clocks + NTP uncertainty bounds.
// ══════════════════════════════════════════════════════════════════

import type {
  HybridTimestamp, TemporalBound, TemporalRights,
  TemporalOrdering, TemporalValidation,
} from '../types/time.js'

// ══════════════════════════════════════
// CREATE TIMESTAMPS
// ══════════════════════════════════════

/** Default NTP drift bound in milliseconds. Conservative estimate. */
export const DEFAULT_NTP_DRIFT_MS = 50

/** Logical clock counter — monotonically increasing per gateway. */
let logicalCounter = 0

/** Create a hybrid timestamp. Gateway-issued — captures both
 *  causal ordering and wall-clock uncertainty. */
export function createHybridTimestamp(
  gatewayId: string,
  driftMs: number = DEFAULT_NTP_DRIFT_MS,
): HybridTimestamp {
  logicalCounter++
  const now = Date.now()
  return {
    logicalTime: logicalCounter,
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
