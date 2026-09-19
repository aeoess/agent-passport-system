// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// External action_ref (action-ref-v1-jcs-sha256): Cross-Ecosystem Correlation Key
// ══════════════════════════════════════════════════════════════════
// This is the cross-ecosystem correlation key. It is NOT the APS-native
// action_ref.
//
// The APS-native action_ref (computeActionRef, draft-pidlisnyi-aps-01 §4.1)
// and this external key are distinct primitives with intentionally different
// preimages. Use computeActionRef for APS receipts and request equivalence.
// Use this helper only to correlate an APS action with the external
// action-ref-v1 form computed by independent ecosystem implementations
// (see docs/specs/action-ref-v1.md and conformance/action-ref-v1/).
//
// Differences from the APS-native §4.1 form:
//   - snake_case preimage keys {action_type, agent_id, scope, timestamp}
//   - scope is a single string, not the APS multi-scope array
//   - timestamp is an RFC 3339 date-time in UTC at exactly millisecond
//     precision (three fractional-second digits and a literal Z), hashed as
//     the byte sequence supplied and never normalized. Second 00-60 is
//     accepted lexically per the RFC 3339 ABNF (a validator cannot consult
//     the leap-second table, so :60 is accepted without leap-second
//     verification), but the year-month-day must name a day that exists
//     under the proleptic Gregorian calendar. A non-conforming value
//     (wrong shape, non-string, or a calendar-invalid date) is rejected,
//     never coerced, truncated, extended or renormalized.
// ══════════════════════════════════════════════════════════════════

import { canonicalHashJCS } from './canonical-jcs.js'

// Canonical external timestamp shape: RFC 3339 UTC, exactly three
// fractional-second digits, mandatory Z, second 00-60 (leap second accepted
// lexically). Calendar validity (day-in-month) is checked separately below,
// since a regex cannot encode "30 is invalid in February".
const EXTERNAL_TS =
  /^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:([0-5][0-9]|60)\.[0-9]{3}Z$/

/** Input to computeExternalActionRefV1. */
export interface ExternalActionRefV1Input {
  /** External action type, e.g. "payment.send". */
  actionType: string
  /** Agent identifier as the external ecosystem expects it. */
  agentId: string
  /** A single scope string. This differs from the APS-native action_ref,
   *  whose scopeRequired is a multi-scope array. */
  scope: string
  /** Millisecond RFC 3339 UTC instant (YYYY-MM-DDTHH:MM:SS.mmmZ). A canonical
   *  string is hashed as-is; a Date is rendered to the canonical form via
   *  toISOString. Any other string shape is rejected rather than coerced, so
   *  acceptance matches the aps-broker verifier. */
  timestamp: string | Date
}

/** True if `year` is a leap year under the proleptic Gregorian calendar
 *  (divisible by 4 and not by 100, or divisible by 400; year 0000 is a
 *  leap year). */
function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0
}

/** Days in `month` (1-12) of `year` under the proleptic Gregorian calendar. */
function daysInMonth(year: number, month: number): number {
  const lengths = [31, isLeapYear(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  return lengths[month - 1]
}

// Never validate a timestamp string with Date: Date cannot represent a
// leap-second (:60) value, so it would wrongly reject what RFC 3339 admits
// lexically.
function validateTimestampString(ts: string): string {
  const match = EXTERNAL_TS.exec(ts)
  if (!match) {
    throw new Error(
      `computeExternalActionRefV1: timestamp must be RFC 3339 UTC with three fractional digits and a Z suffix (YYYY-MM-DDTHH:MM:SS.mmmZ), got ${JSON.stringify(ts)}`,
    )
  }
  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  if (day > daysInMonth(year, month)) {
    throw new Error(
      `computeExternalActionRefV1: timestamp names a day that does not exist in that month, got ${JSON.stringify(ts)}`,
    )
  }
  return ts
}

function externalTimestamp(ts: string | Date): string {
  if (ts instanceof Date) {
    if (Number.isNaN(ts.getTime())) {
      throw new Error('computeExternalActionRefV1: invalid Date timestamp')
    }
    // A Date outside years 0000-9999 renders via toISOString with an
    // expanded year (e.g. "+010000-01-01T00:00:00.000Z"), which the string
    // check below rejects rather than hashes.
    return validateTimestampString(ts.toISOString())
  }
  if (typeof ts !== 'string') {
    throw new Error('computeExternalActionRefV1: timestamp must be a string or a Date')
  }
  return validateTimestampString(ts)
}

/**
 * Compute the external cross-ecosystem correlation key
 * (action-ref-v1-jcs-sha256): lowercase-hex SHA-256 of the RFC 8785 JCS
 * canonicalization of {action_type, agent_id, scope, timestamp}.
 *
 * This is NOT the APS-native action_ref. See the file header for the preimage
 * differences. Use computeActionRef for APS-native receipts and equivalence.
 *
 * Returns: lowercase hex SHA-256 digest.
 */
export function computeExternalActionRefV1(input: ExternalActionRefV1Input): string {
  if (typeof input.actionType !== 'string') {
    throw new Error('computeExternalActionRefV1: actionType must be a string')
  }
  if (typeof input.agentId !== 'string') {
    throw new Error('computeExternalActionRefV1: agentId must be a string')
  }
  if (typeof input.scope !== 'string') {
    throw new Error('computeExternalActionRefV1: scope must be a string')
  }
  return canonicalHashJCS({
    action_type: input.actionType,
    agent_id: input.agentId,
    scope: input.scope,
    timestamp: externalTimestamp(input.timestamp),
  })
}
