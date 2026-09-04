// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// parseRfc3339 — the strict timestamp parse for security boundaries
// ══════════════════════════════════════════════════════════════════
// A timestamp that arrives on an artifact is attacker-controlled input.
// `new Date(untrusted)` and `Date.parse(untrusted)` do not report failure:
// they yield an Invalid Date whose valueOf() is NaN, and every relational
// comparison against NaN is false. So `new Date(a.expiresAt) < new Date()`
// answers "not expired" for a value that is not a date at all, and
// `Date.now() - new Date(a.evaluated_at).getTime() > maxAge` answers
// "fresh". An unparseable value must reject, never widen acceptance.
//
// Two further properties of the platform parsers matter at a boundary and
// are closed here rather than delegated:
//   - Date.parse('2026-02-30T00:00:00Z') returns a finite instant. A day
//     that does not exist in its month silently rolls forward into the
//     next one, so two distinct strings denote one instant and a window
//     check can be moved by writing an impossible date.
//   - Date.parse('2026-01-01T24:00:00Z') returns a finite instant. RFC 3339
//     bounds time-hour at 23; 24:00:00 is an ISO 8601 end-of-day form that
//     denotes the same instant as the next day's 00:00:00.
// Both are accepted by a regex-plus-`Number.isFinite(Date.parse(v))` shape
// check. This module range-checks every field and computes the instant
// arithmetically instead, so neither string parses.
//
// GRAMMAR ACCEPTED (RFC 3339 §5.6 full-date "T" full-time, narrowed):
//   YYYY-MM-DDTHH:MM:SS[.fff…](Z|±HH:MM)
//   - The date-time separator is an uppercase 'T' and the zero offset is an
//     uppercase 'Z'. RFC 3339 permits the lowercase spellings; they are
//     refused here so one instant has one accepted spelling per offset, and
//     because every timestamp this SDK emits comes from toISOString().
//   - The offset is REQUIRED. A local time with no zone does not denote an
//     instant, so it can never be compared against one.
//
// FRACTIONAL SECONDS: 1 to 9 digits accepted; 0 digits after a '.' or more
// than 9 is malformed. The returned instant is truncated (not rounded) to
// millisecond granularity, matching the resolution of every other time
// value in this SDK. Digits beyond the third are validated for syntax and
// then discarded, so two strings differing only below a millisecond parse
// to one instant and compare equal.
//
// LEAP SECONDS: a time-second of 60 is REFUSED with its own reason. RFC 3339
// admits it, but the instant it denotes has no representation on the
// millisecond timeline this SDK compares against, and silently folding it to
// :59 or to the following :00 would move a boundary. A caller that must
// carry a leap second has to decide what it means before a verifier can.
//
// RANGE: years 0000-9999 (the four-digit grammar). Every accepted instant
// is a safe integer number of milliseconds from the epoch.
//
// This module reads no clock and imports nothing. It is the only place in
// the boundary files that turns a string into an instant; tests/rfc3339-
// boundary-guard.test.ts fails if `new Date(` or `Date.parse(` reappears in
// one of them.
// ══════════════════════════════════════════════════════════════════

/** Why a string was refused as an RFC 3339 instant. */
export type Rfc3339FailureReason =
  /** Input was not a string (null, undefined, number, object, …). */
  | 'not_a_string'
  /** Input did not match the accepted grammar. */
  | 'malformed'
  /** Grammar matched but a field was outside its RFC 3339 range,
   *  including a day that does not exist in its month and hour 24. */
  | 'field_out_of_range'
  /** time-second was 60. See LEAP SECONDS above. */
  | 'leap_second'
  /** The instant is not a safe integer count of milliseconds. */
  | 'not_representable'

/** Outcome of {@link parseRfc3339}. `ok: false` carries a reason and never
 *  an instant, so a caller cannot read a time out of a failed parse. */
export type Rfc3339ParseResult =
  | { ok: true; ms: number }
  | { ok: false; reason: Rfc3339FailureReason }

/**
 * YYYY-MM-DDTHH:MM:SS(.frac)?(Z|±HH:MM). Shape only — every numeric field is
 * range-checked afterwards, because the grammar admits values such as month
 * 13, day 31 in February, and hour 24.
 */
const RFC3339 =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:(Z)|([+-])(\d{2}):(\d{2}))$/

/** Days in `month` (1-12) of `year`, proleptic Gregorian. */
function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0
    return leap ? 29 : 28
  }
  return month === 4 || month === 6 || month === 9 || month === 11 ? 30 : 31
}

/**
 * Days from 1970-01-01 to the given civil date, proleptic Gregorian.
 * Integer arithmetic only: `Date.UTC` maps two-digit years into the 1900s,
 * which would misplace 0001-01-01, and this module must not construct a Date.
 */
function daysFromCivil(year: number, month: number, day: number): number {
  const y = year - (month <= 2 ? 1 : 0)
  const era = Math.floor(y / 400)
  const yoe = y - era * 400
  const doy = Math.floor((153 * (month + (month > 2 ? -3 : 9)) + 2) / 5) + day - 1
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy
  return era * 146097 + doe - 719468
}

/**
 * Parse an RFC 3339 instant strictly, for use at a security boundary.
 *
 * Returns the instant in milliseconds since the Unix epoch, or a reason. It
 * never returns NaN and never throws: a caller that ignores `ok` gets a type
 * error rather than a value that compares false in both directions.
 *
 * Invariants:
 *   - Only the grammar documented at the head of this module is accepted;
 *     an absent offset, a lowercase 'z', a date-only value, whitespace, or
 *     an empty string is `malformed`.
 *   - Every field is range-checked, so 2026-02-30 and 24:00:00 are
 *     `field_out_of_range` rather than instants.
 *   - Equal instants written with different offsets return the same `ms`.
 *   - Sub-millisecond digits are validated and then truncated away.
 */
export function parseRfc3339(value: unknown): Rfc3339ParseResult {
  if (typeof value !== 'string') return { ok: false, reason: 'not_a_string' }

  const m = RFC3339.exec(value)
  if (!m) return { ok: false, reason: 'malformed' }

  const year = Number(m[1])
  const month = Number(m[2])
  const day = Number(m[3])
  const hour = Number(m[4])
  const minute = Number(m[5])
  const second = Number(m[6])
  const frac = m[7]
  const zulu = m[8]
  const offsetSign = m[9]
  const offsetHour = m[10]
  const offsetMinute = m[11]

  if (second === 60) return { ok: false, reason: 'leap_second' }

  if (month < 1 || month > 12) return { ok: false, reason: 'field_out_of_range' }
  if (day < 1 || day > daysInMonth(year, month)) {
    return { ok: false, reason: 'field_out_of_range' }
  }
  if (hour > 23 || minute > 59 || second > 59) {
    return { ok: false, reason: 'field_out_of_range' }
  }

  let offsetSeconds = 0
  if (zulu === undefined) {
    const oh = Number(offsetHour)
    const om = Number(offsetMinute)
    if (oh > 23 || om > 59) return { ok: false, reason: 'field_out_of_range' }
    offsetSeconds = (oh * 3600 + om * 60) * (offsetSign === '-' ? -1 : 1)
  }

  // Truncate to millisecond granularity; pad so '.1' is 100ms, not 1ms.
  const millis = frac === undefined ? 0 : Number(frac.padEnd(3, '0').slice(0, 3))

  const days = daysFromCivil(year, month, day)
  const ms =
    (days * 86400 + hour * 3600 + minute * 60 + second - offsetSeconds) * 1000 + millis

  if (!Number.isSafeInteger(ms)) return { ok: false, reason: 'not_representable' }
  return { ok: true, ms }
}

/** Inverse of {@link daysFromCivil}: civil date from a day count. */
function civilFromDays(z: number): { year: number; month: number; day: number } {
  const zz = z + 719468
  const era = Math.floor(zz / 146097)
  const doe = zz - era * 146097
  const yoe = Math.floor(
    (doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365,
  )
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100))
  const mp = Math.floor((5 * doy + 2) / 153)
  const day = doy - Math.floor((153 * mp + 2) / 5) + 1
  const month = mp + (mp < 10 ? 3 : -9)
  const year = yoe + era * 400 + (month <= 2 ? 1 : 0)
  return { year, month, day }
}

function pad(n: number, width: number): string {
  return String(n).padStart(width, '0')
}

/**
 * Render an instant as the RFC 3339 UTC spelling this SDK emits:
 * YYYY-MM-DDTHH:MM:SS.sssZ, always three fractional digits.
 *
 * The counterpart to {@link parseRfc3339}, and byte-identical to
 * `new Date(ms).toISOString()` for every instant inside the four-digit-year
 * range — tests/rfc3339.test.ts pins that equality, so switching an emission
 * site to this function cannot move any artifact's bytes.
 *
 * It exists so that a file which verifies timestamps never has to construct
 * a Date at all. `new Date(x)` accepts a string as readily as a number, and
 * that ambiguity is the whole of F-04; `formatRfc3339` takes a `number`, so
 * handing it an artifact's field is a compile error rather than a silent
 * reparse. That is what lets the boundary guard ban `new Date(` outright
 * instead of trying to tell emission and interpretation apart by eye.
 *
 * @throws RangeError when `ms` is not a safe integer or falls outside the
 * representable four-digit-year range. An emission site holds an instant it
 * computed itself; a value that is not one is a bug at the caller, not an
 * untrusted input to be folded into a verdict.
 */
export function formatRfc3339(ms: number): string {
  if (!Number.isSafeInteger(ms) || ms < -62167219200000 || ms > 253402300799999) {
    throw new RangeError(`formatRfc3339: instant is not representable (${ms})`)
  }
  const days = Math.floor(ms / 86400000)
  const rest = ms - days * 86400000
  const { year, month, day } = civilFromDays(days)
  const hour = Math.floor(rest / 3600000)
  const minute = Math.floor((rest % 3600000) / 60000)
  const second = Math.floor((rest % 60000) / 1000)
  const millis = rest % 1000
  return (
    `${pad(year, 4)}-${pad(month, 2)}-${pad(day, 2)}` +
    `T${pad(hour, 2)}:${pad(minute, 2)}:${pad(second, 2)}.${pad(millis, 3)}Z`
  )
}
