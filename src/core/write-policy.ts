// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// APS write policy: admissibility rules applied at signing and new-write boundaries.
//
// This is a layer ABOVE canonicalization, not part of it. RFC 8785 canonicalization
// must stay able to canonicalize any valid binary64 number, so nothing here belongs
// inside canonicalizeJCS() or the legacy canonicalize().
//
// The rule refuses an integer-valued JSON number whose absolute value exceeds
// 9007199254740991, which is 2**53 minus 1. RFC 7493 (I-JSON) section 2.2 states that a
// sender cannot expect a receiver to treat integers outside that range exactly, and
// RECOMMENDS JSON strings where exact interchange is required. It recommends; it does
// not mandate. APS adopts the recommendation as a write rule: an exact large quantity is
// carried as a decimal string, which is what draft-pidlisnyi-aps-03 already does with
// "per_action":"5000".
//
// WRITE TIME ONLY. A verifier rebuilding the preimage of an artifact signed before this
// rule existed MUST NOT be given this check, or it would refuse bytes it accepted
// before. That is the highest-risk regression in this change, and it is why the guard
// sits on named producer functions rather than inside any canonicalizer.
//
// Deliberately narrower than assertIJson() in v2/receipt-core and v2/identity-binding.
// Those also reject any value outside a fixed JSON type set, including Date, which
// legacy signing payloads carry (canonical.ts accepts Date, and so does canonicalizeJCS).
// This one inspects numbers, recurses through containers, and leaves every other type
// alone, so adding it to an existing signing path cannot refuse a write that succeeds
// today for a reason unrelated to the number rule.

/** Largest integer magnitude that survives a binary64 round trip exactly. */
export const MAX_SAFE_WRITE_INTEGER = 9007199254740991

/** Stable machine-readable category for this write-policy refusal. */
export const UNSAFE_INTEGER_CATEGORY = 'invalid_number'

/** Stable machine-readable reason for this write-policy refusal. */
export const UNSAFE_INTEGER_REASON = 'integer_exceeds_interoperable_range'

/** A new-write value carries an integer outside the interoperable IEEE 754 range.
 *
 *  Extends Error with a stable category and reason so a caller can branch without
 *  parsing the message. The message names the JSON path of the offending member, which
 *  matches the Go SDK's ErrInvalidIJSON wording and the existing assertIJson message. */
export class UnsafeIntegerError extends Error {
  readonly category = UNSAFE_INTEGER_CATEGORY
  readonly reason = UNSAFE_INTEGER_REASON

  constructor(path: string) {
    super(`${path}: integer exceeds the interoperable IEEE 754 range`)
    this.name = 'UnsafeIntegerError'
  }
}

/** True when a number is integer-valued and outside the interoperable range.
 *
 *  Only integer-valued numbers are bounded. A fractional value carries no claim to
 *  exactness beyond the double itself, which is the same rule the Go SDK applies with
 *  math.Trunc(x) == x. */
export function isUnsafeWriteInteger(value: number): boolean {
  return (
    Number.isFinite(value) &&
    Number.isInteger(value) &&
    Math.abs(value) > MAX_SAFE_WRITE_INTEGER
  )
}

/** Throw UnsafeIntegerError if `value` carries an unsafe integer anywhere within it.
 *
 *  Recurses through arrays and plain objects so the rule applies to the whole artifact
 *  rather than only its top-level members. Values of any other type are left untouched.
 *
 *  LIMITATION, documented rather than discovered. This walks the value and the caller
 *  then canonicalizes it, so the value is read twice. For a plain JSON object that is
 *  immaterial. For an object carrying a getter or a Proxy that answers differently on a
 *  second read, an unsafe integer could pass this walk and still be signed. On the JCS
 *  path use canonicalizeJCSForWrite() from canonical-jcs.js instead, which performs the
 *  number check inside the single emitting walk and is not bypassable that way. On the
 *  legacy canonicalize() path this shape is forced, because that canonicalizer's bytes
 *  are frozen and it cannot be modified. */
export function assertWriteSafeNumbers(
  value: unknown,
  path = '$',
  ancestors: WeakSet<object> = new WeakSet(),
): void {
  if (value === null || value === undefined) return

  const t = typeof value
  if (t === 'number') {
    if (isUnsafeWriteInteger(value as number)) throw new UnsafeIntegerError(path)
    return
  }
  if (t !== 'object') return

  const obj = value as object
  if (obj instanceof Date) return
  if (ancestors.has(obj)) return
  ancestors.add(obj)

  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      assertWriteSafeNumbers(value[i], `${path}[${i}]`, ancestors)
    }
    ancestors.delete(obj)
    return
  }

  for (const key of Object.keys(obj as Record<string, unknown>)) {
    assertWriteSafeNumbers((obj as Record<string, unknown>)[key], `${path}.${key}`, ancestors)
  }
  ancestors.delete(obj)
}
