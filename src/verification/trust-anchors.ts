// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// One normalization for a caller-supplied trust-anchor list
// ══════════════════════════════════════════════════════════════════
// Two guards used to read the same option with OPPOSITE tests:
//
//   verify.ts        Boolean(opts?.trustedIssuers && opts.trustedIssuers.length > 0)
//   trust-posture.ts anchors.length === 0 && opts.allowSelfSigned !== true
//
// One is a positive test and the other an equality test, so any value whose
// `.length` is neither exactly 0 nor greater than 0 fell through BOTH into the
// permissive branch. `{}`, `NaN`, `0`, `true`, `new Map()` and
// `new Set(['key'])` all have `length === undefined`, and `undefined > 0` and
// `undefined === 0` are both false. Driven end to end, every gate in the SDK
// admitted a self-signed admin:everything passport when handed
// `trustedIssuers: {}` and said nothing about it.
//
// The Set case is what makes this more than a curiosity: holding trust anchors
// in a Set is a perfectly natural thing for an operator to do, and doing it
// silently disabled the check they were configuring.
//
// The lesson is not "fix the two guards to agree". It is that a security
// option must be normalized ONCE, at the boundary, into a shape the guards
// cannot disagree about. Both call sites now consume this function's output
// and neither tests `.length` on a caller-supplied value again.

/** A caller-supplied `trustedIssuers` value, resolved into something a guard
 *  can branch on without knowing what shape arrived. */
export interface NormalizedTrustAnchors {
  /** Usable anchors. ALWAYS an array, and always empty when `malformed`. */
  anchors: string[]
  /** True when the caller supplied a value that is not a usable anchor list.
   *  Distinct from an empty list: an empty list is a deliberate "no anchors",
   *  a malformed value is a configuration error that must not be read as
   *  either "no anchors" or "all anchors". */
  malformed: boolean
  /** Why the value is unusable. Present iff `malformed`. */
  reason?: string
}

function describe(value: unknown): string {
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'array'
  if (typeof value === 'number' && Number.isNaN(value)) return 'NaN'
  if (typeof value === 'object') return value.constructor?.name ?? 'object'
  return typeof value
}

/**
 * Normalize a caller-supplied trust-anchor list.
 *
 * `undefined` and `null` mean "no anchors configured", which is a legitimate
 * state that the gate then refuses to admit on without an explicit
 * `allowSelfSigned`. Anything that is not an array of non-empty strings is a
 * configuration error and is reported as malformed, never quietly coerced:
 * coercing it to `[]` would make a typo indistinguishable from a deliberate
 * empty list, and that is the same conflation this whole branch exists to
 * remove.
 *
 * Note on the string case specifically: a bare 64-character key string has a
 * numeric `.length`, so it passed the old `> 0` test, and the membership test
 * downstream was `String.prototype.includes`, i.e. SUBSTRING matching against
 * the issuer key. That is refused here too.
 */
export function normalizeTrustAnchors(value: unknown): NormalizedTrustAnchors {
  if (value === undefined || value === null) {
    return { anchors: [], malformed: false }
  }
  if (!Array.isArray(value)) {
    return {
      anchors: [],
      malformed: true,
      reason: `trustedIssuers must be an array of issuer public keys, received ${describe(value)}`,
    }
  }
  const bad = value.findIndex(entry => typeof entry !== 'string' || entry.length === 0)
  if (bad !== -1) {
    return {
      anchors: [],
      malformed: true,
      reason: `trustedIssuers[${bad}] is not a non-empty string (${describe(value[bad])})`,
    }
  }
  return { anchors: value as string[], malformed: false }
}
