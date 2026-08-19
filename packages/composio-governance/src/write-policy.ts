// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// APS write policy, package-local copy of the new-write admissibility rule.
//
// This adapter signs APS ActionReceipts, so it is a new-write boundary and the rule
// applies to it. It cannot import the SDK's internal write canonicalizer, because that
// helper is deliberately NOT part of the published surface of agent-passport-system:
// package.json exposes only "." and "./core", and neither exports it. Re-exporting it
// to serve this package would create public API, which is a separate decision.
//
// So the rule is restated here, in the same shape any external consumer needs today.
// It VALIDATES ONLY and never serializes, so the canonical bytes this adapter signs are
// exactly the bytes it signed before: canonicalize() from the SDK still produces them.
//
// Rule: at a new-write boundary, refuse an integer-valued JSON number whose absolute
// value exceeds 9007199254740991, which is 2**53 minus 1. RFC 7493 section 2.2 states a
// sender cannot expect a receiver to treat integers outside that range exactly.

/** Largest integer magnitude that survives a binary64 round trip exactly. */
export const MAX_SAFE_WRITE_INTEGER = 9007199254740991

/** A new-write value carries an integer outside the interoperable IEEE 754 range. */
export class UnsafeIntegerError extends Error {
  readonly category = 'invalid_number'
  readonly reason = 'integer_exceeds_interoperable_range'

  constructor(path: string) {
    super(`${path}: integer exceeds the interoperable IEEE 754 range`)
    this.name = 'UnsafeIntegerError'
  }
}

/** Throw if `value` carries an integer-valued number outside the interoperable range.
 *
 *  Validation only: the caller still serializes with the SDK's canonicalize(), so no
 *  byte this adapter signs changes for a value the rule accepts. */
export function assertWriteSafeNumbers(
  value: unknown,
  path = '$',
  ancestors: WeakSet<object> = new WeakSet(),
): void {
  if (value === null || value === undefined) return

  const t = typeof value
  if (t === 'number') {
    const n = value as number
    if (Number.isFinite(n) && Number.isInteger(n) && Math.abs(n) > MAX_SAFE_WRITE_INTEGER) {
      throw new UnsafeIntegerError(path)
    }
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
  } else {
    for (const key of Object.keys(obj as Record<string, unknown>)) {
      assertWriteSafeNumbers((obj as Record<string, unknown>)[key], `${path}.${key}`, ancestors)
    }
  }
  ancestors.delete(obj)
}
