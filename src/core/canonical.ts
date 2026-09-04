// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Canonical JSON — deterministic serialization for signing
// Sorts keys alphabetically, omits null/undefined in object keys (not arrays).
// SECURITY NOTE: Null-stripping is intentional and consistent across all APS implementations
// (SDK, Gateway, Python). {a:1} and {a:1,b:null} produce the same canonical form.
// This means no security-critical field should use null as a meaningful value.
// All implementations MUST strip nulls identically. See also: canonicalizeJCS() for RFC 8785.

import { createHash } from 'node:crypto'
import { isUnsafeWriteInteger, UnsafeIntegerError } from './write-policy.js'
import { parseRfc3339, formatRfc3339 } from './rfc3339.js'

export function canonicalize(obj: unknown, _ancestors?: WeakSet<object>): string {
  if (obj === null || obj === undefined) return 'null'
  if (obj instanceof Date) return JSON.stringify(obj)
  if (typeof obj !== 'object') return JSON.stringify(obj)
  // Cycle detection — path-scoped (only ancestors in current traversal path).
  // Shared sub-references that are not cycles MUST canonicalize successfully;
  // visit-scoped detection (tracking everything ever seen) over-rejected legitimate
  // structures like { x: leaf, y: leaf }. Output is unchanged for all cycle-free
  // inputs, so no canonical hashes change.
  const ancestors = _ancestors ?? new WeakSet()
  if (ancestors.has(obj as object)) throw new Error('Circular reference detected in canonicalize()')
  ancestors.add(obj as object)
  let result: string
  if (Array.isArray(obj)) {
    result = '[' + obj.map(item => canonicalize(item, ancestors)).join(',') + ']'
  } else {
    const sorted = Object.keys(obj as Record<string, unknown>)
      .sort()
      .filter(key => {
        const val = (obj as Record<string, unknown>)[key]
        return val !== null && val !== undefined
      })
      .map(key => {
        const val = (obj as Record<string, unknown>)[key]
        return `${JSON.stringify(key)}:${canonicalize(val, ancestors)}`
      })
    result = '{' + sorted.join(',') + '}'
  }
  ancestors.delete(obj as object)
  return result
}

/** Legacy canonicalization for a NEW WRITE, with the APS unsafe-integer rule applied.
 *
 *  Byte-identical to canonicalize() for every value it accepts: same key sort, same
 *  null and undefined stripping, same Date handling, same cycle rule. The only
 *  difference is that an integer-valued number outside the interoperable IEEE 754 range
 *  is refused rather than emitted. See core/write-policy.ts for the rule.
 *
 *  Use at signing and new-write boundaries ONLY. Verification, recompute and any path
 *  rebuilding the preimage of an existing artifact must keep calling canonicalize(),
 *  which stays unrestricted so historical bytes keep verifying.
 *
 *  READS EACH PROPERTY EXACTLY ONCE. canonicalize() above reads obj[key] twice, once in
 *  its filter and once in its map, so a standalone validator in front of it would make a
 *  third read and a getter or Proxy could answer safe, safe, then unsafe. Here the value
 *  is captured once into `val`, checked, and emitted from that same capture, so the
 *  value checked is the value signed. Do not refactor this back into filter plus map. */
export function canonicalizeForWrite(
  obj: unknown,
  path = '$',
  _ancestors?: WeakSet<object>,
): string {
  if (obj === null || obj === undefined) return 'null'
  if (obj instanceof Date) return JSON.stringify(obj)
  if (typeof obj !== 'object') {
    if (typeof obj === 'number' && isUnsafeWriteInteger(obj)) throw new UnsafeIntegerError(path)
    return JSON.stringify(obj)
  }
  const ancestors = _ancestors ?? new WeakSet()
  if (ancestors.has(obj as object)) {
    throw new Error('Circular reference detected in canonicalizeForWrite()')
  }
  ancestors.add(obj as object)
  let result: string
  if (Array.isArray(obj)) {
    result =
      '[' +
      obj.map((item, i) => canonicalizeForWrite(item, `${path}[${i}]`, ancestors)).join(',') +
      ']'
  } else {
    const rec = obj as Record<string, unknown>
    const pairs: string[] = []
    for (const key of Object.keys(rec).sort()) {
      const val = rec[key] // the single read; everything below uses this capture
      if (val === null || val === undefined) continue
      pairs.push(`${JSON.stringify(key)}:${canonicalizeForWrite(val, `${path}.${key}`, ancestors)}`)
    }
    result = '{' + pairs.join(',') + '}'
  }
  ancestors.delete(obj as object)
  return result
}

// canonicalJson — deterministic JSON serialization of an object.
// Same semantics as canonicalize() but typed to objects for cross-system
// receipt comparison (action_ref, compound_digest, etc.)
export function canonicalJson(obj: Record<string, unknown>): string {
  return canonicalize(obj)
}

// canonicalHash — SHA-256 of canonicalJson(obj), returned as lowercase hex.
export function canonicalHash(obj: Record<string, unknown>): string {
  return createHash('sha256').update(canonicalJson(obj)).digest('hex')
}

/** Write-boundary twin of canonicalHash().
 *
 *  Reaches a canonicalizer indirectly through canonicalJson(), so a census over direct
 *  canonicalizer calls cannot see it. Same digest as canonicalHash() for every value it
 *  accepts; the only difference is that an integer-valued number outside the
 *  interoperable IEEE 754 range is refused instead of hashed. Use at signing and
 *  new-write boundaries ONLY: canonicalHash() stays unrestricted because verifiers
 *  recompute commitments with it over artifacts committed before this rule. */
export function canonicalHashForWrite(obj: Record<string, unknown>): string {
  return createHash('sha256').update(canonicalizeForWrite(obj)).digest('hex')
}

// normalizeTimestamp — force ISO 8601 second-precision UTC.
// Accepts RFC 3339 with an explicit offset or Z; returns YYYY-MM-DDTHH:mm:ssZ.
// Strips fractional seconds and normalizes timezone offsets to UTC.
// Thread claim (A2A#1672): action_ref timestamps are second-precision.
//
// The offset is REQUIRED, and that is the point of this function's strictness.
// Its only caller is the legacy computeActionRef, whose output is a content
// address that lands inside signed bytes and keys the idempotency reservation.
// `new Date('2026-04-05T03:39:31')` reads a zone-less value in the machine's
// LOCAL zone, so the same intent produced one action_ref in UTC and another
// nine hours away in Asia/Tokyo. A content address that depends on where it was
// computed is not an address. Two writers could reserve the same action twice,
// or one could fail to match its own earlier reservation.
//
// Parsing goes through parseRfc3339 so the accepted set is the one this SDK
// already ratified, rather than whatever the JavaScript Date constructor
// happens to take: a date-only value, an impossible day like 2026-02-30 that
// Date rolls into March, and hour 24 are all refused here and were all accepted
// before. Lowercase `t` and `z` stay accepted, because RFC 3339 section 5.6
// permits them and parseRfc3339 takes them; this function does not get to be
// stricter than the parser the rest of the SDK verifies against.
//
// Nothing that already produced an address changes its address. Every input
// with an explicit offset or Z that parsed before produces the same output,
// pinned by test against values captured from the previous implementation.
//
// It throws rather than returning a result, unchanged: this is a derivation
// helper, not a verifier, and a caller that cannot derive an address has
// nothing to carry on with.
export function normalizeTimestamp(ts: string): string {
  const parsed = parseRfc3339(ts)
  if (!parsed.ok) {
    throw new Error(
      `normalizeTimestamp: invalid timestamp "${ts}" (${parsed.reason}). ` +
      'Requires RFC 3339 with an explicit offset or Z: a zone-less value names ' +
      'no instant, so it would produce a different action_ref on every machine.',
    )
  }
  // formatRfc3339 emits .sssZ; action_ref timestamps are second-precision.
  return formatRfc3339(parsed.ms).replace(/\.\d{3}Z$/, 'Z')
}
