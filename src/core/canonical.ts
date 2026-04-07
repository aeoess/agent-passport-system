// Canonical JSON — deterministic serialization for signing
// Sorts keys alphabetically, omits null/undefined in object keys (not arrays).
// SECURITY NOTE: Null-stripping is intentional and consistent across all APS implementations
// (SDK, Gateway, Python). {a:1} and {a:1,b:null} produce the same canonical form.
// This means no security-critical field should use null as a meaningful value.
// All implementations MUST strip nulls identically. See also: canonicalizeJCS() for RFC 8785.

import { createHash } from 'node:crypto'

export function canonicalize(obj: unknown, _seen?: WeakSet<object>): string {
  if (obj === null || obj === undefined) return 'null'
  if (obj instanceof Date) return JSON.stringify(obj)
  if (typeof obj !== 'object') return JSON.stringify(obj)
  // Cycle detection
  const seen = _seen ?? new WeakSet()
  if (seen.has(obj as object)) throw new Error('Circular reference detected in canonicalize()')
  seen.add(obj as object)
  if (Array.isArray(obj)) {
    return '[' + obj.map(item => canonicalize(item, seen)).join(',') + ']'
  }
  const sorted = Object.keys(obj as Record<string, unknown>)
    .sort()
    .filter(key => {
      const val = (obj as Record<string, unknown>)[key]
      return val !== null && val !== undefined
    })
    .map(key => {
      const val = (obj as Record<string, unknown>)[key]
      return `${JSON.stringify(key)}:${canonicalize(val, seen)}`
    })
  return '{' + sorted.join(',') + '}'
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

// normalizeTimestamp — force ISO 8601 second-precision UTC.
// Accepts any parseable timestamp; returns format: YYYY-MM-DDTHH:mm:ssZ
// Strips fractional seconds and normalizes timezone offsets to UTC.
// Thread claim (A2A#1672): action_ref timestamps are second-precision.
export function normalizeTimestamp(ts: string): string {
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) {
    throw new Error(`normalizeTimestamp: invalid timestamp "${ts}"`)
  }
  // ISO with milliseconds: 2026-04-05T03:39:31.123Z → strip ms
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z')
}
