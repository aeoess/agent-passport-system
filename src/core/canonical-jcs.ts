// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// JCS Canonicalization — RFC 8785 compliant JSON Canonicalization
// ══════════════════════════════════════════════════════════════════
// The original canonicalize() filters null values — a deviation from
// RFC 8785 that cannot be changed without breaking existing signatures.
//
// This module provides:
//   canonicalizeJCS() — strict RFC 8785 compliance
//   verifyCanonical()  — detect which variant was used
//
// Migration: new signatures should use JCS. Old signatures keep
// working with the legacy function. Verification tries both.
// ══════════════════════════════════════════════════════════════════

/** Raised when a value cannot be canonicalized under RFC 8785. Subclasses the
 *  built-in Error that canonicalizeJCS already throws, so any existing handler
 *  that catches Error (or `catch (e)`) still catches it and fails closed. */
export class JcsCanonicalizationError extends Error {
  readonly code: string
  /** Stable machine-readable category, shared across the APS SDKs. */
  readonly category = 'invalid_unicode'
  /** Specific failure within the category, e.g. 'lone_surrogate'. */
  readonly reason: string
  constructor(code: string, message: string, reason = 'lone_surrogate') {
    super(message)
    this.name = 'JcsCanonicalizationError'
    this.code = code
    this.reason = reason
  }
}

/** Reject a string containing an unpaired UTF-16 surrogate: a high surrogate
 *  (U+D800..U+DBFF) not immediately followed by a low surrogate (U+DC00..U+DFFF),
 *  or a low surrogate not immediately preceded by a high one. A lone surrogate is
 *  not a valid Unicode scalar and has no UTF-8 encoding, so RFC 8785 requires
 *  rejecting the input rather than escaping it. A valid surrogate PAIR passes. */
function assertNoLoneSurrogate(s: string): void {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0
      if (next >= 0xdc00 && next <= 0xdfff) { i++; continue } // valid pair
      throw new JcsCanonicalizationError('ERR_JCS_LONE_SURROGATE', 'canonicalizeJCS: string contains an unpaired UTF-16 high surrogate; a lone surrogate has no valid UTF-8 encoding and RFC 8785 requires rejection')
    }
    if (c >= 0xdc00 && c <= 0xdfff) {
      throw new JcsCanonicalizationError('ERR_JCS_LONE_SURROGATE', 'canonicalizeJCS: string contains an unpaired UTF-16 low surrogate; a lone surrogate has no valid UTF-8 encoding and RFC 8785 requires rejection')
    }
  }
}

/** RFC 8785 JSON Canonicalization Scheme.
 *  Differences from legacy canonicalize():
 *  - null values ARE preserved (not filtered)
 *  - undefined is REJECTED at any depth with a TypeError naming its path.
 *    undefined is not a JSON value and RFC 8785 defines no canonical form for
 *    it, so coercing it would sign a value the caller never wrote (#101).
 *    A caller that needs the byte null on the wire passes an explicit null.
 *  - Number serialization follows ES2015 spec
 *  - All other behavior is identical (sorted keys, no whitespace)
 *
 *  The undefined walk runs ONCE here, over the whole value, before any byte is
 *  emitted. canonicalizeValue() below is the recursive emitter and does not
 *  re-assert: folding the walk into the recursion would rescan every subtree at
 *  every depth and make canonicalization O(n * depth). */
export function canonicalizeJCS(value: unknown): string {
  assertNoUndefined(value, '$')
  return canonicalizeValue(value)
}

/** RFC 8785 canonicalization for a NEW WRITE, with the APS unsafe-integer rule applied.
 *
 *  Byte-identical to canonicalizeJCS() for every value it accepts. The only difference
 *  is that an integer-valued number outside the interoperable IEEE 754 range is refused
 *  rather than emitted. See core/write-policy.ts for the rule and its rationale.
 *
 *  Use this at signing and new-write boundaries only. A verifier rebuilding the preimage
 *  of an artifact signed before this rule existed must keep calling canonicalizeJCS(),
 *  or it would refuse bytes it accepted before.
 *
 *  The number check runs INSIDE the emitting walk, on the same read that produces the
 *  byte, so a getter or Proxy that answers differently on a second read cannot slip an
 *  unsafe integer past it. Note the pre-existing assertNoUndefined() walk is still a
 *  separate traversal; that exposure predates this change and is not addressed here. */
export function canonicalizeJCSForWrite(value: unknown): string {
  return canonicalizeValue(value, '$')
}

/** Recursive RFC 8785 emitter. Precondition: the value already passed
 *  assertNoUndefined(), so undefined cannot appear here. If one appears anyway,
 *  for instance from a getter that answers differently on a second read, the
 *  default branch throws rather than silently emitting null. */
function canonicalizeValue(value: unknown, writePath?: string): string {
  if (value === null) return 'null'
  // Write path only: reject undefined here rather than in a separate pre-pass, so the
  // whole traversal reads each property exactly once. Same message and path format as
  // assertNoUndefined(), which still guards the ordinary read path above.
  if (writePath !== undefined && value === undefined) {
    throw new TypeError(`canonicalizeJCS: undefined at ${writePath}`)
  }

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false'
    case 'number': {
      if (!isFinite(value)) throw new Error('JCS does not support Infinity or NaN')
      // Write-policy check, threaded from canonicalizeJCSForWrite(). Undefined on the
      // ordinary canonicalizeJCS() path, which stays byte-identical and unrestricted.
      if (writePath !== undefined && isUnsafeWriteInteger(value)) {
        throw new UnsafeIntegerError(writePath)
      }
      // ES2015 number serialization — JSON.stringify handles this correctly
      return JSON.stringify(value)
    }
    case 'string':
      assertNoLoneSurrogate(value)
      return JSON.stringify(value)
    case 'object': {
      if (value instanceof Date) return JSON.stringify(value)
      if (Array.isArray(value)) {
        if (writePath !== undefined) {
          const parts: string[] = []
          for (let i = 0; i < value.length; i++) {
            parts.push(canonicalizeValue(value[i], `${writePath}[${i}]`))
          }
          return '[' + parts.join(',') + ']'
        }
        return '[' + value.map(item => canonicalizeValue(item)).join(',') + ']'
      }
      // Object: sort keys as UTF-16 code unit arrays per RFC 8785 3.2.3, preserve null values
      const obj = value as Record<string, unknown>
      const keys = Object.keys(obj).sort()
      const pairs: string[] = []
      for (const key of keys) {
        assertNoLoneSurrogate(key)
        const v = obj[key]
        pairs.push(`${JSON.stringify(key)}:${canonicalizeValue(
          v, writePath === undefined ? undefined : `${writePath}.${key}`,
        )}`)
      }
      return '{' + pairs.join(',') + '}'
    }
    default:
      throw new Error(`JCS: unsupported type ${typeof value}`)
  }
}

/** Path-tracking walk that rejects `undefined` anywhere in the value.
 *  RFC 8785 canonicalizes JSON data, and `undefined` is not a JSON value, so
 *  there is no defined canonical form for it. Rather than coerce it, which
 *  would silently turn one value into a different one before the bytes are
 *  signed, canonicalizeJCS() names the exact location and refuses. */
function assertNoUndefined(value: unknown, path: string): void {
  if (value === undefined) {
    throw new TypeError(`canonicalizeJCS: undefined at ${path}`)
  }
  if (value === null || typeof value !== 'object') return
  if (value instanceof Date) return
  if (Array.isArray(value)) {
    // An array hole and an explicit undefined element both read as undefined
    // here, which is the intended rejection: neither has a JSON encoding.
    for (let i = 0; i < value.length; i++) assertNoUndefined(value[i], `${path}[${i}]`)
    return
  }
  const obj = value as Record<string, unknown>
  for (const key of Object.keys(obj)) assertNoUndefined(obj[key], `${path}.${key}`)
}

/** @deprecated canonicalizeJCS() is itself strict as of #101; this alias exists only so the name keeps resolving. */
export function canonicalizeJCSStrict(value: unknown): string {
  return canonicalizeJCS(value)
}

/** Detect which canonicalization variant was likely used.
 *  Checks if null values are present — JCS preserves them, legacy strips them. */
export function detectCanonicalVariant(
  obj: unknown,
  canonicalString: string,
): 'jcs' | 'legacy' | 'ambiguous' {
  // If the object has no null values, both variants produce identical output
  if (!hasNullValues(obj)) return 'ambiguous'
  // If canonical string contains `:null`, it's JCS (legacy strips nulls)
  if (canonicalString.includes(':null')) return 'jcs'
  return 'legacy'
}

function hasNullValues(obj: unknown): boolean {
  if (obj === null) return true
  if (typeof obj !== 'object' || obj === undefined) return false
  if (Array.isArray(obj)) return obj.some(hasNullValues)
  return Object.values(obj as Record<string, unknown>).some(v =>
    v === null || v === undefined || hasNullValues(v))
}

import { createHash } from 'crypto'
import { isUnsafeWriteInteger, UnsafeIntegerError } from './write-policy.js'

/** Cross-language test vector for canonicalization verification */
export interface CanonicalizationTestVector {
  id: string
  description: string
  input: unknown
  expected_jcs: string
  expected_legacy: string
  sha256_jcs: string
  sha256_legacy: string
}

/** Generate SHA-256 hex digest of a string */
function sha256hex(input: string): string {
  return createHash('sha256').update(input, 'utf-8').digest('hex')
}

/** SHA-256 (lowercase hex) of canonicalizeJCS(obj). Strict-RFC-8785
 *  counterpart of canonicalHash() from ./canonical.ts. Use this for any
 *  cross-implementation hash whose conformance pin requires strict JCS
 *  (e.g. action_ref per draft-pidlisnyi-aps-01 §4.1). */
export function canonicalHashJCS(obj: Record<string, unknown>): string {
  return sha256hex(canonicalizeJCS(obj))
}

/** Built-in test vectors for cross-language verification */
export function getTestVectors(): CanonicalizationTestVector[] {
  const vectors: CanonicalizationTestVector[] = []

  function addVector(id: string, desc: string, input: unknown, jcs: string, legacy: string) {
    vectors.push({
      id, description: desc, input,
      expected_jcs: jcs, expected_legacy: legacy,
      sha256_jcs: sha256hex(jcs), sha256_legacy: sha256hex(legacy),
    })
  }

  // V1: Simple object — both variants identical
  addVector('cv-001', 'Simple object, no nulls — variants identical',
    { agentId: 'agent-001', scope: 'read' },
    '{"agentId":"agent-001","scope":"read"}',
    '{"agentId":"agent-001","scope":"read"}')

  // V2: Object with null — variants diverge
  addVector('cv-002', 'Null value — JCS preserves, legacy strips',
    { agentId: 'agent-001', metadata: null, scope: 'read' },
    '{"agentId":"agent-001","metadata":null,"scope":"read"}',
    '{"agentId":"agent-001","scope":"read"}')

  // V3: Key ordering
  addVector('cv-003', 'Keys sorted by UTF-16 code units',
    { zebra: 1, alpha: 2, middle: 3 },
    '{"alpha":2,"middle":3,"zebra":1}',
    '{"alpha":2,"middle":3,"zebra":1}')

  // V4: Nested objects with null
  addVector('cv-004', 'Nested object with null at depth',
    { outer: { inner: null, value: 42 }, top: 'ok' },
    '{"outer":{"inner":null,"value":42},"top":"ok"}',
    '{"outer":{"value":42},"top":"ok"}')

  // V5: Arrays with null elements
  addVector('cv-005', 'Array with null elements — both preserve array nulls',
    { items: [1, null, 3] },
    '{"items":[1,null,3]}',
    '{"items":[1,null,3]}')

  // V6: Number edge cases
  addVector('cv-006', 'Number formatting — integers and floats',
    { integer: 42, negative: -7, float: 3.14, zero: 0 },
    '{"float":3.14,"integer":42,"negative":-7,"zero":0}',
    '{"float":3.14,"integer":42,"negative":-7,"zero":0}')

  // V7: Empty structures
  addVector('cv-007', 'Empty object and empty array',
    { emptyArr: [], emptyObj: {} },
    '{"emptyArr":[],"emptyObj":{}}',
    '{"emptyArr":[],"emptyObj":{}}')

  // V8: Unicode
  addVector('cv-008', 'Unicode string content',
    { name: 'Тимофій', emoji: '🔐' },
    '{"emoji":"🔐","name":"Тимофій"}',
    '{"emoji":"🔐","name":"Тимофій"}')

  // V9: Realistic APS object — delegation-like structure
  addVector('cv-009', 'Realistic delegation object with mixed null/present fields',
    {
      delegationId: 'del_abc123',
      delegatedBy: 'did:aps:principal001',
      delegatedTo: 'did:aps:agent002',
      scope: ['data:read', 'commerce:checkout'],
      spendLimit: 500,
      obligationBundleHash: null,
      expiresAt: '2026-04-01T00:00:00Z',
      notBefore: null,
      maxDepth: 3,
      currentDepth: 1,
      createdAt: '2026-03-29T00:00:00Z',
    },
    '{"createdAt":"2026-03-29T00:00:00Z","currentDepth":1,"delegatedBy":"did:aps:principal001","delegatedTo":"did:aps:agent002","delegationId":"del_abc123","expiresAt":"2026-04-01T00:00:00Z","maxDepth":3,"notBefore":null,"obligationBundleHash":null,"scope":["data:read","commerce:checkout"],"spendLimit":500}',
    '{"createdAt":"2026-03-29T00:00:00Z","currentDepth":1,"delegatedBy":"did:aps:principal001","delegatedTo":"did:aps:agent002","delegationId":"del_abc123","expiresAt":"2026-04-01T00:00:00Z","maxDepth":3,"scope":["data:read","commerce:checkout"],"spendLimit":500}')

  // V10: Boolean values
  addVector('cv-010', 'Boolean values',
    { active: true, revoked: false },
    '{"active":true,"revoked":false}',
    '{"active":true,"revoked":false}')

  return vectors
}
