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

/** RFC 8785 JSON Canonicalization Scheme.
 *  Differences from legacy canonicalize():
 *  - null values ARE preserved (not filtered)
 *  - undefined object values become null
 *  - Number serialization follows ES2015 spec
 *  - All other behavior is identical (sorted keys, no whitespace) */
export function canonicalizeJCS(value: unknown): string {
  if (value === null || value === undefined) return 'null'

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false'
    case 'number': {
      if (!isFinite(value)) throw new Error('JCS does not support Infinity or NaN')
      // ES2015 number serialization — JSON.stringify handles this correctly
      return JSON.stringify(value)
    }
    case 'string':
      return JSON.stringify(value)
    case 'object': {
      if (value instanceof Date) return JSON.stringify(value)
      if (Array.isArray(value)) {
        return '[' + value.map(item => canonicalizeJCS(item)).join(',') + ']'
      }
      // Object: sort keys by Unicode code point, preserve null values
      const obj = value as Record<string, unknown>
      const keys = Object.keys(obj).sort()
      const pairs: string[] = []
      for (const key of keys) {
        const v = obj[key]
        // RFC 8785: undefined becomes null, null is preserved
        // Only skip if the key was never set (shouldn't happen with Object.keys)
        pairs.push(`${JSON.stringify(key)}:${canonicalizeJCS(v)}`)
      }
      return '{' + pairs.join(',') + '}'
    }
    default:
      throw new Error(`JCS: unsupported type ${typeof value}`)
  }
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
  addVector('cv-003', 'Keys sorted by Unicode code point',
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
