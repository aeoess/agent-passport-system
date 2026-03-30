// ══════════════════════════════════════════════════════════════════
// JCS Canonicalization (RFC 8785) — Tests
// ══════════════════════════════════════════════════════════════════
// Validates: RFC 8785 compliance, null handling difference from legacy,
// cross-language test vector generation, variant detection.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { canonicalize } from '../src/core/canonical.js'
import {
  canonicalizeJCS, detectCanonicalVariant, getTestVectors,
} from '../src/core/canonical-jcs.js'
import { createHash } from 'crypto'

function sha256(s: string): string {
  return createHash('sha256').update(s, 'utf-8').digest('hex')
}

describe('JCS Canonicalization — RFC 8785 Compliance', () => {
  it('sorts keys by Unicode code point', () => {
    const result = canonicalizeJCS({ z: 1, a: 2, m: 3 })
    assert.strictEqual(result, '{"a":2,"m":3,"z":1}')
  })

  it('preserves null values (RFC 8785 requirement)', () => {
    const result = canonicalizeJCS({ a: 1, b: null, c: 3 })
    assert.strictEqual(result, '{"a":1,"b":null,"c":3}')
  })

  it('legacy canonicalize strips null values', () => {
    const result = canonicalize({ a: 1, b: null, c: 3 })
    assert.strictEqual(result, '{"a":1,"c":3}')
  })

  it('handles undefined as null in JCS', () => {
    const result = canonicalizeJCS({ a: 1, b: undefined })
    assert.strictEqual(result, '{"a":1,"b":null}')
  })

  it('handles nested objects recursively', () => {
    const result = canonicalizeJCS({ outer: { z: 1, a: 2 } })
    assert.strictEqual(result, '{"outer":{"a":2,"z":1}}')
  })

  it('handles arrays (preserves order, null elements kept)', () => {
    const result = canonicalizeJCS([1, null, 'three'])
    assert.strictEqual(result, '[1,null,"three"]')
  })

  it('handles empty structures', () => {
    assert.strictEqual(canonicalizeJCS({}), '{}')
    assert.strictEqual(canonicalizeJCS([]), '[]')
  })

  it('handles booleans', () => {
    assert.strictEqual(canonicalizeJCS(true), 'true')
    assert.strictEqual(canonicalizeJCS(false), 'false')
  })

  it('handles numbers', () => {
    assert.strictEqual(canonicalizeJCS(42), '42')
    assert.strictEqual(canonicalizeJCS(-7), '-7')
    assert.strictEqual(canonicalizeJCS(3.14), '3.14')
    assert.strictEqual(canonicalizeJCS(0), '0')
  })

  it('rejects Infinity and NaN', () => {
    assert.throws(() => canonicalizeJCS(Infinity), /JCS does not support/)
    assert.throws(() => canonicalizeJCS(NaN), /JCS does not support/)
  })

  it('handles strings with special characters', () => {
    assert.strictEqual(canonicalizeJCS('hello "world"'), '"hello \\"world\\""')
  })
})

describe('JCS — Cross-Language Test Vectors', () => {
  const vectors = getTestVectors()

  it('has 10 test vectors', () => {
    assert.strictEqual(vectors.length, 10)
  })

  for (const v of vectors) {
    it(`${v.id}: JCS output matches expected — ${v.description}`, () => {
      const result = canonicalizeJCS(v.input)
      assert.strictEqual(result, v.expected_jcs, `JCS mismatch for ${v.id}`)
    })

    it(`${v.id}: legacy output matches expected — ${v.description}`, () => {
      const result = canonicalize(v.input)
      assert.strictEqual(result, v.expected_legacy, `Legacy mismatch for ${v.id}`)
    })

    it(`${v.id}: SHA-256 hashes match`, () => {
      const jcsHash = sha256(canonicalizeJCS(v.input))
      const legacyHash = sha256(canonicalize(v.input))
      assert.strictEqual(jcsHash, v.sha256_jcs, `JCS hash mismatch for ${v.id}`)
      assert.strictEqual(legacyHash, v.sha256_legacy, `Legacy hash mismatch for ${v.id}`)
    })
  }
})

describe('JCS — Variant Detection', () => {
  it('detects JCS when null values present in output', () => {
    const obj = { a: 1, b: null }
    const jcs = canonicalizeJCS(obj)
    assert.strictEqual(detectCanonicalVariant(obj, jcs), 'jcs')
  })

  it('detects legacy when null values stripped', () => {
    const obj = { a: 1, b: null }
    const legacy = canonicalize(obj)
    assert.strictEqual(detectCanonicalVariant(obj, legacy), 'legacy')
  })

  it('returns ambiguous when no null values in object', () => {
    const obj = { a: 1, b: 2 }
    const result = canonicalize(obj) // same as JCS for this input
    assert.strictEqual(detectCanonicalVariant(obj, result), 'ambiguous')
  })
})

describe('JCS — Agreement with Legacy', () => {
  it('JCS and legacy produce identical output when no null/undefined values', () => {
    const testCases = [
      { a: 1, b: 'hello', c: [1, 2, 3] },
      { nested: { x: true, y: false }, arr: ['a', 'b'] },
      { empty: {}, list: [], num: 3.14 },
      42,
      'simple string',
      [1, 2, 3],
      true,
    ]
    for (const tc of testCases) {
      assert.strictEqual(
        canonicalizeJCS(tc), canonicalize(tc),
        `Mismatch on ${JSON.stringify(tc)}`,
      )
    }
  })
})
