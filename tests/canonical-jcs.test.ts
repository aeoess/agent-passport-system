// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// JCS Canonicalization (RFC 8785) — Tests
// ══════════════════════════════════════════════════════════════════
// Validates: RFC 8785 compliance, null handling difference from legacy,
// cross-language test vector generation, variant detection.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { canonicalize } from '../src/core/canonical.js'
import {
  canonicalizeJCS, canonicalizeJCSStrict, detectCanonicalVariant, getTestVectors,
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

  it('rejects undefined in JCS rather than coercing it to null (#101)', () => {
    // Behavior change in #101. This previously returned '{"a":1,"b":null}',
    // which signed a JSON value the caller never wrote. A caller that wants
    // the byte null on the wire now passes an explicit null.
    assert.throws(
      () => canonicalizeJCS({ a: 1, b: undefined }),
      (e: unknown) =>
        e instanceof TypeError && e.message === 'canonicalizeJCS: undefined at $.b',
    )
    assert.strictEqual(canonicalizeJCS({ a: 1, b: null }), '{"a":1,"b":null}')
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

describe('JCS Nested-Attestation Path Vectors (W2-A3)', () => {
  // The cv-011..cv-015 vectors live in the canonicalization spec JSON, not
  // in the frozen getTestVectors() helper (src/core/canonical-jcs.ts must
  // stay byte-identical to main). Load them from the spec at test time.
  // The test working directory is the repo root.
  interface SpecVector {
    id: string
    description: string
    input: unknown
    expected_jcs: string
    expected_legacy: string
    sha256_jcs: string
    sha256_legacy: string
  }
  const specVectors = JSON.parse(
    readFileSync('specs/test-vectors-canonicalization.json', 'utf-8'),
  ) as SpecVector[]
  const vectors = specVectors.filter(
    v => ['cv-011', 'cv-012', 'cv-013', 'cv-014', 'cv-015'].includes(v.id),
  )
  const byId = (id: string) => {
    const v = vectors.find(x => x.id === id)
    assert.ok(v, `vector ${id} must exist`)
    return v!
  }

  // ── Positive: every nested-attestation vector round-trips byte-identically ──
  for (const id of ['cv-011', 'cv-012', 'cv-013', 'cv-014', 'cv-015']) {
    it(`${id}: round-trips byte-identically through canonicalizeJCS`, () => {
      const v = byId(id)
      assert.strictEqual(canonicalizeJCS(v.input), v.expected_jcs)
      // Hash pin: the SHA-256 of the canonical bytes is fixed by the vector.
      assert.strictEqual(sha256(canonicalizeJCS(v.input)), v.sha256_jcs)
    })
  }

  it('cv-012/cv-013/cv-014: null-at-depth forks JCS (preserves) from legacy (strips)', () => {
    // These three carry a null inside a nested object: JCS keeps it,
    // legacy strips it. The whole point of pinning the divergence.
    for (const id of ['cv-012', 'cv-013', 'cv-014']) {
      const v = byId(id)
      assert.notStrictEqual(
        canonicalizeJCS(v.input), canonicalize(v.input),
        `${id} JCS and legacy must diverge (null at depth)`,
      )
      assert.strictEqual(canonicalize(v.input), v.expected_legacy)
      assert.notStrictEqual(v.sha256_jcs, v.sha256_legacy)
    }
  })

  it('cv-011/cv-015: all-present / absent-key forms agree across JCS and legacy', () => {
    // No null anywhere (predictionError / delegation_expires_at are simply
    // ABSENT, not null), so JCS and legacy produce identical bytes.
    for (const id of ['cv-011', 'cv-015']) {
      const v = byId(id)
      assert.strictEqual(canonicalizeJCS(v.input), canonicalize(v.input))
      assert.strictEqual(v.sha256_jcs, v.sha256_legacy)
    }
  })

  // ── Negative: present-as-null where the field should be OMITTED ──
  // This is the exact silent fork the vectors guard against. An optional
  // nested field that one implementation omits and another writes as
  // explicit null must NOT canonicalize to the same bytes under JCS.
  it('NEGATIVE: predictionError present-as-null does NOT match the absent (omitted) form', () => {
    const absent = byId('cv-011').input // predictionError omitted entirely
    // Mis-canonicalized variant: the optional nested field written as null.
    const presentAsNull = {
      witnessAttestation: {
        attestation: { constraintsVerified: true, executionObserved: true, receiptConsistent: true },
        attestedAt: '2026-05-01T00:00:00Z',
        observationBasis: 'direct_observation',
        predictionError: null, // WRONG: should be omitted, not null
        receiptHash: 'sha256:abc',
        receiptId: 'rcpt-001',
        signature: 'sig-w1',
        witnessId: 'wit-001',
        witnessRole: 'notary',
      },
    }
    const absentBytes = canonicalizeJCS(absent)
    const nullBytes = canonicalizeJCS(presentAsNull)
    assert.notStrictEqual(
      nullBytes, absentBytes,
      'present-as-null must fork from omitted under JCS; this is the divergence the vectors pin',
    )
    // And the omitted form must equal the pinned cv-011 bytes exactly.
    assert.strictEqual(absentBytes, byId('cv-011').expected_jcs)
    // Legacy collapses the two (it strips null), which is precisely why
    // strict JCS is required for the nested-attestation signature fabric.
    assert.strictEqual(canonicalize(presentAsNull), canonicalize(absent))
  })

  it('NEGATIVE: authority_state_at_admission with delegation_expires_at null forks from the absent form', () => {
    const absent = byId('cv-015').input // delegation_expires_at omitted
    const presentAsNull = {
      authority_state_at_admission: {
        checked_at: '2026-05-01T00:00:00Z',
        delegation_expires_at: null, // WRONG: should be omitted when unknown
        delegation_revoked: false,
        source: 'aps_admission',
      },
    }
    assert.notStrictEqual(
      canonicalizeJCS(presentAsNull), canonicalizeJCS(absent),
      'explicit null expiry must not equal the omitted-key signed bytes under JCS',
    )
    assert.strictEqual(canonicalizeJCS(absent), byId('cv-015').expected_jcs)
  })

  it('NEGATIVE: a tampered expected_jcs string does not match the canonical output', () => {
    // Guards the mirror: if someone hand-edits a vector string wrong, the
    // round-trip catches it. We assert the genuine pin holds, then that a
    // mutated copy fails.
    const v = byId('cv-013')
    assert.strictEqual(canonicalizeJCS(v.input), v.expected_jcs)
    const tampered = v.expected_jcs.replace('"divergenceDetails":null,', '')
    assert.notStrictEqual(canonicalizeJCS(v.input), tampered)
  })
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

describe('canonicalizeJCS and its deprecated alias reject undefined at any depth', () => {
  it('throws TypeError for top-level undefined and names the root path', () => {
    assert.throws(
      () => canonicalizeJCSStrict(undefined),
      (e: unknown) => e instanceof TypeError
        && (e as Error).message === 'canonicalizeJCS: undefined at $',
    )
    // As of #101 canonicalizeJCS is itself strict, and canonicalizeJCSStrict is
    // a deprecated alias for it, so the two now agree on rejection.
    assert.throws(
      () => canonicalizeJCS(undefined),
      (e: unknown) => e instanceof TypeError
        && (e as Error).message === 'canonicalizeJCS: undefined at $',
    )
  })

  it('throws for an undefined object member and names the member path', () => {
    assert.throws(
      () => canonicalizeJCSStrict({ a: 1, b: undefined }),
      (e: unknown) => e instanceof TypeError
        && (e as Error).message === 'canonicalizeJCS: undefined at $.b',
    )
  })

  it('throws for an undefined member nested at depth', () => {
    assert.throws(
      () => canonicalizeJCSStrict({ a: { b: { c: undefined } } }),
      (e: unknown) => e instanceof TypeError
        && (e as Error).message === 'canonicalizeJCS: undefined at $.a.b.c',
    )
  })

  it('throws for an undefined array element and names the index', () => {
    assert.throws(
      () => canonicalizeJCSStrict({ a: [1, undefined, 3] }),
      (e: unknown) => e instanceof TypeError
        && (e as Error).message === 'canonicalizeJCS: undefined at $.a[1]',
    )
    assert.throws(
      () => canonicalizeJCSStrict([[{ x: undefined }]]),
      (e: unknown) => e instanceof TypeError
        && (e as Error).message === 'canonicalizeJCS: undefined at $[0][0].x',
    )
  })

  it('preserves explicit null exactly as canonicalizeJCS does', () => {
    assert.strictEqual(canonicalizeJCSStrict({ a: null }), '{"a":null}')
    assert.strictEqual(canonicalizeJCSStrict({ a: 1, b: null, c: [1, null, 2] }),
      '{"a":1,"b":null,"c":[1,null,2]}')
    assert.strictEqual(canonicalizeJCSStrict(null), 'null')
  })

  it('is byte-identical to canonicalizeJCS for every input without undefined', () => {
    const cases: unknown[] = [
      { z: 1, a: 2, m: 3 },
      { a: 1, b: null, c: 3 },
      { outer: { inner: null, value: 42 }, top: 'ok' },
      { items: [1, null, 3] },
      { emptyArr: [], emptyObj: {} },
      { name: 'Тимофій', emoji: '🔐' },
      'simple string',
      [1, 2, 3],
      true,
      42,
      null,
    ]
    for (const tc of cases) {
      assert.strictEqual(
        canonicalizeJCSStrict(tc), canonicalizeJCS(tc),
        `Mismatch on ${JSON.stringify(tc)}`,
      )
    }
    // The published cross-language vectors must also round-trip unchanged.
    for (const v of getTestVectors()) {
      assert.strictEqual(canonicalizeJCSStrict(v.input), v.expected_jcs, v.id)
    }
  })
})
