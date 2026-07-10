// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
/**
 * property-canonical.test.ts
 * Property-based tests (fast-check) for the two canonicalizers:
 * canonicalize() (src/core/canonical.ts) and canonicalizeJCS()
 * (src/core/canonical-jcs.ts, RFC 8785). Both are load-bearing for
 * cross-implementation signature verification, so determinism and
 * valid-JSON-output are checked against randomly generated JSON values
 * rather than only the hand-picked examples in canonical.test.ts and
 * canonical-jcs.test.ts.
 * Run: npx tsx --test tests/property-canonical.test.ts
 */
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as fc from 'fast-check'
import { canonicalize } from '../src/core/canonical.js'
import { canonicalizeJCS } from '../src/core/canonical-jcs.js'

// Extracts object keys in the literal order they appear in a JSON string.
// JSON.parse + Object.keys() cannot be used for this: per the ECMAScript
// spec, integer-index-like keys ("0", "1", ...) are always iterated in
// ascending numeric order before any other own key, regardless of the
// order they appeared in the source text. Restricting values to
// fc.integer() (never containing a quote character) makes every `"...":`
// match in the raw string an object key.
function keysInLiteralOrder(json: string): string[] {
  const keys: string[] = []
  for (const m of json.matchAll(/"((?:[^"\\]|\\.)*)":/g)) keys.push(m[1])
  return keys
}

// Keys restricted to plain alphanumerics: no quote or backslash, so a key
// never needs JSON escaping and its raw text always equals its decoded
// value. That keeps keysInLiteralOrder()'s output directly comparable via
// a plain string sort, matching what canonicalize/canonicalizeJCS compare
// internally (Object.keys(...).sort() on the decoded string values).
const safeKey = fc.string({
  unit: fc.constantFrom(...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.split('')),
  minLength: 1,
  maxLength: 8,
})

describe('canonicalize - property-based (fast-check)', () => {
  it('is deterministic: same value always canonicalizes to the same string', () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        assert.equal(canonicalize(value), canonicalize(value))
      }),
    )
  })

  it('always produces valid, re-parseable JSON', () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        const out = canonicalize(value)
        assert.doesNotThrow(() => JSON.parse(out))
      }),
    )
  })

  it('object key order in the output is sorted (ascending code point)', () => {
    fc.assert(
      fc.property(fc.dictionary(safeKey, fc.integer()), (obj) => {
        const keysInOutput = keysInLiteralOrder(canonicalize(obj))
        assert.deepEqual(keysInOutput, [...keysInOutput].sort())
      }),
    )
  })
})

describe('canonicalizeJCS - property-based (fast-check, RFC 8785)', () => {
  it('is deterministic: same value always canonicalizes to the same string', () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        assert.equal(canonicalizeJCS(value), canonicalizeJCS(value))
      }),
    )
  })

  it('always produces valid, re-parseable JSON', () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        const out = canonicalizeJCS(value)
        assert.doesNotThrow(() => JSON.parse(out))
      }),
    )
  })

  it('preserves null (unlike canonicalize, per RFC 8785)', () => {
    fc.assert(
      fc.property(fc.dictionary(fc.string(), fc.jsonValue()), (obj) => {
        const withNull = { ...obj, __fc_null_probe__: null }
        const out = canonicalizeJCS(withNull)
        assert.ok(out.includes('"__fc_null_probe__":null'))
      }),
    )
  })

  it('object key order in the output is sorted (ascending UTF-16 code unit)', () => {
    fc.assert(
      fc.property(fc.dictionary(safeKey, fc.integer()), (obj) => {
        const keysInOutput = keysInLiteralOrder(canonicalizeJCS(obj))
        assert.deepEqual(keysInOutput, [...keysInOutput].sort())
      }),
    )
  })
})
