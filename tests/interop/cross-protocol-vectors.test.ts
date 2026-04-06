// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Interop: Cross-protocol test vectors round-trip verification

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../src/index.js'

const VECTORS_V1 = JSON.parse(
  readFileSync(new URL('../../specs/cross-protocol-test-vectors.json', import.meta.url).pathname, 'utf-8')
)
const VECTORS_V2 = JSON.parse(
  readFileSync(new URL('../../specs/cross-protocol-test-vectors-v2.json', import.meta.url).pathname, 'utf-8')
)

function sha256Hex(data: string): string {
  return createHash('sha256').update(data).digest('hex')
}

describe('Cross-Protocol Test Vectors v1', () => {
  assert.equal(VECTORS_V1.canonicalization, 'JCS (RFC 8785) — keys sorted recursively, no whitespace, null preserved')

  for (const vector of VECTORS_V1.compound_digest) {
    it(`${vector.id}: ${vector.description}`, () => {
      const canonical = canonicalizeJCS(vector.input)
      const hash = sha256Hex(canonical)
      assert.equal(hash, vector.expected_hash,
        `Hash mismatch for ${vector.id}:\n  got:      ${hash}\n  expected: ${vector.expected_hash}`)
    })
  }

  it('round-trip: serialize -> deserialize -> re-hash matches', () => {
    for (const vector of VECTORS_V1.compound_digest) {
      const json = JSON.stringify(vector.input)
      const parsed = JSON.parse(json)
      const hash = sha256Hex(canonicalizeJCS(parsed))
      assert.equal(hash, vector.expected_hash, `Round-trip failed for ${vector.id}`)
    }
  })
})

describe('Cross-Protocol Test Vectors v2 (Edge Cases)', () => {
  for (const vector of VECTORS_V2.compound_digest_v2) {
    if (vector.input) {
      // Standard single-input vector
      it(`${vector.id}: ${vector.description}`, () => {
        const canonical = canonicalizeJCS(vector.input)
        const hash = sha256Hex(canonical)
        assert.equal(hash, vector.expected_hash,
          `Hash mismatch for ${vector.id}:\n  got:      ${hash}\n  expected: ${vector.expected_hash}`)
      })
    } else if (vector.input_a && vector.input_b) {
      // Dual-input vector: both must produce the same hash
      it(`${vector.id}: ${vector.description}`, () => {
        const hashA = sha256Hex(canonicalizeJCS(vector.input_a))
        const hashB = sha256Hex(canonicalizeJCS(vector.input_b))
        assert.equal(hashA, hashB, `${vector.id}: input_a and input_b should produce identical hashes`)
        assert.equal(hashA, vector.expected_hash,
          `Hash mismatch for ${vector.id}:\n  got:      ${hashA}\n  expected: ${vector.expected_hash}`)
      })
    }
  }

  it('round-trip: v2 vectors with single input survive JSON serialization', () => {
    for (const vector of VECTORS_V2.compound_digest_v2) {
      if (!vector.input) continue
      const json = JSON.stringify(vector.input)
      const parsed = JSON.parse(json)
      const hash = sha256Hex(canonicalizeJCS(parsed))
      assert.equal(hash, vector.expected_hash, `v2 round-trip failed for ${vector.id}`)
    }
  })
})
