// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Cross-implementation JCS byte-match harness.
//
// For every vector in jcs-test-vectors.json (pinned expected canonical
// bytes + SHA-256 generated from rfc8785@0.1.4 on the Python side), this
// test asserts:
//
//   1. canonicalizeJCS(input)               — the SDK strict-JCS path —
//      matches the pinned canonical bytes.
//   2. SHA-256(canonicalizeJCS(input))      — what computeActionRef and
//      computeAttributionActionRef hash through — matches the pinned
//      SHA-256.
//   3. canonicalize@4.0.0(input)            — erdtman's reference impl
//      (one of the RFC 8785 authors) — matches the pinned canonical
//      bytes byte-for-byte.
//   4. SHA-256(canonicalize@4.0.0(input))   — matches the pinned SHA-256.
//
// Oracle pin moved 3.0.0 -> 4.0.0 on 2026-08-20. Verified before taking it:
// all 12 pinned vectors are byte-identical under both versions and both match
// the pinned bytes. An 18-case adversarial probe found exactly one behavioural
// difference: 3.0.0 emitted a lone UTF-16 surrogate silently as \ud800, and
// 4.0.0 rejects it. canonicalizeJCS already rejected lone surrogates with a
// `lone_surrogate` reason, so that divergence existed under 3.0.0 and was
// untested in both directions. 4.0.0 closes it. The pin stays exact, never a
// caret: an oracle that can move under you is not an oracle.
//
// If any vector fails, either the SDK has drifted from strict RFC 8785,
// or the external reference has drifted, or the pinned vectors are stale.
// All three are recoverable signals; silently rewriting the pin is not.
// To regenerate the pinned vectors after an intentional change, run
// `tests/cross-impl/gen-vectors.py` (Python with rfc8785==0.1.4).
//
// CI runs both this test and a parallel Python step that exercises
// rfc8785@0.1.4 against the same vectors. Three-way byte-match across
// SDK + canonicalize@4.0.0 + rfc8785@0.1.4 is the actual conformance
// signal.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { canonicalizeJCS, canonicalHashJCS } from '../../src/core/canonical-jcs.js'
import canonicalize from 'canonicalize'

interface Vector {
  id: string
  description: string
  input: unknown
  expected_canonical_bytes: string
  expected_sha256: string
}

interface Manifest {
  generator: string
  spec: string
  hash: string
  vectors: Vector[]
}

const here = dirname(fileURLToPath(import.meta.url))
const manifest: Manifest = JSON.parse(
  readFileSync(resolve(here, 'jcs-test-vectors.json'), 'utf8'),
)

function sha256Hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

describe('cross-impl JCS byte-match: SDK canonicalizeJCS', () => {
  for (const v of manifest.vectors) {
    it(`${v.id} — canonical bytes match pin`, () => {
      const bytes = canonicalizeJCS(v.input)
      assert.equal(
        bytes,
        v.expected_canonical_bytes,
        `${v.id}: SDK canonicalizeJCS output diverged from pinned bytes`,
      )
    })

    it(`${v.id} — canonicalHashJCS matches pinned SHA-256`, () => {
      const hash = canonicalHashJCS(v.input as Record<string, unknown>)
      assert.equal(
        hash,
        v.expected_sha256,
        `${v.id}: canonicalHashJCS hash diverged from pinned SHA-256`,
      )
    })
  }
})

describe('cross-impl JCS byte-match: canonicalize@4.0.0 reference (erdtman)', () => {
  for (const v of manifest.vectors) {
    it(`${v.id} — reference canonical bytes match pin`, () => {
      const bytes = canonicalize(v.input)
      assert.equal(
        bytes,
        v.expected_canonical_bytes,
        `${v.id}: canonicalize@4.0.0 output diverged from pinned bytes`,
      )
    })

    it(`${v.id} — reference SHA-256 matches pin`, () => {
      const bytes = canonicalize(v.input)
      const hash = sha256Hex(bytes ?? '')
      assert.equal(
        hash,
        v.expected_sha256,
        `${v.id}: canonicalize@4.0.0 SHA-256 diverged from pinned hash`,
      )
    })
  }
})

describe('cross-impl JCS byte-match: SDK vs reference direct equality', () => {
  for (const v of manifest.vectors) {
    it(`${v.id} — SDK and reference produce identical bytes`, () => {
      const sdkBytes = canonicalizeJCS(v.input)
      const refBytes = canonicalize(v.input)
      assert.equal(
        sdkBytes,
        refBytes,
        `${v.id}: SDK canonicalizeJCS and canonicalize@4.0.0 disagree`,
      )
    })
  }
})

describe('manifest metadata sanity', () => {
  it('manifest names rfc8785 as the generator', () => {
    assert.match(manifest.generator, /rfc8785/)
  })

  it('manifest declares RFC 8785 as the spec', () => {
    assert.match(manifest.spec, /RFC 8785/)
  })

  it('manifest declares SHA-256 + lowercase hex as the hash format', () => {
    assert.match(manifest.hash, /SHA-256/)
    assert.match(manifest.hash, /lowercase hex/)
  })

  it('manifest carries at least 10 vectors', () => {
    assert.ok(
      manifest.vectors.length >= 10,
      `expected ≥10 vectors, got ${manifest.vectors.length}`,
    )
  })

  it('every pinned SHA-256 is 64 lowercase hex chars', () => {
    for (const v of manifest.vectors) {
      assert.match(
        v.expected_sha256,
        /^[0-9a-f]{64}$/,
        `${v.id}: pinned SHA-256 is not 64 lowercase hex chars`,
      )
    }
  })
})

// A lone/unpaired UTF-16 surrogate has no UTF-8 encoding. RFC 8785 and the
// reference rfc8785@0.1.4 (Python side) reject it; the SDK strict-JCS path must
// reject it too, rather than emit a \ud800 escape. This keeps the cross-language
// byte-identity property intact on the only input where the implementations
// previously diverged. Valid inputs are unchanged (asserted by the vectors above).
describe('cross-impl JCS: lone surrogate is rejected, not escaped', () => {
  const HIGH = String.fromCharCode(0xd800)
  const LOW = String.fromCharCode(0xdfff)
  const EMOJI = String.fromCodePoint(0x1f600)

  it('SDK canonicalizeJCS rejects a lone high surrogate', () => {
    assert.throws(() => canonicalizeJCS({ v: HIGH }))
  })
  it('SDK canonicalizeJCS rejects a lone low surrogate', () => {
    assert.throws(() => canonicalizeJCS({ v: LOW }))
  })
  it('SDK canonicalizeJCS rejects a lone surrogate after a valid pair', () => {
    assert.throws(() => canonicalizeJCS({ v: EMOJI + HIGH }))
  })
  it('SDK canonicalizeJCS still accepts a valid non-BMP pair as raw UTF-8', () => {
    assert.equal(canonicalizeJCS({ v: EMOJI }), `{"v":"${EMOJI}"}`)
  })
})
