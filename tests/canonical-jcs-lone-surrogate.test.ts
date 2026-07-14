// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// JCS Canonicalization — lone/unpaired UTF-16 surrogate rejection
// ══════════════════════════════════════════════════════════════════
// RFC 8785: a lone surrogate is not a valid Unicode scalar and has no UTF-8
// encoding, so the input is invalid and must be rejected, not escaped. A valid
// surrogate PAIR (a non-BMP character) must still canonicalize to raw UTF-8.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { canonicalizeJCS, JcsCanonicalizationError } from '../src/core/canonical-jcs.js'

const HIGH = String.fromCharCode(0xd800) // lone high surrogate
const LOW = String.fromCharCode(0xdfff) // lone low surrogate
const EMOJI = String.fromCodePoint(0x1f600) // valid non-BMP scalar U+1F600

const isLoneSurrogate = (e: unknown): boolean =>
  e instanceof JcsCanonicalizationError && (e as JcsCanonicalizationError).code === 'ERR_JCS_LONE_SURROGATE'

describe('canonicalizeJCS — lone surrogate rejection (RFC 8785)', () => {
  it('rejects a lone high surrogate', () => {
    assert.throws(() => canonicalizeJCS({ v: HIGH }), isLoneSurrogate)
  })

  it('rejects a lone low surrogate', () => {
    assert.throws(() => canonicalizeJCS({ v: LOW }), isLoneSurrogate)
  })

  it('rejects a lone surrogate appearing after a valid pair', () => {
    assert.throws(() => canonicalizeJCS({ v: EMOJI + HIGH }), isLoneSurrogate)
  })

  it('rejects a lone surrogate in an object key', () => {
    assert.throws(() => canonicalizeJCS({ [HIGH]: 'x' }), isLoneSurrogate)
  })

  it('rejects a bare lone-surrogate string', () => {
    assert.throws(() => canonicalizeJCS(HIGH), isLoneSurrogate)
  })

  it('accepts a valid non-BMP character unchanged (raw UTF-8)', () => {
    assert.equal(canonicalizeJCS(EMOJI), `"${EMOJI}"`)
    assert.equal(canonicalizeJCS({ v: EMOJI }), `{"v":"${EMOJI}"}`)
    // Canonical bytes are the raw 4-byte UTF-8 of U+1F600, unchanged by the fix.
    assert.deepEqual(
      Buffer.from(canonicalizeJCS({ v: EMOJI }), 'utf-8'),
      Buffer.from('{"v":"\u{1F600}"}', 'utf-8'),
    )
  })

  it('accepts U+D7FF just below the surrogate range', () => {
    assert.equal(canonicalizeJCS({ v: '퟿' }), '{"v":"퟿"}')
  })
})

describe('canonicalizeJCS: lone surrogate property-name and structural coverage', () => {
  it('rejects a lone surrogate in a nested object value', () => {
    assert.throws(() => canonicalizeJCS({ a: { b: HIGH } }), isLoneSurrogate)
  })

  it('rejects a lone surrogate in an array element', () => {
    assert.throws(() => canonicalizeJCS({ a: [HIGH] }), isLoneSurrogate)
  })

  it('rejects a lone surrogate in a nested object key', () => {
    assert.throws(() => canonicalizeJCS({ a: { [LOW]: 'x' } }), isLoneSurrogate)
  })

  it('accepts a valid pair immediately followed by a lone low surrogate is still rejected', () => {
    // Off-by-one guard: a valid pair then a lone low surrogate must reject.
    assert.throws(() => canonicalizeJCS({ v: EMOJI + LOW }), isLoneSurrogate)
  })
})

describe('canonicalizeJCS: error contract', () => {
  it('the thrown error is an Error and a JcsCanonicalizationError with a stable category/reason', () => {
    try {
      canonicalizeJCS({ v: HIGH })
      assert.fail('expected throw')
    } catch (e) {
      // Caught by the canonicalizer's declared error type; instanceof Error holds.
      assert.ok(e instanceof Error)
      assert.ok(e instanceof JcsCanonicalizationError)
      const je = e as JcsCanonicalizationError
      assert.equal(je.category, 'invalid_unicode')
      assert.equal(je.reason, 'lone_surrogate')
      // The offending string is not leaked into the message.
      assert.ok(!je.message.includes(HIGH))
    }
  })
})

describe('canonicalizeJCS: signing boundary', () => {
  it('a real sign-preimage API (computeDelegationChainRoot) fails closed on a lone surrogate, producing no output', async () => {
    const { computeDelegationChainRoot } = await import('../src/decisionReceipt.js')
    // A lone surrogate anywhere in the signed preimage must throw before any
    // hash or signature is produced; no fallback to the legacy canonicalizer.
    const chain = [{ scope: [HIGH] }] as unknown as Parameters<typeof computeDelegationChainRoot>[0]
    assert.throws(() => computeDelegationChainRoot(chain), isLoneSurrogate)
  })
})

describe('canonicalizeJCS: adversarial raw payloads reach the same terminal state as Go', () => {
  // The same raw JSON text pinned in the Go scanner tests. TypeScript preserves a
  // lone surrogate through JSON.parse and rejects it at canonicalizeJCS, so it
  // reaches the same accept/reject terminal state as the Go raw-JSON path.
  const parseCanon = (raw: string): string => canonicalizeJCS(JSON.parse(raw))

  const REJECT: Array<[string, string]> = [
    ['space-separated-non-adjacent', String.raw`{"v":"\uD800 \uDC00"}`],
    ['newline-separated-non-adjacent', String.raw`{"v":"\uD800\n\uDC00"}`],
    ['lone-low-first', String.raw`{"v":"\uDC00"}`],
    ['low-then-high', String.raw`{"v":"\uDC00\uD800"}`],
    ['high-then-literal-low', String.raw`{"v":"\uD800\\uDC00"}`],
    ['lone-in-key', String.raw`{"\uD800":"x"}`],
    ['lowercase-hex', String.raw`{"v":"\ud800"}`],
    ['literal-backslash-then-lone', String.raw`{"v":"\\\uD800"}`],
  ]
  for (const [name, raw] of REJECT) {
    it(`rejects ${name}`, () => assert.throws(() => parseCanon(raw), isLoneSurrogate))
  }

  const ACCEPT: Array<[string, string]> = [
    ['valid-adjacent-pair', String.raw`{"v":"😀"}`],
    ['escaped-backslash-literal', String.raw`{"v":"\\uD800"}`],
    ['double-backslash-literal', String.raw`{"v":"\\\\uD800"}`],
    ['genuine-replacement-char', String.raw`{"v":"�"}`],
  ]
  for (const [name, raw] of ACCEPT) {
    it(`accepts ${name}`, () => assert.doesNotThrow(() => parseCanon(raw)))
  }
})
