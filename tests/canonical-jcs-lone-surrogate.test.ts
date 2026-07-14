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
