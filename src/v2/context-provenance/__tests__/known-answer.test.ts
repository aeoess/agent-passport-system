// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// CPA v0.1: RFC 8785 (JCS) KNOWN-ANSWER vectors
// ══════════════════════════════════════════════════════════════════
// This is the canonicalization-CORRECTNESS gate. Same-implementation
// parity (parity.test.ts) cannot catch an RFC-8785 deviation in the
// shared JCS primitive, because both the producer and the reimplementation
// would share the same wrong bytes. Only KNOWN-ANSWER vectors with
// HAND-DERIVED expected bytes can catch it.
//
// The expected side of every assertion below was derived BY HAND from the
// RFC 8785 rules, NOT by calling canonicalizeJCS:
//   - object keys sorted by UTF-16 code unit (lexicographic on UTF-16),
//   - no insignificant whitespace,
//   - shortest round-tripping number formatting (ES2015 / ECMA-262),
//   - minimal string escaping (only " \ and C0 controls; the five
//     short escapes \b \t \n \f \r; forward slash and non-ASCII NOT
//     escaped),
//   - array element order preserved.
// Each EXPECTED_* literal is the canonical string written out by hand, and
// each SHA256_* literal is the 64-hex computed by hashing THAT literal with
// node:crypto. If canonicalizeJCS ever deviates from RFC 8785, one of these
// equalities breaks LOUDLY.
// ══════════════════════════════════════════════════════════════════

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, createPublicKey, verify as nodeVerify } from 'node:crypto'

import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { sign, publicKeyFromPrivate } from '../../../crypto/keys.js'
import {
  LEAF_TAG,
  NODE_TAG,
  leafHash,
  buildPartitionRoot,
  buildTopRoot,
  bytesToHex,
} from '../merkle.js'
import type { ContextItem } from '../types.js'

// ── Independent helpers (node:crypto only; NOT the module's hashers) ──

function sha256Hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

/** sha256 over a sequence of byte chunks, hex out. Used ONLY to recompute
 *  the frozen CPA byte layout directly, without touching merkle.ts. */
function sha256HexBytes(...parts: Uint8Array[]): string {
  const h = createHash('sha256')
  for (const p of parts) h.update(p)
  return h.digest('hex')
}

// ══════════════════════════════════════════════════════════════════
// 1. RFC 8785 (JCS) canonicalization known-answer vectors
// ══════════════════════════════════════════════════════════════════
//
// For each vector the INPUT object is given, then EXPECTED is the canonical
// string DERIVED BY HAND, and SHA256 is the digest of that hand-written
// literal. The test asserts canonicalizeJCS(input) === EXPECTED (proves the
// implementation emits the spec-correct bytes) and sha256(EXPECTED) ===
// SHA256 (pins the digest a cross-language implementer must reproduce).

// ── KAV-1: nested object + non-obvious key sort ────────────────────
// Top-level keys: "1key", "Zebra", "apple", "é".
// UTF-16 code-unit order: '1'=U+0031, 'Z'=U+005A, 'a'=U+0061, 'é'=U+00E9.
//   0x31 < 0x5A < 0x61 < 0xE9  =>  "1key" < "Zebra" < "apple" < "é".
// Nested object under "apple" has keys "b","a" => sorted to "a","b".
// "é" (U+00E9) is a single BMP code unit, emitted as the raw UTF-8 bytes
// (RFC 8785 does NOT escape non-ASCII).
const KAV1_INPUT = { 'é': 'non-ascii', apple: { b: 2, a: 1 }, Zebra: 'upper', '1key': 'digit-first' }
const KAV1_EXPECTED =
  '{"1key":"digit-first","Zebra":"upper","apple":{"a":1,"b":2},"é":"non-ascii"}'
const KAV1_SHA256 = '347dfed718913d7fdc34a874777cf95d7a4722d47f2ce72aa86e1aa40a8f6b40'

// ── KAV-2: integers, decimal, array order, negative, zero ──────────
// Keys "arr","dec","int","neg","zero" are lowercase ASCII, already sorted.
// Numbers use shortest round-tripping form: 42, 3.5, -7, 0 (no "+", no
// trailing ".0", no exponent for these magnitudes). The array [3,1,2]
// PRESERVES element order (arrays are never sorted).
const KAV2_INPUT = { zero: 0, neg: -7, int: 42, dec: 3.5, arr: [3, 1, 2] }
const KAV2_EXPECTED = '{"arr":[3,1,2],"dec":3.5,"int":42,"neg":-7,"zero":0}'
const KAV2_SHA256 = '534b228144a885b47caf14bc5ac3275a2d4ca818f8bb5607d9f3088262fa96e2'

// ── KAV-3: minimal string escaping ─────────────────────────────────
// The JS source string value below contains, in order:
//   a  "  b  \  c  <TAB>  d  <LF>  e  /  f  <U+0001>  g  _  ü
// RFC 8785 minimal escaping:
//   "  -> \"        (mandatory)
//   \  -> \\        (mandatory)
//   TAB-> \t        (short escape)
//   LF -> \n        (short escape)
//   /  -> /         (forward slash is NOT escaped)
//   U+0001 ->  (C0 control with no short escape -> lowercase \uXXXX)
//   ü (U+00FC) -> ü (non-ASCII NOT escaped; raw UTF-8 bytes)
// so the canonical value string is:  a\"b\\c\td\ne/fg_ü
const KAV3_INPUT = { s: 'a"b\\c\td\ne/fg_ü' }
const KAV3_EXPECTED = '{"s":"a\\"b\\\\c\\td\\ne/f\\u0001g_ü"}'
const KAV3_SHA256 = '6359e665aff8e54d4e09f10ea19c27080fdc12ee1929ee0bb86c32d0e06302aa'

// ── KAV-4: CPA leaf preimage shape (frozen four fields) ────────────
// Keys "byte_len","channel","content_ref","ctx_id".
// Sort by UTF-16 code units: all start 'b' or 'c'. 'b'(0x62) < 'c'(0x63),
// so "byte_len" is first. Among the three "c..." keys the second char
// decides: "channel" -> 'h'(0x68), "content_ref" -> 'o'(0x6F),
// "ctx_id" -> 't'(0x74); 0x68 < 0x6F < 0x74 => channel < content_ref <
// ctx_id. Integer byte_len serializes as 15.
const KAV4_INPUT = { ctx_id: 'sc-001', content_ref: 'aa00', channel: 'system-config', byte_len: 15 }
const KAV4_EXPECTED =
  '{"byte_len":15,"channel":"system-config","content_ref":"aa00","ctx_id":"sc-001"}'
const KAV4_SHA256 = 'abaf17ec1e412bb212629249f6a27fea90adcca658f95f7a2abcce304a18a300'

test('JCS KAV-1: nested object, non-obvious key sort, non-ASCII key', () => {
  assert.equal(canonicalizeJCS(KAV1_INPUT), KAV1_EXPECTED)
  assert.equal(sha256Hex(KAV1_EXPECTED), KAV1_SHA256)
  // Belt and suspenders: digest of the live canonical output equals the pin.
  assert.equal(sha256Hex(canonicalizeJCS(KAV1_INPUT)), KAV1_SHA256)
})

test('JCS KAV-2: integers, decimal, array order, negative, zero', () => {
  assert.equal(canonicalizeJCS(KAV2_INPUT), KAV2_EXPECTED)
  assert.equal(sha256Hex(KAV2_EXPECTED), KAV2_SHA256)
  assert.equal(sha256Hex(canonicalizeJCS(KAV2_INPUT)), KAV2_SHA256)
})

test('JCS KAV-3: minimal string escaping (quote, backslash, tab, LF, slash, C0, non-ASCII)', () => {
  assert.equal(canonicalizeJCS(KAV3_INPUT), KAV3_EXPECTED)
  assert.equal(sha256Hex(KAV3_EXPECTED), KAV3_SHA256)
  assert.equal(sha256Hex(canonicalizeJCS(KAV3_INPUT)), KAV3_SHA256)
})

test('JCS KAV-4: CPA leaf-preimage four-field shape', () => {
  assert.equal(canonicalizeJCS(KAV4_INPUT), KAV4_EXPECTED)
  assert.equal(sha256Hex(KAV4_EXPECTED), KAV4_SHA256)
  assert.equal(sha256Hex(canonicalizeJCS(KAV4_INPUT)), KAV4_SHA256)
})

// ══════════════════════════════════════════════════════════════════
// 2. Ed25519 known-answer (cross-checked against Node's native verifier)
// ══════════════════════════════════════════════════════════════════
// A second, independent Ed25519 implementation (Node's native
// crypto.verify) is the cross-check. We sign a fixed canonical byte string
// with the SDK signer using a fixed 32-byte seed, then build the public key
// OBJECT from the raw 32-byte public key via the DER/SPKI prefix and ask
// Node's verifier to accept the signature over those exact bytes. If Node
// accepts, the SDK signature is a valid RFC-8032 Ed25519 signature over the
// message. We also pin determinism (signing twice yields identical hex) and
// the exact public key the seed derives to.

const ED_SEED = '0000000000000000000000000000000000000000000000000000000000000001'
// publicKeyFromPrivate(ED_SEED) is deterministic; pinned here.
const ED_PUB = '4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29'
// A fixed canonical message (already-canonical JCS bytes).
const ED_MSG = '{"hello":"cpa"}'

test('Ed25519: SDK seed derives the pinned public key', () => {
  assert.equal(publicKeyFromPrivate(ED_SEED), ED_PUB)
})

test('Ed25519: SDK signature is accepted by Node native verifier over exact bytes', () => {
  const sigHex = sign(ED_MSG, ED_SEED)
  // Determinism: RFC-8032 Ed25519 is deterministic; two signs match.
  assert.equal(sign(ED_MSG, ED_SEED), sigHex)
  assert.match(sigHex, /^[0-9a-f]{128}$/)

  // Build a public key object from the RAW 32-byte key via DER/SPKI prefix.
  const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')
  const der = Buffer.concat([SPKI_PREFIX, Buffer.from(ED_PUB, 'hex')])
  const pubKeyObj = createPublicKey({ key: der, format: 'der', type: 'spki' })

  // Independent Ed25519 verification (Node native, second implementation).
  const accepted = nodeVerify(null, Buffer.from(ED_MSG, 'utf8'), pubKeyObj, Buffer.from(sigHex, 'hex'))
  assert.equal(accepted, true, 'Node native Ed25519 must accept the SDK signature')

  // Negative control: flipping one message byte must break verification.
  const accepted2 = nodeVerify(null, Buffer.from(ED_MSG + ' ', 'utf8'), pubKeyObj, Buffer.from(sigHex, 'hex'))
  assert.equal(accepted2, false, 'a one-byte message change must not verify')
})

// ══════════════════════════════════════════════════════════════════
// 3. CPA byte-layout pins (frozen domain-tag layout, recomputed directly)
// ══════════════════════════════════════════════════════════════════
// For ONE fixed leaf we recompute the leaf hash DIRECTLY with node:crypto
// from the frozen formula
//     leaf_hash = sha256( utf8("CPA:v0.1:leaf\n") || utf8(JCS(preimage)) )
// and assert the module's exported leafHash reproduces the identical hex.
// We also pin a single-leaf partition root (== that leaf hash), a two-leaf
// partition root recomputed via node:crypto NODE_TAG layout, and the top
// root over a single partition (== that partition root). This pins the
// frozen domain-tag byte layout against an independent recomputation.

const FIXED_LEAF: ContextItem = {
  ctx_id: 'dev-001',
  channel: 'developer',
  content_ref: 'bb11',
  byte_len: 11,
}
const FIXED_LEAF_JCS = '{"byte_len":11,"channel":"developer","content_ref":"bb11","ctx_id":"dev-001"}'
// Direct recomputation: sha256( utf8(LEAF_TAG) || utf8(FIXED_LEAF_JCS) ).
const FIXED_LEAF_HASH = '40eb2153fa36a0c7a9c05965da3d81f9a643d3d02be5ffa954074364cc9b03ce'

test('CPA byte layout: leaf preimage canonicalizes to the pinned bytes', () => {
  assert.equal(canonicalizeJCS({
    byte_len: FIXED_LEAF.byte_len,
    channel: FIXED_LEAF.channel,
    content_ref: FIXED_LEAF.content_ref,
    ctx_id: FIXED_LEAF.ctx_id,
  }), FIXED_LEAF_JCS)
})

test('CPA byte layout: leafHash equals direct node:crypto recomputation under LEAF_TAG', () => {
  // Independent recomputation (NOT via merkle.ts internals).
  const direct = sha256HexBytes(utf8(LEAF_TAG), utf8(FIXED_LEAF_JCS))
  assert.equal(direct, FIXED_LEAF_HASH)
  // The module's exported leafHash must reproduce the same hex.
  assert.equal(bytesToHex(leafHash(FIXED_LEAF)), FIXED_LEAF_HASH)
  // And the literal LEAF_TAG must be the frozen byte value.
  assert.equal(LEAF_TAG, 'CPA:v0.1:leaf\n')
})

test('CPA byte layout: single-leaf partition root == leaf hash (no node hashing)', () => {
  // A one-leaf partition reduces to the leaf digest unchanged.
  assert.equal(buildPartitionRoot([FIXED_LEAF]), FIXED_LEAF_HASH)
})

test('CPA byte layout: two-leaf partition root == direct NODE_TAG recomputation', () => {
  // Second fixed leaf; ctx_id sorts AFTER dev-001 so order is [dev-001, dev-002].
  const LEAF2: ContextItem = { ctx_id: 'dev-002', channel: 'developer', content_ref: 'cc22', byte_len: 7 }
  const leaf2Jcs = '{"byte_len":7,"channel":"developer","content_ref":"cc22","ctx_id":"dev-002"}'
  assert.equal(canonicalizeJCS({
    byte_len: LEAF2.byte_len, channel: LEAF2.channel, content_ref: LEAF2.content_ref, ctx_id: LEAF2.ctx_id,
  }), leaf2Jcs)

  // Direct recomputation of both leaf hashes, then node_hash over raw bytes.
  const lh1 = createHash('sha256').update(utf8(LEAF_TAG)).update(utf8(FIXED_LEAF_JCS)).digest()
  const lh2 = createHash('sha256').update(utf8(LEAF_TAG)).update(utf8(leaf2Jcs)).digest()
  assert.equal(lh1.toString('hex'), FIXED_LEAF_HASH)
  // node_hash = sha256( utf8(NODE_TAG) || left32 || right32 ); leaves sorted
  // ascending by ctx_id => left = dev-001, right = dev-002.
  const nodeDirect = createHash('sha256').update(utf8(NODE_TAG)).update(lh1).update(lh2).digest('hex')

  // The module's buildPartitionRoot must reproduce the same hex, in either
  // input order (it sorts by ctx_id internally).
  assert.equal(buildPartitionRoot([FIXED_LEAF, LEAF2]), nodeDirect)
  assert.equal(buildPartitionRoot([LEAF2, FIXED_LEAF]), nodeDirect)
  assert.equal(NODE_TAG, 'CPA:v0.1:node\n')
})

test('CPA byte layout: top root over a single partition == that partition root', () => {
  const pr = buildPartitionRoot([FIXED_LEAF])
  assert.equal(buildTopRoot([pr]), pr)
})
