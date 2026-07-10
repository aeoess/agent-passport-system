// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// read_fidelity_receipt (v2): shared parity vector generator
// ══════════════════════════════════════════════════════════════════
// Writes read-fidelity-receipt-v0.1-vectors.json next to this file.
// Fully deterministic: every input is a fixed string or derived from
// sha256 over a fixed label. No wall clock, no randomness. The Python
// SDK copies the emitted file BYTE-IDENTICALLY and asserts its
// implementation reproduces every value; Ed25519 signing is
// deterministic, so re-signing the record body with the fixture key
// must yield the identical sig.
//
// Run: npx tsx src/v2/read_fidelity_receipt/vectors/generate.ts
// ══════════════════════════════════════════════════════════════════

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { verify as edVerify, publicKeyFromPrivate, sign } from '../../../crypto/keys.js'
import {
  LEXICON_ID,
  LEXICON_PROFILE,
  PROFILES,
  WORDS,
  decodeProfile,
  encodeProfile,
} from '../../word_handles/index.js'
import type { WordHandleProfileName } from '../../word_handles/index.js'
import {
  canonicalNoSig,
  commitSpans,
  createReadFidelityReceipt,
  deriveSeed,
  sampleSpans,
  verifyAgainstSource,
  verifyReadFidelityReceipt,
} from '../index.js'

function sha256hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex')
}

/** First 4 bytes of sha256(label) as a big-endian uint32. */
function seedUint32(label: string): number {
  return createHash('sha256').update(label, 'utf8').digest().readUInt32BE(0)
}

const WORD_TO_INDEX: ReadonlyMap<string, number> = (() => {
  const m = new Map<string, number>()
  for (let i = 0; i < WORDS.length; i++) m.set(WORDS[i], i)
  return m
})()

// ── jcs_kats ─────────────────────────────────────────────────────

const JCS_KAT_INPUTS: ReadonlyArray<{ name: string; value: unknown }> = [
  {
    name: 'sorted_keys',
    value: { zebra: 1, alpha: 2, nested: { b: 2, a: 1 } },
  },
  {
    name: 'null_preserved',
    value: { present: 'x', absent: null, list: [1, null, 'z'] },
  },
  {
    name: 'unicode_emoji_cyrillic',
    value: { emoji: '🔐🙂', mixed: 'привіт 🌍', мова: 'українська' },
  },
  {
    name: 'number_forms',
    value: { float: 3.14, int: 42, negative: -7, zero: 0 },
  },
  {
    name: 'empty_structures',
    value: { arr: [], obj: {} },
  },
]

const jcs_kats = JCS_KAT_INPUTS.map(({ name, value }) => {
  const canonical = canonicalizeJCS(value)
  return { name, value, canonical, sha256: sha256hex(canonical) }
})

// ── word_handle_cases ────────────────────────────────────────────

const PROFILE_NAMES: readonly WordHandleProfileName[] = [
  'compact',
  'default',
  'high_assurance',
]

const round_trips = []
for (let d = 0; d < 4; d++) {
  const digest = sha256hex(`wh-fixture:${d}`)
  for (const profile of PROFILE_NAMES) {
    const words = encodeProfile(digest, profile)
    const res = decodeProfile(words, profile)
    assert.equal(res.checksumOk, true)
    assert.equal(res.prefixBits, PROFILES[profile].prefixBits)
    round_trips.push({
      digest,
      profile,
      words,
      prefix_hex: res.prefixHex,
      prefix_bits: res.prefixBits,
    })
  }
}

// Substitution negative: one data word replaced, deterministically.
const subDigest = sha256hex('wh-fixture:0')
const subWords = encodeProfile(subDigest, 'default')
const subPos = seedUint32('rf-wh-substitute-pos') % PROFILES.default.dataWords
const subOrig = WORD_TO_INDEX.get(subWords[subPos]) as number
const subDelta = 1 + (seedUint32('rf-wh-substitute-delta') % (WORDS.length - 1))
const subMutated = subWords.slice()
subMutated[subPos] = WORDS[(subOrig + subDelta) % WORDS.length]
const subRes = decodeProfile(subMutated, 'default')
assert.equal(subRes.checksumOk, false)
assert.deepEqual(subRes.outOfLexicon, [])
const substitution_negative = {
  digest: subDigest,
  profile: 'default',
  words: subMutated,
  substituted_index: subPos,
  checksum_ok: false,
}

// Transposition negative: first adjacent differing data word pair swapped.
const trDigest = sha256hex('wh-fixture:1')
const trWords = encodeProfile(trDigest, 'default')
let trPair = -1
for (let i = 0; i < PROFILES.default.dataWords - 1; i++) {
  if (trWords[i] !== trWords[i + 1]) {
    trPair = i
    break
  }
}
assert.ok(trPair >= 0, 'no adjacent differing data words in transposition base')
const trMutated = trWords.slice()
trMutated[trPair] = trWords[trPair + 1]
trMutated[trPair + 1] = trWords[trPair]
const trRes = decodeProfile(trMutated, 'default')
assert.equal(trRes.checksumOk, false)
assert.deepEqual(trRes.outOfLexicon, [])
const transposition_negative = {
  digest: trDigest,
  profile: 'default',
  words: trMutated,
  swapped_indices: [trPair, trPair + 1],
  checksum_ok: false,
}

// Out-of-lexicon negative: two words replaced with non-lexicon strings.
const olDigest = sha256hex('wh-fixture:2')
const olWords = encodeProfile(olDigest, 'default')
const olMutated = olWords.slice()
olMutated[1] = 'notaword'
olMutated[3] = 'xxqqzz'
const olRes = decodeProfile(olMutated, 'default')
assert.deepEqual(olRes.outOfLexicon, [1, 3])
assert.equal(olRes.prefixHex, null)
assert.equal(olRes.checksumOk, false)
const out_of_lexicon_negative = {
  digest: olDigest,
  profile: 'default',
  words: olMutated,
  out_of_lexicon: [1, 3],
  checksum_ok: false,
}

const word_handle_cases = {
  round_trips,
  substitution_negative,
  transposition_negative,
  out_of_lexicon_negative,
}

// ── seed_kats ────────────────────────────────────────────────────

const seedKatPresent = {
  name: 'presentation_digest_present',
  content_digest: `sha256:${sha256hex('rf-seed-content:0')}`,
  presentation_digest: `sha256:${sha256hex('rf-seed-presentation:0')}`,
  nonce: 'seed-kat-nonce-0',
  version: '1',
  seed: '',
}
seedKatPresent.seed = deriveSeed(
  seedKatPresent.content_digest,
  seedKatPresent.presentation_digest,
  seedKatPresent.nonce,
  seedKatPresent.version,
)

const seedKatNull = {
  name: 'presentation_digest_null',
  content_digest: `sha256:${sha256hex('rf-seed-content:1')}`,
  presentation_digest: null as string | null,
  nonce: 'seed-kat-nonce-1',
  version: '1',
  seed: '',
}
seedKatNull.seed = deriveSeed(
  seedKatNull.content_digest,
  null,
  seedKatNull.nonce,
  seedKatNull.version,
)

const seed_kats = [seedKatPresent, seedKatNull]

// ── sampler_cases and record_case ────────────────────────────────

// The record fixture: sampler case 1 uses the record's DERIVED seed so
// that the recorded spans, the record's span_commitments, and
// verifyAgainstSource all agree over the same source text.
const RECORD_PRIVATE_KEY = sha256hex('read-fidelity fixture key v1')
const RECORD_CONTENT_DIGEST = `sha256:${sha256hex('read-fidelity fixture content v1')}`
const RECORD_NONCE = 'fixture-nonce-1'
const RECORD_VERSION = '1'
const RECORD_SEED = deriveSeed(RECORD_CONTENT_DIGEST, null, RECORD_NONCE, RECORD_VERSION)

const CASE1_SOURCE =
  'The quick brown fox jumps over the lazy dog while the verifier ' +
  'samples spans for readback and checks every one of them.'
const CASE1_N = 5
const CASE1_SPAN_LEN = 12

const CASE2_SOURCE =
  'Приймач 🔐 читає текст 🙂 без спотворень і повертає його точно 🌍 назад.'
const CASE2_N = 4
const CASE2_SPAN_LEN = 7

const CASE3_SOURCE =
  'Readback sampling draws n spans at seed-determined positions and ' +
  'compares exact strings. The record carries only commitments, never ' +
  'the raw span texts, so a verifier with the source can recompute ' +
  'everything while the record alone reveals little.'
const CASE3_N = 8
const CASE3_SPAN_LEN = 15

const samplerCaseDefs = [
  { name: 'case1_ascii', source: CASE1_SOURCE, seed: RECORD_SEED, n: CASE1_N, span_len: CASE1_SPAN_LEN },
  { name: 'case2_emoji_cyrillic', source: CASE2_SOURCE, seed: sha256hex('rf-sampler-seed:2'), n: CASE2_N, span_len: CASE2_SPAN_LEN },
  { name: 'case3_longer', source: CASE3_SOURCE, seed: sha256hex('rf-sampler-seed:3'), n: CASE3_N, span_len: CASE3_SPAN_LEN },
]

const sampler_cases = samplerCaseDefs.map((def) => ({
  ...def,
  spans: sampleSpans(def.source, def.seed, def.n, def.span_len),
}))

const case1Spans = sampler_cases[0].spans
const case1Texts = case1Spans.map((s) => s.text)
const responses = case1Texts
const record = createReadFidelityReceipt(
  {
    content_digest: RECORD_CONTENT_DIGEST,
    presentation_digest: null,
    challenge: {
      nonce: RECORD_NONCE,
      seed: RECORD_SEED,
      algorithm: 'span_sample_v1',
      version: RECORD_VERSION,
      span_len: CASE1_SPAN_LEN,
      span_commitments: commitSpans(case1Texts),
    },
    response_digest: `sha256:${sha256hex(canonicalizeJCS(responses))}`,
    k: CASE1_N,
    n: CASE1_N,
    scoring_method: 'exact_match_v1',
    model_claim: 'example-model-v1',
    runtime_claim: 'example-runtime-v1',
    verification_method: 'asserted',
    challenge_issued_at: '2026-07-04T00:00:00Z',
    response_observed_at: '2026-07-04T00:00:00Z',
    receipt_issued_at: '2026-07-04T00:00:00Z',
  },
  RECORD_PRIVATE_KEY,
)

// Self-checks before writing: the fixture must pass its own library.
assert.equal(record.attester, publicKeyFromPrivate(RECORD_PRIVATE_KEY))
assert.deepEqual(verifyReadFidelityReceipt(record), { valid: true })
const against = verifyAgainstSource(record, CASE1_SOURCE)
assert.equal(against.valid, true)
assert.equal(against.signature_valid, true)
assert.equal(against.seed_valid, true)
assert.deepEqual(against.commitment_matches, case1Spans.map(() => true))
// Ed25519 is deterministic: re-signing the body yields the identical sig.
assert.equal(sign(canonicalNoSig(record), RECORD_PRIVATE_KEY), record.sig)

const canonical_no_sig = canonicalNoSig(record)
assert.equal(edVerify(canonical_no_sig, record.sig, record.attester), true)

// The record's source text and responses are not duplicated here: the
// source is sampler_cases[0].source and the responses are its span
// texts (k = n by construction).
const record_case = {
  private_key_hex: RECORD_PRIVATE_KEY,
  record,
  canonical_no_sig_sha256: sha256hex(canonical_no_sig),
  signature_valid: true,
}

// ── write ────────────────────────────────────────────────────────

const vectors = {
  lexicon_id: LEXICON_ID,
  lexicon_profile: LEXICON_PROFILE,
  jcs_kats,
  word_handle_cases,
  seed_kats,
  sampler_cases,
  record_case,
}

const outPath = fileURLToPath(
  new URL('./read-fidelity-receipt-v0.1-vectors.json', import.meta.url),
)
writeFileSync(outPath, `${JSON.stringify(vectors, null, 2)}\n`, 'utf8')
console.log(`wrote ${outPath}`)
