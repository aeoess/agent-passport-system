// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// read_fidelity_receipt (v2): tests
// ══════════════════════════════════════════════════════════════════
// Deterministic throughout: every digest, nonce, seed, and source
// text is a fixed string or derived from sha256 over a fixed label.
// No wall clock, no randomness. The shared parity vectors file
// (vectors/read-fidelity-receipt-v0.1-vectors.json, written by
// vectors/generate.ts) is loaded and replayed here; the Python SDK
// asserts the same values against a byte-identical copy.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { verify as edVerify, publicKeyFromPrivate, sign } from '../../../crypto/keys.js'
import { decodeProfile, encodeProfile } from '../../word_handles/index.js'
import type { WordHandleProfileName } from '../../word_handles/index.js'
import {
  canonicalNoSig,
  commitSpans,
  createReadFidelityReceipt,
  deriveSeed,
  sampleSpans,
  scoreResponses,
  verifyAgainstSource,
  verifyReadFidelityReceipt,
  verifyResponses,
} from '../index.js'
import type { ReadFidelityReceipt, SampledSpan } from '../index.js'

function sha256hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

interface VectorsFile {
  lexicon_id: string
  lexicon_profile: string
  jcs_kats: Array<{ name: string; value: unknown; canonical: string; sha256: string }>
  word_handle_cases: {
    round_trips: Array<{
      digest: string
      profile: WordHandleProfileName
      words: string[]
      prefix_hex: string
      prefix_bits: number
    }>
    substitution_negative: {
      digest: string
      profile: WordHandleProfileName
      words: string[]
      substituted_index: number
      checksum_ok: boolean
    }
    transposition_negative: {
      digest: string
      profile: WordHandleProfileName
      words: string[]
      swapped_indices: [number, number]
      checksum_ok: boolean
    }
    out_of_lexicon_negative: {
      digest: string
      profile: WordHandleProfileName
      words: string[]
      out_of_lexicon: number[]
      checksum_ok: boolean
    }
  }
  seed_kats: Array<{
    name: string
    content_digest: string
    presentation_digest: string | null
    nonce: string
    version: string
    seed: string
  }>
  sampler_cases: Array<{
    name: string
    source: string
    seed: string
    n: number
    span_len: number
    spans: SampledSpan[]
  }>
  record_case: {
    private_key_hex: string
    record: ReadFidelityReceipt
    canonical_no_sig_sha256: string
    signature_valid: boolean
  }
}

const VECTORS: VectorsFile = JSON.parse(
  readFileSync(
    new URL('../vectors/read-fidelity-receipt-v0.1-vectors.json', import.meta.url),
    'utf8',
  ),
)

/** Build a fresh, internally consistent signed record for mutation tests. */
function buildRecord(overrides?: {
  presentationDigest?: string | null
  responses?: readonly string[]
  k?: number
}): {
  record: ReadFidelityReceipt
  source: string
  spanTexts: string[]
  privateKey: string
} {
  const privateKey = sha256hex('rf-test key v1')
  const source =
    'A deterministic test source with enough characters to sample ' +
    'several spans from, none of them overlapping the ends badly.'
  const contentDigest = `sha256:${sha256hex('rf-test content v1')}`
  const presentationDigest = overrides?.presentationDigest ?? null
  const nonce = 'rf-test-nonce-1'
  const version = '1'
  const seed = deriveSeed(contentDigest, presentationDigest, nonce, version)
  const n = 4
  const spanLen = 10
  const spans = sampleSpans(source, seed, n, spanLen)
  const spanTexts = spans.map((s) => s.text)
  const responses = overrides?.responses ?? spanTexts
  const k = overrides?.k ?? scoreResponses(spanTexts, responses).k
  const record = createReadFidelityReceipt(
    {
      content_digest: contentDigest,
      presentation_digest: presentationDigest,
      challenge: {
        nonce,
        seed,
        algorithm: 'span_sample_v1',
        version,
        span_len: spanLen,
        span_commitments: commitSpans(spanTexts),
      },
      response_digest: `sha256:${sha256hex(canonicalizeJCS(responses))}`,
      k,
      n,
      scoring_method: 'exact_match_v1',
      model_claim: 'test-model-v1',
      runtime_claim: 'test-runtime-v1',
      verification_method: 'asserted',
      challenge_issued_at: '2026-07-04T00:00:00Z',
      response_observed_at: '2026-07-04T00:00:01Z',
      receipt_issued_at: '2026-07-04T00:00:02Z',
    },
    privateKey,
  )
  return { record, source, spanTexts, privateKey }
}

/** Re-sign a mutated record body with the given key (sig excluded from preimage). */
function resign(record: ReadFidelityReceipt, privateKey: string): ReadFidelityReceipt {
  return { ...record, sig: sign(canonicalNoSig(record), privateKey) }
}

describe('seed derivation', () => {
  it('matches an independent JCS recompute with presentation_digest present', () => {
    const content = `sha256:${sha256hex('rf-seed-check:content')}`
    const presentation = `sha256:${sha256hex('rf-seed-check:presentation')}`
    const nonce = 'rf-seed-check-nonce'
    // Hand-built RFC 8785 preimage, keys sorted, presentation a distinct member.
    const preimage =
      `{"content_digest":${JSON.stringify(content)},` +
      `"nonce":${JSON.stringify(nonce)},` +
      `"presentation_digest":${JSON.stringify(presentation)},` +
      `"version":"1"}`
    const expected = createHash('sha256').update(preimage, 'utf8').digest('hex')
    assert.equal(deriveSeed(content, presentation, nonce, '1'), expected)
  })

  it('renders a null presentation_digest as a JSON null member, not the empty string', () => {
    const content = `sha256:${sha256hex('rf-seed-check:content-null')}`
    const nonce = 'rf-seed-check-nonce-null'
    const preimage =
      `{"content_digest":${JSON.stringify(content)},` +
      `"nonce":${JSON.stringify(nonce)},` +
      `"presentation_digest":null,` +
      `"version":"1"}`
    const expected = createHash('sha256').update(preimage, 'utf8').digest('hex')
    assert.equal(deriveSeed(content, null, nonce, '1'), expected)
    assert.notEqual(
      deriveSeed(content, null, nonce, '1'),
      deriveSeed(content, `sha256:${'0'.repeat(64)}`, nonce, '1'),
    )
  })

  it('closes the demonstrated null-vs-present splice collision', () => {
    // Adversarial repro (scratchpad/adv/splice.ts): under the old
    // concatenation preimage, a null-presentation record with
    // nonce = P || N derived the SAME seed as a P-presentation record with
    // nonce N, so a verifier that pinned only the seed could not tell them
    // apart. The JCS preimage makes presentation_digest a distinct member,
    // so the two now derive different seeds.
    const content = `sha256:${'11'.repeat(32)}`
    const P = `sha256:${'22'.repeat(32)}`
    const N = 'verifier-nonce-xyz'
    const seedSpliced = deriveSeed(content, null, P + N, '1')
    const seedHonest = deriveSeed(content, P, N, '1')
    assert.notEqual(seedSpliced, seedHonest)

    // v6/v7-style: plant the other case's seed into a record and re-sign.
    // Verification recomputes the seed from (content, presentation, nonce)
    // and rejects the mismatch even though the signature is valid.
    const { record, privateKey } = buildRecord()
    assert.deepEqual(verifyReadFidelityReceipt(record), { valid: true })
    const wrongSeed =
      record.challenge.seed === seedSpliced ? seedHonest : seedSpliced
    const planted = resign(
      { ...record, challenge: { ...record.challenge, seed: wrongSeed } },
      privateKey,
    )
    const res = verifyReadFidelityReceipt(planted)
    assert.equal(res.valid, false)
    assert.equal(res.reason, 'SEED_MISMATCH')
  })

  it('reproduces both seed KATs from the shared vectors', () => {
    assert.equal(VECTORS.seed_kats.length, 2)
    const withPresentation = VECTORS.seed_kats.find(
      (s) => s.presentation_digest !== null,
    )
    const withNull = VECTORS.seed_kats.find((s) => s.presentation_digest === null)
    assert.ok(withPresentation)
    assert.ok(withNull)
    for (const kat of VECTORS.seed_kats) {
      assert.equal(
        deriveSeed(kat.content_digest, kat.presentation_digest, kat.nonce, kat.version),
        kat.seed,
        `seed KAT ${kat.name}`,
      )
    }
  })
})

describe('sampler', () => {
  it('is deterministic for identical inputs', () => {
    const seed = sha256hex('rf-sampler-det:seed')
    const source = 'determinism check source text, long enough to sample from'
    const a = sampleSpans(source, seed, 5, 8)
    const b = sampleSpans(source, seed, 5, 8)
    assert.deepEqual(a, b)
  })

  it('reproduces every sampler case in the shared vectors', () => {
    assert.equal(VECTORS.sampler_cases.length, 3)
    for (const c of VECTORS.sampler_cases) {
      const spans = sampleSpans(c.source, c.seed, c.n, c.span_len)
      assert.deepEqual(spans, c.spans, `sampler case ${c.name}`)
    }
  })

  it('returns distinct positions, exhausting the range when n equals it', () => {
    const seed = sha256hex('rf-sampler-distinct:seed')
    const source = 'abcdefghijklmnop' // 16 code points
    const spanLen = 5
    const range = source.length - spanLen + 1 // 12
    const spans = sampleSpans(source, seed, range, spanLen)
    const positions = spans.map((s) => s.pos)
    assert.equal(new Set(positions).size, range)
    for (const pos of positions) {
      assert.ok(pos >= 0 && pos < range)
    }
  })

  it('throws when n exceeds the position range', () => {
    const seed = sha256hex('rf-sampler-range:seed')
    assert.throws(
      () => sampleSpans('abcdefghij', seed, 7, 5),
      /n 7 exceeds the position range 6/,
    )
    assert.throws(() => sampleSpans('abc', seed, 1, 5), /need at least spanLen 5/)
    assert.throws(() => sampleSpans('abcdef', seed, 0, 2), /positive integer/)
    assert.throws(() => sampleSpans('abcdef', seed, 1, 0), /positive integer/)
  })

  it('slices by unicode code points, never splitting surrogate pairs', () => {
    const seed = sha256hex('rf-sampler-unicode:seed')
    const source = 'аб🔐вг🙂дежз🌍ийкл' // cyrillic plus astral emoji
    const cps = Array.from(source)
    const spanLen = 3
    const range = cps.length - spanLen + 1
    const spans = sampleSpans(source, seed, range, spanLen)
    for (const span of spans) {
      assert.equal(Array.from(span.text).length, spanLen)
      assert.equal(span.text, cps.slice(span.pos, span.pos + spanLen).join(''))
      // No unpaired surrogate at either boundary.
      const first = span.text.charCodeAt(0)
      const last = span.text.charCodeAt(span.text.length - 1)
      assert.ok(first < 0xdc00 || first > 0xdfff, 'starts on a lone low surrogate')
      assert.ok(last < 0xd800 || last > 0xdbff, 'ends on a lone high surrogate')
    }
    // The emoji-bearing vector case double-checks against the fixture.
    const c = VECTORS.sampler_cases[1]
    assert.equal(c.name, 'case2_emoji_cyrillic')
    for (const s of c.spans) {
      assert.equal(Array.from(s.text).length, s.len)
    }
  })

  it('scores responses by exact string equality only', () => {
    const spanTexts = ['alpha', 'beta', 'gamma']
    const { k, results } = scoreResponses(spanTexts, ['alpha', 'Beta', 'gamma'])
    assert.equal(k, 2)
    assert.deepEqual(results, [true, false, true])
    assert.throws(() => scoreResponses(spanTexts, ['alpha']), /does not match span count/)
  })
})

describe('create and verify round trip', () => {
  it('creates a record that verifies, with attester set from the key', () => {
    const { record, privateKey } = buildRecord()
    assert.equal(record.type, 'read_fidelity_receipt')
    assert.equal(record.attester, publicKeyFromPrivate(privateKey))
    assert.match(record.sig, /^[0-9a-f]{128}$/)
    assert.deepEqual(verifyReadFidelityReceipt(record), { valid: true })
  })

  it('fails the signature when content_digest is tampered after signing', () => {
    const { record } = buildRecord()
    const tampered = {
      ...record,
      content_digest: `sha256:${sha256hex('rf-tampered content')}`,
    }
    const res = verifyReadFidelityReceipt(tampered)
    assert.equal(res.valid, false)
    assert.equal(res.reason, 'SIGNATURE_INVALID')
  })

  it('fails on the seed derivation for a replayed nonce, even re-signed', () => {
    const { record, privateKey } = buildRecord()
    // Replay: same commitments and responses under a NEW nonce. The
    // attacker re-signs, so the signature is valid; the seed no longer
    // matches the derivation and the reason names the seed.
    const replayed = resign(
      {
        ...record,
        challenge: { ...record.challenge, nonce: 'rf-replayed-nonce-2' },
      },
      privateKey,
    )
    assert.equal(
      edVerify(canonicalNoSig(replayed), replayed.sig, replayed.attester),
      true,
    )
    const res = verifyReadFidelityReceipt(replayed)
    assert.equal(res.valid, false)
    assert.match(String(res.reason), /SEED/)
  })

  it('fails on the seed derivation for a swapped presentation_digest, even re-signed', () => {
    const { record, privateKey } = buildRecord({
      presentationDigest: `sha256:${sha256hex('rf-presentation v1')}`,
    })
    assert.deepEqual(verifyReadFidelityReceipt(record), { valid: true })
    const swapped = resign(
      {
        ...record,
        presentation_digest: `sha256:${sha256hex('rf-presentation v2')}`,
      },
      privateKey,
    )
    assert.equal(
      edVerify(canonicalNoSig(swapped), swapped.sig, swapped.attester),
      true,
    )
    const res = verifyReadFidelityReceipt(swapped)
    assert.equal(res.valid, false)
    assert.match(String(res.reason), /SEED/)
  })

  it('rejects an n mismatch with span_commitments at create', () => {
    const { record } = buildRecord()
    const { type: _t, attester: _a, sig: _s, ...fields } = record
    assert.throws(
      () =>
        createReadFidelityReceipt(
          { ...fields, n: fields.n + 1 },
          sha256hex('rf-test key v1'),
        ),
      /n \(5\) must equal challenge\.span_commitments\.length \(4\)/,
    )
  })

  it('rejects an n mismatch with span_commitments at verify', () => {
    const { record, privateKey } = buildRecord()
    const mismatched = resign({ ...record, n: record.n + 1 }, privateKey)
    const res = verifyReadFidelityReceipt(mismatched)
    assert.equal(res.valid, false)
    assert.equal(res.reason, 'N_MISMATCH')
  })

  it('rejects a seed that does not match the derivation at create', () => {
    const { record } = buildRecord()
    const { type: _t, attester: _a, sig: _s, ...fields } = record
    assert.throws(
      () =>
        createReadFidelityReceipt(
          {
            ...fields,
            challenge: { ...fields.challenge, seed: sha256hex('rf-wrong-seed') },
          },
          sha256hex('rf-test key v1'),
        ),
      /seed/,
    )
  })
})

describe('verifyAgainstSource', () => {
  it('fully passes on the fixture record over the fixture source', () => {
    const { record } = VECTORS.record_case
    const source = VECTORS.sampler_cases[0].source
    const res = verifyAgainstSource(record, source)
    assert.equal(res.valid, true)
    assert.equal(res.reason, undefined)
    assert.equal(res.signature_valid, true)
    assert.equal(res.seed_valid, true)
    assert.equal(res.commitment_matches.length, record.n)
    assert.deepEqual(
      res.commitment_matches,
      Array.from({ length: record.n }, () => true),
    )
  })

  it('reports commitment mismatches against a different source', () => {
    const { record } = VECTORS.record_case
    const wrongSource =
      'An entirely different source text that still has enough length ' +
      'for the sampler to draw all of its spans from without throwing.'
    const res = verifyAgainstSource(record, wrongSource)
    assert.equal(res.valid, false)
    assert.equal(res.reason, 'COMMITMENT_MISMATCH')
    assert.equal(res.signature_valid, true)
    assert.equal(res.seed_valid, true)
    assert.ok(res.commitment_matches.some((m) => m === false))
  })

  it('reports SPAN_RECOMPUTE_FAILED when the source cannot produce the spans', () => {
    const { record } = VECTORS.record_case
    const res = verifyAgainstSource(record, 'too short')
    assert.equal(res.valid, false)
    assert.equal(res.reason, 'SPAN_RECOMPUTE_FAILED')
    assert.deepEqual(res.commitment_matches, [])
  })
})

describe('verifyResponses', () => {
  it('recomputes k = n for the fixture record with faithful responses', () => {
    const { record } = VECTORS.record_case
    const source = VECTORS.sampler_cases[0].source
    const responses = VECTORS.sampler_cases[0].spans.map((s) => s.text)
    const res = verifyResponses(record, source, responses)
    assert.equal(res.k_recomputed, record.n)
    assert.equal(res.matches_claimed_k, true)
    assert.equal(res.response_digest_ok, true)
  })

  it('recomputes an honest k < n for a record with one missed span', () => {
    const base = buildRecord()
    const degraded = base.spanTexts.slice()
    degraded[2] = `${degraded[2]}!`
    const { record, source } = buildRecord({ responses: degraded })
    assert.equal(record.k, base.spanTexts.length - 1)
    assert.deepEqual(verifyReadFidelityReceipt(record), { valid: true })
    const res = verifyResponses(record, source, degraded)
    assert.equal(res.k_recomputed, record.n - 1)
    assert.equal(res.matches_claimed_k, true)
    assert.equal(res.response_digest_ok, true)
  })

  it('flags a claimed k that the responses do not support', () => {
    const base = buildRecord()
    const degraded = base.spanTexts.slice()
    degraded[0] = `${degraded[0]} `
    const res = verifyResponses(base.record, base.source, degraded)
    assert.equal(res.k_recomputed, base.record.n - 1)
    assert.equal(res.matches_claimed_k, false)
    assert.equal(res.response_digest_ok, false)
  })
})

describe('record_case fixture parity', () => {
  it('reproduces canonical_no_sig_sha256 and the signature verifies', () => {
    const { record, canonical_no_sig_sha256, signature_valid, private_key_hex } =
      VECTORS.record_case
    const canonical = canonicalNoSig(record)
    assert.equal(sha256hex(canonical), canonical_no_sig_sha256)
    assert.equal(signature_valid, true)
    assert.equal(edVerify(canonical, record.sig, record.attester), true)
    assert.equal(record.attester, publicKeyFromPrivate(private_key_hex))
    assert.deepEqual(verifyReadFidelityReceipt(record), { valid: true })
  })

  it('re-signing the record body with the fixture key yields the identical sig', () => {
    const { record, private_key_hex } = VECTORS.record_case
    assert.equal(sign(canonicalNoSig(record), private_key_hex), record.sig)
  })

  it('binds the record to the fixture constants from the build contract', () => {
    const { record, private_key_hex } = VECTORS.record_case
    assert.equal(private_key_hex, sha256hex('read-fidelity fixture key v1'))
    assert.equal(
      record.content_digest,
      `sha256:${sha256hex('read-fidelity fixture content v1')}`,
    )
    assert.equal(record.presentation_digest, null)
    assert.equal(record.challenge.nonce, 'fixture-nonce-1')
    assert.equal(record.challenge.version, '1')
    assert.equal(record.k, record.n)
    assert.equal(record.n, record.challenge.span_commitments.length)
    // The fixture commitments are the commitments of sampler case 1 texts.
    assert.deepEqual(
      record.challenge.span_commitments,
      commitSpans(VECTORS.sampler_cases[0].spans.map((s) => s.text)),
    )
  })
})

describe('shared vectors file integrity', () => {
  it('replays every jcs_kat, including the unicode case', () => {
    assert.ok(VECTORS.jcs_kats.length >= 4)
    assert.ok(VECTORS.jcs_kats.some((k) => k.name === 'unicode_emoji_cyrillic'))
    for (const kat of VECTORS.jcs_kats) {
      assert.equal(canonicalizeJCS(kat.value), kat.canonical, `jcs KAT ${kat.name}`)
      assert.equal(sha256hex(kat.canonical), kat.sha256, `jcs KAT ${kat.name}`)
    }
  })

  it('replays the word handle round trips', () => {
    assert.equal(VECTORS.word_handle_cases.round_trips.length, 12)
    for (const c of VECTORS.word_handle_cases.round_trips) {
      assert.deepEqual(encodeProfile(c.digest, c.profile), c.words)
      const res = decodeProfile(c.words, c.profile)
      assert.equal(res.checksumOk, true)
      assert.equal(res.prefixHex, c.prefix_hex)
      assert.equal(res.prefixBits, c.prefix_bits)
    }
  })

  it('replays the word handle negatives, including the transposition', () => {
    const { substitution_negative, transposition_negative, out_of_lexicon_negative } =
      VECTORS.word_handle_cases

    const sub = decodeProfile(substitution_negative.words, substitution_negative.profile)
    assert.equal(sub.checksumOk, substitution_negative.checksum_ok)
    assert.equal(sub.checksumOk, false)
    const subBase = encodeProfile(substitution_negative.digest, substitution_negative.profile)
    assert.notEqual(
      substitution_negative.words[substitution_negative.substituted_index],
      subBase[substitution_negative.substituted_index],
    )

    const tr = decodeProfile(transposition_negative.words, transposition_negative.profile)
    assert.equal(tr.checksumOk, transposition_negative.checksum_ok)
    assert.equal(tr.checksumOk, false)
    const trBase = encodeProfile(transposition_negative.digest, transposition_negative.profile)
    const [i, j] = transposition_negative.swapped_indices
    assert.equal(transposition_negative.words[i], trBase[j])
    assert.equal(transposition_negative.words[j], trBase[i])

    const ol = decodeProfile(out_of_lexicon_negative.words, out_of_lexicon_negative.profile)
    assert.deepEqual([...ol.outOfLexicon], out_of_lexicon_negative.out_of_lexicon)
    assert.equal(ol.checksumOk, false)
    assert.equal(ol.prefixHex, null)
  })

  it('pins the lexicon identifiers', () => {
    assert.equal(
      VECTORS.lexicon_id,
      'sha256:2a9c4de3b5457154e6bde9d40af0da552c2556d8e80a2dec8b82dee4bca74510',
    )
    assert.equal(VECTORS.lexicon_profile, 'single-list-v1')
  })
})
