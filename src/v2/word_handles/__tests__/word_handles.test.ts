// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// word_handles codec (v2): tests
// ══════════════════════════════════════════════════════════════════
// Deterministic throughout: every derived digest, substituted
// position, replacement word, and transposition site comes from
// sha256 over a fixed label plus a counter. No wall clock, no
// randomness.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

import {
  encode,
  decode,
  encodeProfile,
  decodeProfile,
  minUniquePrefixBits,
  PROFILES,
  LEXICON_PROFILE,
  LEXICON_ID,
  LEXICON_NAME,
  WORDS,
  canonicalWordlistText,
} from '../index.js'

import type { WordHandleProfileName } from '../index.js'

function sha256Hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

/** First 4 bytes of sha256(label) as a big-endian uint32 seed. */
function seedUint32(label: string): number {
  return createHash('sha256').update(label, 'utf8').digest().readUInt32BE(0)
}

const WORD_TO_INDEX: ReadonlyMap<string, number> = (() => {
  const m = new Map<string, number>()
  for (let i = 0; i < WORDS.length; i++) m.set(WORDS[i], i)
  return m
})()

/** Expected prefixHex: first ceil(prefixBits/8) bytes, pad bits zeroed. */
function expectedPrefixHex(digestHex: string, prefixBits: number): string {
  const byteLen = Math.ceil(prefixBits / 8)
  const bytes = Buffer.from(digestHex.slice(0, byteLen * 2), 'hex')
  const rem = prefixBits % 8
  if (rem !== 0) {
    bytes[byteLen - 1] &= (0xff << (8 - rem)) & 0xff
  }
  return bytes.toString('hex')
}

const PROFILE_NAMES: readonly WordHandleProfileName[] = [
  'compact',
  'default',
  'high_assurance',
]

describe('lexicon integrity', () => {
  it('has exactly 2048 words', () => {
    assert.equal(WORDS.length, 2048)
  })

  it('is strictly sorted ascending (implies unique words)', () => {
    for (let i = 1; i < WORDS.length; i++) {
      assert.ok(
        WORDS[i - 1] < WORDS[i],
        `words not strictly sorted at index ${i}: ${WORDS[i - 1]} vs ${WORDS[i]}`,
      )
    }
  })

  it('has unique 4-character prefixes', () => {
    const prefixes = new Set(WORDS.map((w) => w.slice(0, 4)))
    assert.equal(prefixes.size, WORDS.length)
  })

  it('canonical wordlist text hashes to LEXICON_ID', () => {
    assert.equal(LEXICON_NAME, 'aps-handle-en-v1')
    const hex = createHash('sha256')
      .update(canonicalWordlistText(), 'utf8')
      .digest('hex')
    assert.equal(`sha256:${hex}`, LEXICON_ID)
  })

  it('has zero overlap with the bip39_english.txt disjointness input', () => {
    // lexicon-source/bip39_english.txt is a pinned DISJOINTNESS input to
    // the lexicon generator; no lexicon word may appear in it.
    const raw = readFileSync(
      new URL('../lexicon-source/bip39_english.txt', import.meta.url),
      'utf8',
    )
    const banned = new Set(
      raw
        .split('\n')
        .map((w) => w.trim())
        .filter((w) => w.length > 0),
    )
    assert.equal(banned.size, 2048)
    const overlap = WORDS.filter((w) => banned.has(w))
    assert.deepEqual(overlap, [])
  })
})

describe('round-trip across all three profiles', () => {
  it('round-trips 200 derived digests per profile', () => {
    for (let t = 0; t < 200; t++) {
      const digest = sha256Hex(`wh-roundtrip:${t}`)
      for (const name of PROFILE_NAMES) {
        const p = PROFILES[name]
        const words = encodeProfile(digest, name)
        assert.equal(words.length, p.dataWords + p.checksumWords)
        const res = decodeProfile(words, name)
        assert.equal(res.checksumOk, true)
        assert.equal(res.prefixBits, p.prefixBits)
        assert.equal(res.prefixHex, expectedPrefixHex(digest, p.prefixBits))
        assert.equal(res.failedWordIndex, null)
        assert.deepEqual(res.outOfLexicon, [])
      }
    }
  })

  it('accepts a sha256: prefix and raw bytes as equivalent inputs', () => {
    const digest = sha256Hex('wh-input-forms:0')
    const fromHex = encode(digest)
    const fromPrefixed = encode(`sha256:${digest}`)
    const fromBytes = encode(new Uint8Array(Buffer.from(digest, 'hex')))
    assert.deepEqual(fromPrefixed, fromHex)
    assert.deepEqual(fromBytes, fromHex)
  })

  it('exposes the profile table and lexicon profile id', () => {
    assert.equal(LEXICON_PROFILE, 'single-list-v1')
    assert.deepEqual(PROFILES.compact, {
      name: 'compact',
      dataWords: 4,
      checksumWords: 1,
      prefixBits: 44,
    })
    assert.deepEqual(PROFILES.default, {
      name: 'default',
      dataWords: 6,
      checksumWords: 1,
      prefixBits: 66,
    })
    assert.deepEqual(PROFILES.high_assurance, {
      name: 'high_assurance',
      dataWords: 8,
      checksumWords: 2,
      prefixBits: 88,
    })
  })
})

describe('substitution detection (default profile, 600 trials)', () => {
  it('detects >= 597 of 600 single data word substitutions', () => {
    const dataWords = PROFILES.default.dataWords
    let detected = 0
    for (let t = 0; t < 600; t++) {
      const digest = sha256Hex(`wh-substitute:${t}`)
      const words = encode(digest)
      const pos = seedUint32(`wh-substitute-pos:${t}`) % dataWords
      const origIdx = WORD_TO_INDEX.get(words[pos]) as number
      const delta = 1 + (seedUint32(`wh-substitute-word:${t}`) % (WORDS.length - 1))
      const mutated = words.slice()
      mutated[pos] = WORDS[(origIdx + delta) % WORDS.length]
      const res = decode(mutated)
      if (!res.checksumOk) detected++
      if (res.failedWordIndex !== null) {
        assert.equal(
          res.failedWordIndex,
          pos,
          `trial ${t}: localized ${res.failedWordIndex}, substituted ${pos}`,
        )
      }
    }
    assert.ok(detected >= 597, `detected ${detected} of 600, expected >= 597`)
  })
})

describe('transposition detection (default profile, 300 trials)', () => {
  it('detects >= 297 of 300 adjacent differing data word swaps', () => {
    const dataWords = PROFILES.default.dataWords
    let detected = 0
    for (let t = 0; t < 300; t++) {
      const digest = sha256Hex(`wh-transpose:${t}`)
      const words = encode(digest)
      const start = seedUint32(`wh-transpose-pos:${t}`) % (dataWords - 1)
      let pair = -1
      for (let k = 0; k < dataWords - 1; k++) {
        const i = (start + k) % (dataWords - 1)
        if (words[i] !== words[i + 1]) {
          pair = i
          break
        }
      }
      assert.ok(pair >= 0, `trial ${t}: no adjacent differing data words`)
      const mutated = words.slice()
      const tmp = mutated[pair]
      mutated[pair] = mutated[pair + 1]
      mutated[pair + 1] = tmp
      const res = decode(mutated)
      if (!res.checksumOk) detected++
    }
    assert.ok(detected >= 297, `detected ${detected} of 300, expected >= 297`)
  })
})

describe('high_assurance profile (2 checksum words)', () => {
  it('round-trips and reports both checksum words through decode', () => {
    const digest = sha256Hex('wh-high-assurance:0')
    const words = encodeProfile(digest, 'high_assurance')
    assert.equal(words.length, 10)
    const res = decode(words, 2)
    assert.equal(res.checksumOk, true)
    assert.equal(res.prefixBits, 88)
    assert.equal(res.prefixHex, expectedPrefixHex(digest, 88))
  })

  it('detects data word substitutions and localizes them precisely', () => {
    const dataWords = PROFILES.high_assurance.dataWords
    let localized = 0
    for (let t = 0; t < 40; t++) {
      const digest = sha256Hex(`wh-ha-substitute:${t}`)
      const words = encodeProfile(digest, 'high_assurance')
      const pos = seedUint32(`wh-ha-substitute-pos:${t}`) % dataWords
      const origIdx = WORD_TO_INDEX.get(words[pos]) as number
      const delta = 1 + (seedUint32(`wh-ha-substitute-word:${t}`) % (WORDS.length - 1))
      const mutated = words.slice()
      mutated[pos] = WORDS[(origIdx + delta) % WORDS.length]
      const res = decodeProfile(mutated, 'high_assurance')
      assert.equal(res.checksumOk, false, `trial ${t}: substitution not detected`)
      if (res.failedWordIndex !== null) {
        assert.equal(res.failedWordIndex, pos)
        localized++
      }
    }
    // With two checksum words a wrong position is coincidentally fixable
    // with probability about 2047 * 2^-22, so localization is almost
    // always unique.
    assert.ok(localized >= 35, `localized ${localized} of 40, expected >= 35`)
  })
})

describe('out-of-lexicon words', () => {
  it('reports indices and suppresses decoding', () => {
    const digest = sha256Hex('wh-out-of-lexicon:0')
    const words = encode(digest)
    const mutated = words.slice()
    mutated[2] = 'notaword'
    mutated[4] = 'Abacus' // case-sensitive: 'abacus' is in the lexicon, this is not
    const res = decode(mutated)
    assert.deepEqual(res.outOfLexicon, [2, 4])
    assert.equal(res.prefixHex, null)
    assert.equal(res.prefixBits, null)
    assert.equal(res.checksumOk, false)
    assert.equal(res.failedWordIndex, null)
  })

  it('does not trim whitespace (exact code-unit equality)', () => {
    const digest = sha256Hex('wh-out-of-lexicon:1')
    const words = encode(digest)
    const mutated = words.slice()
    mutated[0] = `${mutated[0]} `
    const res = decode(mutated)
    assert.deepEqual(res.outOfLexicon, [0])
    assert.equal(res.checksumOk, false)
  })
})

describe('prefixHex padding semantics', () => {
  it('66-bit decode returns 18 hex chars with pad bits zero and prefixBits 66', () => {
    const allOnes = 'ff'.repeat(32)
    const res = decode(encode(allOnes, 66, 1))
    assert.equal(res.prefixBits, 66)
    assert.equal(res.prefixHex?.length, 18)
    // 66 data bits into 9 bytes: the final byte keeps its top 2 bits and
    // pads the low 6 with zeros, so an all-ones input ends in "c0".
    assert.equal(res.prefixHex, 'ffffffffffffffffc0')
  })

  it('44-bit and 88-bit cases pad to the byte boundary', () => {
    const allOnes = 'ff'.repeat(32)
    const compact = decode(encode(allOnes, 44, 1))
    assert.equal(compact.prefixBits, 44)
    assert.equal(compact.prefixHex, 'fffffffffff0')
    const high = decode(encode(allOnes, 88, 2), 2)
    assert.equal(high.prefixBits, 88)
    assert.equal(high.prefixHex, 'ff'.repeat(11))
  })
})

describe('minUniquePrefixBits', () => {
  it('returns 44 when 44-bit prefixes are already pairwise distinct', () => {
    const digests = [0, 1, 2, 3].map((i) => sha256Hex(`wh-unique:${i}`))
    assert.equal(minUniquePrefixBits(digests), 44)
  })

  it('moves to the next multiple of 11 that separates shared 44-bit prefixes', () => {
    // Shared first 48 bits (12 hex chars), differing at bit 48: 44-bit
    // prefixes collide, 55-bit prefixes differ.
    const shared = '0123456789ab'
    const digests = [`${shared}0${'0'.repeat(19)}`, `${shared}f${'0'.repeat(19)}`]
    assert.equal(minUniquePrefixBits(digests), 55)
    // Shared first 56 bits (14 hex chars), differing at bit 56: 55-bit
    // prefixes collide too, 66-bit prefixes differ.
    const shared56 = '0123456789abcd'
    const digests56 = [`${shared56}0${'0'.repeat(17)}`, `${shared56}f${'0'.repeat(17)}`]
    assert.equal(minUniquePrefixBits(digests56), 66)
  })

  it('rounds startBits up to a multiple of 11', () => {
    const digests = [0, 1].map((i) => sha256Hex(`wh-startbits:${i}`))
    assert.equal(minUniquePrefixBits(digests, 50), 55)
  })

  it('strips sha256: prefixes and returns 44 for a single digest', () => {
    const digest = sha256Hex('wh-single:0')
    assert.equal(minUniquePrefixBits([`sha256:${digest}`]), 44)
  })

  it('throws on duplicates and on empty input', () => {
    const digest = sha256Hex('wh-duplicate:0')
    assert.throws(
      () => minUniquePrefixBits([`sha256:${digest}`, digest]),
      /duplicate digests/,
    )
    assert.throws(() => minUniquePrefixBits([]), /at least one digest/)
  })
})

describe('encode and decode validation errors', () => {
  const digest = sha256Hex('wh-validate:0')

  it('rejects prefixBits that is not a positive multiple of 11', () => {
    assert.throws(() => encode(digest, 12), /positive multiple of 11/)
    assert.throws(() => encode(digest, 0), /positive multiple of 11/)
    assert.throws(() => encode(digest, -11), /positive multiple of 11/)
    assert.throws(() => encode(digest, 11.5), /positive multiple of 11/)
  })

  it('rejects input shorter than prefixBits bits', () => {
    assert.throws(() => encode('abcd', 66), /supplies 16 bits/)
    assert.throws(() => encode(new Uint8Array(8), 88, 2), /supplies 64 bits/)
  })

  it('rejects checksumWords outside {1, 2}', () => {
    assert.throws(() => encode(digest, 66, 0), /checksumWords must be 1 or 2/)
    assert.throws(() => encode(digest, 66, 3), /checksumWords must be 1 or 2/)
    assert.throws(() => encode(digest, 66, 1.5), /checksumWords must be 1 or 2/)
    assert.throws(() => decode(encode(digest), 3), /checksumWords must be 1 or 2/)
  })

  it('rejects non-hex string input', () => {
    assert.throws(() => encode('xyz'), /non-hex characters/)
  })

  it('rejects word counts that leave no data words', () => {
    assert.throws(() => decode([WORDS[0]], 1), /leaves no data words/)
    assert.throws(() => decode([WORDS[0], WORDS[1]], 2), /leaves no data words/)
  })

  it('rejects profile word count mismatches', () => {
    const words = encodeProfile(digest, 'default')
    assert.throws(
      () => decodeProfile(words.slice(0, 5), 'default'),
      /expects 7 words, got 5/,
    )
  })
})
