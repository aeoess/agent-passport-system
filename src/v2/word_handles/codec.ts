// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// word_handles codec (v2): encode, decode, minUniquePrefixBits,
// PROFILES, encodeProfile, decodeProfile
// ══════════════════════════════════════════════════════════════════
// Deterministic, pure functions: no I/O, no clock, no randomness.
//
// Encoding rules (v2):
//   - prefixBits is a positive multiple of 11. checksumWords is 1 or
//     2. Word count = prefixBits/11 + checksumWords.
//   - Bit order is MSB-first from byte 0. Data word i covers bits
//     [11*i, 11*i + 11) as an integer index into WORDS.
//   - packedPrefix = the first prefixBits bits packed into
//     ceil(prefixBits/8) bytes, MSB-first, unused low-order bits of
//     the final byte set to 0.
//   - checksumDigest = sha256( BE16(prefixBits) || packedPrefix ).
//     BE16 is the two-byte big-endian unsigned encoding of prefixBits.
//     Checksum word j (j = 0..checksumWords-1) = bits [11*j, 11*j+11)
//     of checksumDigest, appended after the data words in order.
//   - The construction is position-dependent: the hash runs over the
//     ordered packed bits, so transposing any two differing data words
//     changes packedPrefix and fails the checksum with probability
//     1 - 2^-11 per event for one checksum word (1 - 2^-22 for two).
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'

import { WORDS } from './lexicon.js'
import type { DecodeResult, WordHandleProfile, WordHandleProfileName } from './types.js'

const WORD_BITS = 11
const HEX_RE = /^[0-9a-fA-F]*$/

/** Identifier of the lexicon layout profile used by this codec. */
export const LEXICON_PROFILE = 'single-list-v1'

/**
 * Built-in word handle profiles. Word count = dataWords + checksumWords;
 * prefixBits = 11 * dataWords.
 *
 *   compact:        4+1 (44 bits). Set-scoped display ONLY; render-time
 *                   uniqueness plus lengthening is mandatory
 *                   (minUniquePrefixBits is the tool).
 *   default:        6+1 (66 bits). Minimum for any cross-set reference.
 *   high_assurance: 8+2 (88 bits). Archival and adversarial contexts.
 */
export const PROFILES: Readonly<Record<WordHandleProfileName, WordHandleProfile>> = {
  compact: { name: 'compact', dataWords: 4, checksumWords: 1, prefixBits: 44 },
  default: { name: 'default', dataWords: 6, checksumWords: 1, prefixBits: 66 },
  high_assurance: { name: 'high_assurance', dataWords: 8, checksumWords: 2, prefixBits: 88 },
}

/** Lexicon word to index, built once. Exact code-unit key equality. */
const WORD_INDEX: ReadonlyMap<string, number> = (() => {
  const m = new Map<string, number>()
  for (let i = 0; i < WORDS.length; i++) m.set(WORDS[i], i)
  return m
})()

function validatePrefixBits(prefixBits: number): void {
  if (
    !Number.isInteger(prefixBits) ||
    prefixBits <= 0 ||
    prefixBits % WORD_BITS !== 0
  ) {
    throw new Error(
      `prefixBits must be a positive multiple of ${WORD_BITS}, got ${prefixBits}`,
    )
  }
  if (prefixBits > 0xffff) {
    throw new Error(
      `prefixBits must fit in 16 bits (BE16 header), got ${prefixBits}`,
    )
  }
}

function validateChecksumWords(checksumWords: number): void {
  if (checksumWords !== 1 && checksumWords !== 2) {
    throw new Error(`checksumWords must be 1 or 2, got ${checksumWords}`)
  }
}

/** Strip an optional leading "sha256:" from a hex string. */
function stripSha256Prefix(hex: string): string {
  return hex.startsWith('sha256:') ? hex.slice('sha256:'.length) : hex
}

/**
 * Normalize encode input to bytes plus the exact number of bits the
 * caller supplied. Hex strings supply 4 bits per character; an
 * odd-length hex string is padded with a zero nibble for byte packing
 * but the padding does not count toward the supplied bits.
 */
function toBytes(input: Uint8Array | string): { bytes: Uint8Array; bitLength: number } {
  if (typeof input === 'string') {
    const hex = stripSha256Prefix(input)
    if (!HEX_RE.test(hex)) {
      throw new Error('input hex string contains non-hex characters')
    }
    const bitLength = hex.length * 4
    const padded = hex.length % 2 === 0 ? hex : hex + '0'
    const bytes = new Uint8Array(padded.length / 2)
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(padded.slice(2 * i, 2 * i + 2), 16)
    }
    return { bytes, bitLength }
  }
  return { bytes: input, bitLength: input.length * 8 }
}

/** Bit i of a byte array, MSB-first from byte 0. */
function getBit(bytes: Uint8Array, i: number): number {
  return (bytes[i >> 3] >> (7 - (i & 7))) & 1
}

/**
 * Pack the first prefixBits bits of `bytes` into ceil(prefixBits/8)
 * bytes, MSB-first, unused low-order bits of the final byte set to 0.
 */
function packPrefix(bytes: Uint8Array, prefixBits: number): Uint8Array {
  const byteLen = Math.ceil(prefixBits / 8)
  const packed = new Uint8Array(byteLen)
  packed.set(bytes.subarray(0, byteLen))
  const rem = prefixBits % 8
  if (rem !== 0) {
    packed[byteLen - 1] &= (0xff << (8 - rem)) & 0xff
  }
  return packed
}

/**
 * Checksum word indices: bits [11*j, 11*j + 11) of
 * sha256( BE16(prefixBits) || packedPrefix ) for j = 0..checksumWords-1.
 */
function checksumIndicesFor(
  prefixBits: number,
  packedPrefix: Uint8Array,
  checksumWords: number,
): number[] {
  const msg = new Uint8Array(2 + packedPrefix.length)
  msg[0] = (prefixBits >> 8) & 0xff
  msg[1] = prefixBits & 0xff
  msg.set(packedPrefix, 2)
  const digest = createHash('sha256').update(msg).digest()
  const out: number[] = []
  for (let j = 0; j < checksumWords; j++) {
    let idx = 0
    for (let b = 0; b < WORD_BITS; b++) {
      idx = (idx << 1) | getBit(digest, WORD_BITS * j + b)
    }
    out.push(idx)
  }
  return out
}

/**
 * Encode the first `prefixBits` bits of `input` as a word_digest_handle:
 * prefixBits/11 data words followed by `checksumWords` checksum words.
 *
 * `input` is raw bytes or a hex string; a leading "sha256:" prefix on
 * hex input is stripped. Throws when prefixBits is not a positive
 * multiple of 11, when the input supplies fewer than prefixBits bits,
 * or when checksumWords is not 1 or 2.
 */
export function encode(
  input: Uint8Array | string,
  prefixBits = 66,
  checksumWords = 1,
): string[] {
  validatePrefixBits(prefixBits)
  validateChecksumWords(checksumWords)
  const { bytes, bitLength } = toBytes(input)
  if (bitLength < prefixBits) {
    throw new Error(
      `input supplies ${bitLength} bits, need at least ${prefixBits}`,
    )
  }
  const dataWordCount = prefixBits / WORD_BITS
  const words: string[] = []
  for (let i = 0; i < dataWordCount; i++) {
    let idx = 0
    for (let b = 0; b < WORD_BITS; b++) {
      idx = (idx << 1) | getBit(bytes, WORD_BITS * i + b)
    }
    words.push(WORDS[idx])
  }
  const packed = packPrefix(bytes, prefixBits)
  for (const idx of checksumIndicesFor(prefixBits, packed, checksumWords)) {
    words.push(WORDS[idx])
  }
  return words
}

/** Encode with a named profile (prefixBits and checksumWords from the table). */
export function encodeProfile(
  input: Uint8Array | string,
  profile: WordHandleProfileName,
): string[] {
  const p = PROFILES[profile]
  if (p === undefined) {
    throw new Error(`unknown word handle profile: ${profile}`)
  }
  return encode(input, p.prefixBits, p.checksumWords)
}

/** Rebuild the packed prefix bytes from data word indices. */
function packFromIndices(indices: readonly number[], prefixBits: number): Uint8Array {
  const packed = new Uint8Array(Math.ceil(prefixBits / 8))
  let bitPos = 0
  for (const idx of indices) {
    for (let b = WORD_BITS - 1; b >= 0; b--) {
      if ((idx >> b) & 1) {
        packed[bitPos >> 3] |= 0x80 >> (bitPos & 7)
      }
      bitPos++
    }
  }
  return packed
}

function toHex(bytes: Uint8Array): string {
  let hex = ''
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0')
  }
  return hex
}

/**
 * Decode a word_digest_handle. Never throws on unknown words (reported
 * via `outOfLexicon`); throws when checksumWords is not 1 or 2 or when
 * the word count leaves no data words.
 *
 * `prefixHex` is the full packed prefix, 2*ceil(prefixBits/8) lowercase
 * hex characters with trailing pad bits zero; `prefixBits` is returned
 * so consumers compare BIT-scoped, never by raw string beyond
 * prefixBits. Localization (`failedWordIndex`) is best effort and only
 * attempted when the checksum fails and every word is in the lexicon.
 * See DecodeResult for the exact rules.
 */
export function decode(words: readonly string[], checksumWords = 1): DecodeResult {
  validateChecksumWords(checksumWords)

  const outOfLexicon: number[] = []
  for (let i = 0; i < words.length; i++) {
    if (!WORD_INDEX.has(words[i])) outOfLexicon.push(i)
  }
  if (outOfLexicon.length > 0) {
    return {
      prefixHex: null,
      prefixBits: null,
      checksumOk: false,
      failedWordIndex: null,
      outOfLexicon,
    }
  }

  const dataWordCount = words.length - checksumWords
  if (dataWordCount <= 0) {
    throw new Error(
      `word count ${words.length} with ${checksumWords} checksum word(s) leaves no data words`,
    )
  }
  const prefixBits = WORD_BITS * dataWordCount
  validatePrefixBits(prefixBits)

  const indices = words.slice(0, dataWordCount).map((w) => WORD_INDEX.get(w) as number)
  const givenChecksums = words
    .slice(dataWordCount)
    .map((w) => WORD_INDEX.get(w) as number)
  const packed = packFromIndices(indices, prefixBits)
  const prefixHex = toHex(packed)

  const expectedChecksums = checksumIndicesFor(prefixBits, packed, checksumWords)
  const checksumOk = expectedChecksums.every((e, j) => e === givenChecksums[j])

  let failedWordIndex: number | null = null
  if (!checksumOk) {
    const fixable: number[] = []
    const trial = indices.slice()
    for (let i = 0; i < dataWordCount; i++) {
      const original = trial[i]
      for (let cand = 0; cand < WORDS.length; cand++) {
        if (cand === original) continue
        trial[i] = cand
        const candPacked = packFromIndices(trial, prefixBits)
        const candChecksums = checksumIndicesFor(prefixBits, candPacked, checksumWords)
        if (candChecksums.every((e, j) => e === givenChecksums[j])) {
          fixable.push(i)
          break
        }
      }
      trial[i] = original
    }
    if (fixable.length === 1) {
      failedWordIndex = fixable[0]
    } else if (fixable.length === 0) {
      const differing: number[] = []
      for (let j = 0; j < checksumWords; j++) {
        if (givenChecksums[j] !== expectedChecksums[j]) {
          differing.push(dataWordCount + j)
        }
      }
      failedWordIndex = differing.length === 1 ? differing[0] : null
    } else {
      failedWordIndex = null
    }
  }

  return { prefixHex, prefixBits, checksumOk, failedWordIndex, outOfLexicon }
}

/**
 * Decode with a named profile. Throws when the word count does not
 * match the profile shape (dataWords + checksumWords).
 */
export function decodeProfile(
  words: readonly string[],
  profile: WordHandleProfileName,
): DecodeResult {
  const p = PROFILES[profile]
  if (p === undefined) {
    throw new Error(`unknown word handle profile: ${profile}`)
  }
  const expected = p.dataWords + p.checksumWords
  if (words.length !== expected) {
    throw new Error(
      `profile ${p.name} expects ${expected} words, got ${words.length}`,
    )
  }
  return decode(words, p.checksumWords)
}

/**
 * First `bits` bits of a hex string as a canonical comparison key:
 * ceil(bits/4) hex chars with unused low-order bits of the final
 * nibble masked to zero. Throws when the hex string supplies fewer
 * than `bits` bits.
 */
function bitPrefixKey(hex: string, bits: number): string {
  if (hex.length * 4 < bits) {
    throw new Error(
      `digest supplies ${hex.length * 4} bits, need at least ${bits} to compare prefixes`,
    )
  }
  const chars = Math.ceil(bits / 4)
  const prefix = hex.slice(0, chars)
  const rem = bits % 4
  if (rem === 0) return prefix
  const masked = parseInt(prefix[chars - 1], 16) & ((0xf << (4 - rem)) & 0xf)
  return prefix.slice(0, chars - 1) + masked.toString(16)
}

/**
 * Smallest multiple of 11 that is >= startBits such that the leading
 * prefixes of all digests are pairwise BIT-distinct at that length.
 *
 * Hex inputs may carry "sha256:" prefixes (stripped) and are compared
 * case-insensitively. Throws on empty input or duplicate full digests
 * (no prefix length can separate identical digests).
 */
export function minUniquePrefixBits(digestsHex: readonly string[], startBits = 44): number {
  if (digestsHex.length === 0) {
    throw new Error('minUniquePrefixBits requires at least one digest')
  }
  const normalized = digestsHex.map((d) => {
    const hex = stripSha256Prefix(d).toLowerCase()
    if (hex.length === 0 || !/^[0-9a-f]+$/.test(hex)) {
      throw new Error(`digest is not a hex string: ${d}`)
    }
    return hex
  })
  if (new Set(normalized).size !== normalized.length) {
    throw new Error('duplicate digests: no prefix length can separate them')
  }
  let bits = Math.max(
    WORD_BITS,
    Math.ceil(startBits / WORD_BITS) * WORD_BITS,
  )
  for (;;) {
    const prefixes = new Set(normalized.map((d) => bitPrefixKey(d, bits)))
    if (prefixes.size === normalized.length) return bits
    bits += WORD_BITS
  }
}
