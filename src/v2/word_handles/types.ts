// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// word_handles codec (v2): TypeScript types
// ══════════════════════════════════════════════════════════════════
// A word_digest_handle renders the leading prefixBits bits of a digest
// as words from a versioned 2048-word lexicon (11 bits per word)
// followed by one or two checksum words. Handles are a transcription
// aid, not a cryptographic proof: they carry only prefixBits of the
// underlying digest and must be resolved against a full digest or a
// collision-checked set.
// ══════════════════════════════════════════════════════════════════

/** Names of the built-in word handle profiles. */
export type WordHandleProfileName = 'compact' | 'default' | 'high_assurance'

/**
 * A word handle profile: a fixed (data words, checksum words) shape.
 *
 *   - compact:        4 data + 1 checksum (44 bits). Set-scoped display
 *     only; render-time uniqueness plus lengthening is mandatory
 *     (minUniquePrefixBits is the tool).
 *   - default:        6 data + 1 checksum (66 bits). Minimum for any
 *     cross-set reference.
 *   - high_assurance: 8 data + 2 checksum (88 bits). Archival and
 *     adversarial contexts.
 */
export interface WordHandleProfile {
  readonly name: WordHandleProfileName
  readonly dataWords: number
  readonly checksumWords: 1 | 2
  readonly prefixBits: number
}

/**
 * Result of decoding a word handle back into a digest prefix.
 *
 * Field semantics:
 *   - `outOfLexicon`: 0-based indices of input words that are not
 *     exactly equal (code-unit equality, no trim, no unicode
 *     normalization) to a lexicon word. When non-empty, no decoding is
 *     attempted: `prefixHex` and `prefixBits` are null, `checksumOk`
 *     is false, and `failedWordIndex` is null.
 *   - `prefixHex`: lowercase hex of the packed prefix, exactly
 *     2*ceil(prefixBits/8) characters. Trailing pad bits (bit
 *     positions >= prefixBits) are zero. Consumers must compare
 *     BIT-scoped using `prefixBits`, never by raw string beyond
 *     prefixBits. Null when `outOfLexicon` is non-empty.
 *   - `prefixBits`: 11 times the data word count (word count minus
 *     checksumWords). Null when `outOfLexicon` is non-empty.
 *   - `checksumOk`: whether ALL given checksum words equal the
 *     recomputed checksum words for the recovered prefix.
 *   - `failedWordIndex`: best-effort localization of a single bad
 *     word, populated only when `checksumOk` is false and
 *     `outOfLexicon` is empty. A data position is "fixable" if some
 *     other lexicon word at that position validates ALL checksum
 *     words. Exactly one fixable position: that index. No fixable
 *     position: if exactly one given checksum word differs from the
 *     recomputed one, that absolute index; otherwise null. More than
 *     one fixable position: null (ambiguous). With one checksum word,
 *     a wrong position is coincidentally fixable with probability
 *     about 0.63, so 44-bit localization is frequently ambiguous;
 *     detection itself misses only with probability 2^-11 (2^-22 with
 *     two checksum words). See the module README for the math.
 */
export interface DecodeResult {
  readonly prefixHex: string | null
  readonly prefixBits: number | null
  readonly checksumOk: boolean
  readonly failedWordIndex: number | null
  readonly outOfLexicon: readonly number[]
}
