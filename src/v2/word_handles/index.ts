// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// word_handles (word_digest_handle codec, v2): public surface
// ══════════════════════════════════════════════════════════════════
// Renders the leading bits of a digest as words from the versioned
// aps-handle-en-v1 lexicon (2048 words, 11 bits per word) plus one or
// two position-dependent checksum words. Pure functions: no I/O, no
// clock, no randomness. See README.md for profiles, detection and
// localization math, and the identifier prohibition.
// ══════════════════════════════════════════════════════════════════

export {
  encode,
  decode,
  encodeProfile,
  decodeProfile,
  minUniquePrefixBits,
  PROFILES,
  LEXICON_PROFILE,
} from './codec.js'

export {
  LEXICON_NAME,
  LEXICON_ID,
  WORDS,
  canonicalWordlistText,
} from './lexicon.js'

export type {
  DecodeResult,
  WordHandleProfile,
  WordHandleProfileName,
} from './types.js'
