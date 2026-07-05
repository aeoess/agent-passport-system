# word_handles (word_digest_handle codec, v2)

A word_digest_handle renders the leading `prefixBits` bits of a digest as data words from the versioned `aps-handle-en-v1` lexicon (2048 words, 11 bits per word) followed by one or two checksum words. Handles are a transcription and readback aid for humans and lossy perceptual channels. They are not a cryptographic proof: a handle carries only `prefixBits` of the underlying digest.

Lexicon layout profile id: `single-list-v1` (exported as `LEXICON_PROFILE`).

## Identifier prohibition

A word_digest_handle MUST be resolved against a full digest or a collision-checked set and MUST NOT serve as a sole record identifier, a secret, or wallet material; handles are never rendered in 12, 15, 18, 21, or 24 word groupings (those lengths read as seed phrases). The built-in profiles render 5, 7, and 10 words, none of which falls in that range.

## Profiles

| Profile | Shape | Words | Prefix bits | Use |
| --- | --- | --- | --- | --- |
| `compact` | 4 data + 1 checksum | 5 | 44 | Set-scoped display ONLY. Render-time uniqueness plus lengthening is mandatory; `minUniquePrefixBits` is the tool. |
| `default` | 6 data + 1 checksum | 7 | 66 | Minimum for any cross-set reference. |
| `high_assurance` | 8 data + 2 checksum | 10 | 88 | Archival and adversarial contexts. |

`encodeProfile(input, name)` and `decodeProfile(words, name)` apply the table; `encode(input, prefixBits, checksumWords)` accepts any positive multiple of 11 for `prefixBits` and 1 or 2 checksum words.

## Construction

Bit order is MSB-first from byte 0. Data word `i` is bits `[11i, 11i+11)` of the input as an index into `WORDS`. `packedPrefix` is the first `prefixBits` bits packed into `ceil(prefixBits/8)` bytes with unused low-order bits zero. The checksum digest is `sha256(BE16(prefixBits) || packedPrefix)`; checksum word `j` is bits `[11j, 11j+11)` of that digest, appended after the data words in order.

The construction is position-dependent: the hash runs over the ordered packed bits, so transposing any two differing data words changes `packedPrefix` and fails the checksum.

## Detection and localization

Detection: a substitution or a transposition of differing data words passes the checksum only by chance, with probability `2^-11` for one checksum word and `2^-22` for two. Detection probability per event is therefore `1 - 2^-11` (compact, default) or `1 - 2^-22` (high_assurance).

Localization (`failedWordIndex`) is best effort. When the checksum fails and all words are in the lexicon, the decoder scans each data position for alternative lexicon words that would validate all checksum words. Exactly one fixable position: that index. None fixable: if exactly one given checksum word differs from the recomputed one, that absolute index; otherwise null. More than one fixable: null (ambiguous).

Ambiguity math: with one checksum word, a candidate replacement at a wrong position validates with probability `2^-11`, so across the other 2047 lexicon words a wrong position is coincidentally fixable with probability about `1 - (1 - 2^-11)^2047`, which is about `1 - 1/e`, about 0.63. Localization at 44 bits is therefore frequently ambiguous even though detection misses only with probability `2^-11`. With two checksum words the wrong-position fixability probability drops to about `2047 * 2^-22` (about 0.0005) and localization is usually unique.

## Decode semantics

`decode(words, checksumWords)` returns `{ prefixHex, prefixBits, checksumOk, failedWordIndex, outOfLexicon }`.

- `outOfLexicon` lists indices of words not exactly equal to a lexicon word (code-unit equality, no trim, no unicode normalization). When non-empty, `prefixHex` and `prefixBits` are null, `checksumOk` is false, `failedWordIndex` is null.
- `prefixHex` is the full packed prefix, `2*ceil(prefixBits/8)` lowercase hex characters; trailing pad bits are zero. For the 66-bit default profile that is 18 hex characters with the final bits padded. Consumers must compare BIT-scoped using the returned `prefixBits`, never by raw string beyond `prefixBits`.

## minUniquePrefixBits

`minUniquePrefixBits(digestsHex, startBits = 44)` returns the smallest multiple of 11 at or above `startBits` at which all digest prefixes are pairwise bit-distinct. It strips optional `sha256:` prefixes and throws on empty input or duplicate digests. Use it to lengthen `compact` handles at render time until the displayed set is collision-free.

## Lexicon provenance

The lexicon data file `lexicon.ts` (`LEXICON_NAME` `aps-handle-en-v1`, `LEXICON_ID` pinned by sha256 of the canonical wordlist text) is generated; do not edit it by hand. The generator, pinned inputs, derivation constraints, and CC-BY attribution live in [`lexicon-source/`](./lexicon-source/). The word list is disjoint from the `lexicon-source/bip39_english.txt` input list (a disjointness constraint enforced at generation time and re-checked in tests), every word has a unique 4-letter prefix, and the list is filtered for glyph confusability. The lexicon is versioned and swappable: records pin `lexicon_id`, and custom lexicons are future work.
