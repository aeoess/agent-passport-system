// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// read_fidelity_receipt (v2): seed derivation, span sampler, scoring
// ══════════════════════════════════════════════════════════════════
// Deterministic, pure functions: no I/O, no clock, no randomness.
// Bit-exact across languages:
//   seed = sha256hex(utf8(content_digest
//            + (presentation_digest == null ? "" : presentation_digest)
//            + nonce + version))            (no separators)
//   position i, attempt j:
//     h = sha256(utf8(seed + ":" + i + ":" + j))
//     pos = BE-uint64(first 8 bytes of h) mod range
//     bump j on repeat until the position is unused
//   span text = code points [pos, pos + spanLen), Array.from slicing.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'

import type { SampledSpan, ScoreResponsesResult } from './types.js'

function sha256hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex')
}

/**
 * Derive the challenge seed. Concatenation with no separators, exactly:
 * content_digest, then presentation_digest or the empty string when
 * null, then nonce, then version. The first two components are
 * fixed-format ("sha256:" plus 64 hex chars, 71 chars, or empty),
 * which bounds splice ambiguity between components.
 */
export function deriveSeed(
  contentDigest: string,
  presentationDigestOrNull: string | null,
  nonce: string,
  version: string,
): string {
  const presentation =
    presentationDigestOrNull === null ? '' : presentationDigestOrNull
  return sha256hex(contentDigest + presentation + nonce + version)
}

/**
 * Sample `n` spans of `spanLen` code points from `sourceText` at
 * distinct positions determined by `seed` (algorithm span_sample_v1).
 *
 * The source is split into code points via Array.from, so astral
 * characters (emoji) count as one position each and spans never split
 * a surrogate pair. With L code points the position range is
 * L - spanLen + 1. Throws when spanLen or n is not a positive integer,
 * when the source is shorter than spanLen code points, or when n
 * exceeds the position range.
 */
export function sampleSpans(
  sourceText: string,
  seed: string,
  n: number,
  spanLen: number,
): SampledSpan[] {
  if (!Number.isInteger(spanLen) || spanLen < 1) {
    throw new Error(`spanLen must be a positive integer, got ${spanLen}`)
  }
  if (!Number.isInteger(n) || n < 1) {
    throw new Error(`n must be a positive integer, got ${n}`)
  }
  const cps = Array.from(sourceText)
  const L = cps.length
  if (L < spanLen) {
    throw new Error(
      `source has ${L} code points, need at least spanLen ${spanLen}`,
    )
  }
  const range = L - spanLen + 1
  if (n > range) {
    throw new Error(`n ${n} exceeds the position range ${range}`)
  }
  const used = new Set<number>()
  const spans: SampledSpan[] = []
  for (let i = 0; i < n; i++) {
    for (let j = 0; ; j++) {
      const h = createHash('sha256')
        .update(`${seed}:${i}:${j}`, 'utf8')
        .digest()
      const pos = Number(h.readBigUInt64BE(0) % BigInt(range))
      if (used.has(pos)) continue
      used.add(pos)
      spans.push({
        pos,
        len: spanLen,
        text: cps.slice(pos, pos + spanLen).join(''),
      })
      break
    }
  }
  return spans
}

/**
 * Commit to span texts: "sha256:" + sha256hex(UTF-8 of each span
 * text), in the given (sampling) order.
 */
export function commitSpans(spanTexts: readonly string[]): string[] {
  return spanTexts.map((t) => `sha256:${sha256hex(t)}`)
}

/**
 * Score responses against span texts under exact_match_v1: exact
 * string equality per index. Throws when the arrays differ in length;
 * a missing response is a protocol error, not a miss.
 */
export function scoreResponses(
  spanTexts: readonly string[],
  responses: readonly string[],
): ScoreResponsesResult {
  if (spanTexts.length !== responses.length) {
    throw new Error(
      `responses length ${responses.length} does not match span count ${spanTexts.length}`,
    )
  }
  const results = spanTexts.map((t, i) => responses[i] === t)
  let k = 0
  for (const r of results) {
    if (r) k++
  }
  return { k, results }
}
