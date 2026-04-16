// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Weights — content length weight (Build B § "Content length weight")
// ══════════════════════════════════════════════════════════════════
// content_length_weight(len) = log(1 + len) / log(1 + REF_LEN)

import type { WeightProfile } from './types.js'

export function contentLengthWeight(len: number, profile: WeightProfile): number {
  if (!Number.isFinite(len) || len < 0) {
    throw new Error(`attribution-weights: content_length must be non-negative finite, got ${len}`)
  }
  const ref = profile.length.reference_length
  if (!Number.isFinite(ref) || ref <= 0) {
    throw new Error(
      `attribution-weights: profile.length.reference_length must be > 0, got ${ref}`,
    )
  }
  return Math.log(1 + len) / Math.log(1 + ref)
}
