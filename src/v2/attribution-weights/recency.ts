// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Weights — recency decay (Build B § "Recency decay")
// ══════════════════════════════════════════════════════════════════
// recency_decay(t) = max(MIN_RECENCY, exp(-λ × (t_action − t_source) / τ))

import type { WeightProfile } from './types.js'

const MS_PER_DAY = 86_400_000

/** Compute the recency decay factor for a source given the action and
 *  source timestamps. Timestamps are ISO-8601 strings; the function
 *  parses them and computes age in days. Negative age (future source)
 *  clamps to zero — a source published after the action decays as if
 *  it were produced simultaneously. */
export function recencyDecay(
  tAction: string,
  tSource: string,
  profile: WeightProfile,
): number {
  const actionMs = Date.parse(tAction)
  const sourceMs = Date.parse(tSource)
  if (!Number.isFinite(actionMs)) {
    throw new Error(`attribution-weights: invalid action timestamp "${tAction}"`)
  }
  if (!Number.isFinite(sourceMs)) {
    throw new Error(`attribution-weights: invalid source timestamp "${tSource}"`)
  }
  const ageDays = Math.max(0, (actionMs - sourceMs) / MS_PER_DAY)
  const { min_recency, lambda, tau_days } = profile.recency
  if (tau_days <= 0) {
    throw new Error(
      `attribution-weights: profile.recency.tau_days must be > 0, got ${tau_days}`,
    )
  }
  const decayed = Math.exp((-lambda * ageDays) / tau_days)
  return Math.max(min_recency, decayed)
}
