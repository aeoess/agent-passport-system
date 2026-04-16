// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Weights — D axis (Build B § "The D-axis formula")
// ══════════════════════════════════════════════════════════════════
// w_D(s, a) = role_weight × recency_decay × content_length_weight / Σ
//
// Returns canonical DataAxisEntry[] ready to feed into Build A's
// constructAttributionPrimitive. Weights are emitted as 6-digit decimal
// strings per spec §2.5 (inherited from Build A canonicalization).
// ══════════════════════════════════════════════════════════════════

import { toWeightString } from '../attribution-primitive/canonical.js'
import { contentLengthWeight } from './length.js'
import { recencyDecay } from './recency.js'
import { roleWeight } from './roles.js'
import { validateWeightProfile, DEFAULT_WEIGHT_PROFILE } from './profile.js'
import type {
  AccessReceiptWithRole,
  ComputeDataAxisOptions,
  DataAxisEntry,
} from './types.js'

/** Compute the D-axis weight vector for a list of sources.
 *
 *  Semantics:
 *  - Empty input → empty output (Invariant I-B3).
 *  - All-zero raw weights → throws (Invariant I-B7 / property test 7).
 *    This happens only when every source has role_weight × recency ×
 *    length = 0, which is malformed input since role_weight is >0 for
 *    all defined roles and recency is floored at min_recency.
 *  - Identical inputs produce identical outputs (Invariant I-B5).
 *
 *  Weights are rounded via toWeightString() (6 decimal places). The
 *  rounded values may sum to 1.000000 ± 1e-6 due to rounding; the
 *  sum-to-one invariant (I-B1) is tested on the raw pre-rounded vector
 *  at 1e-9 tolerance per the spec. */
export function computeDataAxisWeights(
  sources: AccessReceiptWithRole[],
  options: ComputeDataAxisOptions,
): DataAxisEntry[] {
  if (!Array.isArray(sources)) {
    throw new Error('attribution-weights: sources must be an array')
  }
  if (sources.length === 0) return []

  if (!options || typeof options.action_timestamp !== 'string') {
    throw new Error('attribution-weights: options.action_timestamp required')
  }

  const profile = options.profile ?? DEFAULT_WEIGHT_PROFILE
  const validation = validateWeightProfile(profile)
  if (!validation.valid) {
    throw new Error(
      `attribution-weights: invalid profile — ${validation.errors.join('; ')}`,
    )
  }

  const rawWeights: number[] = sources.map((s) => {
    if (!s || typeof s !== 'object') {
      throw new Error('attribution-weights: each source must be an object')
    }
    const r = roleWeight(s.role, profile)
    const d = recencyDecay(options.action_timestamp, s.timestamp, profile)
    const l = contentLengthWeight(s.content_length, profile)
    return r * d * l
  })

  const total = rawWeights.reduce((acc, w) => acc + w, 0)
  if (!(total > 0)) {
    throw new Error(
      'attribution-weights: total D-axis raw weight is zero — malformed input (every contributor has zero effective weight)',
    )
  }

  return sources.map((s, i) => ({
    source_did: s.source_did,
    contribution_weight: toWeightString(rawWeights[i] / total),
    access_receipt_hash: s.access_receipt_hash,
  }))
}
