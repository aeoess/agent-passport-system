// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Weights — C axis (Build B § "The C-axis formula")
// ══════════════════════════════════════════════════════════════════
// w_C(p, a) = (prompt_tokens + completion_tokens × COMPLETION_MULTIPLIER) / Σ
// ══════════════════════════════════════════════════════════════════

import { toWeightString } from '../attribution-primitive/canonical.js'
import { DEFAULT_WEIGHT_PROFILE, validateWeightProfile } from './profile.js'
import type {
  ComputeAxisEntry,
  ComputeComputeAxisOptions,
  InferenceBillingRecord,
} from './types.js'

/** Compute the C-axis weight vector for a list of inference billing
 *  records. Empty input → empty output (Invariant I-B3). All-zero
 *  input (zero prompt + zero completion tokens across all providers)
 *  throws. */
export function computeComputeAxisWeights(
  providers: InferenceBillingRecord[],
  options: ComputeComputeAxisOptions = {},
): ComputeAxisEntry[] {
  if (!Array.isArray(providers)) {
    throw new Error('attribution-weights: providers must be an array')
  }
  if (providers.length === 0) return []

  const profile = options.profile ?? DEFAULT_WEIGHT_PROFILE
  const validation = validateWeightProfile(profile)
  if (!validation.valid) {
    throw new Error(
      `attribution-weights: invalid profile — ${validation.errors.join('; ')}`,
    )
  }
  const mult = profile.compute.completion_multiplier

  const rawWeights = providers.map((p) => {
    if (!p || typeof p !== 'object') {
      throw new Error('attribution-weights: each provider must be an object')
    }
    if (!Number.isFinite(p.prompt_tokens) || p.prompt_tokens < 0) {
      throw new Error(
        `attribution-weights: prompt_tokens must be non-negative finite, got ${p.prompt_tokens}`,
      )
    }
    if (!Number.isFinite(p.completion_tokens) || p.completion_tokens < 0) {
      throw new Error(
        `attribution-weights: completion_tokens must be non-negative finite, got ${p.completion_tokens}`,
      )
    }
    return p.prompt_tokens + p.completion_tokens * mult
  })

  const total = rawWeights.reduce((acc, w) => acc + w, 0)
  if (!(total > 0)) {
    throw new Error(
      'attribution-weights: total C-axis raw weight is zero — malformed input (all providers have zero tokens)',
    )
  }

  return providers.map((p, i) => ({
    provider_did: p.provider_did,
    compute_share: toWeightString(rawWeights[i] / total),
    hardware_attestation_hash: p.hardware_attestation_hash,
  }))
}
