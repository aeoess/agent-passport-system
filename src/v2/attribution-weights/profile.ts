// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Weights — default profile, validation, hash (Build B)
// ══════════════════════════════════════════════════════════════════
// Defaults copy the constants from the spec verbatim. The profile is
// canonicalized (sorted keys, no null values) before hashing so the
// hash is byte-stable across runs and across languages.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalize } from '../../core/canonical.js'
import { ATTRIBUTION_ROLES } from './types.js'
import type { ValidationResult, WeightProfile } from './types.js'

/** Defaults from BUILD-B-FRACTIONAL-WEIGHTS.md §§ "Role weight",
 *  "Recency decay", "Content length weight", "The C-axis formula".
 *  Version v0.1 binds these exact numbers. Any tuning produces a new
 *  version and a new hash; receipts under different profiles do not
 *  cross-verify (Invariant I-B6). */
export const DEFAULT_WEIGHT_PROFILE: WeightProfile = {
  version: 'v0.1',
  role_weights: {
    primary_source: 1.0,
    supporting_evidence: 0.6,
    context_only: 0.3,
    background_retrieval: 0.1,
  },
  recency: {
    min_recency: 0.2,
    lambda: Math.LN2,
    tau_days: 30,
  },
  length: {
    reference_length: 1000,
  },
  compute: {
    completion_multiplier: 3.0,
  },
}

/** Structural + numeric validation. Returns a list of error strings; an
 *  empty list means the profile is usable. Catches misconfigurations
 *  that would silently produce nonsense weights (e.g., negative lambda,
 *  missing role entry). */
export function validateWeightProfile(profile: WeightProfile): ValidationResult {
  const errors: string[] = []

  if (typeof profile !== 'object' || profile === null) {
    return { valid: false, errors: ['profile must be an object'] }
  }

  if (typeof profile.version !== 'string' || profile.version.length === 0) {
    errors.push('profile.version must be a non-empty string')
  }

  if (!profile.role_weights || typeof profile.role_weights !== 'object') {
    errors.push('profile.role_weights missing')
  } else {
    for (const role of ATTRIBUTION_ROLES) {
      const v = (profile.role_weights as Record<string, unknown>)[role]
      if (typeof v !== 'number' || !Number.isFinite(v) || v < 0) {
        errors.push(`profile.role_weights.${role} must be a non-negative finite number`)
      }
    }
  }

  if (!profile.recency || typeof profile.recency !== 'object') {
    errors.push('profile.recency missing')
  } else {
    const { min_recency, lambda, tau_days } = profile.recency
    if (typeof min_recency !== 'number' || !Number.isFinite(min_recency) || min_recency < 0 || min_recency > 1) {
      errors.push('profile.recency.min_recency must be in [0, 1]')
    }
    if (typeof lambda !== 'number' || !Number.isFinite(lambda) || lambda < 0) {
      errors.push('profile.recency.lambda must be a non-negative finite number')
    }
    if (typeof tau_days !== 'number' || !Number.isFinite(tau_days) || tau_days <= 0) {
      errors.push('profile.recency.tau_days must be a positive finite number')
    }
  }

  if (!profile.length || typeof profile.length !== 'object') {
    errors.push('profile.length missing')
  } else {
    const { reference_length } = profile.length
    if (typeof reference_length !== 'number' || !Number.isFinite(reference_length) || reference_length <= 0) {
      errors.push('profile.length.reference_length must be a positive finite number')
    }
  }

  if (!profile.compute || typeof profile.compute !== 'object') {
    errors.push('profile.compute missing')
  } else {
    const { completion_multiplier } = profile.compute
    if (typeof completion_multiplier !== 'number' || !Number.isFinite(completion_multiplier) || completion_multiplier < 0) {
      errors.push('profile.compute.completion_multiplier must be a non-negative finite number')
    }
  }

  return { valid: errors.length === 0, errors }
}

/** sha256(canonicalize(profile)) as lowercase hex. Invariant I-B6:
 *  two profiles with any differing field — including version — produce
 *  different hashes. */
export function hashWeightProfile(profile: WeightProfile): string {
  const result = validateWeightProfile(profile)
  if (!result.valid) {
    throw new Error(
      `attribution-weights: cannot hash invalid profile — ${result.errors.join('; ')}`,
    )
  }
  return createHash('sha256').update(canonicalize(profile)).digest('hex')
}
