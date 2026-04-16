// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Weights — role weight lookup (Build B § "Role weight")
// ══════════════════════════════════════════════════════════════════

import type { AttributionRole, WeightProfile } from './types.js'

/** Look up role_weight(role) from a profile. Unknown roles throw — the
 *  taxonomy is locked at v0.1 per the spec's Open Questions. */
export function roleWeight(role: AttributionRole, profile: WeightProfile): number {
  const w = profile.role_weights[role]
  if (typeof w !== 'number' || !Number.isFinite(w) || w < 0) {
    throw new Error(
      `attribution-weights: role "${role}" has invalid weight in profile (must be non-negative finite number)`,
    )
  }
  return w
}
