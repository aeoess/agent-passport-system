// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Attribution Weights — public surface (Build B).
//
// Spec: BUILD-B-FRACTIONAL-WEIGHTS.md. Fills the compute_weight() hole
// left by Build A: canonical D-axis and C-axis weight formulas with a
// signable WeightProfile. Outputs are Build A-ready DataAxisEntry[] /
// ComputeAxisEntry[] with canonical 6-digit decimal weight strings.

export type {
  AccessReceiptWithRole,
  AttributionRole,
  ComputeAxisEntry,
  ComputeComputeAxisOptions,
  ComputeDataAxisOptions,
  DataAxisEntry,
  InferenceBillingRecord,
  ValidationResult,
  WeightProfile,
} from './types.js'
export { ATTRIBUTION_ROLES } from './types.js'

export { roleWeight } from './roles.js'
export { recencyDecay } from './recency.js'
export { contentLengthWeight } from './length.js'

export {
  DEFAULT_WEIGHT_PROFILE,
  validateWeightProfile,
  hashWeightProfile,
} from './profile.js'

export { computeDataAxisWeights } from './data-axis.js'
export { computeComputeAxisWeights } from './compute-axis.js'
