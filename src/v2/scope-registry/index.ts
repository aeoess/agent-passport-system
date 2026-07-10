// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════════
// Scope Dimension Registry. Public barrel.
// ══════════════════════════════════════════════════════════════════════
//
// A registry of delegation scope dimensions. Each dimension declares a
// type, whether it is decidable, and an enforcement_strength. Strict
// decidable dimensions route into the M6 feasibility hard obligation
// (src/v2/feasibility); advisory dimensions are excluded from the hard
// check and carried as honest-scope only. Advisory dimensions can never be
// the basis of a hard deny.
//
// data_class and destination ship here as new decidable set-narrowing
// dimensions. The registry extends M6; it does not duplicate the scope,
// spend, depth, or temporal constraint emission.
//
// See README.md in this directory for the full proof box.
// ══════════════════════════════════════════════════════════════════════

export type {
  DimensionValueType,
  EnforcementStrength,
  DimensionDeclaration,
  DimensionAssignment,
  DimensionClassification,
  DimensionNarrowingResult,
} from './types.js'

export {
  SCOPE_REGISTRY_VERSION,
  CANONICAL_DIMENSIONS,
  buildRegistry,
  classifyDimensions,
  compileStrictDimensions,
  checkSetNarrowing,
  canHardDeny,
} from './registry.js'
export type { ScopeDimensionRegistry } from './registry.js'
