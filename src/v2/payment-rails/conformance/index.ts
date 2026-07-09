// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Payment Rails — conformance public surface
// ══════════════════════════════════════════════════════════════════
// Importable from third-party adapter test suites:
//
//   import {
//     runConformance,
//     STANDARD_SCENARIOS,
//   } from '@aeoess/agent-passport-system/...'
//
// See harness.ts for the contract semantics each scenario asserts.
// See ./fixtures/ for the canonical inputs/outputs adapters pin to.
// ══════════════════════════════════════════════════════════════════

export {
  HARNESS_FIXED_NOW,
  HARNESS_ISSUER_PRIV,
  runConformance,
  STANDARD_SCENARIOS,
} from './harness.js'

export type {
  ConformanceContext,
  ConformanceReport,
  ConformanceScenario,
  RunConformanceOpts,
  ScenarioOutcome,
  ScenarioReport,
} from './harness.js'

export {
  BUILTIN_BINDING_ADAPTERS,
  runBindingConformance,
} from './binding-harness.js'

export type {
  BindingConformanceReport,
  BindingFixtureSet,
  BindingRailAdapter,
  BindingRailName,
  BindingScenarioReport,
  ConformanceFixtureScenario,
  DenialFixtureScenario,
  DeterminismFixtureScenario,
  RunBindingConformanceOpts,
  Tier2Invariant,
} from './binding-harness.js'
