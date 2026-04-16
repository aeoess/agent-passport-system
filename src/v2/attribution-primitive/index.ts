// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Attribution Primitive — public surface.
//
// Spec: ATTRIBUTION-PRIMITIVE-v1.1.md. See README/paper for the structural
// motivation; this module is the protocol primitive only. Visualization,
// cross-tenant analytics, and batch settlement are gateway-side.

export type {
  AttributionAxisTag,
  AttributionAction,
  AttributionAxes,
  AttributionEnvelope,
  AttributionPrimitive,
  AttributionProjection,
  AttributionVerifyResult,
  AttributionConsistencyResult,
  DataAxisEntry,
  DataAxisItem,
  ProtocolAxisEntry,
  ProtocolAxisItem,
  GovernanceAxisEntry,
  ComputeAxisEntry,
  ComputeAxisItem,
  ResidualBucket,
} from './types.js'

export {
  ATTRIBUTION_AXIS_TAGS,
  assertCanonicalTimestamp,
  canonicalTimestamp,
  canonicalHashHex,
  envelopeBytes,
  hashAxisLeaf,
  hashNode,
  normalizeAxes,
  orderGovernanceAxis,
  sortComputeAxis,
  sortDataAxis,
  sortProtocolAxis,
  toWeightString,
} from './canonical.js'

export { buildMerkleFrame, projectionPath, reconstructRoot } from './merkle.js'
export type { MerkleFrame } from './merkle.js'

export {
  computeAttributionActionRef,
  constructAttributionPrimitive,
  resignAttributionPrimitive,
} from './construct.js'
export type { ConstructAttributionParams } from './construct.js'

export {
  projectAttribution,
  projectAllAxes,
  projectionDataAsC,
  projectionDataAsD,
  projectionDataAsG,
  projectionDataAsP,
} from './project.js'

export {
  checkProjectionConsistency,
  verifyAttributionPrimitive,
  verifyAttributionProjection,
} from './verify.js'

export {
  DEFAULT_MIN_WEIGHT,
  aggregateComputeAxis,
  aggregateDataAxis,
  aggregateProtocolAxis,
} from './residual.js'
export type { AggregateOptions, AggregationResult } from './residual.js'
