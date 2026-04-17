// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Attribution Settlement — public surface (Build C).
//
// Spec: BUILD-C-SETTLEMENT-PIPELINE.md. Turns a stream of Attribution
// Primitives over a settlement period into one signed, queryable
// settlement record. Settlement is evidence, not payment: the economic
// conversion (weight → currency) stays gateway-private. Reuses Build A
// canonicalization and Build B weight formats; zero duplicate crypto.

export type {
  SettlementAxisIndex,
  SettlementContributor,
  SettlementPeriod,
  SettlementRecord,
  SettlementResidualBucket,
  SettlementVerifyReason,
  SettlementVerifyResult,
  ContributorQueryAxisBody,
  ContributorQueryResponse,
} from './types.js'

export {
  aggregateAttributionPrimitives,
  contributorLeafHashHex,
  formatSettlementWeight,
  residualLeafHashHex,
} from './aggregate.js'
export type { AggregateOptions } from './aggregate.js'

export {
  buildContributorMerklePath,
  buildMerkleRoot,
  emptyAxisMerkleRoot,
  leafHash as settlementLeafHash,
  verifyMerklePath,
} from './merkle.js'

export {
  settlementRecordHash,
  settlementSigningPayload,
  signSettlementRecord,
  verifySettlementSignature,
} from './sign.js'

export { verifySettlementRecord } from './verify.js'
export type { VerifySettlementOptions } from './verify.js'

export {
  buildContributorQueryResponse,
  verifyContributorQueryResponse,
} from './contributor-query.js'
