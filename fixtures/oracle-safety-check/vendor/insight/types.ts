// Copyright (c) 2026 Insight (oracleinsight.xyz)
// SPDX-License-Identifier: Apache-2.0
//
// Vendor of the Insight OracleSafetyCheck v2 evidence type — constants and
// types only. The 26-field EIP-712 layout, domain and primary type are locked
// and schema-versioned (schema version 2).
//
// SOURCE (provenance): byte-identical copy of github.com/imokokok/insight-aps
// (public reference implementation for this fixture set), path
// fixtures/vendor/insight/types.ts, commit pinned in the conformance suite's
// fixtures/cross-stack/oracle-safety-check/SOURCE.md.

export type Verdict = 'PASS' | 'CAUTION' | 'DANGER' | 'BLOCK'
export type CoverageStatus = 'SUFFICIENT' | 'INSUFFICIENT'
export type IndependenceStatus = 'ASSESSED' | 'INSUFFICIENT_INDEPENDENCE'
export type EvaluationScope = 'SOURCE_ASSET_ONLY'

export const OSC_DOMAIN = {
  name: 'Insight Oracle Safety',
  version: '2',
  chainId: 1,
} as const

export const OSC_PRIMARY_TYPE = 'OracleSafetyCheck'

export const OSC_TYPES = {
  OracleSafetyCheck: [
    { name: 'verdict', type: 'string' },
    { name: 'sourceAssetId', type: 'string' },
    { name: 'destinationAssetId', type: 'string' },
    { name: 'subjectChainId', type: 'uint256' },
    { name: 'action', type: 'string' },
    { name: 'tradeAmountUsd', type: 'uint256' },
    { name: 'consensusPrice', type: 'uint256' },
    { name: 'maxDeviationBps', type: 'uint256' },
    { name: 'manipulationRiskBps', type: 'uint256' },
    { name: 'participantCount', type: 'uint256' },
    { name: 'requiredParticipantCount', type: 'uint256' },
    { name: 'coverageStatus', type: 'string' },
    { name: 'independenceStatus', type: 'string' },
    { name: 'sourceGroupCount', type: 'uint256' },
    { name: 'crossProviderAgreementBps', type: 'uint256' },
    { name: 'maxStablecoinDepegBps', type: 'uint256' },
    { name: 'maxDataAgeSeconds', type: 'uint256' },
    { name: 'recommendedMaxPositionUsd', type: 'uint256' },
    { name: 'reasonCodesHash', type: 'bytes32' },
    { name: 'requestHash', type: 'bytes32' },
    { name: 'evaluationScope', type: 'string' },
    { name: 'evaluatedAssetIdsHash', type: 'bytes32' },
    { name: 'providerObservationsHash', type: 'bytes32' },
    { name: 'validUntil', type: 'uint256' },
    { name: 'checkedAt', type: 'uint256' },
    { name: 'schemaVersion', type: 'uint256' },
  ],
} as const

export const OSC_ARTIFACT_TYPE = 'insight.oracle-safety-check:v2'
export const OSC_VALID_FOR_SECONDS = 600
export const OSC_REQUIRED_PARTICIPANT_COUNT = 3
export const OSC_REQUIRED_NON_DERIVED_GROUPS = 2

/** The 26 signed fields, JSON-safe (uint256 as number, hashes as 0x-hex). */
export interface OracleSafetyCheckData {
  verdict: Verdict
  sourceAssetId: string
  destinationAssetId: string
  subjectChainId: number
  action: string
  tradeAmountUsd: number
  consensusPrice: number
  maxDeviationBps: number
  manipulationRiskBps: number
  participantCount: number
  requiredParticipantCount: number
  coverageStatus: CoverageStatus
  independenceStatus: IndependenceStatus
  sourceGroupCount: number
  crossProviderAgreementBps: number
  maxStablecoinDepegBps: number
  maxDataAgeSeconds: number
  recommendedMaxPositionUsd: number
  reasonCodesHash: `0x${string}`
  requestHash: `0x${string}`
  evaluationScope: EvaluationScope
  evaluatedAssetIdsHash: `0x${string}`
  providerObservationsHash: `0x${string}`
  validUntil: number
  checkedAt: number
  schemaVersion: 2
}

/** The evidence artifact carried by the envelope — production-shaped. */
export interface OracleSafetyAttestation {
  uid: string
  schemaVersion: 2
  attester: string
  attesterLabel: string
  signedAt: string
  validForSeconds: number
  validUntil: number
  signature: string
  data: OracleSafetyCheckData
  eip712: {
    domain: typeof OSC_DOMAIN
    types: typeof OSC_TYPES
    primaryType: typeof OSC_PRIMARY_TYPE
  }
}
