// Copyright (c) 2026 Insight (oracleinsight.xyz)
// SPDX-License-Identifier: Apache-2.0
//
// Insight OracleSafetyCheck v2 — EIP-712 attestation builder, signer, verifier.
// The 26-field type layout, EIP-712 domain and the ABI-keccak commitments
// (see abi.ts) are locked per the vendored implementation and
// schema-versioned (schema version 2).
//
// SOURCE (provenance): byte-identical copy of github.com/imokokok/insight-aps
// (public reference implementation for this fixture set), path
// fixtures/vendor/insight/oracleSafetyCheck.ts, commit pinned in the
// conformance suite's fixtures/cross-stack/oracle-safety-check/SOURCE.md.
// verify-consistency.ts (shipped with the vectors) re-derives the EIP-712
// digest and verifies the secp256k1 signature from oracle_input (2 positive
// vectors) and reproduces all four commitments, 56/56.
//
// DEMO ONLY key handling: production Insight signs via the attester keystore;
// fixtures sign with the deterministic per-role key (see generate-fixtures.ts).

import { hashTypedData, verifyTypedData, type Hex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

import {
  computeEvaluatedAssetIdsHashAbi,
  computeProviderObservationsHashAbi,
  computeReasonCodesHashAbi,
  computeRequestHashAbi,
} from './abi.js'
import {
  OSC_DOMAIN,
  OSC_PRIMARY_TYPE,
  OSC_REQUIRED_NON_DERIVED_GROUPS,
  OSC_REQUIRED_PARTICIPANT_COUNT,
  OSC_TYPES,
  OSC_VALID_FOR_SECONDS,
  type CoverageStatus,
  type IndependenceStatus,
  type OracleSafetyAttestation,
  type OracleSafetyCheckData,
  type Verdict,
} from './types.js'

const PRICE_SCALE = 1e8
const USD_SCALE = 1e6
const PCT_SCALE = 100
const AGREEMENT_SCALE = 1e4
const MANIP_SCALE = 1e4

function toUint(n: number, scale: number): number {
  if (!Number.isFinite(n)) return 0
  return Math.max(0, Math.round(n * scale))
}

export interface ProviderObservationEntry {
  provider: string
  feedId: string
  value: number // USD price (not scaled)
  timestamp: number // observation time, unix seconds
  dataAgeSeconds: number
  included: boolean
  exclusionReason: string // '' when included
}

export interface OracleSafetyCheckInput {
  verdict: Verdict
  sourceAssetId: string
  destinationAssetId: string
  subjectChainId: number
  action: string
  tradeAmountUsd: number
  consensusPrice: number
  maxDeviationPct: number
  manipulationRiskScore: number
  participantCount: number
  crossProviderAgreement: number
  maxStablecoinDepegPct: number
  maxDataAgeSeconds: number
  recommendedMaxPositionUsd: number
  contributingFactors: ReadonlyArray<{ rule: string }>
  providerObservations: ProviderObservationEntry[]
  checkedAt: number
}

export function computeRequestHash(input: Pick<
  OracleSafetyCheckInput,
  'subjectChainId' | 'sourceAssetId' | 'destinationAssetId' | 'action' | 'tradeAmountUsd'
>): Hex {
  return computeRequestHashAbi(input)
}

export function computeReasonCodesHash(codes: string[]): Hex {
  return computeReasonCodesHashAbi(codes)
}

export function computeEvaluatedAssetIdsHash(assetIds: string[]): Hex {
  return computeEvaluatedAssetIdsHashAbi(assetIds)
}

export function computeProviderObservationsHash(observations: ProviderObservationEntry[]): Hex {
  return computeProviderObservationsHashAbi(
    observations.map((o) => ({
      provider: o.provider,
      feedId: o.feedId,
      value: BigInt(toUint(o.value, PRICE_SCALE)),
      timestamp: BigInt(Math.max(0, Math.floor(o.timestamp))),
      dataAgeSeconds: BigInt(Math.max(0, Math.floor(o.dataAgeSeconds))),
      included: o.included,
      exclusionReason: o.exclusionReason,
    }))
  )
}

export function buildOracleSafetyCheck(input: OracleSafetyCheckInput): OracleSafetyCheckData {
  const reasonCodes = input.contributingFactors.map((f) => f.rule).sort()
  const includedProviders = input.providerObservations.filter((o) => o.included).map((o) => o.provider)
  const nonDerivedGroups = new Set(includedProviders).size
  const coverageStatus: CoverageStatus =
    input.participantCount >= OSC_REQUIRED_PARTICIPANT_COUNT ? 'SUFFICIENT' : 'INSUFFICIENT'
  const independenceStatus: IndependenceStatus =
    nonDerivedGroups >= OSC_REQUIRED_NON_DERIVED_GROUPS ? 'ASSESSED' : 'INSUFFICIENT_INDEPENDENCE'

  return {
    verdict: input.verdict,
    sourceAssetId: input.sourceAssetId,
    destinationAssetId: input.destinationAssetId,
    subjectChainId: input.subjectChainId,
    action: input.action,
    tradeAmountUsd: toUint(input.tradeAmountUsd, USD_SCALE),
    consensusPrice: toUint(input.consensusPrice, PRICE_SCALE),
    maxDeviationBps: toUint(input.maxDeviationPct, PCT_SCALE),
    manipulationRiskBps: toUint(input.manipulationRiskScore, MANIP_SCALE),
    participantCount: Math.max(0, Math.floor(input.participantCount)),
    requiredParticipantCount: OSC_REQUIRED_PARTICIPANT_COUNT,
    coverageStatus,
    independenceStatus,
    sourceGroupCount: nonDerivedGroups,
    crossProviderAgreementBps: toUint(input.crossProviderAgreement, AGREEMENT_SCALE),
    maxStablecoinDepegBps: toUint(input.maxStablecoinDepegPct, PCT_SCALE),
    maxDataAgeSeconds: Math.max(0, Math.floor(input.maxDataAgeSeconds)),
    recommendedMaxPositionUsd: toUint(input.recommendedMaxPositionUsd, USD_SCALE),
    reasonCodesHash: computeReasonCodesHash(reasonCodes),
    requestHash: computeRequestHash(input),
    evaluationScope: 'SOURCE_ASSET_ONLY',
    evaluatedAssetIdsHash: computeEvaluatedAssetIdsHash([input.sourceAssetId]),
    providerObservationsHash: computeProviderObservationsHash(input.providerObservations),
    validUntil: input.checkedAt + OSC_VALID_FOR_SECONDS,
    checkedAt: input.checkedAt,
    schemaVersion: 2,
  }
}

function toBigIntMessage(m: OracleSafetyCheckData) {
  return {
    verdict: m.verdict,
    sourceAssetId: m.sourceAssetId,
    destinationAssetId: m.destinationAssetId,
    subjectChainId: BigInt(m.subjectChainId),
    action: m.action,
    tradeAmountUsd: BigInt(m.tradeAmountUsd),
    consensusPrice: BigInt(m.consensusPrice),
    maxDeviationBps: BigInt(m.maxDeviationBps),
    manipulationRiskBps: BigInt(m.manipulationRiskBps),
    participantCount: BigInt(m.participantCount),
    requiredParticipantCount: BigInt(m.requiredParticipantCount),
    coverageStatus: m.coverageStatus,
    independenceStatus: m.independenceStatus,
    sourceGroupCount: BigInt(m.sourceGroupCount),
    crossProviderAgreementBps: BigInt(m.crossProviderAgreementBps),
    maxStablecoinDepegBps: BigInt(m.maxStablecoinDepegBps),
    maxDataAgeSeconds: BigInt(m.maxDataAgeSeconds),
    recommendedMaxPositionUsd: BigInt(m.recommendedMaxPositionUsd),
    reasonCodesHash: m.reasonCodesHash,
    requestHash: m.requestHash,
    evaluationScope: m.evaluationScope,
    evaluatedAssetIdsHash: m.evaluatedAssetIdsHash,
    providerObservationsHash: m.providerObservationsHash,
    validUntil: BigInt(m.validUntil),
    checkedAt: BigInt(m.checkedAt),
    schemaVersion: BigInt(m.schemaVersion),
  }
}

export interface SignOracleOptions {
  privateKey: Hex
  attesterLabel?: string
}

export async function signOracleSafetyCheck(
  input: OracleSafetyCheckInput,
  opts: SignOracleOptions
): Promise<OracleSafetyAttestation> {
  const account = privateKeyToAccount(opts.privateKey)
  const data = buildOracleSafetyCheck(input)
  const message = toBigIntMessage(data)
  const typedData = {
    domain: OSC_DOMAIN,
    types: OSC_TYPES,
    primaryType: OSC_PRIMARY_TYPE,
    message,
  } as const

  const uid = hashTypedData(typedData)
  const signature = await account.signTypedData(typedData)

  return {
    uid,
    schemaVersion: 2,
    attester: account.address,
    attesterLabel: opts.attesterLabel ?? 'Insight Oracle Safety Attestation',
    signedAt: new Date(input.checkedAt * 1000).toISOString(),
    validForSeconds: OSC_VALID_FOR_SECONDS,
    validUntil: data.validUntil,
    signature,
    data,
    eip712: { domain: OSC_DOMAIN, types: OSC_TYPES, primaryType: OSC_PRIMARY_TYPE },
  }
}

export interface VerifyOracleResult {
  valid: boolean
  reasons: string[]
}

export async function verifyOracleSafetyCheck(
  attestation: OracleSafetyAttestation,
  nowMs: number
): Promise<VerifyOracleResult> {
  const reasons: string[] = []
  const message = toBigIntMessage(attestation.data)
  const typedData = {
    domain: OSC_DOMAIN,
    types: OSC_TYPES,
    primaryType: OSC_PRIMARY_TYPE,
    message,
  } as const

  if (hashTypedData(typedData) !== attestation.uid) {
    reasons.push('UID_MISMATCH')
  }

  const validSig = await verifyTypedData({
    ...typedData,
    address: attestation.attester as `0x${string}`,
    signature: attestation.signature as `0x${string}`,
  })
  if (!validSig) reasons.push('SIGNATURE_INVALID')

  const nowSec = Math.floor(nowMs / 1000)
  if (attestation.data.checkedAt > nowSec + 5) reasons.push('CHECKED_AT_FUTURE')
  if (attestation.data.validUntil < nowSec) reasons.push('EXPIRED')

  return { valid: reasons.length === 0, reasons }
}

export { OSC_VALID_FOR_SECONDS, OSC_PRIMARY_TYPE }
