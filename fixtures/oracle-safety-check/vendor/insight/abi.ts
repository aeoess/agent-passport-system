// Copyright (c) 2026 Insight (oracleinsight.xyz)
// SPDX-License-Identifier: Apache-2.0
//
// ABI-keccak commitment pipeline for the four bytes32 fields of
// OracleSafetyCheck v2: requestHash, reasonCodesHash,
// evaluatedAssetIdsHash, providerObservationsHash.
//
// SOURCE (provenance): byte-identical copy of github.com/imokokok/insight-aps
// (public reference implementation for this fixture set), path
// fixtures/vendor/insight/abi.ts, commit pinned in the conformance suite's
// fixtures/cross-stack/oracle-safety-check/SOURCE.md. The commitments are
// independently reproducible from a vector's oracle_input by
// verify-consistency.ts (shipped with the vectors), 56/56.
//
//   requestHash               = EIP-712 hashTypedData(CanonicalPreTradeRequest)
//   reasonCodesHash           = keccak256(abi.encode(['string[]'], [sortedUnique]))
//   evaluatedAssetIdsHash     = keccak256(abi.encode(['string[]'], [sortedUnique]))
//   providerObservationsHash  = keccak256(concat(sorted(keccak256(abi.encode(entry))...)))

import { concat, encodeAbiParameters, hashTypedData, keccak256 } from 'viem'

// ---------------------------------------------------------------------------
// requestHash — EIP-712 typed hash of CanonicalPreTradeRequest
// ---------------------------------------------------------------------------

export const CANONICAL_REQUEST_DOMAIN = {
  name: 'Insight Canonical Pre-Trade Request',
  version: '1',
  chainId: 1,
} as const

export const CANONICAL_REQUEST_PRIMARY_TYPE = 'CanonicalPreTradeRequest'

export const CANONICAL_REQUEST_TYPES = {
  CanonicalPreTradeRequest: [
    { name: 'subjectChainId', type: 'uint256' },
    { name: 'sourceAssetId', type: 'string' }, // CAIP-19
    { name: 'destinationAssetId', type: 'string' }, // CAIP-19
    { name: 'action', type: 'string' },
    { name: 'tradeAmountUsd', type: 'uint256' }, // ×1e6
  ],
} as const

const USD_SCALE = 1e6

export interface CanonicalRequestInput {
  subjectChainId: number
  sourceAssetId: string
  destinationAssetId: string
  action: string
  tradeAmountUsd: number
}

function toUint(n: number, scale: number): bigint {
  if (!Number.isFinite(n)) return 0n
  return BigInt(Math.max(0, Math.round(n * scale)))
}

export function computeRequestHashAbi(input: CanonicalRequestInput): `0x${string}` {
  return hashTypedData({
    domain: CANONICAL_REQUEST_DOMAIN,
    types: CANONICAL_REQUEST_TYPES,
    primaryType: CANONICAL_REQUEST_PRIMARY_TYPE,
    message: {
      subjectChainId: BigInt(input.subjectChainId),
      sourceAssetId: input.sourceAssetId,
      destinationAssetId: input.destinationAssetId,
      action: input.action,
      tradeAmountUsd: toUint(input.tradeAmountUsd, USD_SCALE),
    },
  })
}

// ---------------------------------------------------------------------------
// reasonCodesHash / evaluatedAssetIdsHash — keccak256(abi.encode(string[]))
// ---------------------------------------------------------------------------

export function computeReasonCodesHashAbi(reasonCodes: ReadonlyArray<string>): `0x${string}` {
  const sorted = [...new Set(reasonCodes)].sort()
  return keccak256(encodeAbiParameters([{ type: 'string[]', name: 'reasonCodes' }], [sorted]))
}

export function computeEvaluatedAssetIdsHashAbi(assetIds: ReadonlyArray<string>): `0x${string}` {
  const sorted = [...new Set(assetIds)].sort()
  return keccak256(encodeAbiParameters([{ type: 'string[]', name: 'assetIds' }], [sorted]))
}

// ---------------------------------------------------------------------------
// providerObservationsHash — per-entry ABI tuple → keccak → sort → concat → keccak
// ---------------------------------------------------------------------------

export interface ProviderObservationAbiEntry {
  provider: string
  feedId: string
  value: bigint // ×1e8
  timestamp: bigint // unix seconds
  dataAgeSeconds: bigint
  included: boolean
  exclusionReason: string // '' when included
}

const ENTRY_ABI = [
  { name: 'provider', type: 'string' },
  { name: 'feedId', type: 'string' },
  { name: 'value', type: 'uint256' },
  { name: 'timestamp', type: 'uint256' },
  { name: 'dataAgeSeconds', type: 'uint256' },
  { name: 'included', type: 'bool' },
  { name: 'exclusionReason', type: 'string' },
] as const

function encodeEntry(e: ProviderObservationAbiEntry): `0x${string}` {
  return encodeAbiParameters(ENTRY_ABI, [
    e.provider,
    e.feedId,
    e.value,
    e.timestamp,
    e.dataAgeSeconds,
    e.included,
    e.exclusionReason,
  ])
}

function compareHex(a: string, b: string): number {
  const la = a.toLowerCase()
  const lb = b.toLowerCase()
  return la < lb ? -1 : la > lb ? 1 : 0
}

export function computeProviderObservationsHashAbi(
  entries: ProviderObservationAbiEntry[]
): `0x${string}` {
  if (entries.length === 0) return keccak256('0x')
  const entryHashes = entries.map((e) => keccak256(encodeEntry(e))).sort(compareHex)
  return keccak256(concat(entryHashes as `0x${string}`[]))
}
