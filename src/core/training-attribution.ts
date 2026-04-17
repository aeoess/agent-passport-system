// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * DEPRECATED — Training Attribution Ledger and Derivation Chain have moved
 * to the AEOESS Gateway.
 *
 * These are product intelligence (training event ledger, multi-hop
 * attribution resolution). The SDK retains cryptographic primitives in
 * `v2/attribution-*` modules. Implementation at @aeoess/gateway
 * (src/sdk-migrated/core/training-attribution.ts).
 *
 * See MIGRATION.md#data-lifecycle.
 */

const MOVED = 'Training attribution ledger has moved to @aeoess/gateway. See MIGRATION.md#data-lifecycle'

export type TrainingUseType = never
export type TrainingAttributionReceipt = never
export type TrainingAttributionVerification = never
export type TrainingAttributionLedger = never
export type DerivationRecord = never
export type DerivationStore = never
export type ResolvedAttribution = never

export function createTrainingAttribution(..._args: unknown[]): never { throw new Error(MOVED) }
export function verifyTrainingAttribution(..._args: unknown[]): never { throw new Error(MOVED) }
export function createTrainingLedger(..._args: unknown[]): never { throw new Error(MOVED) }
export function recordTrainingAttribution(..._args: unknown[]): never { throw new Error(MOVED) }
export function getModelDataSources(..._args: unknown[]): never { throw new Error(MOVED) }
export function getSourceTrainingCount(..._args: unknown[]): never { throw new Error(MOVED) }
export function createDerivation(..._args: unknown[]): never { throw new Error(MOVED) }
export function createDerivationStore(..._args: unknown[]): never { throw new Error(MOVED) }
export function recordDerivation(..._args: unknown[]): never { throw new Error(MOVED) }
export function resolveAttributionChain(..._args: unknown[]): never { throw new Error(MOVED) }
