// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * DEPRECATED — Data Contribution Ledger has moved to the AEOESS Gateway.
 *
 * The ledger is product intelligence (aggregation, metering, compensation
 * accrual across receipts). Primitive types live in `../types/data-contribution.js`
 * and stay in the SDK. Implementation at @aeoess/gateway
 * (src/sdk-migrated/core/data-contribution.ts).
 *
 * See MIGRATION.md#data-lifecycle.
 */

const MOVED = 'ContributionLedger has moved to @aeoess/gateway. See MIGRATION.md#data-lifecycle'

export type ContributionLedger = never

export function createContributionLedger(): never { throw new Error(MOVED) }
export function recordContribution(..._args: unknown[]): never { throw new Error(MOVED) }
export function queryContributions(..._args: unknown[]): never { throw new Error(MOVED) }
export function getSourceMetrics(..._args: unknown[]): never { throw new Error(MOVED) }
export function getAgentDataFootprint(..._args: unknown[]): never { throw new Error(MOVED) }
