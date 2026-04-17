// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * DEPRECATED — Data Settlement Protocol has moved to the AEOESS Gateway.
 *
 * Settlement generation, verification, and compliance reporting are product
 * intelligence. Primitive types stay in `../types/data-contribution.js`.
 * Implementation at @aeoess/gateway (src/sdk-migrated/core/data-settlement.ts).
 *
 * See MIGRATION.md#data-lifecycle.
 */

const MOVED = 'SettlementGenerator has moved to @aeoess/gateway. See MIGRATION.md#data-lifecycle'

export function generateSettlement(..._args: unknown[]): never { throw new Error(MOVED) }
export function verifySettlement(..._args: unknown[]): never { throw new Error(MOVED) }
export function generateDataComplianceReport(..._args: unknown[]): never { throw new Error(MOVED) }
