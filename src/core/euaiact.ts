// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * DEPRECATED — EU AI Act compliance automation has moved to the AEOESS Gateway.
 *
 * Classification, article mapping, gap analysis, and full compliance reports
 * are product intelligence (regulatory automation). Primitive types stay in
 * `../types/euaiact.js`. Implementation at @aeoess/gateway
 * (src/sdk-migrated/core/euaiact.ts).
 *
 * See MIGRATION.md#data-lifecycle.
 */

const MOVED = 'EU AI Act compliance automation has moved to @aeoess/gateway. See MIGRATION.md#data-lifecycle'

export function classifyRisk(..._args: unknown[]): never { throw new Error(MOVED) }
export function mapArticles(..._args: unknown[]): never { throw new Error(MOVED) }
export function generateTransparencyDisclosure(..._args: unknown[]): never { throw new Error(MOVED) }
export function generateComplianceProfile(..._args: unknown[]): never { throw new Error(MOVED) }
export function identifyGaps(..._args: unknown[]): never { throw new Error(MOVED) }
export function generateComplianceReport(..._args: unknown[]): never { throw new Error(MOVED) }
