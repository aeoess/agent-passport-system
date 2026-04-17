// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * DEPRECATED — `IntentNetwork` has moved to the AEOESS Gateway.
 *
 * Agent-mediated matching (ranking, introductions, digests) is product
 * intelligence. Primitive types stay in `../types/intent-network.js`.
 * Implementation at @aeoess/gateway (src/sdk-migrated/core/intent-network.ts).
 *
 * See MIGRATION.md#data-lifecycle.
 */

const MOVED = 'IntentNetwork has moved to @aeoess/gateway. See MIGRATION.md#data-lifecycle'

export function createIntentNetwork(..._args: unknown[]): never { throw new Error(MOVED) }
export function createIntentCard(..._args: unknown[]): never { throw new Error(MOVED) }
export function verifyIntentCard(..._args: unknown[]): never { throw new Error(MOVED) }
export function isCardExpired(..._args: unknown[]): never { throw new Error(MOVED) }
export function publishCard(..._args: unknown[]): never { throw new Error(MOVED) }
export function removeCard(..._args: unknown[]): never { throw new Error(MOVED) }
export function computeRelevance(..._args: unknown[]): never { throw new Error(MOVED) }
export function searchMatches(..._args: unknown[]): never { throw new Error(MOVED) }
export function requestIntro(..._args: unknown[]): never { throw new Error(MOVED) }
export function respondToIntro(..._args: unknown[]): never { throw new Error(MOVED) }
export function getDigest(..._args: unknown[]): never { throw new Error(MOVED) }
export function getVisibleItems(..._args: unknown[]): never { throw new Error(MOVED) }
