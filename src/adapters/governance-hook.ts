// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * DEPRECATED — `GovernanceHook` has moved to the AEOESS Gateway.
 *
 * This stateful session-runtime class was product intelligence, not a protocol
 * primitive, and lives at @aeoess/gateway (src/sdk-migrated/governance-hook.ts).
 *
 * See MIGRATION.md for callback-based replacements that consume only public
 * SDK primitives.
 */

const MOVED = 'GovernanceHook has moved to @aeoess/gateway. See MIGRATION.md'

export class GovernanceHook {
  constructor(_config?: unknown) {
    throw new Error(MOVED)
  }
}

export type GovernanceHookConfig = never
export type ActionDescriptor = never
export type GovernanceVerdict = never
export type GovernanceResult = never
export type GovernanceReceipt = never
