// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * DEPRECATED — `AgentContext` has moved to the AEOESS Gateway.
 *
 * This stateful session runtime was product intelligence, not a protocol
 * primitive. Implementation lives at @aeoess/gateway
 * (src/sdk-migrated/core/context.ts).
 *
 * Agents that need automatic 3-signature enforcement should consume the
 * gateway's AgentContext. Callers building their own runtime should use the
 * policy, delegation, and receipt primitives still exported from this SDK.
 *
 * See MIGRATION.md#data-lifecycle.
 */

const MOVED = 'AgentContext has moved to @aeoess/gateway. See MIGRATION.md#data-lifecycle'

export class AgentContext {
  constructor(..._args: unknown[]) {
    throw new Error(MOVED)
  }
}

export function createAgentContext(..._args: unknown[]): never { throw new Error(MOVED) }
