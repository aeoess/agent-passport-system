// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Google ADK Adapter — primitive mappings between ADK plugin contexts
 * and APS action descriptors.
 *
 * ADK pattern: before_action(context) → action → after_action(context, result)
 *
 * This module is a pure mapping layer. Stateful runtime (pending-intent
 * tracking, audit trail) lives in the gateway.
 */

import { scopeAuthorizes } from '../core/delegation.js'

export interface ADKActionContext {
  tool_name: string
  tool_input: Record<string, unknown>
  agent_name: string
  session_id?: string
}

export interface ADKActionDescriptor {
  type: string
  target: string
  scopeRequired: string
  metadata: Record<string, unknown>
}

/** Map an ADK tool context to an APS action descriptor. */
export function adkContextToAction(ctx: ADKActionContext): ADKActionDescriptor {
  return {
    type: `adk:tool:${ctx.tool_name}`,
    target: ctx.tool_name,
    scopeRequired: `tool:${ctx.tool_name}`,
    metadata: { agent: ctx.agent_name, session: ctx.session_id, ...ctx.tool_input },
  }
}

/** Derive the APS scope string an ADK tool call requires. */
export function adkToolToScope(toolName: string): string {
  return `tool:${toolName}`
}

/** Check whether a delegation authorizes a given ADK tool call. */
export function adkAuthorizes(delegationScopes: string[], toolName: string): boolean {
  return scopeAuthorizes(delegationScopes, adkToolToScope(toolName))
}
