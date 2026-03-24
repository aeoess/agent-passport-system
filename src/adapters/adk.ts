// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Google ADK Adapter — maps ADK's GovernancePlugin pattern to APS governance.
 *
 * ADK pattern: before_action(context) → action → after_action(context, result)
 * APS pattern: beforeAction(descriptor) → execute → afterAction(result) → receipt
 */

import { GovernanceHook } from './governance-hook.js'
import type { GovernanceHookConfig, ActionDescriptor, GovernanceResult, GovernanceReceipt } from './governance-hook.js'

export interface ADKActionContext {
  tool_name: string
  tool_input: Record<string, unknown>
  agent_name: string
  session_id?: string
}

export interface ADKGovernancePlugin {
  before_action: (ctx: ADKActionContext) => { allowed: boolean; reason: string; intentId: string }
  after_action: (ctx: ADKActionContext, result: unknown) => GovernanceReceipt
  get_audit_trail: () => GovernanceReceipt[]
  hook: GovernanceHook
}

export function createADKGovernancePlugin(config: GovernanceHookConfig): ADKGovernancePlugin {
  const hook = new GovernanceHook(config)
  const pendingIntents = new Map<string, { governance: GovernanceResult; action: ActionDescriptor; startedAt: string }>()

  const before_action = (ctx: ADKActionContext) => {
    const action: ActionDescriptor = {
      type: `adk:tool:${ctx.tool_name}`,
      target: ctx.tool_name,
      scopeRequired: `tool:${ctx.tool_name}`,
      metadata: { agent: ctx.agent_name, session: ctx.session_id, ...ctx.tool_input },
    }
    const governance = hook.beforeAction(action)
    if (governance.verdict !== 'deny') {
      pendingIntents.set(governance.intentId, { governance, action, startedAt: new Date().toISOString() })
    }
    return { allowed: governance.verdict !== 'deny', reason: governance.reason, intentId: governance.intentId }
  }


  const after_action = (ctx: ADKActionContext, _result: unknown): GovernanceReceipt => {
    // Find the pending intent from before_action
    let pending = [...pendingIntents.entries()].find(([_, v]) => v.action.target === ctx.tool_name)
    if (!pending) {
      // No matching intent — create a standalone receipt
      const action: ActionDescriptor = {
        type: `adk:tool:${ctx.tool_name}`,
        target: ctx.tool_name,
        scopeRequired: `tool:${ctx.tool_name}`,
        metadata: { agent: ctx.agent_name },
      }
      const gov = hook.beforeAction(action)
      return hook.afterAction(gov, action, 'success', new Date().toISOString())
    }

    const [intentId, { governance, action, startedAt }] = pending
    pendingIntents.delete(intentId)
    return hook.afterAction(governance, action, 'success', startedAt)
  }

  return {
    before_action,
    after_action,
    get_audit_trail: () => hook.getReceipts(),
    hook,
  }
}
