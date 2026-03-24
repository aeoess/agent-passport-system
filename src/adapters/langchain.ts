// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * LangChain Adapter — maps LangChain's callback handler lifecycle to APS governance.
 *
 * LangChain pattern: on_tool_start → tool runs → on_tool_end / on_tool_error
 * APS pattern: beforeAction → execute → afterAction → receipt
 */

import { GovernanceHook } from './governance-hook.js'
import type { GovernanceHookConfig, ActionDescriptor, GovernanceResult, GovernanceReceipt } from './governance-hook.js'

export interface LangChainGovernanceHandler {
  on_tool_start: (toolName: string, input: string, runId: string) => { allowed: boolean; intentId: string }
  on_tool_end: (output: string, runId: string) => GovernanceReceipt | null
  on_tool_error: (error: string, runId: string) => GovernanceReceipt | null
  on_chain_start: (chainType: string, inputs: Record<string, unknown>, runId: string) => { allowed: boolean; intentId: string }
  on_chain_end: (outputs: Record<string, unknown>, runId: string) => GovernanceReceipt | null
  get_audit_trail: () => GovernanceReceipt[]
  hook: GovernanceHook
}

export function createLangChainGovernanceHandler(config: GovernanceHookConfig): LangChainGovernanceHandler {
  const hook = new GovernanceHook(config)
  const pending = new Map<string, { governance: GovernanceResult; action: ActionDescriptor; startedAt: string }>()

  const on_tool_start = (toolName: string, input: string, runId: string) => {
    const action: ActionDescriptor = {
      type: `langchain:tool:${toolName}`,
      target: toolName,
      scopeRequired: `tool:${toolName}`,
      metadata: { input: input.slice(0, 500), runId },
    }
    const governance = hook.beforeAction(action)
    if (governance.verdict !== 'deny') {
      pending.set(runId, { governance, action, startedAt: new Date().toISOString() })
    }
    return { allowed: governance.verdict !== 'deny', intentId: governance.intentId }
  }

  const on_tool_end = (_output: string, runId: string): GovernanceReceipt | null => {
    const p = pending.get(runId)
    if (!p) return null
    pending.delete(runId)
    return hook.afterAction(p.governance, p.action, 'success', p.startedAt)
  }

  const on_tool_error = (_error: string, runId: string): GovernanceReceipt | null => {
    const p = pending.get(runId)
    if (!p) return null
    pending.delete(runId)
    return hook.afterAction(p.governance, p.action, 'failure', p.startedAt)
  }

  const on_chain_start = (chainType: string, inputs: Record<string, unknown>, runId: string) => {
    const action: ActionDescriptor = {
      type: `langchain:chain:${chainType}`,
      target: chainType,
      scopeRequired: `chain:${chainType}`,
      metadata: { ...inputs, runId },
    }
    const governance = hook.beforeAction(action)
    if (governance.verdict !== 'deny') {
      pending.set(runId, { governance, action, startedAt: new Date().toISOString() })
    }
    return { allowed: governance.verdict !== 'deny', intentId: governance.intentId }
  }

  const on_chain_end = (_outputs: Record<string, unknown>, runId: string): GovernanceReceipt | null => {
    const p = pending.get(runId)
    if (!p) return null
    pending.delete(runId)
    return hook.afterAction(p.governance, p.action, 'success', p.startedAt)
  }

  return {
    on_tool_start, on_tool_end, on_tool_error,
    on_chain_start, on_chain_end,
    get_audit_trail: () => hook.getReceipts(),
    hook,
  }
}
