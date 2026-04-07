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


// ══════════════════════════════════════
// v2: Direct receipt-builder governance (IBAC pattern)
// ══════════════════════════════════════

import { scopeAuthorizes, verifyDelegation } from '../core/delegation.js'
import { verifyPassport } from '../verification/verify.js'
import { sign } from '../crypto/keys.js'
import { canonicalize } from '../core/canonical.js'
import type { Delegation, ActionReceipt, SignedPassport } from '../types/passport.js'
import { reportReceipt, type GatewayReporterConfig } from './gateway-reporter.js'

export interface LangChainToolCall {
  name: string
  args: Record<string, unknown>
  id?: string
}

export interface GovernedToolResult {
  output: unknown
  receipt: ActionReceipt
}

export interface DeniedToolResult {
  denied: true
  reason: string
  receipt: ActionReceipt
}

export interface LangChainGovernanceConfig {
  passport: SignedPassport
  delegation: Delegation
  privateKey: string
  scopeMapping?: Record<string, string>
  gateway?: GatewayReporterConfig
  onReceipt?: (r: ActionReceipt) => void
  onDenied?: (info: { tool: string; reason: string }) => void
}

function buildLCReceipt(
  agentId: string, delegationId: string, privateKey: string,
  toolName: string, scope: string, status: 'success' | 'failure', summary: string,
): ActionReceipt {
  const data: Omit<ActionReceipt, 'signature'> = {
    receiptId: `rcpt_lc_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
    version: '1.1',
    timestamp: new Date().toISOString(),
    agentId, delegationId,
    action: { type: 'langchain_tool', target: toolName, scopeUsed: scope },
    result: { status, summary },
    delegationChain: [],
  }
  const sig = sign(canonicalize(data), privateKey)
  return { ...data, signature: sig } as ActionReceipt
}

/** Map LangChain tool name to APS scope */
export function langchainToolToScope(
  toolName: string,
  scopeMapping?: Record<string, string>,
): string {
  if (scopeMapping && scopeMapping[toolName]) return scopeMapping[toolName]
  return `tools:${toolName}`
}

/** Govern a single LangChain tool call */
export async function governLangChainTool(
  call: LangChainToolCall,
  execute: (args: Record<string, unknown>) => Promise<unknown>,
  config: LangChainGovernanceConfig,
): Promise<GovernedToolResult | DeniedToolResult> {
  const scope = langchainToolToScope(call.name, config.scopeMapping)
  const { passport, delegation, privateKey } = config

  // Passport check
  const pc = verifyPassport(passport)
  if (!pc.valid) {
    const reason = `Passport invalid: ${pc.errors.join(', ')}`
    if (config.onDenied) config.onDenied({ tool: call.name, reason })
    const receipt = buildLCReceipt(passport.passport.agentId, delegation.delegationId, privateKey, call.name, scope, 'failure', reason)
    if (config.onReceipt) config.onReceipt(receipt)
    if (config.gateway) reportReceipt(receipt, config.gateway).catch(() => {})
    return { denied: true, reason, receipt }
  }

  // Delegation check
  const dc = verifyDelegation(delegation)
  if (!dc.valid) {
    const reason = `Delegation invalid: ${dc.errors.join(', ')}`
    if (config.onDenied) config.onDenied({ tool: call.name, reason })
    const receipt = buildLCReceipt(passport.passport.agentId, delegation.delegationId, privateKey, call.name, scope, 'failure', reason)
    if (config.onReceipt) config.onReceipt(receipt)
    if (config.gateway) reportReceipt(receipt, config.gateway).catch(() => {})
    return { denied: true, reason, receipt }
  }

  // Scope check
  if (!scopeAuthorizes(delegation.scope, scope)) {
    const reason = `Scope "${scope}" not covered by delegation [${delegation.scope.join(', ')}]`
    if (config.onDenied) config.onDenied({ tool: call.name, reason })
    const receipt = buildLCReceipt(passport.passport.agentId, delegation.delegationId, privateKey, call.name, scope, 'failure', reason)
    if (config.onReceipt) config.onReceipt(receipt)
    if (config.gateway) reportReceipt(receipt, config.gateway).catch(() => {})
    return { denied: true, reason, receipt }
  }

  // Execute
  const output = await execute(call.args)
  const receipt = buildLCReceipt(passport.passport.agentId, delegation.delegationId, privateKey, call.name, scope, 'success', 'Tool executed successfully')
  if (config.onReceipt) config.onReceipt(receipt)
  if (config.gateway) reportReceipt(receipt, config.gateway).catch(() => {})
  return { output, receipt }
}

/** Create a governance middleware for LangGraph */
export function createLangGraphGovernance(config: LangChainGovernanceConfig) {
  return (call: LangChainToolCall, execute: (args: Record<string, unknown>) => Promise<unknown>) =>
    governLangChainTool(call, execute, config)
}
