// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * LangChain Adapter — primitive mappings between LangChain tool calls and APS delegations.
 *
 * Pure mapping + receipt-builder layer. Stateful runtime (pending-intent tracking,
 * audit trail, gateway reporting) lives in the gateway — callers that need those
 * behaviours supply them via the `onReceipt` / `onDenied` hooks.
 */

import { scopeAuthorizes, verifyDelegation } from '../core/delegation.js'
import { verifyPassport } from '../verification/verify.js'
import { sign } from '../crypto/keys.js'
import { canonicalize } from '../core/canonical.js'
import type { Delegation, ActionReceipt, SignedPassport } from '../types/passport.js'

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
    return { denied: true, reason, receipt }
  }

  // Delegation check
  const dc = verifyDelegation(delegation)
  if (!dc.valid) {
    const reason = `Delegation invalid: ${dc.errors.join(', ')}`
    if (config.onDenied) config.onDenied({ tool: call.name, reason })
    const receipt = buildLCReceipt(passport.passport.agentId, delegation.delegationId, privateKey, call.name, scope, 'failure', reason)
    if (config.onReceipt) config.onReceipt(receipt)
    return { denied: true, reason, receipt }
  }

  // Scope check
  if (!scopeAuthorizes(delegation.scope, scope)) {
    const reason = `Scope "${scope}" not covered by delegation [${delegation.scope.join(', ')}]`
    if (config.onDenied) config.onDenied({ tool: call.name, reason })
    const receipt = buildLCReceipt(passport.passport.agentId, delegation.delegationId, privateKey, call.name, scope, 'failure', reason)
    if (config.onReceipt) config.onReceipt(receipt)
    return { denied: true, reason, receipt }
  }

  // Execute
  const output = await execute(call.args)
  const receipt = buildLCReceipt(passport.passport.agentId, delegation.delegationId, privateKey, call.name, scope, 'success', 'Tool executed successfully')
  if (config.onReceipt) config.onReceipt(receipt)
  return { output, receipt }
}

/** Create a governance middleware for LangGraph */
export function createLangGraphGovernance(config: LangChainGovernanceConfig) {
  return (call: LangChainToolCall, execute: (args: Record<string, unknown>) => Promise<unknown>) =>
    governLangChainTool(call, execute, config)
}
