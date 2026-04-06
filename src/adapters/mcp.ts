// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * MCP Adapter — Generic governance wrapper for any MCP tool call.
 *
 * Works with any MCP server, any client. No MCP SDK dependency.
 * Wraps tool calls with APS delegation checks and signed receipts.
 */

import { scopeAuthorizes, verifyDelegation } from '../core/delegation.js'
import { verifyPassport } from '../verification/verify.js'
import { sign } from '../crypto/keys.js'
import { canonicalize } from '../core/canonical.js'
import type { Delegation, ActionReceipt, SignedPassport } from '../types/passport.js'

// ── Types ──

export interface MCPToolCall {
  name: string
  arguments: Record<string, unknown>
  server?: string
}

export interface MCPGovernanceConfig {
  passport: SignedPassport
  delegation: Delegation
  privateKey: string
  scopePrefix?: string
  destructiveTools?: string[]
  onReceipt?: (r: ActionReceipt) => void
  onDenied?: (info: { tool: string; reason: string }) => void
}

// ── Helpers ──

const DEFAULT_DESTRUCTIVE = ['delete', 'drop', 'remove', 'destroy', 'purge', 'truncate']

function buildMCPReceipt(
  agentId: string, delegationId: string, privateKey: string,
  toolName: string, scope: string, status: 'success' | 'failure', summary: string,
): ActionReceipt {
  const data: Omit<ActionReceipt, 'signature'> = {
    receiptId: `rcpt_mcp_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
    version: '1.1',
    timestamp: new Date().toISOString(),
    agentId, delegationId,
    action: { type: 'mcp_tool_call', target: toolName, scopeUsed: scope },
    result: { status, summary },
    delegationChain: [],
  }
  const sig = sign(canonicalize(data), privateKey)
  return { ...data, signature: sig } as ActionReceipt
}

function isDestructive(toolName: string, customList?: string[]): boolean {
  const list = customList || DEFAULT_DESTRUCTIVE
  const lower = toolName.toLowerCase()
  return list.some(d => lower.includes(d))
}

// ── Core functions ──

/** Derive APS scope from MCP tool call */
export function mcpToolToScope(
  call: MCPToolCall,
  config: Pick<MCPGovernanceConfig, 'scopePrefix' | 'destructiveTools'>,
): string {
  if (isDestructive(call.name, config.destructiveTools)) {
    return call.server ? `admin:${call.server}:${call.name}` : `admin:${call.name}`
  }
  const prefix = config.scopePrefix || (call.server ? `mcp:${call.server}` : 'tools')
  return `${prefix}:${call.name}`
}

/** Govern a single MCP tool call */
export async function governMCPToolCall(
  call: MCPToolCall,
  execute: (args: Record<string, unknown>) => Promise<unknown>,
  config: MCPGovernanceConfig,
): Promise<{ result: unknown; receipt: ActionReceipt } | { denied: true; reason: string; receipt: ActionReceipt }> {
  const scope = mcpToolToScope(call, config)
  const { passport, delegation, privateKey } = config

  const pc = verifyPassport(passport)
  if (!pc.valid) {
    const reason = `Passport invalid: ${pc.errors.join(', ')}`
    if (config.onDenied) config.onDenied({ tool: call.name, reason })
    const receipt = buildMCPReceipt(passport.passport.agentId, delegation.delegationId, privateKey, call.name, scope, 'failure', reason)
    if (config.onReceipt) config.onReceipt(receipt)
    return { denied: true, reason, receipt }
  }

  const dc = verifyDelegation(delegation)
  if (!dc.valid) {
    const reason = `Delegation invalid: ${dc.errors.join(', ')}`
    if (config.onDenied) config.onDenied({ tool: call.name, reason })
    const receipt = buildMCPReceipt(passport.passport.agentId, delegation.delegationId, privateKey, call.name, scope, 'failure', reason)
    if (config.onReceipt) config.onReceipt(receipt)
    return { denied: true, reason, receipt }
  }

  if (!scopeAuthorizes(delegation.scope, scope)) {
    const reason = `Scope "${scope}" not covered by delegation [${delegation.scope.join(', ')}]`
    if (config.onDenied) config.onDenied({ tool: call.name, reason })
    const receipt = buildMCPReceipt(passport.passport.agentId, delegation.delegationId, privateKey, call.name, scope, 'failure', reason)
    if (config.onReceipt) config.onReceipt(receipt)
    return { denied: true, reason, receipt }
  }

  const result = await execute(call.arguments)
  const receipt = buildMCPReceipt(passport.passport.agentId, delegation.delegationId, privateKey, call.name, scope, 'success', 'MCP tool executed successfully')
  if (config.onReceipt) config.onReceipt(receipt)
  return { result, receipt }
}

/** Create a governance interceptor for an MCP client */
export function createMCPGovernanceInterceptor(config: MCPGovernanceConfig) {
  return (call: MCPToolCall, execute: (args: Record<string, unknown>) => Promise<unknown>) =>
    governMCPToolCall(call, execute, config)
}
