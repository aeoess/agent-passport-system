// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS Governance Adapter for Composio Tool Execution
 *
 * Wraps tool actions with Agent Passport System delegation checks.
 * Before any tool executes, APS verifies:
 *   1. Passport valid (agent identity)
 *   2. Delegation scope covers this tool and action type
 *   3. Destructive actions require explicit scope
 *
 * Works with: Composio, MCP, LangChain, or any { name, description, execute() }
 */

import {
  scopeAuthorizes,
  verifyDelegation,
  verifyPassport,
  evaluateRecovery,
  sign,
  canonicalize,
  type ActionReceipt,
} from 'agent-passport-system'

import type {
  ComposioAction,
  ToolGovernanceConfig,
  GovernedAction,
  GovernedResult,
} from './types.js'

// ── Destructive action patterns ──

const DESTRUCTIVE_VERBS = ['delete', 'destroy', 'drop', 'remove', 'purge', 'wipe', 'truncate']

function isDestructiveAction(toolName: string): boolean {
  const lower = toolName.toLowerCase()
  return DESTRUCTIVE_VERBS.some(verb => lower.includes(verb))
}

function toolToScope(toolName: string): string {
  const parts = toolName.toLowerCase().split(/[_.\-/]/)
  if (parts.length >= 2) {
    return `${parts[0]}:${parts[1]}`
  }
  return toolName.toLowerCase()
}

// ── Receipt builder ──

function buildReceipt(
  agentId: string,
  delegationId: string,
  privateKey: string,
  toolName: string,
  scope: string,
  params: Record<string, unknown>,
  result: Record<string, unknown>,
): ActionReceipt {
  const receipt: Omit<ActionReceipt, 'signature'> = {
    receiptId: `rcpt_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
    version: '1.1',
    timestamp: new Date().toISOString(),
    agentId,
    delegationId,
    action: { type: 'tool_call', target: toolName, scopeUsed: scope },
    result: { status: result.success ? 'success' as const : 'failure' as const, summary: JSON.stringify(result) },
    delegationChain: [],
  }
  const canonical = canonicalize(receipt)
  const signature = sign(canonical, privateKey)
  return { ...receipt, signature } as ActionReceipt
}

// ── Core: Govern a single action ──

/**
 * Wrap a tool action with APS governance.
 * Returns governed version that checks delegation before execution.
 */
export function governComposioAction(opts: ToolGovernanceConfig & { action: ComposioAction }): GovernedAction {
  const { passport, delegation, privateKey, action } = opts

  return {
    name: action.name,
    description: `[APS Governed] ${action.description}`,
    execute: async (params: Record<string, unknown>): Promise<GovernedResult> => {
      const scope = toolToScope(action.name)
      const timestamp = new Date().toISOString()

      // Gate 1: Passport valid
      const passportCheck = verifyPassport(passport)
      if (!passportCheck.valid) {
        const reason = `Passport invalid: ${passportCheck.errors.join(', ')}`
        return emitDenial(opts, action.name, scope, reason, timestamp)
      }

      // Gate 2: Delegation valid and scope covers this tool
      const delegationCheck = verifyDelegation(delegation)
      if (!delegationCheck.valid) {
        const reason = `Delegation invalid: ${delegationCheck.errors.join(', ')}`
        return emitDenial(opts, action.name, scope, reason, timestamp)
      }

      if (!scopeAuthorizes(delegation.scope, scope)) {
        const reason = `Scope "${scope}" not covered by delegation [${delegation.scope.join(', ')}]`
        return emitDenial(opts, action.name, scope, reason, timestamp)
      }

      // Gate 3: Destructive action check
      if (isDestructiveAction(action.name)) {
        const hasDestructiveScope = delegation.scope.some(s =>
          s.includes('delete') || s.includes('destroy') || s.includes('admin') || s.includes('*')
        )
        if (!hasDestructiveScope) {
          const reason = `Destructive action "${action.name}" requires explicit delete/destroy/admin scope`
          return emitDenial(opts, action.name, scope, reason, timestamp)
        }
      }

      // All gates passed, execute
      try {
        const result = await action.execute(params)
        const receipt = buildReceipt(
          passport.passport.agentId, delegation.delegationId, privateKey,
          action.name, scope, params, { success: true, data: result },
        )
        if (opts.onReceipt) opts.onReceipt(receipt)
        return { result, receipt }
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : String(err)

        if (opts.recoveryPolicy) {
          const recovery = evaluateRecovery({
            policy: opts.recoveryPolicy,
            failureType: 'tool_error',
          })
          if (opts.onDenied) {
            opts.onDenied({
              tool: action.name,
              reason: `Tool error: ${errorMessage}. Recovery strategy: ${recovery.strategy}`,
              scope,
              timestamp: new Date().toISOString(),
            })
          }
        }

        const receipt = buildReceipt(
          passport.passport.agentId, delegation.delegationId, privateKey,
          action.name, scope, params, { success: false, error: errorMessage },
        )
        if (opts.onReceipt) opts.onReceipt(receipt)
        return { result: { error: errorMessage }, receipt }
      }
    },
  }
}

// ── Batch: Govern all tools ──

/**
 * Wrap all tools for an agent with APS governance.
 */
export function governComposioToolkit(opts: ToolGovernanceConfig & { tools: ComposioAction[] }): GovernedAction[] {
  return opts.tools.map(action => governComposioAction({
    passport: opts.passport,
    delegation: opts.delegation,
    privateKey: opts.privateKey,
    action,
    valuesFloor: opts.valuesFloor,
    recoveryPolicy: opts.recoveryPolicy,
    onDenied: opts.onDenied,
    onReceipt: opts.onReceipt,
  }))
}

// ── Helpers ──

function emitDenial(
  opts: Pick<ToolGovernanceConfig, 'passport' | 'delegation' | 'privateKey' | 'onDenied' | 'onReceipt'>,
  toolName: string,
  scope: string,
  reason: string,
  timestamp: string,
): { denied: true; reason: string; denialReceipt: ActionReceipt } {
  if (opts.onDenied) {
    opts.onDenied({ tool: toolName, reason, scope, timestamp })
  }

  const receipt: Omit<ActionReceipt, 'signature'> = {
    receiptId: `rcpt_deny_${Date.now().toString(36)}`,
    version: '1.1',
    timestamp,
    agentId: opts.passport.passport.agentId,
    delegationId: opts.delegation.delegationId,
    action: { type: 'tool_call', target: toolName, scopeUsed: scope },
    result: { status: 'failure', summary: reason },
    delegationChain: [],
  }
  const canonical = canonicalize(receipt)
  const signature = sign(canonical, opts.privateKey)
  const denialReceipt = { ...receipt, signature } as ActionReceipt

  if (opts.onReceipt) opts.onReceipt(denialReceipt)
  return { denied: true, reason, denialReceipt }
}
