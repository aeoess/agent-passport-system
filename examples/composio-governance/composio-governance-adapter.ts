/**
 * APS Governance Adapter for Composio Tool Execution
 *
 * Wraps Composio (or any compatible) tool actions with Agent Passport
 * System delegation checks. Before any tool executes, APS verifies:
 *
 *   1. Passport valid (agent identity)
 *   2. Delegation scope covers this tool and action type
 *   3. Tool on allowed list for this delegation
 *   4. Destructive actions flagged for extra scrutiny
 *
 * After execution, produces a signed ActionReceipt linking the tool
 * call back to the human principal's delegation chain.
 *
 * Works with: Composio, or any tool object with { name, description, execute() }
 * Does NOT import Composio as a dependency.
 */

import {
  createReceipt,
  scopeAuthorizes,
  verifyDelegation,
  verifyPassport,
  evaluateRecovery,
  createDefaultRecoveryPolicy,
  evaluateCompliance,
  sign,
  canonicalize,
  type SignedPassport,
  type Delegation,
  type ActionReceipt,
  type ValuesFloor,
  type RecoveryPolicy,
} from 'agent-passport-system'

// ── Composio-Agnostic Tool Interface ──

/** Any tool object with name, description, and execute(). */
export interface ComposioAction {
  name: string
  description: string
  execute: (params: Record<string, unknown>) => Promise<unknown>
}

// ── Events ──

export interface DenialEvent {
  tool: string
  reason: string
  scope: string
  timestamp: string
}

// ── Config ──

export interface GovernedComposioConfig {
  /** Agent's signed passport */
  passport: SignedPassport
  /** Standard APS delegation from human principal */
  delegation: Delegation
  /** Agent's private key for signing receipts */
  privateKey: string
  /** Optional values floor for compliance checks */
  valuesFloor?: ValuesFloor
  /** Optional recovery policy for failed tool calls */
  recoveryPolicy?: RecoveryPolicy
  /** Callback when an action is denied */
  onDenied?: (event: DenialEvent) => void
  /** Callback for every receipt (audit logging) */
  onReceipt?: (receipt: ActionReceipt) => void
}

// ── Governed Action ──

export interface GovernedAction {
  name: string
  description: string
  execute: (params: Record<string, unknown>) => Promise<{
    result: unknown
    receipt: ActionReceipt
  } | {
    denied: true
    reason: string
    denialReceipt: ActionReceipt
  }>
}

// ── Destructive action patterns ──

const DESTRUCTIVE_VERBS = ['delete', 'destroy', 'drop', 'remove', 'purge', 'wipe', 'truncate']

function isDestructiveAction(toolName: string): boolean {
  const lower = toolName.toLowerCase()
  return DESTRUCTIVE_VERBS.some(verb => lower.includes(verb))
}

function toolToScope(toolName: string): string {
  // Convert tool names like "SALESFORCE_READ_ACCOUNT" to "salesforce:read"
  const parts = toolName.toLowerCase().split(/[_.\-/]/)
  if (parts.length >= 2) {
    return `${parts[0]}:${parts[1]}`
  }
  return toolName.toLowerCase()
}

// ── Core: Govern a single action ──

/**
 * Wrap a Composio tool action with APS governance.
 * Returns governed version that checks delegation before execution.
 */
export function governComposioAction(opts: {
  passport: SignedPassport
  delegation: Delegation
  privateKey: string
  action: ComposioAction
  valuesFloor?: ValuesFloor
  recoveryPolicy?: RecoveryPolicy
  onDenied?: (event: DenialEvent) => void
  onReceipt?: (receipt: ActionReceipt) => void
}): GovernedAction {
  const { passport, delegation, privateKey, action } = opts

  return {
    name: action.name,
    description: `[APS Governed] ${action.description}`,
    execute: async (params: Record<string, unknown>) => {
      const scope = toolToScope(action.name)
      const timestamp = new Date().toISOString()

      // Gate 1: Passport valid
      const passportCheck = verifyPassport(passport, passport.passport.publicKey)
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

      // Gate 4: Values floor compliance (if configured)
      if (opts.valuesFloor) {
        const compliance = evaluateCompliance(opts.valuesFloor, {
          action: action.name,
          scope,
          timestamp,
        })
        if (!compliance.compliant) {
          const reason = `Values floor violation: ${compliance.violations.map(v => v.principle).join(', ')}`
          return emitDenial(opts, action.name, scope, reason, timestamp)
        }
      }

      // All gates passed, execute
      try {
        const result = await action.execute(params)

        const receipt = createReceipt({
          agentId: passport.passport.agentId,
          delegationId: delegation.delegationId,
          delegation,
          privateKey,
          action: {
            tool: action.name,
            scopeUsed: scope,
            params,
          },
          result: { success: true, data: result },
        })

        if (opts.onReceipt) opts.onReceipt(receipt)

        return { result, receipt }
      } catch (err) {
        // Tool execution failed: consult recovery policy
        const errorMessage = err instanceof Error ? err.message : String(err)

        if (opts.recoveryPolicy) {
          const recovery = evaluateRecovery({
            policy: opts.recoveryPolicy,
            failureType: 'tool_error',
          })
          // Log recovery suggestion but still produce the receipt
          if (opts.onDenied) {
            opts.onDenied({
              tool: action.name,
              reason: `Tool error: ${errorMessage}. Recovery strategy: ${recovery.strategy}`,
              scope,
              timestamp: new Date().toISOString(),
            })
          }
        }

        const receipt = createReceipt({
          agentId: passport.passport.agentId,
          delegationId: delegation.delegationId,
          delegation,
          privateKey,
          action: {
            tool: action.name,
            scopeUsed: scope,
            params,
          },
          result: { success: false, error: errorMessage },
        })

        if (opts.onReceipt) opts.onReceipt(receipt)

        return { result: { error: errorMessage }, receipt }
      }
    },
  }
}

// ── Batch: Govern all tools ──

/**
 * Wrap all Composio tools for an agent with APS governance.
 */
export function governComposioToolkit(opts: {
  passport: SignedPassport
  delegation: Delegation
  privateKey: string
  tools: ComposioAction[]
  valuesFloor?: ValuesFloor
  recoveryPolicy?: RecoveryPolicy
  onDenied?: (event: DenialEvent) => void
  onReceipt?: (receipt: ActionReceipt) => void
}): GovernedAction[] {
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
  opts: {
    passport: SignedPassport
    delegation: Delegation
    privateKey: string
    onDenied?: (event: DenialEvent) => void
    onReceipt?: (receipt: ActionReceipt) => void
  },
  toolName: string,
  scope: string,
  reason: string,
  timestamp: string,
): { denied: true; reason: string; denialReceipt: ActionReceipt } {
  if (opts.onDenied) {
    opts.onDenied({ tool: toolName, reason, scope, timestamp })
  }

  // Build denial receipt directly (createReceipt validates scope, which would throw on denials)
  const receipt: Omit<ActionReceipt, 'signature'> = {
    receiptId: `rcpt_deny_${Date.now().toString(36)}`,
    version: '1.1',
    timestamp,
    agentId: opts.passport.passport.agentId,
    delegationId: opts.delegation.delegationId,
    action: { tool: toolName, scopeUsed: scope, params: {} },
    result: { success: false, denied: true, reason },
  }
  const canonical = canonicalize(receipt)
  const signature = sign(canonical, opts.privateKey)
  const denialReceipt = { ...receipt, signature } as ActionReceipt

  if (opts.onReceipt) opts.onReceipt(denialReceipt)

  return { denied: true, reason, denialReceipt }
}
