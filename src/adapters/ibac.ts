// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * IBAC Adapter — Intent-Based Access Control Bridge
 *
 * Bridges Ken Huang's IBAC framework (CSA MAESTRO, OWASP AIVSS, ITU ANS)
 * into APS enforcement. IBAC defines the intent. APS proves it was enforced.
 *
 * Pipeline: Intent → Scope mapping → Delegation check → Signed receipt
 */

import { createDelegation, scopeAuthorizes } from '../core/delegation.js'
import { sign } from '../crypto/keys.js'
import { canonicalize } from '../core/canonical.js'
import type { Delegation, ActionReceipt, SignedPassport } from '../types/passport.js'
import { reportReceipt, type GatewayReporterConfig } from './gateway-reporter.js'

// ── Types ──

export interface IBACIntent {
  task: string
  subject: { id: string; role?: string }
  actions: IBACAction[]
  constraints?: Record<string, unknown>
  timestamp: string
}

export interface IBACAction {
  verb: string
  resource: string
  constraints?: Record<string, unknown>
}

export interface IBACTuple {
  principal: string
  action: string
  resource: string
  constraints?: Record<string, unknown>
}

export interface IBACEvaluationResult {
  intent: IBACIntent
  delegation: Delegation
  tupleResults: Array<{
    tuple: IBACTuple
    authorized: boolean
    scope: string
    reason: string
  }>
  receipt: ActionReceipt
}

// ── Verb → scope prefix mapping ──

const VERB_PREFIX: Record<string, string> = {
  read: 'data:read',
  query: 'data:read',
  write: 'data:write',
  send: 'comms:send',
  delete: 'admin:delete',
}

// ── Core functions ──

/**
 * Convert IBAC intent to APS delegation scope strings.
 * Maps verb+resource to hierarchical scope: `prefix:resource`
 */
export function ibacIntentToScope(intent: IBACIntent): string[] {
  if (!intent.actions || intent.actions.length === 0) return []
  return intent.actions.map(action => {
    const prefix = VERB_PREFIX[action.verb] || `data:${action.verb}`
    return `${prefix}:${action.resource}`
  })
}

/**
 * Convert IBAC tuples to an APS delegation.
 * Each tuple becomes a scope entry in the delegation.
 */
export function ibacTuplesToDelegation(
  tuples: IBACTuple[],
  principalKey: string,
  agentKey: string,
  privateKey: string,
  opts?: { expiresInHours?: number; spendLimit?: number },
): Delegation {
  const scope = tuples.map(t => {
    const verb = t.action.replace(/^tool:/, '')
    const prefix = VERB_PREFIX[verb] || `data:${verb}`
    return `${prefix}:${t.resource}`
  })

  return createDelegation({
    delegatedTo: agentKey,
    delegatedBy: principalKey,
    scope,
    privateKey,
    spendLimit: opts?.spendLimit,
    expiresInHours: opts?.expiresInHours,
  })
}

/**
 * Evaluate IBAC tuples against an existing APS delegation.
 * Returns per-tuple authorized/denied with reason.
 */
export function evaluateIBACTuples(
  tuples: IBACTuple[],
  delegation: Delegation,
): { tupleResults: Array<{ tuple: IBACTuple; authorized: boolean; scope: string; reason: string }> } {
  const tupleResults = tuples.map(tuple => {
    const verb = tuple.action.replace(/^tool:/, '')
    const prefix = VERB_PREFIX[verb] || `data:${verb}`
    const scope = `${prefix}:${tuple.resource}`

    // Check expiry
    if (new Date(delegation.expiresAt) <= new Date()) {
      return { tuple, authorized: false, scope, reason: 'Delegation expired' }
    }

    const authorized = scopeAuthorizes(delegation.scope, scope)
    const reason = authorized
      ? `Scope "${scope}" authorized by delegation`
      : `Scope "${scope}" not covered by delegation [${delegation.scope.join(', ')}]`

    return { tuple, authorized, scope, reason }
  })

  return { tupleResults }
}

/**
 * Full pipeline: intent → scope mapping → evaluation → signed receipt.
 * IBAC defines the intent. APS proves it was enforced.
 */
export function governIBACIntent(
  intent: IBACIntent,
  config: {
    passport: SignedPassport
    delegation: Delegation
    privateKey: string
    gateway?: GatewayReporterConfig
    onReceipt?: (r: ActionReceipt) => void
  },
): IBACEvaluationResult {
  // Convert intent to tuples
  const tuples: IBACTuple[] = intent.actions.map(action => ({
    principal: `agent:${intent.subject.id}`,
    action: `tool:${action.verb}`,
    resource: action.resource,
    constraints: action.constraints,
  }))

  // Evaluate
  const { tupleResults } = evaluateIBACTuples(tuples, config.delegation)

  const allAuthorized = tupleResults.every(r => r.authorized)
  const scopesUsed = tupleResults.map(r => r.scope).join(', ')

  // Build signed receipt
  const receiptData: Omit<ActionReceipt, 'signature'> = {
    receiptId: `rcpt_ibac_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
    version: '1.1',
    timestamp: new Date().toISOString(),
    agentId: config.passport.passport.agentId,
    delegationId: config.delegation.delegationId,
    action: {
      type: 'ibac_evaluation',
      target: intent.task,
      scopeUsed: scopesUsed,
    },
    result: {
      status: allAuthorized ? 'success' : 'failure',
      summary: allAuthorized
        ? `All ${tupleResults.length} IBAC tuples authorized`
        : `${tupleResults.filter(r => !r.authorized).length} of ${tupleResults.length} tuples denied`,
    },
    delegationChain: [],
  }

  const canonical = canonicalize(receiptData)
  const signature = sign(canonical, config.privateKey)
  const receipt = { ...receiptData, signature } as ActionReceipt

  if (config.onReceipt) config.onReceipt(receipt)
  if (config.gateway) reportReceipt(receipt, config.gateway).catch(() => {})

  return { intent, delegation: config.delegation, tupleResults, receipt }
}
