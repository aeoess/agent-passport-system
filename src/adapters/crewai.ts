// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * CrewAI Adapter — primitive mappings between CrewAI tasks and APS delegations.
 *
 * Pure mapping + receipt-builder layer. Stateful runtime (audit trail,
 * spend tracking, gateway reporting) lives in the gateway — callers that
 * need those behaviours supply them via the `onReceipt` / `onDenied` hooks.
 */

import { scopeAuthorizes, verifyDelegation } from '../core/delegation.js'
import { verifyPassport } from '../verification/verify.js'
import { sign } from '../crypto/keys.js'
import { canonicalize } from '../core/canonical.js'
import type { Delegation, ActionReceipt, SignedPassport } from '../types/passport.js'

export interface CrewTask {
  description: string
  agent: string
  tools?: string[]
  expected_output?: string
}

export interface CrewGovernanceConfig {
  passport: SignedPassport
  delegation: Delegation
  privateKey: string
  onReceipt?: (r: ActionReceipt) => void
  onDenied?: (info: { task: string; agent: string; reason: string }) => void
}

export interface GovernedTaskResult {
  output: unknown
  receipt: ActionReceipt
  toolReceipts: ActionReceipt[]
}

function buildCrewReceipt(
  agentId: string, delegationId: string, privateKey: string,
  target: string, scope: string, status: 'success' | 'failure', summary: string,
): ActionReceipt {
  const data: Omit<ActionReceipt, 'signature'> = {
    receiptId: `rcpt_crew_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
    version: '1.1',
    timestamp: new Date().toISOString(),
    agentId, delegationId,
    action: { type: 'crew_task', target, scopeUsed: scope },
    result: { status, summary },
    delegationChain: [],
  }
  const sig = sign(canonicalize(data), privateKey)
  return { ...data, signature: sig } as ActionReceipt
}

/** Generate scopes needed for a CrewTask */
export function crewTaskToScopes(task: CrewTask): string[] {
  const scopes = [`crew:execute:${task.agent}`]
  if (task.tools) {
    for (const tool of task.tools) {
      scopes.push(`tools:${tool}`)
    }
  }
  return scopes
}

/** Verify crew member has authority for task */
export function verifyCrewMember(
  agentName: string,
  task: CrewTask,
  config: CrewGovernanceConfig,
): { authorized: boolean; reason: string; scope: string } {
  const scopes = crewTaskToScopes(task)
  const mainScope = scopes[0]

  const pc = verifyPassport(config.passport)
  if (!pc.valid) return { authorized: false, reason: `Passport invalid: ${pc.errors.join(', ')}`, scope: mainScope }

  const dc = verifyDelegation(config.delegation)
  if (!dc.valid) return { authorized: false, reason: `Delegation invalid: ${dc.errors.join(', ')}`, scope: mainScope }

  for (const scope of scopes) {
    if (!scopeAuthorizes(config.delegation.scope, scope)) {
      return { authorized: false, reason: `Scope "${scope}" not covered by delegation`, scope }
    }
  }

  return { authorized: true, reason: `All ${scopes.length} scopes authorized`, scope: mainScope }
}

/** Wrap task execution with governance */
export async function governCrewTask(
  task: CrewTask,
  execute: (task: CrewTask) => Promise<unknown>,
  config: CrewGovernanceConfig,
): Promise<GovernedTaskResult | { denied: true; reason: string; receipt: ActionReceipt }> {
  const check = verifyCrewMember(task.agent, task, config)
  const { passport, delegation, privateKey } = config

  if (!check.authorized) {
    if (config.onDenied) config.onDenied({ task: task.description, agent: task.agent, reason: check.reason })
    const receipt = buildCrewReceipt(passport.passport.agentId, delegation.delegationId, privateKey, task.description, check.scope, 'failure', check.reason)
    if (config.onReceipt) config.onReceipt(receipt)
    return { denied: true, reason: check.reason, receipt }
  }

  const output = await execute(task)

  // Build tool-level receipts
  const toolReceipts: ActionReceipt[] = (task.tools || []).map(tool => {
    const scope = `tools:${tool}`
    return buildCrewReceipt(passport.passport.agentId, delegation.delegationId, privateKey, tool, scope, 'success', `Tool ${tool} used during task`)
  })

  const mainScope = crewTaskToScopes(task).join(', ')
  const receipt = buildCrewReceipt(passport.passport.agentId, delegation.delegationId, privateKey, task.description, mainScope, 'success', `Task completed with ${(task.tools || []).length} tools`)
  if (config.onReceipt) config.onReceipt(receipt)
  for (const tr of toolReceipts) { if (config.onReceipt) config.onReceipt(tr) }

  return { output, receipt, toolReceipts }
}
