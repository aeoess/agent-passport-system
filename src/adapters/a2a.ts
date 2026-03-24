// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Google A2A Adapter — maps A2A Agent Cards to APS passports
 * and A2A Tasks to APS coordination.
 *
 * A2A pattern: Agent Card (discovery) → Task (work) → Artifact (output)
 * APS pattern: Passport (identity) → Intent/Decision (governance) → Receipt (proof)
 */

import { GovernanceHook } from './governance-hook.js'
import type { GovernanceHookConfig, ActionDescriptor, GovernanceReceipt, GovernanceResult } from './governance-hook.js'
import type { A2AAgentCard } from '../types/a2a.js'

export interface A2AGovernance {
  /** Map an A2A Agent Card to APS-compatible scopes */
  deriveScopes: (card: A2AAgentCard) => string[]
  /** Govern an A2A task send */
  governTaskSend: (
    targetCard: A2AAgentCard,
    taskDescription: string,
    execute: () => Promise<unknown>,
  ) => Promise<{ result: unknown; receipt: GovernanceReceipt; governance: GovernanceResult }>
  /** Govern receiving a task */
  governTaskReceive: (
    senderUrl: string,
    taskDescription: string,
    execute: () => Promise<unknown>,
  ) => Promise<{ result: unknown; receipt: GovernanceReceipt; governance: GovernanceResult }>
  get_audit_trail: () => GovernanceReceipt[]
  hook: GovernanceHook
}

export function createA2AGovernance(config: GovernanceHookConfig): A2AGovernance {
  const hook = new GovernanceHook(config)

  const deriveScopes = (card: A2AAgentCard): string[] => {
    const scopes: string[] = []
    if (card.skills) {
      for (const skill of card.skills) {
        scopes.push(`a2a:skill:${skill.id}`)
      }
    }
    if (card.capabilities?.streaming) scopes.push('a2a:streaming')
    if (card.capabilities?.pushNotifications) scopes.push('a2a:push')
    if (scopes.length === 0) scopes.push('a2a:task:execute')
    return scopes
  }

  const governTaskSend = async (
    targetCard: A2AAgentCard,
    taskDescription: string,
    execute: () => Promise<unknown>,
  ) => {
    const action: ActionDescriptor = {
      type: 'a2a:task:send',
      target: targetCard.url,
      scopeRequired: 'a2a:task:execute',
      metadata: { targetName: targetCard.name, task: taskDescription.slice(0, 200) },
    }
    return hook.wrap(action, execute)
  }

  const governTaskReceive = async (
    senderUrl: string,
    taskDescription: string,
    execute: () => Promise<unknown>,
  ) => {
    const action: ActionDescriptor = {
      type: 'a2a:task:receive',
      target: senderUrl,
      scopeRequired: 'a2a:task:execute',
      metadata: { sender: senderUrl, task: taskDescription.slice(0, 200) },
    }
    return hook.wrap(action, execute)
  }

  return {
    deriveScopes,
    governTaskSend,
    governTaskReceive,
    get_audit_trail: () => hook.getReceipts(),
    hook,
  }
}
