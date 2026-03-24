// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * CrewAI Adapter — wraps APS GovernanceHook for CrewAI's callback lifecycle.
 *
 * Usage:
 *   import { createCrewAIGovernance } from 'agent-passport-system'
 *   const gov = createCrewAIGovernance({ agentId, ...keys, delegationId, allowedScopes })
 *
 *   // In CrewAI task config:
 *   task = Task(
 *     description="...",
 *     callback=gov.taskCallback
 *   )
 *
 *   // Or wrap any tool call:
 *   const result = await gov.governedToolCall('search', { query: '...' }, searchTool)
 */

import { GovernanceHook } from './governance-hook.js'
import type { GovernanceHookConfig, ActionDescriptor, GovernanceReceipt, GovernanceResult } from './governance-hook.js'

export interface CrewAITaskOutput {
  description: string
  result: string
  agent: string
}

export interface CrewAIGovernance {
  /** Use as CrewAI task callback */
  taskCallback: (output: CrewAITaskOutput) => GovernanceReceipt
  /** Wrap a tool call with governance */
  governedToolCall: <T>(
    toolName: string,
    params: Record<string, unknown>,
    execute: () => Promise<T>,
    estimatedCost?: number,
  ) => Promise<{ result: T | null; receipt: GovernanceReceipt; governance: GovernanceResult }>
  /** Get all receipts */
  getReceipts: () => GovernanceReceipt[]
  /** Get the underlying hook */
  hook: GovernanceHook
}

/**
 * Create a CrewAI governance adapter.
 * Maps CrewAI's task/tool lifecycle to APS governance.
 */
export function createCrewAIGovernance(config: GovernanceHookConfig): CrewAIGovernance {
  const hook = new GovernanceHook(config)

  const taskCallback = (output: CrewAITaskOutput): GovernanceReceipt => {
    const action: ActionDescriptor = {
      type: 'crewai:task_complete',
      target: output.description.slice(0, 100),
      scopeRequired: 'task:execute',
      metadata: { agent: output.agent, resultLength: output.result.length },
    }
    const governance = hook.beforeAction(action)
    return hook.afterAction(governance, action, 'success', new Date().toISOString())
  }

  const governedToolCall = async <T>(
    toolName: string,
    params: Record<string, unknown>,
    execute: () => Promise<T>,
    estimatedCost?: number,
  ) => {
    const action: ActionDescriptor = {
      type: `crewai:tool:${toolName}`,
      target: toolName,
      scopeRequired: `tool:${toolName}`,
      metadata: params,
      estimatedCost,
    }
    return hook.wrap(action, execute)
  }

  return {
    taskCallback,
    governedToolCall,
    getReceipts: () => hook.getReceipts(),
    hook,
  }
}
