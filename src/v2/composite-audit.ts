// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS v2 Composite Workflow Audit (Authority Laundering)
 *
 * Agent A has scope [read], Agent B has scope [write]. Neither can
 * read+write alone. But if A reads and passes to B who writes, the
 * composite pipeline achieves read+write — something no single
 * delegation authorized.
 *
 * This module tracks action pipelines across agents and detects when
 * the composite set of capabilities exceeds what any individual holds.
 */

import type {
  PipelineAction, CompositeCapability,
} from './types.js'

// ── Stores ──
const pipelineActions: PipelineAction[] = []
const compositeFlags: CompositeCapability[] = []

// ── Record Pipeline Actions ──

export function recordPipelineAction(action: PipelineAction): void {
  pipelineActions.push(action)
}

export function getPipelineActions(agentId?: string): PipelineAction[] {
  if (agentId) return pipelineActions.filter(a => a.agent_id === agentId)
  return [...pipelineActions]
}

// ── Build Pipeline Graph ──
// Trace chains of actions where one agent's output feeds another's input

function buildPipelines(): Map<string, PipelineAction[]> {
  const pipelines = new Map<string, PipelineAction[]>()

  // Find chain starts (actions with no input_from)
  const starts = pipelineActions.filter(a => a.input_from === null)

  for (const start of starts) {
    const chain: PipelineAction[] = [start]
    let current = start

    // Follow the chain: current.output_to === next.input_from
    while (current.output_to) {
      const next = pipelineActions.find(
        a => a.agent_id === current.output_to && a.input_from === current.agent_id
      )
      if (!next || chain.includes(next)) break // prevent cycles
      chain.push(next)
      current = next
    }

    if (chain.length > 1) {
      const pipelineId = `pipeline-${chain.map(a => a.agent_id).join('-')}`
      pipelines.set(pipelineId, chain)
    }
  }
  return pipelines
}

// ── Audit Composite Capabilities ──

export function auditCompositeCapabilities(): CompositeCapability[] {
  const pipelines = buildPipelines()
  const newFlags: CompositeCapability[] = []

  for (const [pipelineId, chain] of pipelines) {
    const agents = chain.map(a => a.agent_id)
    const individualScopes: Record<string, string[]> = {}
    const allScopes: Set<string> = new Set()

    for (const action of chain) {
      individualScopes[action.agent_id] = action.delegation_scope
      for (const s of action.delegation_scope) allScopes.add(s)
    }

    // Composite capabilities = union of all scopes
    const composite = [...allScopes]

    // Check: does the composite achieve something no single agent holds?
    // The real authority laundering check: does ANY single agent hold
    // the full composite capability set? If not, the pipeline achieves
    // something no individual was authorized to do.
    const compositeSet = new Set(composite)
    const anyoneHoldsAll = Object.values(individualScopes).some(scopes => {
      const agentSet = new Set(scopes)
      return [...compositeSet].every(c => agentSet.has(c))
    })

    if (!anyoneHoldsAll && composite.length > 1) {
      const flag: CompositeCapability = {
        pipeline_id: pipelineId,
        agents,
        individual_scopes: individualScopes,
        composite_capabilities: composite,
        unauthorized_composites: composite, // the full set is unauthorized as a unit
        flagged: true,
        description: `Pipeline ${agents.join(' → ')} achieves composite [${composite.join(', ')}] — no single agent holds all capabilities`,
        created_at: new Date().toISOString(),
      }
      compositeFlags.push(flag)
      newFlags.push(flag)
    }
  }
  return newFlags
}

// ── Query ──

export function getCompositeFlags(agentId?: string): CompositeCapability[] {
  if (agentId) return compositeFlags.filter(f => f.agents.includes(agentId))
  return [...compositeFlags]
}

export function isAgentInLaunderingPipeline(agentId: string): boolean {
  return compositeFlags.some(f => f.agents.includes(agentId) && f.flagged)
}

export function clearCompositeAuditStores(): void {
  pipelineActions.length = 0
  compositeFlags.length = 0
}
