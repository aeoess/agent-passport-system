// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS v2 Inaction Auditing (Proportionality Freeze Defense)
 *
 * Under audit pressure, honest agents develop bias toward under-action.
 * Caution is legible; judgment is ambiguous. This module tracks what
 * agents could have done but chose not to, making inaction as
 * reviewable as action.
 */

export interface AvailableAction {
  id: string
  agent_id: string
  task_id: string
  action_description: string
  risk_class: string
  available_at: string
}

export interface InactionRecord {
  id: string
  agent_id: string
  available_action_id: string
  reason: string            // why the agent chose not to act
  consequence: string | null // observed consequence of inaction
  flagged: boolean
  created_at: string
}

const availableActions: Map<string, AvailableAction> = new Map()
const inactionRecords: Map<string, InactionRecord> = new Map()

export function recordAvailableAction(params: {
  agent_id: string; task_id: string; action_description: string; risk_class: string;
}): AvailableAction {
  const a: AvailableAction = {
    id: `avail-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    ...params, available_at: new Date().toISOString(),
  }
  availableActions.set(a.id, a)
  return a
}

export function recordInaction(availableActionId: string, reason: string): InactionRecord {
  const action = availableActions.get(availableActionId)
  if (!action) throw new Error(`Available action ${availableActionId} not found`)
  const r: InactionRecord = {
    id: `inaction-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    agent_id: action.agent_id, available_action_id: availableActionId,
    reason, consequence: null, flagged: false,
    created_at: new Date().toISOString(),
  }
  inactionRecords.set(r.id, r)
  return r
}

export function recordConsequence(inactionId: string, consequence: string): InactionRecord {
  const r = inactionRecords.get(inactionId)
  if (!r) throw new Error(`Inaction record ${inactionId} not found`)
  r.consequence = consequence
  r.flagged = true // consequence of inaction = auto-flag
  return r
}

export function analyzeInactionPattern(agentId: string): {
  total_available: number; total_inactions: number; inaction_rate: number;
  consequential_inactions: number; flagged: boolean;
} {
  const available = [...availableActions.values()].filter(a => a.agent_id === agentId)
  const inactions = [...inactionRecords.values()].filter(r => r.agent_id === agentId)
  const consequential = inactions.filter(r => r.consequence !== null)
  const rate = available.length > 0 ? inactions.length / available.length : 0
  return {
    total_available: available.length, total_inactions: inactions.length,
    inaction_rate: Math.round(rate * 1000) / 1000,
    consequential_inactions: consequential.length,
    flagged: rate > 0.7 || consequential.length >= 2,
  }
}

export function getInactionRecords(agentId?: string): InactionRecord[] {
  const all = [...inactionRecords.values()]
  return agentId ? all.filter(r => r.agent_id === agentId) : all
}

export function clearInactionAuditStores(): void {
  availableActions.clear()
  inactionRecords.clear()
}
