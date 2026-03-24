// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS v2 Externality Accounting (Section 7)
 *
 * Each agent's resource usage is within scope. Aggregate usage exceeds
 * shared infrastructure capacity. This module tracks shared resources
 * and flags when agents exceed their externality budget.
 */

export interface SharedResource {
  id: string; name: string; capacity: number; unit: string;
}

export interface ExternalityRecord {
  id: string; agent_id: string; action_id: string;
  resource_id: string; cost: number; timestamp: string;
}

const resources: Map<string, SharedResource> = new Map()
const records: ExternalityRecord[] = []

export function registerSharedResource(name: string, capacity: number, unit: string): SharedResource {
  const r: SharedResource = {
    id: `resource-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    name, capacity, unit,
  }
  resources.set(r.id, r)
  return r
}

export function recordExternality(agentId: string, actionId: string, resourceId: string, cost: number): ExternalityRecord {
  if (!resources.has(resourceId)) throw new Error(`Resource ${resourceId} not found`)
  const r: ExternalityRecord = {
    id: `ext-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    agent_id: agentId, action_id: actionId,
    resource_id: resourceId, cost, timestamp: new Date().toISOString(),
  }
  records.push(r)
  return r
}

export function computeExternalityBudget(agentId: string, resourceId: string, budgetLimit: number): {
  agent_id: string; resource_id: string; total_cost: number;
  budget_limit: number; over_budget: boolean; computed_at: string;
} {
  const total = records
    .filter(r => r.agent_id === agentId && r.resource_id === resourceId)
    .reduce((s, r) => s + r.cost, 0)
  return {
    agent_id: agentId, resource_id: resourceId,
    total_cost: total, budget_limit: budgetLimit,
    over_budget: total > budgetLimit,
    computed_at: new Date().toISOString(),
  }
}

export function getResourceUtilization(resourceId: string): {
  total_usage: number; capacity: number; utilization_pct: number;
} {
  const res = resources.get(resourceId)
  if (!res) throw new Error(`Resource ${resourceId} not found`)
  const total = records.filter(r => r.resource_id === resourceId).reduce((s, r) => s + r.cost, 0)
  return {
    total_usage: total, capacity: res.capacity,
    utilization_pct: Math.round((total / res.capacity) * 1000) / 10,
  }
}

export function isOverBudget(agentId: string, resourceId: string, limit: number): boolean {
  return computeExternalityBudget(agentId, resourceId, limit).over_budget
}

export function clearExternalityStores(): void { resources.clear(); records.length = 0 }
