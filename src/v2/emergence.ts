/**
 * APS v2 Emergence Detection (Aggregate Governance)
 *
 * The protocol governs individual actions. But 10,000 honest compliant
 * agents can produce systemic outcomes no single principal authorized:
 * market concentration, epistemic monoculture, resource depletion.
 *
 * This module tracks aggregate patterns across the entire agent population
 * and flags emergent risks that individual-action governance misses.
 */

import type {
  AgentActionSummary, SystemMetrics, EmergencePatternType,
  EmergenceFlag, RiskClass,
} from './types.js'

// ── Stores ──
const actionSummaries: AgentActionSummary[] = []
const metricsHistory: SystemMetrics[] = []
const emergenceFlags: EmergenceFlag[] = []

// ── Record Agent Activity ──

export function recordAgentActivity(summary: AgentActionSummary): void {
  actionSummaries.push(summary)
}

export function getActivitySummaries(agentId?: string): AgentActionSummary[] {
  if (agentId) return actionSummaries.filter(s => s.agent_id === agentId)
  return [...actionSummaries]
}

// ── Shannon Entropy ──
// Measures diversity of action distribution. 0 = monoculture, higher = diverse.

function shannonEntropy(counts: number[]): number {
  const total = counts.reduce((s, c) => s + c, 0)
  if (total === 0) return 0
  let entropy = 0
  for (const c of counts) {
    if (c === 0) continue
    const p = c / total
    entropy -= p * Math.log2(p)
  }
  return entropy
}

// Normalize to 0-1 range (1 = max diversity)
function normalizedEntropy(counts: number[]): number {
  const maxEntropy = Math.log2(counts.length || 1)
  if (maxEntropy === 0) return 0
  return shannonEntropy(counts) / maxEntropy
}

// ── Compute System Metrics ──

export function computeSystemMetrics(): SystemMetrics {
  if (actionSummaries.length === 0) {
    return {
      id: `metrics-${Date.now()}`, diversity_index: 1,
      resource_velocity: 0, convergence_score: 0,
      top_action_concentration: 0, top_agent_concentration: 0,
      agent_count: 0, action_count: 0,
      computed_at: new Date().toISOString(),
    }
  }

  // Action category distribution
  const categoryCount: Record<string, number> = {}
  const agentCount: Record<string, number> = {}
  let totalActions = 0
  for (const s of actionSummaries) {
    categoryCount[s.action_category] = (categoryCount[s.action_category] || 0) + s.count
    agentCount[s.agent_id] = (agentCount[s.agent_id] || 0) + s.count
    totalActions += s.count
  }

  const catCounts = Object.values(categoryCount)
  const agCounts = Object.values(agentCount)

  // Diversity index: entropy of action categories
  const diversity = normalizedEntropy(catCounts)

  // Convergence: how similar agents' behavior profiles are (1 - agent entropy)
  const convergence = 1 - normalizedEntropy(agCounts)

  // Top concentrations
  const maxCategory = Math.max(...catCounts)
  const maxAgent = Math.max(...agCounts)
  const topActionConc = totalActions > 0 ? maxCategory / totalActions : 0
  const topAgentConc = totalActions > 0 ? maxAgent / totalActions : 0

  // Resource velocity (total actions per unique period)
  const periods = new Set(actionSummaries.map(s => s.period))
  const velocity = periods.size > 0 ? totalActions / periods.size : 0

  const metrics: SystemMetrics = {
    id: `metrics-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    diversity_index: Math.round(diversity * 1000) / 1000,
    resource_velocity: Math.round(velocity * 100) / 100,
    convergence_score: Math.round(convergence * 1000) / 1000,
    top_action_concentration: Math.round(topActionConc * 1000) / 1000,
    top_agent_concentration: Math.round(topAgentConc * 1000) / 1000,
    agent_count: Object.keys(agentCount).length,
    action_count: totalActions,
    computed_at: new Date().toISOString(),
  }
  metricsHistory.push(metrics)
  return metrics
}

export function getMetricsHistory(): SystemMetrics[] {
  return [...metricsHistory]
}

// ── Emergence Detection ──

export function detectEmergence(thresholds?: {
  monoculture_diversity?: number;
  concentration_agent?: number;
  concentration_action?: number;
}): EmergenceFlag[] {
  const metrics = computeSystemMetrics()
  const newFlags: EmergenceFlag[] = []
  const t = {
    monoculture_diversity: thresholds?.monoculture_diversity ?? 0.3,
    concentration_agent: thresholds?.concentration_agent ?? 0.5,
    concentration_action: thresholds?.concentration_action ?? 0.6,
  }

  // Epistemic monoculture: agents all doing the same thing
  if (metrics.diversity_index < t.monoculture_diversity && metrics.agent_count > 2) {
    const allAgents = [...new Set(actionSummaries.map(s => s.agent_id))]
    newFlags.push(createFlag('epistemic_monoculture', 'high',
      `Diversity index ${metrics.diversity_index} below ${t.monoculture_diversity} threshold. ${metrics.agent_count} agents converging on same action patterns.`,
      allAgents, metrics,
      'Introduce action diversity requirements or review principal consent for convergent behavior'))
  }

  // Market concentration: one agent dominates
  if (metrics.top_agent_concentration > t.concentration_agent && metrics.agent_count > 1) {
    const agentCounts: Record<string, number> = {}
    for (const s of actionSummaries) agentCounts[s.agent_id] = (agentCounts[s.agent_id] || 0) + s.count
    const topAgent = Object.entries(agentCounts).sort((a, b) => b[1] - a[1])[0][0]
    newFlags.push(createFlag('market_concentration', 'high',
      `Agent ${topAgent} controls ${(metrics.top_agent_concentration * 100).toFixed(0)}% of all actions`,
      [topAgent], metrics,
      'Review delegation scope limits or introduce anti-monopoly constraints'))
  }

  // Action concentration: one category dominates
  if (metrics.top_action_concentration > t.concentration_action) {
    const catCounts: Record<string, number> = {}
    for (const s of actionSummaries) catCounts[s.action_category] = (catCounts[s.action_category] || 0) + s.count
    const topCat = Object.entries(catCounts).sort((a, b) => b[1] - a[1])[0][0]
    const allAgents = [...new Set(actionSummaries.map(s => s.agent_id))]
    newFlags.push(createFlag('resource_depletion', 'medium',
      `Action category "${topCat}" is ${(metrics.top_action_concentration * 100).toFixed(0)}% of all activity — potential resource overcommitment`,
      allAgents, metrics,
      'Introduce rate limits or diversification requirements for dominant action categories'))
  }

  for (const f of newFlags) emergenceFlags.push(f)
  return newFlags
}

function createFlag(
  pattern: EmergencePatternType, severity: RiskClass,
  description: string, agents: string[],
  metrics: SystemMetrics, recommended: string,
): EmergenceFlag {
  return {
    id: `emerge-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    pattern_type: pattern, severity, description,
    affected_agents: agents, metrics_snapshot: metrics,
    recommended_action: recommended,
    reviewed: false, review_outcome: null,
    created_at: new Date().toISOString(),
  }
}

// ── Query & Management ──

export function getEmergenceFlags(patternType?: EmergencePatternType): EmergenceFlag[] {
  if (patternType) return emergenceFlags.filter(f => f.pattern_type === patternType)
  return [...emergenceFlags]
}

export function getUnreviewedEmergenceFlags(): EmergenceFlag[] {
  return emergenceFlags.filter(f => !f.reviewed)
}

export function reviewEmergenceFlag(flagId: string, outcome: string): EmergenceFlag | undefined {
  const flag = emergenceFlags.find(f => f.id === flagId)
  if (!flag) return undefined
  flag.reviewed = true
  flag.review_outcome = outcome
  return flag
}

export function clearEmergenceStores(): void {
  actionSummaries.length = 0
  metricsHistory.length = 0
  emergenceFlags.length = 0
}
