/**
 * APS v2 Outcome Registration
 * Three-way reporting: agent, principal, adjudicated.
 * Uses v1 crypto.
 */

import { v4 as uuidv4 } from 'uuid'
import { signObject } from './bridge.js'
import type {
  PolicyContext, OutcomeRecord, OutcomePerspective, OutcomeClass,
  SemanticUncertainty, AssuranceClass,
} from './types.js'

const outcomeStore: Map<string, OutcomeRecord> = new Map()

export function getV2OutcomeRecord(id: string): OutcomeRecord | undefined {
  return outcomeStore.get(id)
}
export function getV2OutcomesForAgent(agentId: string): OutcomeRecord[] {
  return Array.from(outcomeStore.values()).filter(o => o.agent_id === agentId)
}

// ═══════════════════════════════════════════════
// CREATE OUTCOME (agent perspective)
// ═══════════════════════════════════════════════

export function createV2OutcomeRecord(params: {
  action_id: string
  agent_id: string
  declared_intent: string
  semantic_uncertainty: SemanticUncertainty
  observed_outcome: string
  outcome_class: OutcomeClass
  divergence_score: number
  agent_private_key: string
  policy_context: PolicyContext
}): OutcomeRecord {
  if (params.divergence_score < 0 || params.divergence_score > 1) {
    throw new Error('Divergence score must be between 0 and 1')
  }
  const perspData = {
    reporter: params.agent_id,
    observed_outcome: params.observed_outcome,
    outcome_class: params.outcome_class,
    divergence_score: params.divergence_score,
    reported_at: new Date().toISOString(),
  }
  const sig = signObject(perspData as Record<string, unknown>, params.agent_private_key)
  const agentReport: OutcomePerspective = { ...perspData, signature: sig }
  const record: OutcomeRecord = {
    id: uuidv4(), action_id: params.action_id, agent_id: params.agent_id,
    declared_intent: params.declared_intent,
    semantic_uncertainty: params.semantic_uncertainty,
    agent_report: agentReport,
    principal_report: null, adjudicated_report: null, consensus: false,
    policy_context: params.policy_context,
    assurance_class: 'evidentially_auditable' as AssuranceClass,
  }
  outcomeStore.set(record.id, record)
  return record
}

// ═══════════════════════════════════════════════
// ADD PRINCIPAL PERSPECTIVE
// ═══════════════════════════════════════════════

export function addV2PrincipalReport(params: {
  outcome_id: string
  principal_id: string
  observed_outcome: string
  outcome_class: OutcomeClass
  divergence_score: number
  principal_private_key: string
}): OutcomeRecord {
  const record = outcomeStore.get(params.outcome_id)
  if (!record) throw new Error(`OutcomeRecord ${params.outcome_id} not found`)
  if (record.principal_report) throw new Error('Principal report already exists')
  if (params.divergence_score < 0 || params.divergence_score > 1) {
    throw new Error('Divergence score must be between 0 and 1')
  }
  const perspData = {
    reporter: params.principal_id,
    observed_outcome: params.observed_outcome,
    outcome_class: params.outcome_class,
    divergence_score: params.divergence_score,
    reported_at: new Date().toISOString(),
  }
  const sig = signObject(perspData as Record<string, unknown>, params.principal_private_key)
  const principalReport: OutcomePerspective = { ...perspData, signature: sig }
  const consensus =
    record.agent_report.outcome_class === principalReport.outcome_class &&
    Math.abs(record.agent_report.divergence_score - principalReport.divergence_score) < 0.15
  const updated = { ...record, principal_report: principalReport, consensus }
  outcomeStore.set(updated.id, updated)
  return updated
}

// ═══════════════════════════════════════════════
// ADD ADJUDICATED PERSPECTIVE
// ═══════════════════════════════════════════════

export function addV2AdjudicatedReport(params: {
  outcome_id: string
  adjudicator_id: string
  observed_outcome: string
  outcome_class: OutcomeClass
  divergence_score: number
  adjudicator_private_key: string
}): OutcomeRecord {
  const record = outcomeStore.get(params.outcome_id)
  if (!record) throw new Error(`OutcomeRecord ${params.outcome_id} not found`)
  if (!record.principal_report) throw new Error('Cannot adjudicate before principal has reported')
  if (record.consensus) throw new Error('Already in consensus; adjudication not needed')
  if (record.adjudicated_report) throw new Error('Already adjudicated')
  if (params.adjudicator_id === record.agent_id) throw new Error('Adjudicator cannot be the agent')
  if (params.adjudicator_id === record.principal_report.reporter) throw new Error('Adjudicator cannot be the principal')
  if (params.divergence_score < 0 || params.divergence_score > 1) throw new Error('Divergence 0-1')

  const perspData = {
    reporter: params.adjudicator_id, observed_outcome: params.observed_outcome,
    outcome_class: params.outcome_class, divergence_score: params.divergence_score,
    reported_at: new Date().toISOString(),
  }
  const sig = signObject(perspData as Record<string, unknown>, params.adjudicator_private_key)
  const updated = { ...record, adjudicated_report: { ...perspData, signature: sig } }
  outcomeStore.set(updated.id, updated)
  return updated
}

// ═══════════════════════════════════════════════
// ANALYTICS
// ═══════════════════════════════════════════════

/** Effective divergence: adjudicated > principal > agent */
export function getV2EffectiveDivergence(record: OutcomeRecord): number {
  if (record.adjudicated_report) return record.adjudicated_report.divergence_score
  if (record.principal_report) return record.principal_report.divergence_score
  return record.agent_report.divergence_score
}

export function getV2AgentDivergenceAverage(agentId: string): number {
  const outcomes = getV2OutcomesForAgent(agentId)
  if (outcomes.length === 0) return 0
  return outcomes.reduce((sum, o) => sum + getV2EffectiveDivergence(o), 0) / outcomes.length
}

export function getV2DisputedOutcomes(threshold: number = 0.3): OutcomeRecord[] {
  return Array.from(outcomeStore.values()).filter(o => {
    if (!o.principal_report) return false
    return Math.abs(o.agent_report.divergence_score - o.principal_report.divergence_score) >= threshold
  })
}

export function isV2AgentFlaggedForReview(
  agentId: string, threshold: number = 0.4, minOutcomes: number = 5
): boolean {
  const outcomes = getV2OutcomesForAgent(agentId)
  if (outcomes.length < minOutcomes) return false
  return getV2AgentDivergenceAverage(agentId) > threshold
}

export function clearV2OutcomeStore(): void { outcomeStore.clear() }
