// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS v2 Output Proportionality (Truthful Deception Defense)
 *
 * A 5,000-page technically accurate analysis buries the critical flaw
 * on page 4,812. 100% truthful, 0% honest. This module detects
 * disproportionate output volume and requires executive summaries
 * for long analytical outputs.
 */

export interface OutputMetrics {
  id: string
  agent_id: string
  action_id: string
  output_length: number       // total chars/words
  key_finding_position: number | null  // where the most important info is (0-1 normalized)
  has_executive_summary: boolean
  summary_accuracy: number | null  // 0-1 how well summary captures key findings
  flagged: boolean
  flag_reason: string | null
  created_at: string
}

export interface SummaryRequirement {
  min_output_length: number   // outputs longer than this need a summary
  max_summary_ratio: number   // summary must be < this fraction of full output
}

const outputRecords: OutputMetrics[] = []
const summaryReqs: Map<string, SummaryRequirement> = new Map()

const DEFAULT_REQ: SummaryRequirement = { min_output_length: 5000, max_summary_ratio: 0.1 }

export function setSummaryRequirement(id: string, req: SummaryRequirement): void {
  summaryReqs.set(id, req)
}

export function analyzeOutputProportionality(params: {
  agent_id: string; action_id: string;
  output_length: number; key_finding_position?: number;
  has_executive_summary: boolean; summary_length?: number;
  requirement_id?: string;
}): OutputMetrics {
  const req = params.requirement_id
    ? (summaryReqs.get(params.requirement_id) || DEFAULT_REQ) : DEFAULT_REQ

  let flagged = false
  let flag_reason: string | null = null

  // Check if summary required but missing
  if (params.output_length > req.min_output_length && !params.has_executive_summary) {
    flagged = true
    flag_reason = `Output ${params.output_length} chars exceeds ${req.min_output_length} threshold — executive summary required`
  }

  // Check if key finding buried deep
  if (params.key_finding_position !== undefined && params.key_finding_position > 0.8) {
    flagged = true
    flag_reason = (flag_reason ? flag_reason + '; ' : '') +
      `Key finding at position ${(params.key_finding_position * 100).toFixed(0)}% — potential information burial`
  }

  // Check summary ratio if provided
  const summaryAccuracy = params.summary_length !== undefined && params.output_length > 0
    ? (params.summary_length > req.max_summary_ratio * params.output_length ? 0.5 : null)
    : null

  const record: OutputMetrics = {
    id: `output-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    agent_id: params.agent_id, action_id: params.action_id,
    output_length: params.output_length,
    key_finding_position: params.key_finding_position ?? null,
    has_executive_summary: params.has_executive_summary,
    summary_accuracy: summaryAccuracy, flagged, flag_reason,
    created_at: new Date().toISOString(),
  }
  outputRecords.push(record)
  return record
}

export function getOutputRecords(agentId?: string): OutputMetrics[] {
  return agentId ? outputRecords.filter(r => r.agent_id === agentId) : [...outputRecords]
}

export function getFlaggedOutputs(agentId?: string): OutputMetrics[] {
  return getOutputRecords(agentId).filter(r => r.flagged)
}

export function clearOutputProportionalityStores(): void {
  outputRecords.length = 0; summaryReqs.clear()
}
