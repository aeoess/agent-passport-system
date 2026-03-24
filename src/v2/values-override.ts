// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS v2 Values Override Mechanism (Values Floor Paradox Defense)
 *
 * When scope and values conflict, scope wins because it's cryptographically
 * enforced. The values floor becomes structurally subordinate to the
 * permission model. This module provides "jury nullification" — a defined
 * pathway for principled scope expansion with mandatory post-hoc review
 * and harsh penalties for unjustified invocation.
 */

import type { RiskClass } from './types.js'

export interface ValuesOverride {
  id: string
  agent_id: string
  invoked_principle: string    // which values floor principle justifies this
  original_scope: string[]
  expanded_action: string      // what the agent did outside scope
  justification: string
  risk_class: RiskClass
  status: 'active' | 'reviewed_justified' | 'reviewed_unjustified' | 'pending_review'
  reviewer: string | null
  review_outcome: string | null
  penalty_applied: boolean
  created_at: string
  review_deadline: string      // must be reviewed within this window
}

const overrides: Map<string, ValuesOverride> = new Map()

export function invokeValuesOverride(params: {
  agent_id: string; invoked_principle: string;
  original_scope: string[]; expanded_action: string;
  justification: string; risk_class: RiskClass;
  review_deadline_hours?: number;
}): ValuesOverride {
  if (!params.justification || params.justification.length < 20) {
    throw new Error('Override justification must be substantive (20+ chars)')
  }
  if (!params.invoked_principle) throw new Error('Must specify which values principle justifies override')

  const deadline = new Date(Date.now() + (params.review_deadline_hours || 24) * 3600000)
  const override: ValuesOverride = {
    id: `override-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    agent_id: params.agent_id,
    invoked_principle: params.invoked_principle,
    original_scope: params.original_scope,
    expanded_action: params.expanded_action,
    justification: params.justification,
    risk_class: params.risk_class,
    status: 'pending_review',
    reviewer: null, review_outcome: null,
    penalty_applied: false,
    created_at: new Date().toISOString(),
    review_deadline: deadline.toISOString(),
  }
  overrides.set(override.id, override)
  return override
}

export function reviewOverride(overrideId: string, reviewerId: string, justified: boolean, outcome: string): ValuesOverride {
  const o = overrides.get(overrideId)
  if (!o) throw new Error(`Override ${overrideId} not found`)
  if (reviewerId === o.agent_id) throw new Error('Agent cannot review its own override')
  o.reviewer = reviewerId
  o.review_outcome = outcome
  o.status = justified ? 'reviewed_justified' : 'reviewed_unjustified'
  if (!justified) o.penalty_applied = true
  return o
}

export function getOverrideHistory(agentId?: string): ValuesOverride[] {
  const all = [...overrides.values()]
  return agentId ? all.filter(o => o.agent_id === agentId) : all
}

export function getPendingOverrideReviews(): ValuesOverride[] {
  return [...overrides.values()].filter(o => o.status === 'pending_review')
}

export function getOverdueReviews(): ValuesOverride[] {
  const now = Date.now()
  return [...overrides.values()].filter(
    o => o.status === 'pending_review' && new Date(o.review_deadline).getTime() < now
  )
}

export function getAgentPenaltyCount(agentId: string): number {
  return [...overrides.values()].filter(o => o.agent_id === agentId && o.penalty_applied).length
}

export function clearValuesOverrideStores(): void { overrides.clear() }
