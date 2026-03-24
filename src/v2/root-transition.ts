// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS v2 Root Authority Transition
 *
 * Every governance system has a pre-governance founding period where
 * decisions are made without the legitimacy framework. The question
 * isn't who holds root — it's whether root is designed to be surrendered.
 *
 * This module provides mechanisms for transitioning from founding
 * authority to democratic governance through multi-signer plans,
 * phase transitions, and root sunset.
 */

import type {
  AuthorityTransitionPlan, GovernancePhase,
  ConditionSet,
} from './types.js'
import { evaluateConditions } from './bridge.js'

// ── Stores ──
const transitionPlans: Map<string, AuthorityTransitionPlan> = new Map()
const phaseHistory: Array<{ phase: GovernancePhase; transitioned_at: string; plan_id: string }> = []
let currentPhase: GovernancePhase = 'founding'

// ── Phase Management ──

export function getCurrentPhase(): GovernancePhase {
  return currentPhase
}

export function getPhaseHistory() {
  return [...phaseHistory]
}

// ── Create Transition Plan ──

export function createTransitionPlan(params: {
  target_phase: GovernancePhase;
  conditions: ConditionSet;
  required_signers: string[];
  minimum_agent_count: number;
  transition_justification: string;
  sunset_root_after_transition: boolean;
}): AuthorityTransitionPlan {
  // Phase must advance, not regress
  const order: GovernancePhase[] = ['founding', 'operational', 'transitional', 'democratic']
  const currentIdx = order.indexOf(currentPhase)
  const targetIdx = order.indexOf(params.target_phase)
  if (targetIdx <= currentIdx) {
    throw new Error(`Cannot transition from ${currentPhase} to ${params.target_phase} — phases only advance`)
  }

  const plan: AuthorityTransitionPlan = {
    id: `transition-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    current_phase: currentPhase,
    target_phase: params.target_phase,
    conditions: params.conditions,
    required_signers: params.required_signers,
    minimum_agent_count: params.minimum_agent_count,
    transition_justification: params.transition_justification,
    sunset_root_after_transition: params.sunset_root_after_transition,
    created_at: new Date().toISOString(),
    status: 'proposed',
  }
  transitionPlans.set(plan.id, plan)
  return plan
}

// ── Approve Transition ──

export function approveTransition(planId: string, signerId: string): AuthorityTransitionPlan {
  const plan = transitionPlans.get(planId)
  if (!plan) throw new Error(`Plan ${planId} not found`)
  if (plan.status !== 'proposed') throw new Error(`Plan status is ${plan.status}, not proposed`)
  if (!plan.required_signers.includes(signerId)) {
    throw new Error(`${signerId} is not a required signer for this plan`)
  }
  // Track approvals via a side store
  const approvals = getApprovals(planId)
  if (approvals.includes(signerId)) throw new Error(`${signerId} already approved`)
  approvals.push(signerId)
  setApprovals(planId, approvals)

  // Check if all required signers have approved
  if (approvals.length >= plan.required_signers.length) {
    plan.status = 'approved'
  }
  return plan
}

// Side store for tracking approvals (not in the plan object to keep it serializable)
const approvalTracker: Map<string, string[]> = new Map()
function getApprovals(planId: string): string[] { return approvalTracker.get(planId) || [] }
function setApprovals(planId: string, signers: string[]) { approvalTracker.set(planId, signers) }

// ── Execute Transition ──

export function executeTransition(planId: string, context: Record<string, string | number | boolean>): AuthorityTransitionPlan {
  const plan = transitionPlans.get(planId)
  if (!plan) throw new Error(`Plan ${planId} not found`)
  if (plan.status !== 'approved') throw new Error(`Plan must be approved before execution (current: ${plan.status})`)

  // Evaluate conditions
  if (plan.conditions.all_of || plan.conditions.any_of) {
    const conditionsMet = evaluateConditions(plan.conditions, context)
    if (!conditionsMet) throw new Error('Transition conditions not met')
  }

  // Execute
  plan.status = 'executing'
  currentPhase = plan.target_phase
  plan.status = 'completed'

  phaseHistory.push({
    phase: plan.target_phase,
    transitioned_at: new Date().toISOString(),
    plan_id: planId,
  })

  return plan
}

// ── Abort Transition ──

export function abortTransition(planId: string, reason: string): AuthorityTransitionPlan {
  const plan = transitionPlans.get(planId)
  if (!plan) throw new Error(`Plan ${planId} not found`)
  if (plan.status === 'completed') throw new Error('Cannot abort completed transition')
  plan.status = 'aborted'
  return plan
}

// ── Query ──

export function getTransitionPlan(planId: string): AuthorityTransitionPlan | undefined {
  return transitionPlans.get(planId)
}

export function getAllTransitionPlans(): AuthorityTransitionPlan[] {
  return [...transitionPlans.values()]
}

export function getApprovalStatus(planId: string): { required: string[]; approved: string[]; remaining: string[] } {
  const plan = transitionPlans.get(planId)
  if (!plan) throw new Error(`Plan ${planId} not found`)
  const approved = getApprovals(planId)
  const remaining = plan.required_signers.filter(s => !approved.includes(s))
  return { required: plan.required_signers, approved, remaining }
}

export function clearRootTransitionStores(): void {
  transitionPlans.clear()
  approvalTracker.clear()
  phaseHistory.length = 0
  currentPhase = 'founding'
}
