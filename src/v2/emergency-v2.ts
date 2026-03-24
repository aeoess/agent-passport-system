// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS v2 Emergency Pathways
 * Pre-authorized emergency protocols defined at delegation time.
 * Agent does NOT decide what's an emergency — delegator defines conditions in advance.
 */

import { v4 as uuidv4 } from 'uuid'
import { signObject } from './bridge.js'
import type {
  PolicyContext, ConditionSet, V2ScopeDefinition, AssuranceClass, ActivationStatus,
} from './types.js'

export interface V2EmergencyPathway {
  id: string
  delegation_ref: string
  trigger_conditions: ConditionSet
  expanded_scope: V2ScopeDefinition
  max_duration: string // ISO 8601 duration
  mandatory_review_deadline: string
  review_authority: string
  description: string
  policy_context: PolicyContext
  delegator_signature: string
  assurance_class: AssuranceClass
}

export interface V2EmergencyActivation {
  id: string
  pathway_id: string
  agent_id: string
  trigger_evidence: string
  activated_at: string
  expires_at: string
  review_deadline: string
  actions_during_emergency: string[]
  status: ActivationStatus
  review_outcome: string | null
  review_signature: string | null
  agent_signature: string
  policy_context: PolicyContext
  assurance_class: AssuranceClass
}

const pathwayStore: Map<string, V2EmergencyPathway> = new Map()
const activationStore: Map<string, V2EmergencyActivation> = new Map()

export function getV2Pathway(id: string) { return pathwayStore.get(id) }
export function getV2PathwaysForDelegation(delRef: string) {
  return Array.from(pathwayStore.values()).filter(p => p.delegation_ref === delRef)
}
export function getV2Activation(id: string) { return activationStore.get(id) }
export function getV2ActiveEmergencies(agentId: string) {
  return Array.from(activationStore.values())
    .filter(a => a.agent_id === agentId && a.status === 'active')
}

export function defineV2EmergencyPathway(params: {
  delegation_ref: string
  trigger_conditions: ConditionSet
  expanded_scope: V2ScopeDefinition
  max_duration: string
  mandatory_review_deadline: string
  review_authority: string
  description: string
  policy_context: PolicyContext
  delegator_private_key: string
}): V2EmergencyPathway {
  if (!params.description?.trim()) throw new Error('Description required')
  const conds = params.trigger_conditions
  if ((!conds.all_of || conds.all_of.length === 0) && (!conds.any_of || conds.any_of.length === 0)) {
    throw new Error('At least one trigger condition required')
  }
  const data: Record<string, unknown> = {
    id: uuidv4(),
    delegation_ref: params.delegation_ref,
    trigger_conditions: params.trigger_conditions,
    expanded_scope: params.expanded_scope,
    max_duration: params.max_duration,
    mandatory_review_deadline: params.mandatory_review_deadline,
    review_authority: params.review_authority,
    description: params.description,
    policy_context: params.policy_context,
    assurance_class: 'mechanically_enforceable',
  }
  const sig = signObject(data, params.delegator_private_key)
  const pathway = { ...data, delegator_signature: sig } as V2EmergencyPathway
  pathwayStore.set(pathway.id, pathway)
  return pathway
}

function addDuration(date: Date, iso: string): Date {
  const r = new Date(date)
  const hm = iso.match(/PT(\d+)([HMS])/i)
  if (hm) {
    const n = parseInt(hm[1])
    if (hm[2].toUpperCase() === 'H') r.setHours(r.getHours() + n)
    else if (hm[2].toUpperCase() === 'M') r.setMinutes(r.getMinutes() + n)
    else r.setSeconds(r.getSeconds() + n)
    return r
  }
  const dm = iso.match(/P(\d+)D/i)
  if (dm) { r.setDate(r.getDate() + parseInt(dm[1])); return r }
  throw new Error(`Invalid duration: ${iso}`)
}

export function activateV2Emergency(params: {
  pathway_id: string
  agent_id: string
  trigger_evidence: string
  agent_private_key: string
  policy_context: PolicyContext
}): V2EmergencyActivation {
  const pw = pathwayStore.get(params.pathway_id)
  if (!pw) throw new Error(`Pathway ${params.pathway_id} not found`)
  if (!params.trigger_evidence?.trim()) throw new Error('Trigger evidence required')
  const existing = Array.from(activationStore.values())
    .find(a => a.pathway_id === params.pathway_id && a.agent_id === params.agent_id && a.status === 'active')
  if (existing) throw new Error('Already active for this pathway')

  const now = new Date()
  const expiresAt = addDuration(now, pw.max_duration)
  const reviewDeadline = addDuration(expiresAt, pw.mandatory_review_deadline)
  const data: Record<string, unknown> = {
    id: uuidv4(), pathway_id: params.pathway_id, agent_id: params.agent_id,
    trigger_evidence: params.trigger_evidence,
    activated_at: now.toISOString(), expires_at: expiresAt.toISOString(),
    review_deadline: reviewDeadline.toISOString(),
    actions_during_emergency: [], status: 'active',
    review_outcome: null, review_signature: null,
    policy_context: params.policy_context, assurance_class: 'evidentially_auditable',
  }
  const sig = signObject(data, params.agent_private_key)
  const activation = { ...data, agent_signature: sig } as V2EmergencyActivation
  activationStore.set(activation.id, activation)
  return activation
}

export function logV2EmergencyAction(activationId: string, actionId: string): void {
  const a = activationStore.get(activationId)
  if (!a) throw new Error(`Activation ${activationId} not found`)
  if (a.status !== 'active') throw new Error('Cannot log for inactive emergency')
  if (new Date() > new Date(a.expires_at)) {
    activationStore.set(activationId, { ...a, status: 'expired' as ActivationStatus })
    throw new Error('Emergency expired')
  }
  activationStore.set(activationId, {
    ...a, actions_during_emergency: [...a.actions_during_emergency, actionId]
  })
}

export function reviewV2Emergency(params: {
  activation_id: string
  reviewer_id: string
  outcome: 'justified' | 'unjustified' | 'ambiguous'
  review_notes: string
  reviewer_private_key: string
}): V2EmergencyActivation {
  const a = activationStore.get(params.activation_id)
  if (!a) throw new Error(`Activation ${params.activation_id} not found`)
  const pw = pathwayStore.get(a.pathway_id)
  if (!pw) throw new Error(`Pathway not found`)
  if (params.reviewer_id !== pw.review_authority) {
    throw new Error('Only designated review authority can review')
  }
  if (a.review_outcome !== null) throw new Error('Already reviewed')

  const statusMap: Record<string, ActivationStatus> = {
    justified: 'reviewed_justified', unjustified: 'reviewed_unjustified', ambiguous: 'reviewed_ambiguous',
  }
  const reviewData = {
    activation_id: params.activation_id, outcome: params.outcome,
    review_notes: params.review_notes, reviewed_at: new Date().toISOString(),
  }
  const sig = signObject(reviewData as Record<string, unknown>, params.reviewer_private_key)
  const updated: V2EmergencyActivation = {
    ...a, status: statusMap[params.outcome],
    review_outcome: `${params.outcome}: ${params.review_notes}`,
    review_signature: sig,
  }
  activationStore.set(updated.id, updated)
  return updated
}

export function getV2OverdueReviews(): V2EmergencyActivation[] {
  const now = new Date()
  return Array.from(activationStore.values()).filter(a =>
    (a.status === 'active' || a.status === 'expired') &&
    a.review_outcome === null && now > new Date(a.review_deadline)
  )
}

export function clearV2EmergencyStores(): void {
  pathwayStore.clear()
  activationStore.clear()
}
