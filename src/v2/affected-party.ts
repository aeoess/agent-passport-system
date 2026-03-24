// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS v2 Affected-Party Standing (Section 9.10)
 *
 * Agent actions affect people who are not parties to any delegation.
 * Content moderation affects users. Hiring agents affect candidates.
 * This module gives non-parties voice through complaint, challenge,
 * and appeal mechanisms. Voice, not veto.
 */

export type ComplaintStatus = 'filed' | 'acknowledged' | 'investigating' | 'resolved' | 'dismissed'
export type ChallengeType = 'action_challenge' | 'scope_challenge' | 'values_challenge' | 'outcome_challenge'

export interface AffectedParty {
  id: string
  name: string
  relationship: string      // how they're affected: 'user', 'candidate', 'customer', 'bystander'
  registered_at: string
}

export interface ComplaintEvent {
  id: string
  complainant_id: string    // affected party
  agent_id: string          // agent whose action is complained about
  action_id: string
  complaint_type: ChallengeType
  description: string
  status: ComplaintStatus
  resolution: string | null
  resolved_by: string | null
  created_at: string
}

export interface AppealPathway {
  id: string
  complaint_id: string
  appeal_reason: string
  appeal_to: string          // review authority
  status: 'filed' | 'under_review' | 'upheld' | 'overturned'
  outcome: string | null
  created_at: string
}

const parties: Map<string, AffectedParty> = new Map()
const complaints: Map<string, ComplaintEvent> = new Map()
const appeals: Map<string, AppealPathway> = new Map()

export function registerAffectedParty(name: string, relationship: string): AffectedParty {
  const p: AffectedParty = {
    id: `party-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    name, relationship, registered_at: new Date().toISOString(),
  }
  parties.set(p.id, p)
  return p
}

export function fileComplaint(params: {
  complainant_id: string; agent_id: string; action_id: string;
  complaint_type: ChallengeType; description: string;
}): ComplaintEvent {
  if (!parties.has(params.complainant_id)) throw new Error('Complainant must be registered affected party')
  const c: ComplaintEvent = {
    id: `complaint-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    complainant_id: params.complainant_id, agent_id: params.agent_id,
    action_id: params.action_id, complaint_type: params.complaint_type,
    description: params.description, status: 'filed',
    resolution: null, resolved_by: null,
    created_at: new Date().toISOString(),
  }
  complaints.set(c.id, c)
  return c
}

export function resolveComplaint(complaintId: string, resolverId: string, resolution: string, dismiss?: boolean): ComplaintEvent {
  const c = complaints.get(complaintId)
  if (!c) throw new Error(`Complaint ${complaintId} not found`)
  c.status = dismiss ? 'dismissed' : 'resolved'
  c.resolution = resolution
  c.resolved_by = resolverId
  return c
}

export function fileAppeal(complaintId: string, reason: string, appealTo: string): AppealPathway {
  const c = complaints.get(complaintId)
  if (!c) throw new Error(`Complaint ${complaintId} not found`)
  if (c.status !== 'resolved' && c.status !== 'dismissed') throw new Error('Can only appeal resolved/dismissed complaints')
  const a: AppealPathway = {
    id: `appeal-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    complaint_id: complaintId, appeal_reason: reason,
    appeal_to: appealTo, status: 'filed', outcome: null,
    created_at: new Date().toISOString(),
  }
  appeals.set(a.id, a)
  return a
}

export function resolveAppeal(appealId: string, outcome: string, upheld: boolean): AppealPathway {
  const a = appeals.get(appealId)
  if (!a) throw new Error(`Appeal ${appealId} not found`)
  a.status = upheld ? 'upheld' : 'overturned'
  a.outcome = outcome
  return a
}

export function getComplaints(agentId?: string): ComplaintEvent[] {
  const all = [...complaints.values()]
  return agentId ? all.filter(c => c.agent_id === agentId) : all
}

export function getAppeals(complaintId?: string): AppealPathway[] {
  const all = [...appeals.values()]
  return complaintId ? all.filter(a => a.complaint_id === complaintId) : all
}

export function getAffectedParty(id: string): AffectedParty | undefined { return parties.get(id) }

export function clearAffectedPartyStores(): void {
  parties.clear(); complaints.clear(); appeals.clear()
}
