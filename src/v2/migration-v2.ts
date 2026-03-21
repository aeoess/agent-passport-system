/**
 * APS v2 Fork-and-Sunset Migration
 * State freeze → fork → handover → reputation inheritance → sunset
 * No agent ever expands its own permissions. System evolves through controlled reincarnation.
 */

import { v4 as uuidv4 } from 'uuid'
import { signObject, hashObject } from './bridge.js'
import type {
  PolicyContext, ReputationInheritance, AssuranceClass,
} from './types.js'
import type { MigrationRequest, MigrationRecord } from './types.js'

const requestStore: Map<string, MigrationRequest> = new Map()
const migrationStore: Map<string, MigrationRecord> = new Map()

export function getV2MigrationRequest(id: string) { return requestStore.get(id) }
export function getV2MigrationRecord(id: string) { return migrationStore.get(id) }
export function getV2MigrationsForAgent(agentId: string) {
  return Array.from(migrationStore.values()).filter(m =>
    m.source_agent === agentId || m.target_agent === agentId
  )
}
export function getV2ActiveProbations() {
  return Array.from(migrationStore.values()).filter(m => m.probation_active)
}

// ── Request Migration ──

export function requestV2Migration(params: {
  source_agent: string
  source_delegation: string
  limitation: string
  requested_scope_change: string
  justification: string
  agent_private_key: string
  policy_context: PolicyContext
}): MigrationRequest {
  if (!params.limitation?.trim()) throw new Error('Limitation description required')
  if (!params.justification?.trim()) throw new Error('Justification required')
  const data = {
    id: uuidv4(), source_agent: params.source_agent,
    source_delegation: params.source_delegation,
    limitation: params.limitation, requested_scope_change: params.requested_scope_change,
    justification: params.justification, policy_context: params.policy_context,
    status: 'pending' as const,
    approver_response: null, approver_signature: null,
    created_at: new Date().toISOString(),
  }
  const sig = signObject(data as Record<string, unknown>, params.agent_private_key)
  const req: MigrationRequest = { ...data, agent_signature: sig }
  requestStore.set(req.id, req)
  return req
}

// ── Approve/Deny ──

export function approveV2Migration(params: {
  request_id: string; approver: string; approved: boolean
  response: string; approver_private_key: string
}): MigrationRequest {
  const req = requestStore.get(params.request_id)
  if (!req) throw new Error(`Request ${params.request_id} not found`)
  if (req.status !== 'pending') throw new Error(`Already ${req.status}`)
  const respData = {
    request_id: params.request_id, approved: params.approved,
    response: params.response, responded_at: new Date().toISOString(),
  }
  const sig = signObject(respData as Record<string, unknown>, params.approver_private_key)
  const updated: MigrationRequest = {
    ...req, status: params.approved ? 'approved' : 'denied',
    approver_response: params.response, approver_signature: sig,
  }
  requestStore.set(updated.id, updated)
  return updated
}

// ── Execute Migration ──

function parseDays(d: string): number {
  const m = d.match(/P(\d+)D/i); return m ? parseInt(m[1]) : 30
}

export function executeV2Migration(params: {
  request_id: string
  target_agent: string
  target_delegation: string
  state_data: string
  reputation_inheritance: ReputationInheritance
  migration_factor?: number
  probation_duration?: string
  approver: string
  approver_private_key: string
  source_private_key: string
  target_private_key: string
  policy_context: PolicyContext
}): MigrationRecord {
  const req = requestStore.get(params.request_id)
  if (!req) throw new Error(`Request ${params.request_id} not found`)
  if (req.status !== 'approved') throw new Error('Must be approved first')
  if (!params.state_data) throw new Error('State data required')
  const factor = params.migration_factor ?? 0.75
  if (factor < 0 || factor > 1) throw new Error('Migration factor must be 0-1')
  const probDur = params.probation_duration || 'P30D'
  const now = new Date()
  const probEnds = new Date(now)
  probEnds.setDate(probEnds.getDate() + parseDays(probDur))

  const stateHash = hashObject({ state: params.state_data } as Record<string, unknown>)
  const data: Record<string, unknown> = {
    id: uuidv4(), source_agent: req.source_agent,
    source_delegation: req.source_delegation,
    target_agent: params.target_agent, target_delegation: params.target_delegation,
    state_hash: stateHash, state_size: Buffer.byteLength(params.state_data, 'utf-8'),
    reputation_inheritance: params.reputation_inheritance,
    migration_factor: factor, probation_duration: probDur,
    probation_ends_at: probEnds.toISOString(), probation_active: true,
    justification: req.justification, request_ref: req.id,
    approver: params.approver, policy_context: params.policy_context,
    assurance_class: 'evidentially_auditable',
    created_at: now.toISOString(), status: 'active',
  }
  const approverSig = signObject(data, params.approver_private_key)
  const sourceSig = signObject(data, params.source_private_key)
  const targetSig = signObject(data, params.target_private_key)
  const record: MigrationRecord = {
    ...data, approver_signature: approverSig,
    source_signature: sourceSig, target_signature: targetSig,
  } as MigrationRecord
  migrationStore.set(record.id, record)
  return record
}

// ── Probation & Reputation ──

export function isV2InProbation(agentId: string): boolean {
  return getV2MigrationsForAgent(agentId).some(
    m => m.target_agent === agentId && m.probation_active
  )
}

export function computeV2MigrationDiscount(rawRep: number, agentId: string): number {
  const asTarget = getV2MigrationsForAgent(agentId)
    .filter(m => m.target_agent === agentId)
  if (asTarget.length === 0) return rawRep
  const latest = asTarget.sort((a, b) =>
    new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  )[0]
  return rawRep * latest.migration_factor
}

export function traceV2MigrationLineage(agentId: string): MigrationRecord[] {
  const lineage: MigrationRecord[] = []
  let current = agentId
  while (true) {
    const asTarget = Array.from(migrationStore.values()).find(m => m.target_agent === current)
    if (!asTarget) break
    lineage.unshift(asTarget)
    current = asTarget.source_agent
  }
  return lineage
}

export function rollbackV2Migration(migrationId: string, reason: string): MigrationRecord {
  const r = migrationStore.get(migrationId)
  if (!r) throw new Error(`Migration ${migrationId} not found`)
  if (!r.probation_active) throw new Error('Can only rollback during probation')
  const updated = { ...r, status: 'rolled_back' as const, probation_active: false }
  migrationStore.set(migrationId, updated)
  return updated
}

export function processV2CompletedProbations(): string[] {
  const now = new Date()
  const completed: string[] = []
  for (const [id, r] of migrationStore) {
    if (r.probation_active && now > new Date(r.probation_ends_at)) {
      migrationStore.set(id, { ...r, probation_active: false, status: 'probation_complete' as const })
      completed.push(id)
    }
  }
  return completed
}

export function clearV2MigrationStores(): void {
  requestStore.clear()
  migrationStore.clear()
}
