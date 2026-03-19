// Bounded Escalation — Module 27 (Fourth Attenuation Invariant)
// Exception authority is pre-committed, bounded, temporary, challengeable.
// Escalation grants are delegations — subject to monotonic narrowing.
// v1: human_authorized only, tentative actions only, single active, hard TTL.

import { v4 as uuidv4 } from 'uuid'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import { scopeAuthorizes } from './delegation.js'

// ══════════════════════════════════════
// TYPES
// ══════════════════════════════════════

export type EscalationTriggerType =
  | 'human_authorized'
  | 'multi_witness'

export type ActionClass = 'tentative' | 'compensable' | 'irreversible'

export interface EscalationGrant {
  grantId: string
  delegationId: string
  grantedTo: string
  grantedBy: string
  ceiling: {
    scope: string[]
    maxSpend: number
    maxDurationMs: number
  }
  allowedTriggers: EscalationTriggerType[]
  allowedActionClasses: ActionClass[]
  createdAt: string
  expiresAt: string
  signature: string
}

export interface EscalationRequest {
  requestId: string
  grantId: string
  agentPublicKey: string
  trigger: {
    type: EscalationTriggerType
    evidence: string
    humanApprovalSignature?: string
  }
  requestedAt: string
  signature: string
}

export interface ActiveEscalation {
  escalationId: string
  grantId: string
  requestId: string
  agentPublicKey: string
  effectiveScope: string[]
  effectiveSpendLimit: number
  activatedAt: string
  expiresAt: string
  status: 'active' | 'expired' | 'revoked'
  provisionalReceipts: string[]
  spentDuringEscalation: number
  gatewaySignature: string
}

export interface EscalationVerification {
  valid: boolean
  errors: string[]
  grantValid: boolean
  ceilingWithinScope: boolean
  triggerAccepted: boolean
  temporalValid: boolean
}

// ══════════════════════════════════════
// CREATE ESCALATION GRANT
// ══════════════════════════════════════

export function createEscalationGrant(opts: {
  delegationId: string
  grantedTo: string
  grantedBy: string
  granterPrivateKey: string
  ceiling: EscalationGrant['ceiling']
  allowedTriggers?: EscalationTriggerType[]
  allowedActionClasses?: ActionClass[]
  expiresAt: string
}): EscalationGrant {
  const {
    delegationId, grantedTo, grantedBy, granterPrivateKey,
    ceiling, allowedTriggers, allowedActionClasses, expiresAt
  } = opts
  const now = new Date().toISOString()
  const grantId = 'esc_' + uuidv4().slice(0, 12)

  const signable = canonicalize({
    grantId, delegationId, grantedTo, grantedBy,
    ceiling, allowedTriggers: allowedTriggers ?? ['human_authorized'],
    allowedActionClasses: allowedActionClasses ?? ['tentative'],
    createdAt: now, expiresAt,
  })
  const signature = sign(signable, granterPrivateKey)

  return {
    grantId, delegationId, grantedTo, grantedBy,
    ceiling,
    allowedTriggers: allowedTriggers ?? ['human_authorized'],
    allowedActionClasses: allowedActionClasses ?? ['tentative'],
    createdAt: now, expiresAt, signature,
  }
}

// ══════════════════════════════════════
// VERIFY ESCALATION GRANT
// ══════════════════════════════════════

export function verifyEscalationGrant(
  grant: EscalationGrant,
  granterScope: string[]
): EscalationVerification {
  const errors: string[] = []

  // Verify signature
  let grantValid = false
  try {
    const signable = canonicalize({
      grantId: grant.grantId, delegationId: grant.delegationId,
      grantedTo: grant.grantedTo, grantedBy: grant.grantedBy,
      ceiling: grant.ceiling, allowedTriggers: grant.allowedTriggers,
      allowedActionClasses: grant.allowedActionClasses,
      createdAt: grant.createdAt, expiresAt: grant.expiresAt,
    })
    grantValid = verify(signable, grant.signature, grant.grantedBy)
  } catch { grantValid = false }
  if (!grantValid) errors.push('Invalid grant signature')

  // Verify ceiling within granter's scope (monotonic narrowing)
  let ceilingWithinScope = true
  for (const s of grant.ceiling.scope) {
    if (!scopeAuthorizes(granterScope, s)) {
      ceilingWithinScope = false
      errors.push(`Ceiling scope "${s}" exceeds granter's scope`)
    }
  }

  // Verify temporal validity
  const now = Date.now()
  const temporalValid = now < new Date(grant.expiresAt).getTime()
  if (!temporalValid) errors.push('Grant has expired')

  // Trigger validation
  const triggerAccepted = grant.allowedTriggers.length > 0
  if (!triggerAccepted) errors.push('No triggers defined')

  return {
    valid: grantValid && ceilingWithinScope && temporalValid && triggerAccepted,
    errors, grantValid, ceilingWithinScope, triggerAccepted, temporalValid,
  }
}

// ══════════════════════════════════════
// REQUEST ESCALATION
// ══════════════════════════════════════

export function requestEscalation(opts: {
  grant: EscalationGrant
  agentPrivateKey: string
  agentPublicKey: string
  trigger: EscalationRequest['trigger']
}): EscalationRequest {
  const { grant, agentPrivateKey, agentPublicKey, trigger } = opts
  const now = new Date().toISOString()
  const requestId = 'escreq_' + uuidv4().slice(0, 12)

  if (!grant.allowedTriggers.includes(trigger.type)) {
    throw new Error(`Trigger type "${trigger.type}" not allowed by this grant`)
  }

  if (grant.grantedTo !== agentPublicKey) {
    throw new Error('Agent is not the grantee of this escalation grant')
  }

  const signable = canonicalize({
    requestId, grantId: grant.grantId, agentPublicKey,
    trigger, requestedAt: now,
  })
  const signature = sign(signable, agentPrivateKey)

  return { requestId, grantId: grant.grantId, agentPublicKey, trigger, requestedAt: now, signature }
}

// ══════════════════════════════════════
// ACTIVATE ESCALATION (gateway validates and activates)
// ══════════════════════════════════════

export function activateEscalation(opts: {
  grant: EscalationGrant
  request: EscalationRequest
  gatewayPrivateKey: string
}): ActiveEscalation {
  const { grant, request, gatewayPrivateKey } = opts
  const now = new Date().toISOString()
  const escalationId = 'active_esc_' + uuidv4().slice(0, 12)

  // Validate request matches grant
  if (request.grantId !== grant.grantId) {
    throw new Error('Request does not reference this grant')
  }
  if (request.agentPublicKey !== grant.grantedTo) {
    throw new Error('Requesting agent is not the grantee')
  }

  // Validate grant not expired
  if (Date.now() >= new Date(grant.expiresAt).getTime()) {
    throw new Error('Escalation grant has expired')
  }

  // Validate trigger type
  if (!grant.allowedTriggers.includes(request.trigger.type)) {
    throw new Error(`Trigger "${request.trigger.type}" not allowed`)
  }

  // For human_authorized, verify the human signature exists
  if (request.trigger.type === 'human_authorized' && !request.trigger.humanApprovalSignature) {
    throw new Error('human_authorized trigger requires humanApprovalSignature')
  }

  const expiresAt = new Date(Date.now() + grant.ceiling.maxDurationMs).toISOString()

  const signable = canonicalize({
    escalationId, grantId: grant.grantId, requestId: request.requestId,
    agentPublicKey: request.agentPublicKey,
    effectiveScope: grant.ceiling.scope,
    effectiveSpendLimit: grant.ceiling.maxSpend,
    activatedAt: now, expiresAt,
  })
  const gatewaySignature = sign(signable, gatewayPrivateKey)

  return {
    escalationId, grantId: grant.grantId, requestId: request.requestId,
    agentPublicKey: request.agentPublicKey,
    effectiveScope: grant.ceiling.scope,
    effectiveSpendLimit: grant.ceiling.maxSpend,
    activatedAt: now, expiresAt, status: 'active',
    provisionalReceipts: [], spentDuringEscalation: 0,
    gatewaySignature,
  }
}

// ══════════════════════════════════════
// CHECK ESCALATED ACTION
// ══════════════════════════════════════

export function checkEscalatedAction(opts: {
  escalation: ActiveEscalation
  grant: EscalationGrant
  action: string
  actionClass: ActionClass
  spend?: number
}): { permitted: boolean; errors: string[]; effectClass: ActionClass } {
  const { escalation, grant, action, actionClass, spend } = opts
  const errors: string[] = []

  // Check escalation is active
  if (escalation.status !== 'active') {
    errors.push(`Escalation is ${escalation.status}, not active`)
  }

  // Check not expired
  if (Date.now() >= new Date(escalation.expiresAt).getTime()) {
    errors.push('Escalation has expired')
  }

  // Check action class is permitted
  if (!grant.allowedActionClasses.includes(actionClass)) {
    errors.push(`Action class "${actionClass}" not permitted by grant (allowed: ${grant.allowedActionClasses.join(', ')})`)
  }

  // Check scope coverage
  if (!scopeAuthorizes(escalation.effectiveScope, action)) {
    errors.push(`Action "${action}" not within escalation scope`)
  }

  // Check spend
  if (spend !== undefined && spend > 0) {
    const remaining = escalation.effectiveSpendLimit - escalation.spentDuringEscalation
    if (spend > remaining) {
      errors.push(`Spend $${spend} exceeds remaining escalation budget $${remaining}`)
    }
  }

  return { permitted: errors.length === 0, errors, effectClass: actionClass }
}

// ══════════════════════════════════════
// REVOKE ESCALATION
// ══════════════════════════════════════

export function revokeEscalation(escalation: ActiveEscalation): ActiveEscalation {
  return { ...escalation, status: 'revoked' }
}

// ══════════════════════════════════════
// CHECK IF ACTIVE (utility)
// ══════════════════════════════════════

export function isEscalationActive(escalation: ActiveEscalation): boolean {
  if (escalation.status !== 'active') return false
  if (Date.now() >= new Date(escalation.expiresAt).getTime()) return false
  return true
}
