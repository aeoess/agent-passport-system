// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS v2 HumanEscalationFlag — per-action-class owner confirmation.
 *
 * Tactical circuit breaker for high-stakes action classes where the
 * provisional/binding distinction isn't enough. The owner (delegator)
 * must sign a confirmation before the action can execute.
 *
 * Default flagged action classes (documented, not enforced here):
 *   org_creation, third_party_attribution, spend_above_threshold,
 *   charter_amendment, delegation_scope_expansion
 *
 * Additive to the existing delegation verify chain — when a scope has
 * no escalation_requirements, behavior is unchanged.
 */

import { v4 as uuidv4 } from 'uuid'
import { sha256, signObject, verifyObject } from './bridge.js'
import { validateV2Delegation } from './delegation-v2.js'
import type {
  V2Delegation, EscalationRequirement, ConfirmationRequest,
  OwnerConfirmation, ConfirmationScope,
} from './types.js'

// ── Action shape accepted by escalation checks ──
export interface EscalationAction {
  action_class: string
  action_details: Record<string, unknown>
  session_id?: string | null
}

export interface EscalationCheck {
  required: boolean
  reason?: string
  requirement?: EscalationRequirement
}

// ── Hash the content that the confirmation binds to ──
export function hashActionDetails(details: Record<string, unknown>): string {
  return sha256(JSON.stringify(details))
}

function findRequirement(
  delegation: V2Delegation,
  action_class: string,
): EscalationRequirement | undefined {
  const reqs = delegation.scope.escalation_requirements
  if (!reqs) return undefined
  return reqs.find(r => r.action_class === action_class && r.requires_owner_confirmation)
}

// ═══════════════════════════════════════════════
// CHECK ESCALATION REQUIRED
// ═══════════════════════════════════════════════

export function checkEscalationRequired(
  delegation: V2Delegation,
  action: EscalationAction,
): EscalationCheck {
  const requirement = findRequirement(delegation, action.action_class)
  if (!requirement) return { required: false }
  return {
    required: true,
    requirement,
    reason: `action_requires_confirmation: ${action.action_class}`,
  }
}

// ═══════════════════════════════════════════════
// REQUEST OWNER CONFIRMATION
// ═══════════════════════════════════════════════

export function requestOwnerConfirmation(
  delegation: V2Delegation,
  action: EscalationAction,
): ConfirmationRequest {
  const requirement = findRequirement(delegation, action.action_class)
  if (!requirement) {
    throw new Error(
      `No escalation requirement for action_class="${action.action_class}" on delegation ${delegation.id}`,
    )
  }
  if (requirement.confirmation_scope === 'per_session' && !action.session_id) {
    throw new Error('per_session confirmation requires action.session_id')
  }
  return {
    id: uuidv4(),
    delegation_id: delegation.id,
    action_class: action.action_class,
    action_details_hash: hashActionDetails(action.action_details),
    confirmation_scope: requirement.confirmation_scope,
    session_id: action.session_id ?? null,
    confirmation_ttl_ms: requirement.confirmation_ttl_ms,
    created_at: new Date().toISOString(),
  }
}

// ═══════════════════════════════════════════════
// RECORD OWNER CONFIRMATION (owner signs)
// ═══════════════════════════════════════════════

export interface RecordConfirmationParams {
  request: ConfirmationRequest
  delegation: V2Delegation
  owner_private_key: string
}

export function recordOwnerConfirmation(params: RecordConfirmationParams): OwnerConfirmation {
  const { request, delegation, owner_private_key } = params
  if (request.delegation_id !== delegation.id) {
    throw new Error('ConfirmationRequest delegation_id does not match delegation.id')
  }
  const confirmed_at = new Date()
  const expires_at = new Date(confirmed_at.getTime() + request.confirmation_ttl_ms)
  const data: Record<string, unknown> = {
    id: uuidv4(),
    request_id: request.id,
    delegation_id: request.delegation_id,
    action_class: request.action_class,
    action_details_hash: request.action_details_hash,
    confirmation_scope: request.confirmation_scope,
    session_id: request.session_id,
    confirmed_by: delegation.delegator,
    confirmed_at: confirmed_at.toISOString(),
    expires_at: expires_at.toISOString(),
  }
  const signature = signObject(data, owner_private_key)
  return { ...data, signature } as OwnerConfirmation
}

// ═══════════════════════════════════════════════
// VALIDITY / VERIFICATION
// ═══════════════════════════════════════════════

export function isConfirmationValid(
  confirmation: OwnerConfirmation,
  now: Date = new Date(),
): boolean {
  return now.getTime() <= new Date(confirmation.expires_at).getTime()
}

export interface ConfirmationVerdict {
  valid: boolean
  reason?: string
}

function matchesAction(
  confirmation: OwnerConfirmation,
  action: EscalationAction,
  scope: ConfirmationScope,
): ConfirmationVerdict {
  if (confirmation.action_class !== action.action_class) {
    return { valid: false, reason: 'action_class mismatch' }
  }
  if (scope === 'per_action') {
    const expected = hashActionDetails(action.action_details)
    if (confirmation.action_details_hash !== expected) {
      return { valid: false, reason: 'per_action details hash mismatch' }
    }
  } else if (scope === 'per_session') {
    if (!action.session_id || confirmation.session_id !== action.session_id) {
      return { valid: false, reason: 'per_session session_id mismatch' }
    }
  }
  // time_window: any action of the same class within ttl
  return { valid: true }
}

export function verifyOwnerConfirmation(
  confirmation: OwnerConfirmation,
  action: EscalationAction,
  delegation: V2Delegation,
  now: Date = new Date(),
): ConfirmationVerdict {
  if (confirmation.delegation_id !== delegation.id) {
    return { valid: false, reason: 'delegation_id mismatch' }
  }
  if (confirmation.confirmed_by !== delegation.delegator) {
    return { valid: false, reason: 'confirmed_by is not the delegator' }
  }
  if (!isConfirmationValid(confirmation, now)) {
    return { valid: false, reason: 'confirmation expired' }
  }
  const requirement = findRequirement(delegation, action.action_class)
  if (!requirement) {
    return { valid: false, reason: 'no matching escalation requirement on delegation' }
  }
  if (confirmation.confirmation_scope !== requirement.confirmation_scope) {
    return { valid: false, reason: 'confirmation_scope mismatch' }
  }
  const match = matchesAction(confirmation, action, requirement.confirmation_scope)
  if (!match.valid) return match
  // Verify signature
  const signable = { ...confirmation } as Record<string, unknown>
  delete signable.signature
  if (!verifyObject(signable, confirmation.signature, delegation.delegator)) {
    return { valid: false, reason: 'signature verification failed' }
  }
  return { valid: true }
}

// ═══════════════════════════════════════════════
// VERIFY CHAIN — delegation + escalation composite
// ═══════════════════════════════════════════════

export interface VerifyForActionResult {
  valid: boolean
  reason?: string
  escalation_required?: boolean
}

export function verifyV2DelegationForAction(
  delegation: V2Delegation,
  action: EscalationAction,
  confirmations: OwnerConfirmation[] = [],
  now: Date = new Date(),
): VerifyForActionResult {
  const base = validateV2Delegation(delegation, now)
  if (!base.valid) return { valid: false, reason: base.reason }

  const esc = checkEscalationRequired(delegation, action)
  if (!esc.required) return { valid: true }

  for (const conf of confirmations) {
    const v = verifyOwnerConfirmation(conf, action, delegation, now)
    if (v.valid) return { valid: true, escalation_required: true }
  }
  return {
    valid: false,
    escalation_required: true,
    reason: 'action_requires_confirmation',
  }
}

// ═══════════════════════════════════════════════
// DEFAULT FLAGGED ACTION CLASSES (documentation only)
// ═══════════════════════════════════════════════

export const DEFAULT_FLAGGED_ACTION_CLASSES: readonly string[] = Object.freeze([
  'org_creation',
  'third_party_attribution',
  'spend_above_threshold',
  'charter_amendment',
  'delegation_scope_expansion',
])
