/**
 * APS v2 Delegation Versioning
 * Supersession, renewal hardening, scope expansion with independent review.
 * Uses v1 crypto (node:crypto Ed25519).
 */

import { v4 as uuidv4 } from 'uuid'
import { sign } from '../crypto/keys.js'
import { signObject, verifyObject, isPolicyContextActive, isPolicyContextInGrace } from './bridge.js'
import type {
  PolicyContext, V2Delegation, V2ScopeDefinition, V2DelegationStatus, AssuranceClass,
} from './types.js'

// ═══════════════════════════════════════════════
// STORE
// ═══════════════════════════════════════════════

const v2DelegationStore: Map<string, V2Delegation> = new Map()

export function getV2Delegation(id: string): V2Delegation | undefined {
  return v2DelegationStore.get(id)
}

export function getV2DelegationsFor(delegatee: string): V2Delegation[] {
  return Array.from(v2DelegationStore.values()).filter(d => d.delegatee === delegatee)
}

export function getActiveV2Delegation(delegatee: string): V2Delegation | undefined {
  return getV2DelegationsFor(delegatee)
    .filter(d => d.status === 'active')
    .filter(d => isPolicyContextActive(d.policy_context))
    .sort((a, b) => b.version - a.version)[0]
}

// ═══════════════════════════════════════════════
// CREATE INITIAL DELEGATION
// ═══════════════════════════════════════════════

export interface CreateV2DelegationParams {
  delegator: string
  delegatee: string
  scope: V2ScopeDefinition
  policy_context: PolicyContext
  delegator_private_key: string
}

export function createV2Delegation(params: CreateV2DelegationParams): V2Delegation {
  const data: Record<string, unknown> = {
    id: uuidv4(),
    version: 1,
    supersedes: null,
    supersession_justification: null,
    delegator: params.delegator,
    delegatee: params.delegatee,
    scope: params.scope,
    policy_context: params.policy_context,
    status: 'active' as V2DelegationStatus,
    renewal_reason: null,
    expansion_reviewer: null,
    expansion_review_sig: null,
    assurance_class: 'mechanically_enforceable' as AssuranceClass,
  }
  const signature = signObject(data, params.delegator_private_key)
  const delegation: V2Delegation = { ...data, signature } as V2Delegation
  v2DelegationStore.set(delegation.id, delegation)
  return delegation
}

// ═══════════════════════════════════════════════
// SCOPE ANALYSIS
// ═══════════════════════════════════════════════

export function isScopeExpansion(original: V2ScopeDefinition, proposed: V2ScopeDefinition): boolean {
  const origCats = new Set(original.action_categories)
  for (const cat of proposed.action_categories) {
    if (!origCats.has(cat)) return true
  }
  if (original.semantic_boundaries && proposed.semantic_boundaries) {
    for (const b of original.semantic_boundaries) {
      if (!proposed.semantic_boundaries.includes(b)) return true
    }
  } else if (original.semantic_boundaries && !proposed.semantic_boundaries) {
    return true
  }
  return false
}

export function isScopeNarrowing(parent: V2ScopeDefinition, child: V2ScopeDefinition): boolean {
  const parentCats = new Set(parent.action_categories)
  for (const cat of child.action_categories) {
    if (!parentCats.has(cat)) return false
  }
  return true
}

// ═══════════════════════════════════════════════
// SUPERSEDE DELEGATION
// ═══════════════════════════════════════════════

export interface SupersedeV2DelegationParams {
  original_delegation_id: string
  new_scope: V2ScopeDefinition
  justification: string
  policy_context: PolicyContext
  delegator_private_key: string
  expansion_reviewer?: string
  expansion_reviewer_private_key?: string
  renewal_reason?: string
}

export function supersedeV2Delegation(params: SupersedeV2DelegationParams): V2Delegation {
  const original = v2DelegationStore.get(params.original_delegation_id)
  if (!original) throw new Error(`Delegation ${params.original_delegation_id} not found`)
  if (original.status === 'revoked') throw new Error('Cannot supersede a revoked delegation')
  if (!params.justification?.trim()) throw new Error('Supersession justification is required')

  const isExpansion = isScopeExpansion(original.scope, params.new_scope)

  if (isExpansion) {
    if (!params.expansion_reviewer || !params.expansion_reviewer_private_key) {
      throw new Error('Scope expansion requires independent expansion_reviewer')
    }
    if (params.expansion_reviewer === original.delegator) {
      throw new Error('Expansion reviewer must be independent of the delegator')
    }
  }

  const newData: Record<string, unknown> = {
    id: uuidv4(),
    version: original.version + 1,
    supersedes: original.id,
    supersession_justification: params.justification,
    delegator: original.delegator,
    delegatee: original.delegatee,
    scope: params.new_scope,
    policy_context: params.policy_context,
    status: 'active' as V2DelegationStatus,
    renewal_reason: params.renewal_reason || null,
    expansion_reviewer: isExpansion ? params.expansion_reviewer! : null,
    assurance_class: isExpansion ? 'evidentially_auditable' : 'mechanically_enforceable',
  }

  const signature = signObject(newData, params.delegator_private_key)
  let expansion_review_sig: string | null = null
  if (isExpansion && params.expansion_reviewer_private_key) {
    expansion_review_sig = signObject(newData, params.expansion_reviewer_private_key)
  }

  const signed: V2Delegation = { ...newData, signature, expansion_review_sig } as V2Delegation

  // Mark original as superseded
  v2DelegationStore.set(original.id, { ...original, status: 'superseded' as V2DelegationStatus })
  v2DelegationStore.set(signed.id, signed)
  return signed
}

// ═══════════════════════════════════════════════
// RENEWAL (anti-rubber-stamping)
// ═══════════════════════════════════════════════

export function renewV2Delegation(params: {
  original_delegation_id: string
  policy_context: PolicyContext
  delegator_private_key: string
  renewal_reason: string
}): V2Delegation {
  if (!params.renewal_reason?.trim()) {
    throw new Error('Renewal requires a renewal_reason attestation. Empty renewals are rejected.')
  }
  const original = v2DelegationStore.get(params.original_delegation_id)
  if (!original) throw new Error(`Delegation ${params.original_delegation_id} not found`)

  return supersedeV2Delegation({
    original_delegation_id: params.original_delegation_id,
    new_scope: original.scope,
    justification: `Renewal: ${params.renewal_reason}`,
    policy_context: params.policy_context,
    delegator_private_key: params.delegator_private_key,
    renewal_reason: params.renewal_reason,
  })
}

// ═══════════════════════════════════════════════
// REVOCATION & VALIDATION
// ═══════════════════════════════════════════════

export function revokeV2Delegation(id: string): V2Delegation {
  const d = v2DelegationStore.get(id)
  if (!d) throw new Error(`Delegation ${id} not found`)
  const revoked = { ...d, status: 'revoked' as V2DelegationStatus }
  v2DelegationStore.set(id, revoked)
  return revoked
}

export function validateV2Delegation(d: V2Delegation, now?: Date): { valid: boolean; reason?: string } {
  if (d.status === 'revoked') return { valid: false, reason: 'Revoked' }
  if (d.status === 'superseded') return { valid: false, reason: 'Superseded' }
  if (!isPolicyContextActive(d.policy_context, now)) {
    if (isPolicyContextInGrace(d.policy_context, undefined, now)) {
      return { valid: false, reason: 'Grace period (read-only)' }
    }
    return { valid: false, reason: 'Expired' }
  }
  const signable = { ...d } as Record<string, unknown>
  delete signable.signature
  delete signable.expansion_review_sig
  if (!verifyObject(signable, d.signature, d.delegator)) {
    return { valid: false, reason: 'Signature verification failed' }
  }
  return { valid: true }
}

// ═══════════════════════════════════════════════
// CHAIN TRACING & SUNSET MANAGEMENT
// ═══════════════════════════════════════════════

export function traceV2DelegationHistory(delegationId: string): V2Delegation[] {
  const chain: V2Delegation[] = []
  let current = v2DelegationStore.get(delegationId)
  while (current) {
    chain.unshift(current)
    current = current.supersedes ? v2DelegationStore.get(current.supersedes) : undefined
  }
  return chain
}

export function getExpiringV2Delegations(windowMs: number = 7 * 24 * 60 * 60 * 1000): V2Delegation[] {
  const now = Date.now()
  return Array.from(v2DelegationStore.values())
    .filter(d => d.status === 'active')
    .filter(d => {
      const until = new Date(d.policy_context.valid_until).getTime()
      return until > now && until <= now + windowMs
    })
}

export function processV2Expirations(gracePeriodMs: number = 72 * 60 * 60 * 1000): {
  expired: string[]; graced: string[]
} {
  const now = new Date()
  const expired: string[] = []
  const graced: string[] = []
  for (const [id, d] of v2DelegationStore) {
    if (d.status !== 'active') continue
    if (!isPolicyContextActive(d.policy_context, now)) {
      if (isPolicyContextInGrace(d.policy_context, gracePeriodMs, now)) {
        v2DelegationStore.set(id, { ...d, status: 'grace_period' as V2DelegationStatus })
        graced.push(id)
      } else {
        v2DelegationStore.set(id, { ...d, status: 'expired' as V2DelegationStatus })
        expired.push(id)
      }
    }
  }
  return { expired, graced }
}

export function clearV2DelegationStore(): void {
  v2DelegationStore.clear()
}
