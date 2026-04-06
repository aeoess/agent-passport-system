// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS v2 Bridge — Connects v1 SDK primitives to v2 protocol extensions
 * Uses v1's crypto (node:crypto Ed25519) and canonical serialization.
 */

import crypto from 'node:crypto'
import { v4 as uuidv4 } from 'uuid'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from '../core/canonical.js'

import type { Delegation } from '../types/passport.js'
import type {
  PolicyContext, V2Delegation, V2ScopeDefinition, V2DelegationStatus,
  AssuranceClass, ArtifactProvenance, RiskClass, BehavioralEvidenceMetadata,
  SemanticUncertainty, Condition, ConditionSet,
} from './types.js'
import type { BehavioralAttestationResult } from '../types/attestation.js'
import { validateAttestationResult } from '../core/evaluation-context.js'


// ═══════════════════════════════════════════════
// CRYPTO BRIDGE — v1 sign/verify adapted for v2 object signing
// ═══════════════════════════════════════════════

export function sha256(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex')
}

export function hashObject(obj: Record<string, unknown>): string {
  const canonical = canonicalize(obj)
  return sha256(canonical)
}

export function signObject(obj: Record<string, unknown>, privateKey: string): string {
  const hash = hashObject(obj)
  return sign(hash, privateKey)
}

export function verifyObject(obj: Record<string, unknown>, signature: string, publicKey: string): boolean {
  const hash = hashObject(obj)
  return verify(hash, signature, publicKey)
}


// ═══════════════════════════════════════════════
// POLICY CONTEXT — Universal Invariant
// ═══════════════════════════════════════════════

const DEFAULT_MAX_LIFETIME_MS = 180 * 24 * 60 * 60 * 1000

export function createPolicyContext(params: {
  policy_version: string
  values_floor_version: string
  trust_epoch: number
  issuer_id: string
  valid_from?: string
  valid_until: string
}): PolicyContext {
  const now = new Date().toISOString()
  const ctx: PolicyContext = {
    policy_version: params.policy_version,
    values_floor_version: params.values_floor_version,
    trust_epoch: params.trust_epoch,
    issuer_id: params.issuer_id,
    created_at: now,
    valid_from: params.valid_from || now,
    valid_until: params.valid_until,
  }
  if (!ctx.valid_until) throw new Error('PolicyContext: valid_until is MANDATORY')
  const from = new Date(ctx.valid_from).getTime()
  const until = new Date(ctx.valid_until).getTime()
  if (until <= from) throw new Error('PolicyContext: valid_until must be after valid_from')
  if (until - from > DEFAULT_MAX_LIFETIME_MS) {
    throw new Error(`PolicyContext: lifetime exceeds maximum (${DEFAULT_MAX_LIFETIME_MS / 86400000} days)`)
  }
  return ctx
}

export function isPolicyContextActive(ctx: PolicyContext, now?: Date): boolean {
  const t = (now || new Date()).getTime()
  return t >= new Date(ctx.valid_from).getTime() && t <= new Date(ctx.valid_until).getTime()
}

export function isPolicyContextInGrace(
  ctx: PolicyContext, gracePeriodMs: number = 72 * 60 * 60 * 1000, now?: Date
): boolean {
  const t = (now || new Date()).getTime()
  const until = new Date(ctx.valid_until).getTime()
  return t > until && t <= until + gracePeriodMs
}


// ═══════════════════════════════════════════════
// v1 → v2 TYPE CONVERSION
// ═══════════════════════════════════════════════

export function v1DelegationToV2(v1: Delegation, policyContext: PolicyContext): V2Delegation {
  return {
    id: v1.delegationId,
    version: 1,
    supersedes: null,
    supersession_justification: null,
    delegator: v1.delegatedBy,
    delegatee: v1.delegatedTo,
    scope: { action_categories: v1.scope },
    policy_context: policyContext,
    signature: v1.signature,
    status: 'active' as V2DelegationStatus,
    renewal_reason: null,
    expansion_reviewer: null,
    expansion_review_sig: null,
    assurance_class: 'mechanically_enforceable' as AssuranceClass,
  }
}

export function v2DelegationToV1(
  v2: V2Delegation, maxDepth: number = 5, currentDepth: number = 0
): Delegation {
  return {
    delegationId: v2.id,
    delegatedTo: v2.delegatee,
    delegatedBy: v2.delegator,
    scope: v2.scope.action_categories,
    expiresAt: v2.policy_context.valid_until,
    maxDepth,
    currentDepth,
    createdAt: v2.policy_context.created_at,
    signature: v2.signature,
  }
}

// ═══════════════════════════════════════════════
// ARTIFACT PROVENANCE
// ═══════════════════════════════════════════════

export function createArtifactProvenance(params: {
  authoring_agent: string
  authority_scope: V2ScopeDefinition
  delegation_ref: string
  intended_use: string
  risk_class: RiskClass
  requires_human_execution: boolean
  content: string
  artifact_type: string
  policy_context: PolicyContext
  agent_private_key: string
  behavioralAttestation?: BehavioralAttestationResult
}): ArtifactProvenance {
  const contentHash = sha256(params.content)
  const contentSize = Buffer.byteLength(params.content, 'utf-8')
  const provenanceData: Record<string, unknown> = {
    artifact_id: uuidv4(),
    authoring_agent: params.authoring_agent,
    authority_scope: params.authority_scope,
    delegation_ref: params.delegation_ref,
    intended_use: params.intended_use,
    risk_class: params.risk_class,
    requires_human_execution: params.requires_human_execution,
    content_hash: contentHash,
    content_size: contentSize,
    artifact_type: params.artifact_type,
    policy_context: params.policy_context,
    assurance_class: 'evidentially_auditable',
  }

  // Wire BehavioralAttestationResult into provenance (Issue #9)
  if (params.behavioralAttestation) {
    const validation = validateAttestationResult(params.behavioralAttestation)
    if (!validation.valid) {
      throw new Error(`Invalid behavioral attestation: ${validation.errors.join(', ')}`)
    }
    provenanceData.behavioralEvidence = {
      evaluationContextHash: params.behavioralAttestation.evaluationContextHash,
      aggregateScore: params.behavioralAttestation.aggregateScore,
      classification: params.behavioralAttestation.classification,
      confidence: params.behavioralAttestation.confidence,
    } satisfies BehavioralEvidenceMetadata
  }

  const signature = signObject(provenanceData, params.agent_private_key)
  return { ...provenanceData, signature } as ArtifactProvenance
}

export function verifyArtifactIntegrity(provenance: ArtifactProvenance, content: string): boolean {
  return sha256(content) === provenance.content_hash
}


// ═══════════════════════════════════════════════
// REPUTATION DECAY (query-time, raw data never modified)
// ═══════════════════════════════════════════════

const DEFAULT_DECAY_FACTOR = 0.85
const DOMAIN_DECAY_OVERRIDES: Record<string, number> = {
  'cybersecurity': 0.75,
  'document_processing': 0.92,
}

export function computeDecayedWeight(
  rawWeight: number, earningEpoch: number,
  currentEpoch: number, domain?: string,
): number {
  const delta = Math.max(0, currentEpoch - earningEpoch)
  const factor = (domain && DOMAIN_DECAY_OVERRIDES[domain]) || DEFAULT_DECAY_FACTOR
  return rawWeight * Math.pow(factor, delta)
}

// ═══════════════════════════════════════════════
// SEMANTIC UNCERTAINTY ENFORCEMENT
// ═══════════════════════════════════════════════

export function getUncertaintyRequirements(level: SemanticUncertainty): {
  requires_attestation: boolean
  requires_outcome_registration: boolean
  requires_external_cosign: boolean
  review_mode: 'async' | 'sync' | 'none'
  audit_sample_rate: number
} {
  switch (level) {
    case 'low': return { requires_attestation: false, requires_outcome_registration: false, requires_external_cosign: false, review_mode: 'none', audit_sample_rate: 0 }
    case 'medium': return { requires_attestation: true, requires_outcome_registration: true, requires_external_cosign: false, review_mode: 'none', audit_sample_rate: 0.05 }
    case 'high': return { requires_attestation: true, requires_outcome_registration: true, requires_external_cosign: true, review_mode: 'async', audit_sample_rate: 0.2 }
    case 'critical': return { requires_attestation: true, requires_outcome_registration: true, requires_external_cosign: true, review_mode: 'sync', audit_sample_rate: 1.0 }
  }
}

export function resolveUncertaintyLevel(
  delegatorAssigned: SemanticUncertainty,
  agentAssessed: SemanticUncertainty,
): SemanticUncertainty {
  const order: SemanticUncertainty[] = ['low', 'medium', 'high', 'critical']
  return order[Math.max(order.indexOf(delegatorAssigned), order.indexOf(agentAssessed))]
}


// ═══════════════════════════════════════════════
// EMERGENCY CONDITION EVALUATION
// ═══════════════════════════════════════════════

export function evaluateConditions(conditions: ConditionSet, context: Record<string, unknown>): boolean {
  if (conditions.all_of?.length) {
    return conditions.all_of.every(c => evaluateSingle(c, context))
  }
  if (conditions.any_of?.length) {
    return conditions.any_of.some(c => evaluateSingle(c, context))
  }
  return false
}

function evaluateSingle(condition: Condition, context: Record<string, unknown>): boolean {
  const actual = context[condition.field]
  if (actual === undefined) return false
  switch (condition.operator) {
    case 'eq': return actual === condition.value
    case 'neq': return actual !== condition.value
    case 'gt': return (actual as number) > (condition.value as number)
    case 'lt': return (actual as number) < (condition.value as number)
    case 'gte': return (actual as number) >= (condition.value as number)
    case 'lte': return (actual as number) <= (condition.value as number)
    case 'contains': return String(actual).includes(String(condition.value))
    case 'matches': return new RegExp(String(condition.value)).test(String(actual))
    default: return false
  }
}
