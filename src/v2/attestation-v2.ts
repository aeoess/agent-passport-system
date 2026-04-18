// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Attestation v2 — pure primitives (signing + quality scoring).
// ══════════════════════════════════════════════════════════════════════
// The attestation store and per-agent aggregate queries that used to live
// here have been split out to attestation-ledger.ts in @aeoess/gateway
// (src/sdk-migrated/v2/). This module keeps ONLY:
//
//   signAttestation                 — pure signed-record constructor
//   assessV2AttestationQuality      — pure quality predicate over a record
//
// Stateful helpers (createV2Attestation, getV2Attestation,
// getV2AttestationForAction, getV2AttestationsForAgent,
// getV2AgentAttestationQualityAvg, clearV2AttestationStore) remain
// exported as deprecation stubs that throw and point callers to the
// gateway module.
// ══════════════════════════════════════════════════════════════════════

import { v4 as uuidv4 } from 'uuid'
import { signObject } from './bridge.js'
import type {
  PolicyContext, SemanticUncertainty,
  AlternativeRejected, ContextualAttestation, AttestationQuality,
} from './types.js'

const MOVED =
  'This function has moved to attestation-ledger in @aeoess/gateway ' +
  '(src/sdk-migrated/v2/attestation-ledger.ts). ' +
  'Pure primitives signAttestation + assessV2AttestationQuality stay in the SDK. See MIGRATION.md.'

// ══════════════════════════════════════
// SIGNING PRIMITIVE
// ══════════════════════════════════════

/**
 * Pure: validates required fields, signs the attestation record, and
 * returns it. Does not store. Gateway's createV2Attestation wraps this
 * with the attestation ledger.
 */
export function signAttestation(params: {
  action_id: string
  agent_id: string
  delegation_ref: string
  context_understanding: string
  factors_considered: string[]
  alternatives_rejected: AlternativeRejected[]
  expected_outcome: string
  confidence: number
  semantic_uncertainty: SemanticUncertainty
  required: boolean
  policy_context: PolicyContext
  agent_private_key: string
}): ContextualAttestation {
  if (!params.context_understanding?.trim()) throw new Error('Context understanding required')
  if (params.factors_considered.length === 0) throw new Error('At least one factor required')
  if (!params.expected_outcome?.trim()) throw new Error('Expected outcome required')
  if (params.confidence < 0 || params.confidence > 1) throw new Error('Confidence must be 0-1')

  if (params.required) {
    if (params.context_understanding.length < 20) {
      throw new Error('Required attestation needs substantive context (min 20 chars)')
    }
    if (params.factors_considered.length < 2) {
      throw new Error('Required attestation needs at least 2 factors')
    }
  }

  const data: Record<string, unknown> = {
    id: uuidv4(), action_id: params.action_id,
    agent_id: params.agent_id, delegation_ref: params.delegation_ref,
    context_understanding: params.context_understanding,
    factors_considered: params.factors_considered,
    alternatives_rejected: params.alternatives_rejected,
    expected_outcome: params.expected_outcome,
    confidence: params.confidence,
    semantic_uncertainty: params.semantic_uncertainty,
    required: params.required,
    policy_context: params.policy_context,
    assurance_class: 'evidentially_auditable',
    created_at: new Date().toISOString(),
  }
  const sig = signObject(data, params.agent_private_key)
  return { ...data, signature: sig } as ContextualAttestation
}

// ══════════════════════════════════════
// QUALITY SCORING (pure)
// ══════════════════════════════════════

export function assessV2AttestationQuality(att: ContextualAttestation): AttestationQuality {
  const hasContext = att.context_understanding.length >= 30
  const hasFactors = att.factors_considered.length >= 2
  const hasAlternatives = att.alternatives_rejected.length >= 1
  const confidenceCalibrated = att.confidence > 0.05 && att.confidence < 0.95
  let score = 0
  if (hasContext) score += 0.3
  if (hasFactors) score += 0.25
  if (hasAlternatives) score += 0.25
  if (confidenceCalibrated) score += 0.2
  return {
    has_context: hasContext, has_factors: hasFactors,
    has_alternatives: hasAlternatives, confidence_calibrated: confidenceCalibrated,
    quality_score: Math.round(score * 100) / 100,
  }
}

// ══════════════════════════════════════════════════════════════════════
// STATEFUL HELPERS — moved to @aeoess/gateway
// ══════════════════════════════════════════════════════════════════════

export function createV2Attestation(_params: {
  action_id: string
  agent_id: string
  delegation_ref: string
  context_understanding: string
  factors_considered: string[]
  alternatives_rejected: AlternativeRejected[]
  expected_outcome: string
  confidence: number
  semantic_uncertainty: SemanticUncertainty
  required: boolean
  policy_context: PolicyContext
  agent_private_key: string
}): ContextualAttestation { throw new Error(MOVED) }

export function getV2Attestation(_id: string): ContextualAttestation | undefined {
  throw new Error(MOVED)
}

export function getV2AttestationForAction(_actionId: string): ContextualAttestation | undefined {
  throw new Error(MOVED)
}

export function getV2AttestationsForAgent(_agentId: string): ContextualAttestation[] {
  throw new Error(MOVED)
}

export function getV2AgentAttestationQualityAvg(_agentId: string): number {
  throw new Error(MOVED)
}

export function clearV2AttestationStore(): void {
  // No-op: SDK no longer holds state. Gateway owns the store.
}
