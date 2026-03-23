/**
 * APS v2 Contextual Attestation
 * Pre-action reasoning records. Required for medium+ risk.
 * Clinical note to the action's prescription.
 */

import { v4 as uuidv4 } from 'uuid'
import { signObject } from './bridge.js'
import type {
  PolicyContext, SemanticUncertainty,
  AlternativeRejected, ContextualAttestation, AttestationQuality,
} from './types.js'

const attestationStore: Map<string, ContextualAttestation> = new Map()

export function getV2Attestation(id: string) { return attestationStore.get(id) }
export function getV2AttestationForAction(actionId: string) {
  return Array.from(attestationStore.values()).find(a => a.action_id === actionId)
}
export function getV2AttestationsForAgent(agentId: string) {
  return Array.from(attestationStore.values()).filter(a => a.agent_id === agentId)
}

export function createV2Attestation(params: {
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
  const att = { ...data, signature: sig } as ContextualAttestation
  attestationStore.set(att.id, att)
  return att
}

// ── Quality Analysis ──

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

export function getV2AgentAttestationQualityAvg(agentId: string): number {
  const atts = getV2AttestationsForAgent(agentId)
  if (atts.length === 0) return 0
  const total = atts.reduce((s, a) => s + assessV2AttestationQuality(a).quality_score, 0)
  return Math.round((total / atts.length) * 100) / 100
}

export function clearV2AttestationStore(): void { attestationStore.clear() }
