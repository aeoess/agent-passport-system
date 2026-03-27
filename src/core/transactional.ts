// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Transactional Integrity — Pure SDK Functions
// ══════════════════════════════════════════════════════════════════
// Escrow + Dispute + Witness + Finality as one coherent layer.
// These are protocol primitives — pure functions, no gateway state.
// Gateway enforcement wiring is in gateway.ts (Session 2).
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type { FinalityState } from '../types/finality.js'
import type { EscrowHold, EscrowFulfillmentCondition } from '../types/escrow.js'
import type { DisputeArtifact, DisputeBond, DisputeOverlay,
  DisputeSubject } from '../types/dispute.js'
import type { TypedEvidence } from '../types/evidence.js'
import type { WitnessAttestation, WitnessObservationBasis } from '../types/gateway.js'

// ══════════════════════════════════════
// Escrow — Create & Verify
// ══════════════════════════════════════

export function createEscrowHold(input: {
  initiatorAgentId: string
  counterpartyAgentId: string
  delegationId: string
  amount: { value: number; currency: string }
  fulfillmentCondition: EscrowFulfillmentCondition
  expiresInSeconds: number
  gatewayId: string
  initiatorPrivateKey: string
  gatewayPrivateKey: string
}): EscrowHold {
  const now = new Date().toISOString()
  const escrowId = `esc_${createHash('sha256').update(
    `${input.initiatorAgentId}:${input.counterpartyAgentId}:${Date.now()}`
  ).digest('hex').slice(0, 24)}`

  const expiresAt = new Date(Date.now() + input.expiresInSeconds * 1000).toISOString()

  const finality: FinalityState = { status: 'provisional', since: now }

  const holdData = {
    escrowId, initiatorAgentId: input.initiatorAgentId,
    counterpartyAgentId: input.counterpartyAgentId,
    delegationId: input.delegationId, amount: input.amount,
    fulfillmentCondition: input.fulfillmentCondition,
    createdAt: now, expiresAt,
    status: 'held' as const, finality,
    gatewayId: input.gatewayId,
  }

  const payload = canonicalize(holdData)
  const initiatorSignature = sign(payload, input.initiatorPrivateKey)
  const gatewaySignature = sign(payload, input.gatewayPrivateKey)

  return { ...holdData, initiatorSignature, gatewaySignature }
}

export function verifyEscrowHold(
  escrow: EscrowHold, initiatorPublicKey: string, gatewayPublicKey: string
): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  const { initiatorSignature, gatewaySignature, ...rest } = escrow
  const payload = canonicalize(rest)

  // Reconstruct the signed payload (immutable creation fields only)
  const signedData = {
    escrowId: escrow.escrowId,
    initiatorAgentId: escrow.initiatorAgentId,
    counterpartyAgentId: escrow.counterpartyAgentId,
    delegationId: escrow.delegationId,
    amount: escrow.amount,
    fulfillmentCondition: escrow.fulfillmentCondition,
    createdAt: escrow.createdAt,
    expiresAt: escrow.expiresAt,
    status: 'held' as const,
    finality: { status: 'provisional' as const, since: escrow.createdAt },
    gatewayId: escrow.gatewayId,
  }
  const reconstructed = canonicalize(signedData)

  if (!verify(reconstructed, initiatorSignature, initiatorPublicKey)) {
    errors.push('Invalid initiator signature')
  }
  if (!verify(reconstructed, gatewaySignature, gatewayPublicKey)) {
    errors.push('Invalid gateway signature')
  }
  if (escrow.amount.value <= 0) errors.push('Escrow amount must be positive')
  if (new Date(escrow.expiresAt) <= new Date(escrow.createdAt)) {
    errors.push('Expiry must be after creation')
  }
  return { valid: errors.length === 0, errors }
}

// ══════════════════════════════════════
// Dispute — Create & Verify
// ══════════════════════════════════════

export function createDisputeArtifact(input: {
  claimantId: string
  claimantPrivateKey: string
  bond: DisputeBond
  subject: DisputeSubject
  challengedArtifactId: string
  challengedArtifactType: 'receipt' | 'escrow' | 'deliverable' | 'delegation'
  claim: string
  evidence: TypedEvidence[]
  respondentId: string
  resolutionTTLSeconds: number
  freezeScope: { escrowIds: string[]; actionScopes?: string[] }
  freezeSeverity: 'hard' | 'soft' | 'warning'
  gatewayId: string
  gatewayPrivateKey: string
}): DisputeArtifact {
  const now = new Date().toISOString()
  const disputeId = `dsp_${createHash('sha256').update(
    `${input.claimantId}:${input.challengedArtifactId}:${Date.now()}`
  ).digest('hex').slice(0, 24)}`

  const resolutionTTL = new Date(Date.now() + input.resolutionTTLSeconds * 1000).toISOString()
  const finality: FinalityState = { status: 'provisional', since: now }

  const disputeData = {
    disputeId, claimantId: input.claimantId,
    bond: input.bond, subject: input.subject,
    challengedArtifactId: input.challengedArtifactId,
    challengedArtifactType: input.challengedArtifactType,
    claim: input.claim, evidence: input.evidence,
    respondentId: input.respondentId,
    status: 'filed' as const, finality,
    filedAt: now, resolutionTTL,
    freezeScope: input.freezeScope,
    freezeSeverity: input.freezeSeverity,
    gatewayId: input.gatewayId,
  }

  const payload = canonicalize(disputeData)
  const claimantSignature = sign(payload, input.claimantPrivateKey)
  const gatewaySignature = sign(payload, input.gatewayPrivateKey)

  return { ...disputeData, claimantSignature, gatewaySignature }
}

export function verifyDisputeArtifact(
  dispute: DisputeArtifact, claimantPublicKey: string, gatewayPublicKey: string
): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  const { claimantSignature, gatewaySignature, responseEvidence,
    contestedUpstream, resolution, ...rest } = dispute
  const signedData = {
    ...rest, status: 'filed' as const,
    finality: { status: 'provisional' as const, since: dispute.filedAt },
  }
  const payload = canonicalize(signedData)
  if (!verify(payload, claimantSignature, claimantPublicKey)) {
    errors.push('Invalid claimant signature')
  }
  if (!verify(payload, gatewaySignature, gatewayPublicKey)) {
    errors.push('Invalid gateway signature')
  }
  if (dispute.bond.amount < 0) errors.push('Bond amount cannot be negative')
  if (dispute.evidence.length === 0) errors.push('Dispute must include at least one evidence item')
  return { valid: errors.length === 0, errors }
}

// ══════════════════════════════════════
// Witness — Create & Verify
// ══════════════════════════════════════

export function createWitnessAttestation(input: {
  witnessId: string
  witnessPrivateKey: string
  witnessRole: WitnessAttestation['witnessRole']
  receiptId: string
  receiptHash: string
  attestation: WitnessAttestation['attestation']
  observationBasis: WitnessObservationBasis
  predictionError?: WitnessAttestation['predictionError']
}): WitnessAttestation {
  const now = new Date().toISOString()
  const attData = {
    witnessId: input.witnessId, witnessRole: input.witnessRole,
    receiptId: input.receiptId, receiptHash: input.receiptHash,
    attestedAt: now, attestation: input.attestation,
    observationBasis: input.observationBasis,
    ...(input.predictionError ? { predictionError: input.predictionError } : {}),
  }
  const payload = canonicalize(attData)
  const signature = sign(payload, input.witnessPrivateKey)
  return { ...attData, signature }
}

export function verifyWitnessAttestation(
  att: WitnessAttestation, witnessPublicKey: string
): boolean {
  const { signature, ...rest } = att
  return verify(canonicalize(rest), signature, witnessPublicKey)
}

// ══════════════════════════════════════
// Dispute Overlay — Defeasible evaluation (pure function)
// ══════════════════════════════════════
// Applied AFTER monotone lattice evaluation. Not a lattice facet.
// This is defeasible logic: disputes are defeaters that suppress
// otherwise valid authority. Dismissal removes the defeater.

export function evaluateDisputeOverlay(
  activeDisputes: DisputeArtifact[],
  requestedScope: string,
  agentId: string,
): DisputeOverlay {
  // Filter disputes relevant to this agent (as respondent)
  const relevant = activeDisputes.filter(d =>
    d.respondentId === agentId &&
    (d.status === 'filed' || d.status === 'acknowledged' || d.status === 'investigating')
  )

  if (relevant.length === 0) {
    return {
      hasActiveDispute: false, activeDisputeIds: [],
      frozenScopes: [], effectiveSeverity: 'none', actionAffected: false,
    }
  }

  // Collect frozen scopes and determine if this action is affected
  const frozenScopes = relevant.flatMap(d => d.freezeScope.actionScopes ?? [])
  const actionAffected = frozenScopes.some(scope =>
    requestedScope === scope || requestedScope.startsWith(scope + ':')
  )

  // Effective severity: highest severity among relevant disputes
  let effectiveSeverity = 'none' as 'hard' | 'soft' | 'warning' | 'none'
  for (const d of relevant) {
    if (d.freezeSeverity === 'hard') { effectiveSeverity = 'hard'; break }
    if (d.freezeSeverity === 'soft' && effectiveSeverity !== 'hard') effectiveSeverity = 'soft'
    if (d.freezeSeverity === 'warning' && effectiveSeverity === 'none') effectiveSeverity = 'warning'
  }

  return {
    hasActiveDispute: true,
    activeDisputeIds: relevant.map(d => d.disputeId),
    frozenScopes,
    effectiveSeverity: actionAffected ? effectiveSeverity : 'none',
    actionAffected,
  }
}
