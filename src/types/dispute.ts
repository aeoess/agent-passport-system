// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Dispute — Defeasible overlay on transactional state
// ══════════════════════════════════════════════════════════════════
// A dispute is NOT a constraint facet. It is an epistemological defeater
// (Defeasible Logic, Nute 1994) that suppresses otherwise valid authority.
// The product lattice stays monotone. Disputes sit in an overlay layer.
// When dismissed, the defeater is REMOVED — authority was never "lost."
//
// Filing a dispute costs a slashing bond (options pricing theory):
// a free dispute is a free option. Dismissed = bond slashed to respondent.
// ══════════════════════════════════════════════════════════════════

import type { FinalityState } from './finality.js'
import type { TypedEvidence } from './evidence.js'

export type DisputeStatus =
  | 'filed'
  | 'acknowledged'
  | 'investigating'
  | 'resolved'
  | 'escalated'
  | 'dismissed'
  | 'timeout'

export type DisputeResolution = 'upheld' | 'dismissed' | 'compromise' | 'timeout'

export type DisputeSubject =
  | 'action'           // challenge to a specific tool execution
  | 'receipt'          // challenge to a receipt's validity
  | 'delivery'         // deliverable quality or completeness
  | 'payment'          // payment/escrow dispute
  | 'scope_violation'  // agent exceeded authorized scope
  | 'quality'          // work quality below agreed standard
  | 'non_performance'  // counterparty failed to perform

/** Resolver neutrality class — who resolved and under what authority.
 *  Critical for later distinguishing self-serving resolution from neutral arbitration. */
export type ResolverRole =
  | 'initiating_principal'     // principal who initiated the escrow
  | 'counterparty_principal'   // the other party's principal
  | 'joint_resolution'         // both parties agreed
  | 'designated_arbitrator'    // third-party arbitrator agent
  | 'timeout_default'          // auto-resolution on TTL expiry

/** Slashing bond — filing a dispute costs spend/reputation.
 *  Dismissed = bond slashed to respondent (compensation for frozen capital).
 *  Upheld = bond returned to claimant.
 *  Options pricing theory: a free dispute is a free option exploit. */
export interface DisputeBond {
  amount: number
  delegationId: string
  /** false if bond-exempt (e.g., principal filing against own agent) */
  slashable: boolean
}

export interface DisputeArtifact {
  disputeId: string
  // ── Claimant ──
  claimantId: string
  claimantSignature: string
  bond: DisputeBond
  // ── Subject ──
  subject: DisputeSubject
  challengedArtifactId: string
  challengedArtifactType: 'receipt' | 'escrow' | 'deliverable' | 'delegation'
  // ── Claim ──
  claim: string                    // human/agent-readable description
  evidence: TypedEvidence[]
  // ── Respondent ──
  respondentId: string
  responseEvidence?: TypedEvidence[]
  // ── State ──
  status: DisputeStatus
  finality: FinalityState
  filedAt: string
  /** Hard deadline for resolution (ISO datetime). Un-extendable.
   *  Escrow TTL pauses during dispute, but only up to this deadline. */
  resolutionTTL: string
  // ── Freeze semantics (scoped, not broad) ──
  freezeScope: {
    escrowIds: string[]
    actionScopes?: string[]        // tool scopes blocked during dispute
  }
  freezeSeverity: 'hard' | 'soft' | 'warning'
  /** Upstream contamination — SIR epidemiological model.
   *  Receipt IDs that this dispute taints (cascade dispute). */
  contestedUpstream?: string[]
  // ── Resolution ──
  resolution?: {
    outcome: DisputeResolution
    resolvedBy: string
    resolverRole: ResolverRole
    resolvedAt: string
    reasoning: string
    enforcement: {
      escrowAction?: 'release' | 'refund' | 'split'
      splitRatio?: number          // 0.0 = full refund, 1.0 = full release
      bondAction: 'return' | 'slash' | 'partial_slash'
      bondSlashRatio?: number      // for partial_slash
      reputationImpact?: Array<{
        agentId: string
        adjustment: 'penalize' | 'reward' | 'none'
        magnitude?: number
      }>
      revocationTriggered?: string[]
    }
  }
  // ── Gateway ──
  gatewayId: string
  gatewaySignature: string
}

// ══════════════════════════════════════════════════════════════════
// Dispute Overlay — Defeasible layer on ConstraintVector
// ══════════════════════════════════════════════════════════════════
// This is NOT a lattice facet. The product lattice stays monotone.
// The overlay is an epistemological defeater: it suppresses otherwise
// valid authority. When the dispute is dismissed, the defeater is
// removed — authority was never "lost," just institutionally suspended.

/** Defeasible dispute overlay — applied AFTER lattice evaluation */
export interface DisputeOverlay {
  /** Is the agent currently under active dispute? */
  hasActiveDispute: boolean
  /** Active dispute IDs affecting this agent */
  activeDisputeIds: string[]
  /** Scopes currently frozen by disputes */
  frozenScopes: string[]
  /** Effective severity of the overlay */
  effectiveSeverity: 'hard' | 'soft' | 'warning' | 'none'
  /** Whether this specific action's scope overlaps a frozen scope */
  actionAffected: boolean
}
