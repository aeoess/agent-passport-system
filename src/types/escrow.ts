// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Escrow — Gateway-enforced spend reservation with conditional finality
// ══════════════════════════════════════════════════════════════════
// An EscrowHold does NOT move money. It freezes authorization capacity
// on a delegation until a fulfillment condition is met. This is the
// first transactional primitive: exchange requires hold → verify → release.
// ══════════════════════════════════════════════════════════════════

import type { FinalityState } from './finality.js'

/** Escrow lifecycle states.
 *  Extended per consilium: includes partial fulfillment, orphaned, force states. */
export type EscrowStatus =
  | 'held'                  // funds reserved, awaiting fulfillment
  | 'partially_fulfilled'   // some milestones met, not all
  | 'verification_pending'  // fulfilled, awaiting verification/acceptance
  | 'fulfilled'             // all conditions met
  | 'disputed'              // dispute filed, frozen
  | 'expired'               // TTL passed without fulfillment
  | 'released'              // funds authorized to counterparty
  | 'refunded'              // funds returned to initiator
  | 'force_released'        // override by principal/arbitrator
  | 'orphaned'              // counterparty unreachable / gateway failure

export interface EscrowMilestone {
  id: string
  description: string
  /** Amount released when this milestone is fulfilled */
  amount: number
  fulfilled: boolean
  fulfilledAt?: string
}

export interface EscrowFulfillmentCondition {
  type: 'receipt_generated' | 'deliverable_accepted' | 'manual_release' | 'milestone'
  /** For receipt_generated: which receipt unlocks the escrow */
  receiptId?: string
  /** For deliverable_accepted: which deliverable triggers release */
  deliverableId?: string
  /** For milestone: structured milestone payouts */
  milestones?: EscrowMilestone[]
}

export interface EscrowHold {
  escrowId: string
  // ── Parties ──
  initiatorAgentId: string        // Agent A (buyer/task poster)
  counterpartyAgentId: string     // Agent B (seller/task executor)
  // ── What's held (hard reservation — immediately deducted from delegation) ──
  delegationId: string
  amount: { value: number; currency: string }
  // ── Conditions ──
  fulfillmentCondition: EscrowFulfillmentCondition
  // ── Timing ──
  createdAt: string
  expiresAt: string               // hard TTL — auto-refund if not fulfilled
  // ── State ──
  status: EscrowStatus
  finality: FinalityState
  // ── Resolution links ──
  fulfillmentReceiptId?: string   // the receipt that triggered release
  disputeId?: string              // if disputed, links to DisputeArtifact
  // ── Gateway metadata (federation-ready) ──
  gatewayId: string
  // ── Signatures ──
  initiatorSignature: string      // Agent A signs the hold creation
  gatewaySignature: string        // Gateway signs enforcement
}

// ══════════════════════════════════════════════════════════════════
// Danger Signals — Matzinger Danger Model (1994)
// ══════════════════════════════════════════════════════════════════
// The gateway doesn't wait for someone to file a dispute.
// It autonomously detects escrow anomaly patterns and emits signals.
// DangerSignals are NOT disputes — they're pre-dispute alerts.

export type DangerType =
  | 'escrow_ttl_approaching'      // escrow near expiry with no fulfillment
  | 'spend_velocity_anomaly'      // agent burning budget at abnormal rate
  | 'fulfillment_abandoned'       // partial fulfillment then silence
  | 'repeated_disputes'           // agent involved in multiple disputes
  | 'witness_refusal_pattern'     // witnesses refusing to attest this agent

export interface DangerSignal {
  signalId: string
  type: DangerType
  agentId: string
  /** The artifact that triggered the signal (escrowId, receiptId, etc.) */
  relatedArtifactId: string
  severity: 'low' | 'medium' | 'high'
  detectedAt: string
  /** Should this auto-escalate to a dispute if unaddressed? */
  autoEscalate: boolean
  message: string
}
