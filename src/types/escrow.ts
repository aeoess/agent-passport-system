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


// ══════════════════════════════════════════════════════════════════
// Escrow-Aware Revocation (Gemini S2 Q3)
// ══════════════════════════════════════════════════════════════════
// Consilium Q3 resolution: revocation enters locked settlement state
// if active escrows exist. The delegation's authority drops to 0 for
// NEW actions, but remains valid ONLY for resolution of existing escrows.
//
// This is a state machine rule, not agent rights. The gateway enforces
// the split between "no new actions" and "existing escrows can resolve."
// ══════════════════════════════════════════════════════════════════

/** Escrow-aware revocation status. */
export type EscrowRevocationStatus =
  | 'pending_escrow_clearance'  // waiting for blocking escrows to resolve
  | 'executed'                  // all escrows resolved, revocation complete
  | 'failed'                    // grace period expired, force revocation

/** Escrow-aware revocation record. When a principal revokes a delegation
 *  that has active escrows, the revocation enters a holding state.
 *  New actions are immediately blocked. Existing escrows continue to resolution. */
export interface EscrowAwareRevocation {
  /** Unique revocation identifier */
  revocationId: string
  /** Delegation being revoked */
  targetDelegationId: string
  /** Ed25519 signature by the principal authorizing revocation */
  principalSignature: string
  /** Current revocation status */
  status: EscrowRevocationStatus
  /** Escrow IDs that must resolve before revocation completes */
  blockingEscrowIds: string[]
  /** ISO datetime — max time to wait before force-canceling escrows */
  gracePeriodExpiresAt: string
  /** Authority state during grace period:
   *  delegation authority = 0 for NEW actions.
   *  delegation remains valid ONLY for resolution of existing escrows. */
  newActionsBlocked: boolean
  /** Existing escrows are protected during the grace period */
  existingEscrowsProtected: boolean
  /** ISO datetime — when this revocation was initiated */
  createdAt: string
  /** Gateway signature enforcing the revocation state */
  gatewaySignature: string
}
