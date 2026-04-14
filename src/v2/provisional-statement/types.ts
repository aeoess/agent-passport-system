// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Provisional Statement — agent-to-agent negotiation default
// ══════════════════════════════════════════════════════════════════
// Default status for a statement emitted by an agent during negotiation
// is "provisional". Binding status requires an explicit PromotionEvent
// that satisfies a PromotionPolicy (m-of-n principal signatures). The
// dead-man path expires into "withdrawn", never into "promoted" —
// absence of confirmation is not consent.
// ══════════════════════════════════════════════════════════════════

import type { HybridTimestamp } from '../../types/time.js'

export type AgentDID = string
export type PrincipalDID = string
export type Ed25519Signature = string
/** Duration in milliseconds. */
export type Duration = number

export type ProvisionalStatus = 'provisional' | 'promoted' | 'withdrawn'

export type PromotionKind =
  | 'principal_signature'
  | 'counter_signature'
  | 'dead_man_elapsed'

export interface PromotionEvent {
  kind: PromotionKind
  promoted_at: HybridTimestamp
  /** Principal (for principal_signature), counterparty agent (for
   *  counter_signature), or the system (for dead_man_elapsed). */
  promoter: PrincipalDID | AgentDID
  /** Ed25519 signature over the canonical promotion payload. Empty
   *  string for dead_man_elapsed (no signer). */
  promoter_signature: Ed25519Signature
  /** The PromotionPolicy.id that this event satisfies. */
  policy_reference: string
}

export interface ProvisionalStatement {
  id: string
  version: '1.0'
  author: AgentDID
  author_principal: PrincipalDID
  content: string
  status: ProvisionalStatus
  created_at: HybridTimestamp
  /** Optional dead-man deadline. If reached without explicit promotion
   *  or withdrawal, the statement auto-transitions to "withdrawn". */
  dead_man_expires_at?: HybridTimestamp
  author_signature: Ed25519Signature
  promotion?: PromotionEvent
}

export interface PromotionPolicy {
  id: string
  /** Principals whose signatures count toward the threshold. */
  required_signers: PrincipalDID[]
  /** m-of-n: minimum number of signatures from required_signers. */
  threshold: number
  /** Maximum time from created_at to promoted_at, in milliseconds. */
  max_time_to_promote: Duration
}

export interface PromotionVerifyResult {
  valid: boolean
  errors: string[]
}
