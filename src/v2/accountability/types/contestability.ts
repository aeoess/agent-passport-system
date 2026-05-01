// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// ContestabilityReceipt — declares a challenge filed against an action
// ══════════════════════════════════════════════════════════════════
// Spec: specs/full-accountability-mvp.md
// The wedge primitive: every observability surface in the market today
// is operator-facing. ContestabilityReceipt is the first cryptographic
// format designed for STANDING — the right of an affected party to
// challenge an automated decision and force a tracked response.
//
// The contestant signs a receipt about the FILING. If a controller
// later responds, the response is appended with an INDEPENDENT
// signature inside controller_response — the contestants outer
// signature does not cover that response, so the response cannot
// retroactively rewrite the original claim.
// ══════════════════════════════════════════════════════════════════

import type { AccountabilityReceiptBase } from './base.js'

export type StandingBasis =
  | 'data_subject'
  | 'third_party'
  | 'regulator'
  | 'court'
  | 'internal_audit'
  | 'insurer'
  | 'principal'

export type RequestedRemedy =
  | 'rollback'
  | 'review'
  | 'explanation'
  | 'compensation'
  | 'erasure'
  | 'modification'

export type ContestStatus =
  | 'filed'
  | 'under_review'
  | 'upheld'
  | 'rejected'
  | 'remedied'
  | 'expired'
  | 'abandoned'

export interface ContestabilityControllerResponse {
  status: ContestStatus
  /** ISO 8601 UTC with milliseconds, ending Z. */
  responded_at: string
  responder_did: string
  /** Ed25519 hex over canonicalizeJCS(receipt with response_signature emptied). */
  response_signature: string
  response_detail?: string
}

export interface ContestabilityContestant {
  /** Optional — pseudonymous filings are allowed. At least one of did
   *  or pseudonym_hash MUST be present. */
  did?: string
  /** sha256 hex when the contestant prefers a pseudonym. */
  pseudonym_hash?: string
  standing_basis: StandingBasis
}

export interface ContestabilityReceipt extends AccountabilityReceiptBase {
  claim_type: 'aps:contestability:v1'
  contestant: ContestabilityContestant
  /** References the contested ActionReceipt.receipt_id. */
  action_id: string
  grounds: string
  requested_remedy: RequestedRemedy
  controller_response?: ContestabilityControllerResponse
}
