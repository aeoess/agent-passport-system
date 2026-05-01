// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// AuthorityBoundaryReceipt — gateway-side ruling on whether an action
// fell inside, outside, or at the edge of the agent's delegated scope
// ══════════════════════════════════════════════════════════════════
// Spec: specs/full-accountability-mvp.md
// Pairs with ActionReceipt: the action is what the agent did; the
// authority-boundary receipt is the evaluator's call on whether that
// action was authorized. Different signers, distinct trust roles.
// ══════════════════════════════════════════════════════════════════

import type { AccountabilityReceiptBase } from './base.js'

export type BoundaryResult = 'inside' | 'outside' | 'indeterminate'

export interface AuthorityBoundaryReceipt extends AccountabilityReceiptBase {
  claim_type: 'aps:authority_boundary:v1'
  /** receipt_id of the ActionReceipt this ruling is about. */
  action_id: string
  /** DID of the entity that ran the boundary check (typically the gateway). */
  evaluator_did: string
  /** sha256 hex of the canonical delegation chain evaluated against. */
  delegation_chain_root: string
  result: BoundaryResult
  /** Optional human-readable explanation. e.g. "scope 'commerce.purchase'
   *  not in delegation" when result='outside'. */
  result_detail?: string
}
