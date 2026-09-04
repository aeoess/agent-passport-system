// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Receipt context-layer verification (shippable)
// ══════════════════════════════════════════════════════════════════
// The crypto layer (verifyActionReceipt) answers "is this receipt a
// well-formed, correctly-signed, un-tampered aps:action:v1 receipt".
// That is necessary but not sufficient. A cryptographically sound
// receipt can still be presented OUTSIDE the envelope it was issued
// for: against an expired or revoked delegation, over budget, by the
// wrong principal, under a stale policy, replayed, or as proof of a
// claim it never made. Those are CONTEXT rejections.
//
// None of the context inputs live inside the signed bytes. They are
// the relying party's own ground truth (its revocation view, its
// budget ceiling, the principal it expects to be accountable, the
// receipt_ids it has already honored). A conformant verifier MUST
// apply both layers.
//
// This module was promoted from the conformance generator so the
// offline verifier and the relying-party middleware can consume it as
// shippable API. The reason taxonomy and the check ORDER are pinned:
// the golden negative fixtures assert WHY each rejection happens, so a
// reorder or rename would break the conformance corpus. Extend by
// adding new reasons at the end, never by reordering existing checks.
//
// SCOPE OF CLAIM (dogfooded):
//   Proves: a receipt that passes both layers is a well-formed,
//     correctly-signed receipt presented inside the envelope the
//     relying party's supplied context describes.
//   Does NOT prove: that the off-protocol side effect the receipt
//     names actually happened, that the signer's key was honestly
//     held, or that the relying party's context is itself accurate. A
//     receipt is a signed declaration, not a causal proof.
// ══════════════════════════════════════════════════════════════════

import { verifyActionReceipt } from '../accountability/verify/action.js'
import { isRecord } from '../../core/is-record.js'
import { parseRfc3339 } from '../../core/rfc3339.js'
import type { ActionReceipt } from '../accountability/types/action.js'

// ── Reasons a conformant verifier rejects a receipt ─────────────────
// The crypto layer (verifyActionReceipt) closes three modes directly.
// The remaining modes are CONTEXT rejections: the signature is fine but
// the receipt is being used outside the envelope it was issued for.
export type RejectReason =
  // crypto-layer (verifyActionReceipt)
  | 'INVALID_CLAIM_TYPE'
  | 'RECEIPT_ID_MISMATCH' // mismatched-hash / tampered body
  | 'SIGNATURE_INVALID' // invalid signature
  // context-layer (verifyReceiptContext)
  | 'DELEGATION_EXPIRED' // expired delegation
  | 'DELEGATION_REVOKED' // revoked / stale revocation not honored
  | 'OVER_BUDGET' // over-budget action
  | 'WRONG_PRINCIPAL' // wrong-principal: receipt principal != asserted beneficiary
  | 'STALE_POLICY' // policy version evaluated is older than the active one
  | 'REPLAYED' // receipt_id already seen in this verification window
  | 'WRONG_CLAIM' // valid receipt presented as proof of a claim it does not make
  | 'POLICY_NOT_EXECUTED' // policy evaluated but execution never happened
  | 'DELEGATION_ROOT_MISMATCH' // receipt's chain root is not the root the verifier treats as authoritative
  | 'INVALID_TIMESTAMP' // a timestamp on either side of a window check is not a readable instant

/** The closed set of crypto-layer reasons, for callers that want to
 *  branch on which layer surfaced a rejection without re-running the
 *  verifier. Mirrors {@link RejectReason}'s crypto subset. */
export const CRYPTO_LAYER_REASONS: readonly RejectReason[] = [
  'INVALID_CLAIM_TYPE',
  'RECEIPT_ID_MISMATCH',
  'SIGNATURE_INVALID',
]

// Context an external verifier checks the receipt against. None of this
// is inside the signed bytes; it is the verifier's own ground truth.
export interface ReceiptContext {
  now: string
  /** Delegation chain root the verifier currently treats as authoritative. */
  active_delegation_root: string
  /** Delegation expiry, ISO 8601. Receipt timestamp must be at or before this. */
  delegation_expires_at: string
  /** Delegation roots the verifier has seen revoked. */
  revoked_delegation_roots: string[]
  /** Budget ceiling, integer base units. */
  budget_base_units: bigint
  /** Cost the receipt's action draws against the budget, base units. */
  action_cost_base_units: bigint
  /** Principal the verifier expects to be accountable. */
  expected_principal_did: string
  /** Policy version the verifier currently enforces. */
  active_policy_version: number
  /** Policy version actually evaluated, carried in the receipt's policy_ref. */
  evaluated_policy_version: number
  /** receipt_ids the verifier has already accepted in this window. */
  seen_receipt_ids: string[]
  /** The claim the receipt is being presented to support. */
  presented_as_claim_type: string
  /** Whether an execution attestation accompanies the policy decision. */
  execution_attested: boolean
}

export interface ContextVerifyResult {
  valid: boolean
  reason?: RejectReason
}

/**
 * Context-layer verification. Runs the crypto verifier first, then the
 * verifier-responsibility checks an external party MUST apply before
 * treating a receipt as authoritative. Order matters: a tampered or
 * unsigned receipt is rejected before any context is consulted.
 *
 * Pure and offline. No I/O, no network, no clock read; the verifier's
 * notion of "now" and "already seen" is supplied entirely through
 * {@link ReceiptContext}.
 */
export function verifyReceiptContext(
  receipt: ActionReceipt,
  ctx: ReceiptContext,
): ContextVerifyResult {
  // Null / undefined / non-object rejects at the crypto layer rather than
  // throwing on a downstream property access.
  if (!isRecord(receipt)) {
    return { valid: false, reason: 'INVALID_CLAIM_TYPE' }
  }
  const crypto = verifyActionReceipt(receipt)
  if (!crypto.valid) {
    return { valid: false, reason: crypto.reason as RejectReason }
  }

  // wrong-claim: the receipt is sound but does not make the claim it is
  // being presented to support.
  if (ctx.presented_as_claim_type !== receipt.claim_type) {
    return { valid: false, reason: 'WRONG_CLAIM' }
  }

  // wrong-principal: receipt accountable party is not the expected one.
  if (receipt.agent_did !== ctx.expected_principal_did) {
    return { valid: false, reason: 'WRONG_PRINCIPAL' }
  }

  // revoked delegation: cascade revocation must be honored even if the
  // receipt itself is older than the revocation event.
  if (ctx.revoked_delegation_roots.includes(receipt.delegation_chain_root)) {
    return { valid: false, reason: 'DELEGATION_REVOKED' }
  }

  // expired delegation: the receipt was issued after the chain expired.
  //
  // Both sides are read as instants rather than compared as text. RFC 3339
  // gives one instant many spellings, and lexical order is not temporal order
  // across them: a receipt stamped '2026-01-01T01:00:00.000-09:00' is five
  // hours later than an expiry of '2026-01-01T05:00:00.000Z' and sorts before
  // it, so string comparison accepted a receipt issued after the delegation
  // had expired. The same divergence refused receipts issued before expiry,
  // and ordered two spellings of one instant as strictly apart.
  //
  // A timestamp neither side can read bounds nothing, so it rejects rather
  // than being compared. It reports INVALID_TIMESTAMP rather than
  // DELEGATION_EXPIRED because "the delegation had expired" is a different
  // claim from "this verifier could not tell", and only one of them is true.
  const receiptAt = parseRfc3339(receipt.timestamp)
  const expiresAt = parseRfc3339(ctx.delegation_expires_at)
  if (!receiptAt.ok || !expiresAt.ok) {
    return { valid: false, reason: 'INVALID_TIMESTAMP' }
  }
  if (receiptAt.ms > expiresAt.ms) {
    return { valid: false, reason: 'DELEGATION_EXPIRED' }
  }

  // over-budget: the action draws more than the ceiling allows.
  if (ctx.action_cost_base_units > ctx.budget_base_units) {
    return { valid: false, reason: 'OVER_BUDGET' }
  }

  // stale-policy: the policy version evaluated is older than the active
  // one the verifier now enforces.
  if (ctx.evaluated_policy_version < ctx.active_policy_version) {
    return { valid: false, reason: 'STALE_POLICY' }
  }

  // replay: the receipt_id has already been accepted in this window.
  if (ctx.seen_receipt_ids.includes(receipt.receipt_id)) {
    return { valid: false, reason: 'REPLAYED' }
  }

  // policy-evaluated-but-never-executed: a policy decision is not a
  // proof that the gated action ran. Without an execution attestation
  // the receipt cannot be treated as proof of execution.
  if (!ctx.execution_attested) {
    return { valid: false, reason: 'POLICY_NOT_EXECUTED' }
  }

  // wrong delegation root: the receipt's chain root is not the root this
  // verifier treats as authoritative. Distinct from DELEGATION_REVOKED: a
  // root the verifier does not recognise is not the same as one it has
  // seen revoked. Appended last so every pre-existing first-failure
  // classification is unchanged, per the extend-at-the-end rule above.
  if (receipt.delegation_chain_root !== ctx.active_delegation_root) {
    return { valid: false, reason: 'DELEGATION_ROOT_MISMATCH' }
  }

  return { valid: true }
}
