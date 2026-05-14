// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Payment Rails — public SDK contract
// ══════════════════════════════════════════════════════════════════
// Spec: every payment rail (Nano, Lightning, USDC, Stripe, etc.) MUST
// implement this interface AND wire the GovernanceHooks before money
// moves. The contract:
//
//   1. preAuthorize() runs before any state-changing rail call.
//      Returns a PaymentReceipt skeleton (success path) or a
//      PaymentDenial (fail path). No retry; no partial state.
//
//   2. On rail-side success, emit a fully-signed PaymentReceipt that
//      binds (rail_name, action_ref, delegation_ref, amount, currency,
//      tx_proof) to an Ed25519 signature.
//
//   3. On rail-side failure, emit a fully-signed PaymentDenial citing
//      one of the closed-taxonomy denial_reason values.
//
//   4. revokeRail(walletId) MUST stop subsequent operations bound to
//      the named wallet. Cascade revocation lives outside this SDK
//      (gateway product), but the rail interface guarantees the cut.
//
// The gateway runtime composes these rails with credential storage,
// wallet derivation, and routing. Those stay private. This SDK ships
// the canonical signed-receipt format so audits replay across rails.
// ══════════════════════════════════════════════════════════════════

import type { EscalationRequirement, OwnerConfirmation } from '../types.js'
import type { ScopeOfClaim } from '../accountability/types/base.js'
export type { EscalationRequirement, OwnerConfirmation } from '../types.js'
export type { ScopeOfClaim } from '../accountability/types/base.js'

// ── Closed taxonomies ──────────────────────────────────────────────

export type InvoiceStatus = 'pending' | 'confirmed' | 'expired' | 'failed'

export type DenialReason =
  | 'no_commerce_scope'
  | 'spend_limit_exceeded'
  | 'wallet_revoked'
  | 'time_window_violation'
  | 'rail_error'
  | 'requires_owner_confirmation'

// ── Core data shapes ───────────────────────────────────────────────

export interface PaymentInvoice {
  invoice_id: string
  rail_name: string
  /** Smallest currency unit as a string (raw for Nano, satoshis for LN,
   *  cents for fiat). String form avoids JS number precision loss for
   *  values above 2^53. */
  amount_base_units: string
  /** Human-readable form for display: "0.001 XNO", "4200 sats", "$3.14". */
  amount_human: string
  currency: string
  destination: string
  memo?: string
  status: InvoiceStatus
  created_at: string
  expires_at?: string
  /** Optional opaque metadata. Rails may include rail-specific data
   *  (e.g. expected raw amount for the Nano amount-uniqueness pattern). */
  metadata?: Record<string, unknown>
}

/**
 * PaymentReceipt — proof of rail event occurrence (Phase 4.1 / Q1).
 *
 * NEGATIVE EVIDENTIARY SEMANTIC. A PaymentReceipt proves:
 *   - A payment instruction reached the rail under V2Delegation D
 *   - The rail returned the recorded outcome (tx_proof anchors it)
 *   - The instruction was canonically signed by the issuer
 *
 * It does NOT prove:
 *   - The recipient earned the value
 *     (use AttributionReceipt or DeliveryReceipt — out of scope here)
 *   - The contribution backing the payment was valid
 *   - Settlement is final (rails have refund / dispute / chargeback windows)
 *   - The counterparty's legal identity is what they claim
 *
 * APSBundle aggregators MUST enforce this distinction: a
 * PaymentReceipt in a bundle says "money moved on the rail," NOT
 * "the recipient earned it."
 *
 * Phase 4.1 / Q1 fields (`timestamp`, `scope_of_claim`) are optional
 * for compatible-superset migration. Receipts minted by the new
 * `emitReceipt` path populate them; legacy receipts (no timestamp,
 * no scope_of_claim) continue to verify under the existing path.
 */
export interface PaymentReceipt {
  /** Accepted literals (verifier-side, superset over time):
   *    - Legacy:                   `'aps:payment_receipt:v1'`
   *    - Phase 4.1 / Q1 rail:      `'rail.payment.v1'`
   *    - Vocab #91 / SDK #25 budget_reservation lifecycle:
   *      `'rail.budget_reservation.permit.v1'`
   *      `'rail.budget_reservation.release.v1'`
   *  The default emit path still produces `'rail.payment.v1'` (or legacy
   *  on the legacy emit path); the additional literals are receiver-side
   *  acceptance for receipts issued by Cycles / goodmeta and any other
   *  rail that adopts the budget_reservation namespace. */
  claim_type: string
  /** sha256 hex of canonical(receipt without signature). Content-addressed. */
  receipt_id: string
  /** Ed25519 hex pubkey of the signer (the rail issuer or the gateway). */
  signer_did: string
  /** ISO 8601 UTC ms + Z. */
  issued_at: string
  /** Phase 4.1 / Q1: alias of issued_at for AccountabilityReceiptBase
   *  alignment. New signers populate both with identical values. Optional
   *  for legacy compatibility. */
  timestamp?: string
  /** Phase 4.1 / Q1: AccountabilityReceiptBase scope-of-claim declaration.
   *  Optional on legacy receipts; populated by the new emit path with the
   *  rail's negative-evidentiary defaults. */
  scope_of_claim?: ScopeOfClaim
  /** Receipt_id of the delegation that authorized this spend. */
  delegation_ref: string
  /** action_ref (Module 37 / A2A#1672 hex sha256) that the payment
   *  is bound to. Audit anchor across rails and APS evaluations. */
  action_ref: string
  /** Rail identifier ('nano', 'lightning', 'usdc-base', ...). */
  rail_name: string
  /** Smallest currency unit as a string. */
  amount_base_units: string
  currency: string
  /** Rail-specific transaction proof: block hash (Nano), txid (LN),
   *  charge_id (Stripe), tx hash (EVM). Opaque to APS. */
  tx_proof: string
  /** Optional invoice_id this receipt settles. */
  invoice_id?: string
  /** Phase 4.1 / Q2: cross-receipt link to an AttributionReceipt this
   *  payment is settling. The chain is intent-side: the AttributionReceipt
   *  proves entitlement; this field declares which one. */
  attribution_receipt_id?: string
  /** Phase 4.1 / Q2: cross-receipt link to a SettlementRecord whose
   *  `payment_obligations[]` includes this payment. Pair with
   *  attribution_receipt_id for full chain traversal. */
  settlement_record_id?: string
  /** Ed25519 signature over canonical(receipt with signature emptied), hex. */
  signature: string
}

export interface PaymentDenial {
  /** Accepted literals (verifier-side, superset over time):
   *    - Legacy:                   `'aps:payment_denial:v1'`
   *    - Phase 4.1 / Q1 rail:      `'rail.payment.denial.v1'`
   *    - Vocab #91 / SDK #25 budget_reservation:
   *      `'rail.budget_reservation.denial.v1'`
   *  The default emit path still produces `'rail.payment.denial.v1'` (or
   *  legacy on the legacy emit path); the additional literal is
   *  receiver-side acceptance for denials issued by Cycles / goodmeta and
   *  any other rail that adopts the budget_reservation namespace. */
  claim_type: string
  /** sha256 hex of canonical(denial without signature). */
  receipt_id: string
  /** Ed25519 hex pubkey of the issuer. */
  signer_did: string
  /** ISO 8601 UTC ms + Z. */
  issued_at: string
  /** Phase 4.1 / Q1: alias of issued_at; populated by new emit path. */
  timestamp?: string
  /** Phase 4.1 / Q1: AccountabilityReceiptBase scope-of-claim. */
  scope_of_claim?: ScopeOfClaim
  delegation_ref: string
  action_ref: string
  rail_name: string
  /** Attempted amount, for audit even when denied. */
  amount_base_units: string
  currency: string
  denial_reason: DenialReason
  /** Optional human-readable detail. Closed taxonomy stays in
   *  denial_reason; this field carries context like "scope 'commerce.refund'
   *  not in delegation". */
  reason_detail?: string
  signature: string
}

// ── PaymentRail interface ─────────────────────────────────────────

export interface CreateInvoiceOpts {
  /** Smallest currency unit as a string. Rails accept numeric inputs at
   *  the adapter boundary and convert to base-unit strings here. */
  amount_base_units: string
  settlement_id?: string
  agent_id?: string
  memo?: string
  expires_in_seconds?: number
}

export interface SendPaymentOpts {
  destination: string
  amount_base_units: string
  memo?: string
}

export interface VerifyTransactionResult {
  verified: boolean
  amount_base_units: string
  sender?: string
  receiver?: string
  timestamp?: string
  error?: string
}

export interface PaymentRail {
  readonly name: string
  readonly currency: string

  /** Build a payment request. Rails may add a uniqueness fingerprint
   *  (Nano amount offset, LN payment hash, etc.) inside the returned
   *  invoice; APS does not constrain how. */
  createInvoice(opts: CreateInvoiceOpts): Promise<PaymentInvoice>

  /** Read-only check of invoice state. MUST NOT change anything. */
  checkStatus(invoiceId: string): Promise<PaymentInvoice>

  /** Verify a settled tx is real and matches expected amount. Rails
   *  consult their on-chain or processor API. */
  verifyTransaction(
    txProof: string,
    expectedAmountBaseUnits?: string,
  ): Promise<VerifyTransactionResult>

  /** Stop operations bound to walletId. Idempotent; calling on an
   *  already-revoked wallet returns true without error. Cascade
   *  revocation across rails is the gateway's job. */
  revokeWallet(walletId: string): Promise<boolean>

  /** Returns true if the named wallet is revoked. */
  isWalletRevoked(walletId: string): boolean
}

// ── Pre-authorization input + result ──────────────────────────────

export interface DelegationView {
  /** Receipt_id of the delegation. */
  receipt_id: string
  /** Granted scopes, e.g. ['commerce.purchase', 'commerce.refund']. */
  scope: string[]
  /** Spend limit in the rail's smallest currency unit, as a string. */
  spend_limit_base_units: string
  /** Optional UTC ms timestamps bracketing when this delegation is
   *  permitted to authorize spending. */
  not_before?: string
  not_after?: string
  /** Wallet identifier this delegation is bound to. Rails consult
   *  isWalletRevoked(wallet_id) before authorizing. */
  wallet_id: string
  /** Currency the spend_limit is expressed in. Must match the rail's
   *  currency at preAuthorize time. */
  currency: string
  /** HumanEscalationFlag carry-through. When the underlying V2Delegation
   *  declares per-action-class owner-confirmation requirements, callers
   *  populate this on the DelegationView so the rail's preAuthorize
   *  gate can enforce them. Foundation rails (Nano, x402, Stripe-Issuing)
   *  read this; ACP/MPP read the full V2Delegation directly. */
  escalation_requirements?: EscalationRequirement[]
  /** Ed25519 hex pubkey of the delegator (the owner whose key signs
   *  OwnerConfirmations). Required for verifying any OwnerConfirmation
   *  attached to a PreAuthorizeInput; optional otherwise. */
  delegator?: string
}

export interface PreAuthorizeInput {
  delegation: DelegationView
  required_scope: string
  amount_base_units: string
  currency: string
  /** Caller-provided clock for testing; defaults to Date.now() in
   *  preAuthorize when omitted. */
  now?: Date
  /** Owner-signed confirmation, when the delegation's escalation_requirements
   *  flag the action class as needing one. The gate verifies signer ==
   *  delegation.delegator, action_class match, and expires_at not passed.
   *  When the delegation has no matching escalation requirement, this is
   *  ignored. */
  owner_confirmation?: OwnerConfirmation
  /** Action class to compare against escalation_requirements. Defaults
   *  to required_scope when omitted (foundation rails treat scope strings
   *  like 'commerce.purchase' as the action class). */
  action_class?: string
  /** Per-action confirmation_scope binds details_hash; passing the same
   *  details a confirmation was issued for is required when scope is
   *  'per_action'. Optional otherwise. */
  action_details?: Record<string, unknown>
  /** session_id for 'per_session' confirmation scope. */
  session_id?: string | null
}

export type PreAuthorizeResult =
  | { ok: true }
  | { ok: false; denial_reason: DenialReason; reason_detail?: string }

// ── GovernanceHooks ───────────────────────────────────────────────

export interface EmitReceiptInput {
  delegation_ref: string
  action_ref: string
  rail_name: string
  amount_base_units: string
  currency: string
  tx_proof: string
  invoice_id?: string
  /** Optional override; defaults to new Date().toISOString(). */
  issued_at?: string
  /** Phase 4.1 / Q1: override the rail's default scope_of_claim declaration.
   *  When set (or accountability_shape: true), emit produces the new
   *  AccountabilityReceiptBase-aligned shape: claim_type='rail.payment.v1',
   *  timestamp aliases issued_at, scope_of_claim populated. When neither
   *  is supplied, emit produces the legacy shape (byte-stable to fixtures). */
  scope_of_claim?: ScopeOfClaim
  /** Opt into the Phase 4.1 / Q1 accountability shape without overriding
   *  scope_of_claim. Default false → legacy shape. */
  accountability_shape?: boolean
  /** Phase 4.1 / P12: when supplied alongside `issuer_key_ref`, signer_did
   *  becomes a DID URI of the form `${issuer_agent_id}#${issuer_key_ref}`.
   *  When either is omitted, signer_did falls back to the legacy raw hex
   *  pubkey form (publicKeyFromPrivate). Compatible-superset. */
  issuer_agent_id?: string
  issuer_key_ref?: string
  /** Phase 4.1 / Q2: link to the AttributionReceipt this payment settles. */
  attribution_receipt_id?: string
  /** Phase 4.1 / Q2: link to the SettlementRecord whose payment_obligations
   *  declared this payment. */
  settlement_record_id?: string
}

export interface EmitDenialInput {
  delegation_ref: string
  action_ref: string
  rail_name: string
  amount_base_units: string
  currency: string
  denial_reason: DenialReason
  reason_detail?: string
  /** Optional override; defaults to new Date().toISOString(). */
  issued_at?: string
  /** Phase 4.1 / Q1: override the rail's default scope_of_claim. */
  scope_of_claim?: ScopeOfClaim
  /** Opt into the Phase 4.1 / Q1 accountability shape. */
  accountability_shape?: boolean
  /** Phase 4.1 / P12: see EmitReceiptInput.issuer_agent_id. */
  issuer_agent_id?: string
  issuer_key_ref?: string
}

export interface GovernanceHooks {
  /** MUST be called before any state-changing rail operation. */
  preAuthorize(input: PreAuthorizeInput, rail: PaymentRail): PreAuthorizeResult

  /** Emits a signed PaymentReceipt. Caller provides the issuer's
   *  Ed25519 private key (hex). The signer_did is derived from it. */
  emitReceipt(input: EmitReceiptInput, issuerPrivateKeyHex: string): PaymentReceipt

  /** Emits a signed PaymentDenial. Caller provides the issuer's
   *  Ed25519 private key (hex). */
  emitDenial(input: EmitDenialInput, issuerPrivateKeyHex: string): PaymentDenial
}
