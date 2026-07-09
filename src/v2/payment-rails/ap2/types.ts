// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// AP2 v0.2 mandate types — TypeScript dict shapes
// ══════════════════════════════════════════════════════════════════
// Pinned to AP2 v0.2 (April 2026). Source schemas:
//   https://github.com/google-agentic-commerce/AP2 @ main
//   code/sdk/schemas/ap2/{checkout_mandate,open_checkout_mandate,
//     payment_mandate,open_payment_mandate}.json
//
// Field names mirror the AP2 JSON schemas exactly. AP2 v0.2 uses
// SD-JWT / JWS for the wire format; this module ships the unsigned
// dict shape and lets callers either:
//   - sign with APS Ed25519 + RFC 8785 JCS (cross-impl APS audit),
//   - or wrap the dict in a JWS at the gateway layer (interop with
//     the Google reference impl).
//
// Convenience aliases match the common informal names:
//   IntentMandate  ≈ OpenCheckoutMandate (open intent / future cart)
//   CartMandate    ≈ CheckoutMandate     (closed cart / specific items)
// ══════════════════════════════════════════════════════════════════

/** Pinned protocol version. Bump when the upstream schema changes. */
import type { ScopeOfClaim } from '../../accountability/types/base.js'
export type { ScopeOfClaim } from '../../accountability/types/base.js'

export const AP2_VERSION = '0.2'

// ── Shared types ──────────────────────────────────────────────────

/** ISO 4217 currency-code string + integer minor-units amount.
 *  Mirrors code/sdk/schemas/ap2/types/amount.json. Example: USD $279.99
 *  is `{ currency: "USD", value: 27999 }`. */
export interface AP2Amount {
  currency: string
  value: number
}

/** A merchant — payee of a CheckoutMandate / PaymentMandate.
 *  Mirrors types/merchant.json's required fields. AP2's full merchant
 *  schema includes optional location/contact fields; this surface
 *  carries the audit-load-bearing fields and lets callers extend. */
export interface AP2Merchant {
  /** Stable merchant identifier. */
  id: string
  /** Human-readable name. */
  name: string
  /** Optional URL of the merchant's site or API. */
  url?: string
}

/** A line item in a checkout cart. Mirrors types/item.json. */
export interface AP2Item {
  id: string
  name: string
  quantity: number
  /** Unit price; per-item cost. Cart subtotal = sum(quantity * unit_price). */
  unit_price: AP2Amount
  description?: string
}

/** Confirmation claim per RFC 7800 §3.1. AP2 uses this for SD-JWT
 *  key binding — the subject's public key that proves possession of
 *  the mandate. APS callers populate this with the delegatee DID. */
export interface AP2Cnf {
  /** JWK form. APS adapter populates with `{ kty: 'OKP', crv: 'Ed25519',
   *  x: <base64url of ed25519 pubkey> }`. */
  jwk?: {
    kty: string
    crv?: string
    x?: string
  }
  /** Alternative form: confirmation key reference (DID, kid, etc.). */
  kid?: string
}

/** AP2 Payment Initiation Service Provider reference. */
export interface AP2Pisp {
  id: string
  name?: string
  url?: string
}

/** AP2 Payment Instrument reference. */
export interface AP2PaymentInstrument {
  /** Instrument type ("card", "ach", "sepa", "nano-wallet", etc.). */
  type: string
  /** Stable instrument id. */
  id: string
  /** Optional last-four / display tag for UI. */
  display?: string
}

// ── CheckoutMandate (closed cart) ─────────────────────────────────
// Schema: code/sdk/schemas/ap2/checkout_mandate.json
// Required AP2 fields: vct, checkout_jwt, checkout_hash.
// Note: real AP2 v0.2 stores the cart inside the merchant-signed
// checkout_jwt (base64url-encoded JWT). For SDK-internal interop we
// also expose the decoded cart contents alongside the JWT so callers
// can audit without decoding the JWT first.

export type AP2VctCheckout = 'mandate.checkout.1'

export interface AP2CheckoutMandate {
  /** Verifiable Credential Type. Always 'mandate.checkout.1'. */
  vct: AP2VctCheckout
  /** base64url-encoded merchant-signed JWT of the checkout payload.
   *  When the gateway emits the mandate it populates this; APS-only
   *  audit may carry an empty string and rely on the decoded cart
   *  fields below. */
  checkout_jwt: string
  /** base64url-encoded sha256 hash of `checkout_jwt`. Uniquely
   *  identifies the checkout. */
  checkout_hash: string
  /** Issued-at Unix epoch (seconds). */
  iat?: number
  /** Expiry Unix epoch (seconds). */
  exp?: number

  // ── APS interop extensions (not in upstream schema) ──
  // These fields let APS callers audit the mandate semantically
  // without decoding the JWT. The gateway integration layer ensures
  // the JWT body matches these values when emitting wire-compatible
  // mandates. Documented as "APS extension fields" in ap2-interop.md.

  /** Decoded payee (merchant). */
  payee?: AP2Merchant
  /** Decoded line items. */
  items?: AP2Item[]
  /** Decoded total amount. */
  total?: AP2Amount
  /** Confirmation key (key binding). */
  cnf?: AP2Cnf
}

// ── OpenCheckoutMandate (open intent / future cart) ───────────────
// Schema: code/sdk/schemas/ap2/open_checkout_mandate.json
// Required: vct, constraints, cnf.

export type AP2VctOpenCheckout = 'mandate.checkout.open.1'

/** Constraint: limit checkouts to a fixed set of merchants. */
export interface AP2AllowedMerchantsConstraint {
  type: 'checkout.allowed_merchants'
  allowed: AP2Merchant[]
}

/** Constraint: required line-item shape for the future checkout. */
export interface AP2LineItemRequirement {
  id: string
  acceptable_items: AP2Item[]
  quantity: number
}

export interface AP2LineItemsConstraint {
  type: 'checkout.line_items'
  items: AP2LineItemRequirement[]
}

export type AP2CheckoutConstraint =
  | AP2AllowedMerchantsConstraint
  | AP2LineItemsConstraint

export interface AP2OpenCheckoutMandate {
  vct: AP2VctOpenCheckout
  constraints: AP2CheckoutConstraint[]
  cnf: AP2Cnf
  iat?: number
  exp?: number
}

// ── PaymentMandate (closed payment authorization) ─────────────────
// Schema: code/sdk/schemas/ap2/payment_mandate.json
// Required: vct, transaction_id, payee, payment_amount, payment_instrument.

export type AP2VctPayment = 'mandate.payment.1'

export interface AP2PaymentMandate {
  vct: AP2VctPayment
  /** base64url-encoded sha256 hash of the originating checkout_jwt. */
  transaction_id: string
  payee: AP2Merchant
  pisp?: AP2Pisp
  payment_amount: AP2Amount
  payment_instrument: AP2PaymentInstrument
  /** ISO 8601 date of execution. Absent = immediate. */
  execution_date?: string
  /** Risk-signal map collected by the trusted surface at mandate time. */
  risk_data?: Record<string, unknown>
  iat?: number
  exp?: number
  /** APS extension: confirmation key for cross-impl audit. */
  cnf?: AP2Cnf
}

// ── OpenPaymentMandate (open authorization to future payments) ────
// Schema: code/sdk/schemas/ap2/open_payment_mandate.json
// Constraint types: agent_recurrence, allowed_payees, allowed_payment_instruments,
//                   allowed_pisps, amount_range, budget, execution_date, payment_reference.

export type AP2VctOpenPayment = 'mandate.payment.open.1'

export interface AP2BudgetConstraint {
  type: 'payment.budget'
  /** Max cumulative amount across all authorized payments. */
  total: AP2Amount
}

export interface AP2AmountRangeConstraint {
  type: 'payment.amount_range'
  min?: AP2Amount
  max?: AP2Amount
}

export interface AP2AllowedPaymentInstrumentsConstraint {
  type: 'payment.allowed_payment_instruments'
  allowed: AP2PaymentInstrument[]
}

export interface AP2AllowedPayeesConstraint {
  type: 'payment.allowed_payees'
  allowed: AP2Merchant[]
}

export interface AP2PaymentReferenceConstraint {
  type: 'payment.payment_reference'
  reference: string
}

export type AP2PaymentConstraint =
  | AP2BudgetConstraint
  | AP2AmountRangeConstraint
  | AP2AllowedPaymentInstrumentsConstraint
  | AP2AllowedPayeesConstraint
  | AP2PaymentReferenceConstraint

export interface AP2OpenPaymentMandate {
  vct: AP2VctOpenPayment
  constraints: AP2PaymentConstraint[]
  cnf: AP2Cnf
  payee?: AP2Merchant
  payment_amount?: AP2Amount
  payment_instrument?: AP2PaymentInstrument
  pisp?: AP2Pisp
  execution_date?: string
  iat?: number
  exp?: number
}

// ── Convenience type aliases ──────────────────────────────────────
// These aliases mirror common informal names callers may prefer.
// Inside AP2 v0.2 the canonical names are CheckoutMandate /
// OpenCheckoutMandate; the aliases below are NOT official AP2 terms.

/** Alias for OpenCheckoutMandate (open intent / future cart). */
export type IntentMandate = AP2OpenCheckoutMandate

/** Alias for CheckoutMandate (closed cart). */
export type CartMandate = AP2CheckoutMandate

/** Discriminated union of every AP2 mandate the SDK supports. */
export type AP2Mandate =
  | AP2CheckoutMandate
  | AP2OpenCheckoutMandate
  | AP2PaymentMandate
  | AP2OpenPaymentMandate

// ── APS-side input shapes ─────────────────────────────────────────

/** Cart details the caller passes to apsToAp2CartMandate. AP2's
 *  CheckoutMandate locks the specific items + price; APS delegations
 *  carry scope and budget but not item lists, so the caller supplies
 *  the cart at conversion time. */
export interface CartDetails {
  payee: AP2Merchant
  items: AP2Item[]
  total: AP2Amount
}

// ── Signed envelope (APS-flavored) ────────────────────────────────
// AP2 v0.2 signs mandates as SD-JWT/JWS at the wire layer. This SDK
// signs the AP2 dict with APS Ed25519 over RFC 8785 JCS so cross-impl
// APS audit can verify without an SD-JWT runtime. The gateway can
// re-encode as JWS for interop with the Google reference impl.

/**
 * SignedAP2Mandate — APS-signed AP2 mandate envelope (Phase 4.1 / Q1).
 *
 * NEGATIVE EVIDENTIARY SEMANTIC. A SignedAP2Mandate proves:
 *   - An AP2 mandate dict was issued and signed by the named APS signer
 *   - The mandate's authority (cnf, iat, exp, vct) is byte-bound by the
 *     Ed25519 signature over canonicalize_jcs(mandate)
 *   - At signing time, the cited V2Delegation's spend cap and validity
 *     window were honored by the construction function
 *
 * It does NOT prove:
 *   - A payment occurred — a mandate is a permission, not a settlement
 *     (see PaymentReceipt or rail-specific receipts for settlement evidence)
 *   - The merchant accepted the mandate at the wire layer (AP2 v0.2 wire
 *     format is SD-JWT; this APS shape is for cross-impl audit only)
 *   - The buyer's identity is what `cnf.jwk` claims (cnf is a key, not an identity)
 *   - Future mandate use will fall inside scope (replay is gateway product)
 *
 * APSBundle aggregators MUST treat a SignedAP2Mandate as evidence of "an
 * AP2 mandate was issued under delegation" — not "payment was made."
 *
 * Phase 4.1 / Q1 fields (`claim_type`, `timestamp`, `scope_of_claim`) are
 * optional for compatible-superset migration.
 */
export interface SignedAP2Mandate<T extends AP2Mandate = AP2Mandate> {
  /** The mandate dict, byte-identical across signing methods. */
  mandate: T
  /** Ed25519 hex public key of the APS-side signer. */
  signer_did: string
  /** Ed25519 hex signature over canonicalize_jcs(mandate). */
  signature: string

  /** Phase 4.1 / Q1: AccountabilityReceiptBase-aligned claim_type. */
  claim_type?: 'rail.ap2.mandate.v1'
  /** Phase 4.1 / Q1: ISO 8601 wall-clock alongside the mandate's iat. */
  timestamp?: string
  /** Phase 4.1 / Q1: scope-of-claim declaration. */
  scope_of_claim?: ScopeOfClaim
  /** Phase 4.1 / Q2: cross-receipt link to the AttributionReceipt this
   *  mandate is paying against. Sits on the envelope, not the mandate
   *  dict, so the AP2 wire-format signature stays byte-identical. */
  attribution_receipt_id?: string
  /** Phase 4.1 / Q2: cross-receipt link to the SettlementRecord whose
   *  payment_obligations[] declared the payment this mandate authorizes. */
  settlement_record_id?: string
}

// ── Mandate-verify result ─────────────────────────────────────────

export type Ap2VerifyReason =
  | 'INVALID_VCT'
  | 'EXPIRED'
  | 'NOT_YET_VALID'
  | 'MISSING_REQUIRED_FIELD'
  | 'SIGNATURE_INVALID'
  | 'DID_RESOLVER_MISSING'
  | 'DID_URI_INVALID'
  | 'DID_DOC_NOT_FOUND'
  | 'DID_KEY_NOT_IN_DOC'
  | 'DID_KEY_RETIRED'

export interface Ap2VerifyResult {
  valid: boolean
  reason?: Ap2VerifyReason
  detail?: string
}
