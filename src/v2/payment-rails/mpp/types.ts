// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// MPP — Machine Payments Protocol (Stripe + Tempo + Visa), draft-httpauth-payment-00
// ══════════════════════════════════════════════════════════════════
// MPP is an HTTP authentication scheme for machine-initiated
// payments. Co-authored by Stripe, Tempo, and Visa and announced
// March 18 2026; the IETF draft 'draft-httpauth-payment-00' was
// posted March 30 2026 (mpp.dev, paymentauth.org).
//
// Wire shape: a server returns 402 with a 'WWW-Authenticate: Payment'
// challenge listing one or more payment methods. The client fulfills
// one method (signs a chain transaction, runs a card auth via the
// Visa MPP card spec, settles a Lightning invoice) and retries with
// 'Authorization: Payment' carrying proof. The server then returns
// 200 plus a 'Payment-Receipt' header.
//
// Defining property: payment-method agnostic. Methods are first-class
// protocol extensions — Tempo stablecoins, Stripe cards via the Visa
// MPP card spec, Bitcoin Lightning, and any future scheme bolt on as
// new MppMethod variants without changing the envelope. This is what
// distinguishes MPP from x402, which assumes a USDC-on-EVM
// facilitator and a single 'exact' scheme.
//
// This adapter binds APS V2 governance to MPP at the 402 challenge-
// response boundary. APS signs and verifies receipts over each
// settled payment, crosswalks V2Delegation to permitted methods +
// currencies + per-charge caps, and maps APS denial reasons to MPP
// HTTP error envelopes (status code + WWW-Authenticate error= token)
// so the resource server emits a well-formed 402/403/410/503 instead
// of a transport failure.
//
// SDK scope: type model + crosswalk + APS-signed receipts/denials
// over canonicalized challenge/authorization envelopes. Out of scope
// (gateway product): live HTTP intercept, on-chain settlement
// verification, escrow session orchestration, multi-method routing
// policy, dispute orchestration.
// ══════════════════════════════════════════════════════════════════

/** IETF draft pin. Bump when the upstream draft revision changes. */
import type { ScopeOfClaim } from '../../accountability/types/base.js'
export type { ScopeOfClaim } from '../../accountability/types/base.js'

export const MPP_VERSION = 'draft-httpauth-payment-00' as const

/**
 * Method-type discriminator. The three concrete variants below cover
 * the launch methods (Tempo stablecoin, Visa MPP card, Bitcoin
 * Lightning); the open string tail leaves room for future extensions
 * (e.g. SEPA Instant, ACH, FedNow) without a breaking type change.
 */
export type MppMethodType = 'tempo' | 'card' | 'lightning' | (string & {})

// ── Challenge envelope (server → client, 402 body / header) ───────

/**
 * The payload a server emits in WWW-Authenticate: Payment. The
 * challenge enumerates accepted methods; the client selects one,
 * fulfills it, and references challenge_id in the retry.
 */
export interface MppPaymentChallenge {
  challenge_id: string
  methods: MppMethod[]
  /**
   * String-typed to accommodate non-fiat amounts (chain token decimals,
   * msat) without precision loss. Optional because some methods carry
   * their own amount field (Lightning bolt11, card amount_minor_units).
   */
  required_amount?: string
  /** ISO 4217 lowercase OR token contract address (e.g. 0x20c0... USDC). */
  currency?: string
  /** Canonical URI of the resource being paid for. */
  resource: string
  /** ISO 8601 UTC. After this instant the challenge MUST be rejected. */
  expires_at: string
  /** Server-chosen anti-replay nonce; opaque to the client. */
  nonce: string
}

// ── Method variants (discriminated union on method_type) ──────────

/**
 * Tempo (Stripe + Paradigm L1). Settlement is on-chain; recipient
 * address and currency-as-contract pin the destination. max_amount
 * is the upper bound the client is authorized to send for this
 * challenge — a wallet may settle for less.
 */
export interface MppMethodTempo {
  method_type: 'tempo'
  /** Recipient EOA or contract address, hex with 0x prefix. */
  recipient_address: string
  /** Token contract address — e.g. USDC on Tempo. Empty = native. */
  currency: string
  network: 'mainnet' | 'testnet'
  /** Decimal string, native-denomination units of `currency`. */
  max_amount?: string
}

/**
 * Visa MPP card spec — the agent-driven cardholder-authentication
 * flow. Stripe is the launch acceptance partner; supported_brands
 * enumerates accepted networks. Amounts are minor-unit integers per
 * card-network convention.
 */
export interface MppMethodCard {
  method_type: 'card'
  /** Visa MPP card-spec endpoint the client posts the auth request to. */
  acceptance_url: string
  supported_brands: string[]
  amount_minor_units: number
  /** ISO 4217 lowercase. */
  currency: string
}

/**
 * Bitcoin Lightning. The bolt11 invoice carries amount + payment
 * hash + recipient route hints; amount_msat is denormalized for the
 * gate's convenience but MUST agree with the bolt11 amount.
 */
export interface MppMethodLightning {
  method_type: 'lightning'
  bolt11_invoice: string
  amount_msat: number
}

export type MppMethod = MppMethodTempo | MppMethodCard | MppMethodLightning

// ── Authorization envelope (client → server, retry header) ────────

/**
 * Payload the client sends in Authorization: Payment after
 * fulfilling one of the challenge methods. payment_proof is method-
 * specific: a chain tx hash for tempo, a card auth code for card, a
 * preimage for lightning.
 */
export interface MppAuthorization {
  challenge_id: string
  method_type: MppMethodType
  payment_proof: string
  /** ISO 8601 UTC of when the proof was generated. */
  paid_at: string
}

// ── Receipt envelope (server → client, 200 + Payment-Receipt) ─────

/**
 * The payload servers return in the Payment-Receipt response header
 * (and optionally the response body) after accepting an MPP
 * authorization. The pure MPP receipt is unsigned at the wire layer;
 * APS wraps it in MppApsReceipt below to add a verifiable signature.
 */
export interface MppPaymentReceipt {
  receipt_id: string
  receipt_kind: 'mpp.payment_settled'
  mpp_version: typeof MPP_VERSION
  challenge_id: string
  method_type: MppMethodType
  /** Decimal string, in the units of `currency`. */
  amount_paid: string
  currency: string
  paid_at: string
  resource: string
}

/**
 * MppApsReceipt — APS-signed proof of an MPP 402 → 200 round-trip (Phase 4.1 / Q1).
 *
 * NEGATIVE EVIDENTIARY SEMANTIC. An MppApsReceipt proves:
 *   - An MPP 402 challenge was satisfied by an `Authorization: Payment` proof
 *   - The chosen method_type, currency, and amount fell inside the V2Delegation's
 *     allow-list and per-charge cap at gate time
 *   - The resource server returned a `Payment-Receipt` header
 *
 * It does NOT prove:
 *   - On-chain or processor-side settlement finality
 *     (Tempo/Lightning preimages and card chargeback windows are out of scope)
 *   - The resource served was what the buyer expected
 *   - Replay was prevented (caller maintains the nonce cache)
 *   - The counterparty's legal identity matches the resource URL
 *
 * APSBundle aggregators MUST treat an MppApsReceipt as evidence of "the 402
 * was answered under delegation" — not "settlement is final."
 *
 * Phase 4.1 / Q1 fields (`claim_type`, `timestamp`, `scope_of_claim`) are
 * optional for compatible-superset migration.
 */
export interface MppApsReceipt extends MppPaymentReceipt {
  /** APS V2Delegation id; required for non-trivial settlements. */
  delegation_ref?: string | null
  agent_id: string
  /** Hex Ed25519 public key of the signer (typically the agent). */
  signer: string
  /** ISO 8601 UTC with millisecond precision + Z. */
  issued_at: string
  /** Phase 4.1 / Q2: cross-receipt link to the AttributionReceipt this
   *  payment settles. Intent-side; not Merkle-bound. */
  attribution_receipt_id?: string
  /** Phase 4.1 / Q2: cross-receipt link to the SettlementRecord whose
   *  payment_obligations[] declared this payment. */
  settlement_record_id?: string
  /** Hex Ed25519 signature over the canonical receipt body, sig field cleared. */
  signature: string

  /** Phase 4.1 / Q1: AccountabilityReceiptBase-aligned claim_type. */
  claim_type?: 'rail.mpp.v1'
  /** Phase 4.1 / Q1: alias of issued_at. */
  timestamp?: string
  /** Phase 4.1 / Q1: scope-of-claim declaration. */
  scope_of_claim?: ScopeOfClaim
}

// ── Denial envelope ───────────────────────────────────────────────

/** Closed taxonomy of reasons an APS gate refuses an MPP exchange. */
export type MppDenialReason =
  | 'spend_limit_exceeded'
  | 'method_not_allowed'
  | 'currency_not_allowed'
  | 'delegation_expired'
  | 'no_payment_scope'
  | 'challenge_expired'
  | 'invalid_authorization'
  | 'session_replay'
  | 'wallet_revoked'
  | 'mpp_version_mismatch'
  | 'requires_owner_confirmation'

/**
 * Signed denial — the audit object emitted when APS refuses to allow
 * an MPP challenge or authorization to proceed. Carries both the APS
 * reason taxonomy AND the deterministic HTTP error envelope the
 * resource server would have surfaced (status + WWW-Authenticate
 * error= token from RFC 6750 §3.1), so callers can either re-emit
 * the wire-level 402/403/410/503 or audit the APS-side reason.
 */
export interface MppDenial {
  denial_id: string
  denial_kind: 'mpp.payment_denial'
  mpp_version: typeof MPP_VERSION
  challenge_id?: string | null
  method_type?: MppMethodType | null
  delegation_ref?: string | null
  agent_id: string
  signer: string
  reason: MppDenialReason
  /** Mapped HTTP status the resource server should return. */
  http_status: 402 | 403 | 410 | 503
  /** Mapped RFC 6750-style error= token for the WWW-Authenticate header. */
  www_authenticate_error: 'invalid_request' | 'invalid_token' | 'insufficient_funds' | 'expired'
  issued_at: string
  signature: string

  /** Phase 4.1 / Q1 accountability fields (optional, compatible-superset). */
  claim_type?: 'rail.mpp.denial.v1'
  timestamp?: string
  scope_of_claim?: ScopeOfClaim
}

// ── Verification result types ─────────────────────────────────────

export type MppVerifyReason =
  | 'INVALID_VERSION'
  | 'INVALID_RECEIPT_KIND'
  | 'INVALID_METHOD_TYPE'
  | 'MISSING_REQUIRED_FIELD'
  | 'SIGNATURE_INVALID'
  | 'EXPIRED'
  | 'DID_RESOLVER_MISSING'
  | 'DID_URI_INVALID'
  | 'DID_DOC_NOT_FOUND'
  | 'DID_KEY_NOT_IN_DOC'
  | 'DID_KEY_RETIRED'

export type MppVerifyResult =
  | { valid: true }
  | { valid: false; reason: MppVerifyReason; detail?: string }
