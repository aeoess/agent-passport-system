// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// ACP — Agentic Commerce Protocol (OpenAI + Stripe), v2025-09-29
// ══════════════════════════════════════════════════════════════════
// ACP is an interaction model for connecting buyers, their AI agents,
// and businesses to complete purchases over a stable REST API. The
// merchant remains the system of record; orders, payments, taxes,
// and compliance run on the merchant's existing commerce stack. ACP
// defines the wire shape of the checkout-session lifecycle that an
// agent platform (e.g. ChatGPT) calls into.
//
// This adapter binds APS V2 governance to ACP at the boundary where
// an agent is about to call a merchant's checkout endpoint. APS
// signs and verifies receipts over each checkout-session operation,
// crosswalks V2Delegation to permitted operations, and maps APS
// denial reasons to ACP error types/codes so the merchant sees a
// well-formed ACP error response instead of a transport failure.
//
// SDK scope: type model + crosswalk + APS-signed receipts/denials
// over canonicalized operation envelopes. Out of scope (gateway
// product): live HTTP transport, webhook routing, multi-tenant
// merchant onboarding, settlement, dispute orchestration.
// ══════════════════════════════════════════════════════════════════

import type { ScopeOfClaim } from '../../accountability/types/base.js'
export type { ScopeOfClaim } from '../../accountability/types/base.js'

/** ACP wire-version header. Date-versioned per the spec. */
export const ACP_API_VERSION = '2025-09-29' as const

// ── Core spec types ───────────────────────────────────────────────

export type AcpCheckoutSessionStatus =
  | 'not_ready_for_payment'
  | 'ready_for_payment'
  | 'in_progress'
  | 'completed'
  | 'canceled'

export interface AcpItem {
  /** Merchant-defined product/SKU id. */
  id: string
  quantity: number
}

export interface AcpLineItem {
  /** ACP-assigned line-item id, distinct from item.id. */
  id: string
  item: AcpItem
  /** All amounts are integers in minor units (e.g. cents). */
  base_amount: number
  discount: number
  subtotal: number
  tax: number
  total: number
}

export interface AcpBuyer {
  first_name: string
  last_name: string
  email: string
}

export interface AcpFulfillmentAddress {
  name: string
  line_one: string
  line_two?: string
  city: string
  state: string
  country: string
  postal_code: string
}

export interface AcpFulfillmentOption {
  type: 'shipping' | 'pickup' | 'digital'
  id: string
  title: string
  subtitle?: string
  carrier?: string
  earliest_delivery_time?: string // ISO 8601
  latest_delivery_time?: string // ISO 8601
  subtotal: number
  tax: number
  total: number
}

/** Stripe is the first PSP; the field is open-string for future PSPs. */
export type AcpPaymentProviderName = 'stripe' | (string & {})
export type AcpPaymentMethod = 'card' | (string & {})

export interface AcpPaymentProvider {
  provider: AcpPaymentProviderName
  supported_payment_methods: AcpPaymentMethod[]
}

/** Token-only — agents NEVER see raw card numbers. PSP mints the token. */
export interface AcpPaymentData {
  token: string
  provider: AcpPaymentProviderName
  billing_address?: AcpFulfillmentAddress
}

export type AcpTotalType =
  | 'items_base_amount'
  | 'subtotal'
  | 'tax'
  | 'discount'
  | 'fulfillment'
  | 'total'

export interface AcpTotal {
  type: AcpTotalType
  display_text: string
  amount: number
}

export type AcpMessageType = 'info' | 'error'
export type AcpMessageContentType = 'plain' | 'markdown'

/** Closed taxonomy from the agentic_checkout RFC. */
export type AcpErrorCode =
  | 'missing'
  | 'invalid'
  | 'out_of_stock'
  | 'payment_declined'
  | 'requires_sign_in'
  | 'requires_3ds'

export interface AcpMessage {
  type: AcpMessageType
  code?: AcpErrorCode
  /** RFC 9535 JSONPath into the request body, when applicable. */
  param?: string
  content_type: AcpMessageContentType
  content: string
}

export interface AcpCheckoutSession {
  id: string
  status: AcpCheckoutSessionStatus
  /** ISO 4217 lowercase. */
  currency: string
  line_items: AcpLineItem[]
  buyer?: AcpBuyer
  fulfillment_address?: AcpFulfillmentAddress
  fulfillment_options?: AcpFulfillmentOption[]
  fulfillment_option_id?: string
  payment_provider?: AcpPaymentProvider
  totals: AcpTotal[]
  messages?: AcpMessage[]
  /** Metadata is opaque to ACP; we use it to carry APS receipt ids. */
  metadata?: Record<string, string>
}

// ── Request shapes ────────────────────────────────────────────────

export interface AcpCreateCheckoutSessionRequest {
  items: AcpItem[]
  buyer?: AcpBuyer
  fulfillment_address?: AcpFulfillmentAddress
}

export interface AcpUpdateCheckoutSessionRequest {
  items?: AcpItem[]
  buyer?: AcpBuyer
  fulfillment_address?: AcpFulfillmentAddress
  fulfillment_option_id?: string
}

export interface AcpCompleteCheckoutSessionRequest {
  payment_data: AcpPaymentData
}

// ── Error envelope ────────────────────────────────────────────────

export type AcpErrorType =
  | 'invalid_request'
  | 'request_not_idempotent'
  | 'processing_error'
  | 'service_unavailable'

export interface AcpErrorResponse {
  type: AcpErrorType
  code?: AcpErrorCode | string
  message: string
  /** RFC 9535 JSONPath. */
  param?: string
}

// ── APS-bound envelopes ───────────────────────────────────────────

/** Which checkout-session operation the receipt/denial covers. */
export type AcpOp = 'create' | 'update' | 'complete' | 'cancel' | 'retrieve'

/**
 * AcpReceipt — APS-signed proof of an ACP checkout-session op (Phase 4.1 / Q1).
 *
 * NEGATIVE EVIDENTIARY SEMANTIC. An AcpReceipt proves:
 *   - An ACP checkout-session operation (create/update/complete/cancel/retrieve)
 *     was issued under a V2Delegation scoped to it
 *   - The canonical request body digest was bound to the delegation_ref
 *   - The merchant's frozen session_state was captured at receipt mint time
 *
 * It does NOT prove:
 *   - Funds settled successfully (ACP op may complete and still be reversed)
 *   - The merchant's legal identity is what `payment_provider.provider` claims
 *   - The buyer received the goods or services
 *   - Idempotency was enforced (caller maintains the idempotency cache)
 *
 * APSBundle aggregators MUST treat an AcpReceipt as evidence of "the ACP
 * op was authorized and crossed the wire" — not "the purchase delivered."
 *
 * Phase 4.1 / Q1 fields (`claim_type`, `timestamp`, `scope_of_claim`) are
 * optional for compatible-superset migration. Receipts minted by the
 * accountability-aligned signing path populate them; legacy receipts
 * continue to verify under the existing per-rail verifier path.
 */
export interface AcpReceipt {
  receipt_id: string
  receipt_kind: 'acp.checkout_session_op'

  /** Pinned to ACP_API_VERSION at receipt mint time. */
  acp_version: typeof ACP_API_VERSION

  op: AcpOp
  session_id: string

  /** APS V2Delegation id; required for non-trivial operations. */
  delegation_ref?: string | null
  agent_id: string
  /** Hex Ed25519 public key of the signer (typically the agent). */
  signer: string

  /** Frozen state attached to this receipt — what the merchant returned. */
  session_state: AcpCheckoutSession

  /** sha256 hex of the canonicalized (JCS) request body. */
  request_digest: string

  /** ISO 8601 UTC with millisecond precision + Z. */
  issued_at: string

  /** Phase 4.1 / Q2: cross-receipt link to the AttributionReceipt this
   *  ACP op is paying against. */
  attribution_receipt_id?: string
  /** Phase 4.1 / Q2: cross-receipt link to the SettlementRecord whose
   *  payment_obligations[] declared this payment. */
  settlement_record_id?: string

  /** Hex Ed25519 signature over the canonical receipt body, sig field cleared. */
  signature: string

  /** Phase 4.1 / Q1: AccountabilityReceiptBase-aligned claim_type literal.
   *  Populated by new signing path with `'rail.acp.v1'`; absent on legacy. */
  claim_type?: 'rail.acp.v1'
  /** Phase 4.1 / Q1: alias of issued_at. */
  timestamp?: string
  /** Phase 4.1 / Q1: scope-of-claim declaration. */
  scope_of_claim?: ScopeOfClaim
}

/** Reasons APS will refuse to allow an ACP operation. */
export type AcpDenialReason =
  | 'spend_limit_exceeded'
  | 'merchant_not_allowed'
  | 'delegation_expired'
  | 'currency_mismatch'
  | 'wallet_revoked'
  | 'no_commerce_scope'
  | 'idempotency_conflict'
  | 'invalid_session_state'
  | 'api_version_mismatch'
  | 'requires_owner_confirmation'

export interface AcpDenial {
  denial_id: string
  denial_kind: 'acp.checkout_session_denial'

  acp_version: typeof ACP_API_VERSION

  op: AcpOp
  session_id?: string | null

  delegation_ref?: string | null
  agent_id: string
  signer: string

  /** APS-side reason — the closed taxonomy above. */
  reason: AcpDenialReason

  /**
   * Mapped ACP error code that the merchant would have surfaced. The
   * mapping is deterministic and lives in apsToAcpError().
   */
  acp_error_code: AcpErrorCode
  acp_error_type: AcpErrorType
  /** JSONPath into the offending field of the original request, when known. */
  acp_error_param?: string | null

  /** sha256 hex of the canonicalized rejected request body. */
  request_digest: string

  issued_at: string
  signature: string

  /** Phase 4.1 / Q1 accountability fields (optional, compatible-superset). */
  claim_type?: 'rail.acp.denial.v1'
  timestamp?: string
  scope_of_claim?: ScopeOfClaim
}

// ── Verification result types ─────────────────────────────────────

export type AcpVerifyReason =
  | 'INVALID_API_VERSION'
  | 'INVALID_RECEIPT_KIND'
  | 'INVALID_OP'
  | 'MISSING_REQUIRED_FIELD'
  | 'SIGNATURE_INVALID'
  | 'EXPIRED'
  | 'DID_RESOLVER_MISSING'
  | 'DID_URI_INVALID'
  | 'DID_DOC_NOT_FOUND'
  | 'DID_KEY_NOT_IN_DOC'
  | 'DID_KEY_RETIRED'

export type AcpVerifyResult =
  | { valid: true }
  | { valid: false; reason: AcpVerifyReason; detail?: string }

// ── Configuration for the ACP rail-side hook ──────────────────────

/**
 * Caller-tunable knobs for the APS gate. Defaults follow the AP2 and
 * Stripe-Issuing adapter conventions: receipts expire 24h after
 * issuance, signer-verification on by default, idempotency-key
 * tracking optional and caller-provided.
 */
export interface AcpHookConfig {
  /** Default 24h. Receipts older than this fail verification. */
  receipt_ttl_seconds?: number
  /** If true, emitted receipts include the buyer email; default false. */
  include_buyer_in_metadata?: boolean
}
