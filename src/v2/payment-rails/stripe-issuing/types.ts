// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Stripe Issuing adapter — public types
// ══════════════════════════════════════════════════════════════════
// Subsets of the Stripe Issuing API objects relevant to agent-bound
// virtual cards. Field names match Stripe's JSON shape exactly so
// callers can pass through raw API responses without re-keying.
// We do NOT re-export Stripe's full object graph; only the surface
// the rail actually consumes or returns.
// ══════════════════════════════════════════════════════════════════

import type { DelegationView } from '../types.js'

// ── SpendingControls ──────────────────────────────────────────────

export type SpendingLimitInterval =
  | 'per_authorization'
  | 'daily'
  | 'weekly'
  | 'monthly'
  | 'yearly'
  | 'all_time'

export interface SpendingLimit {
  /** Amount in the smallest unit of the card's currency (cents for USD). */
  amount: number
  interval: SpendingLimitInterval
  /** Optional MCC list this limit scopes to. */
  categories?: string[]
}

export interface SpendingControls {
  spending_limits?: SpendingLimit[]
  /** Stripe MCC names. APS scope categories (e.g. 'commerce.purchase')
   *  are NOT MCCs; the mapper translates explicitly via the
   *  `allowed_merchant_categories` constraint. */
  allowed_categories?: string[]
  blocked_categories?: string[]
  allowed_merchant_countries?: string[]
  blocked_merchant_countries?: string[]
  /** Currency code for spending_limits[].amount (lowercase ISO 4217). */
  spending_limits_currency?: string
}

// ── Cardholder + Card ─────────────────────────────────────────────

export interface CardholderRef {
  /** 'ich_...' */
  id: string
  /** Stripe billing.address.country at time of issuance. */
  country?: string
}

export interface VirtualCard {
  /** 'ic_...' */
  id: string
  object: 'issuing.card'
  type: 'virtual'
  status: 'active' | 'inactive' | 'canceled'
  /** Lowercase ISO 4217. */
  currency: string
  cardholder: string | CardholderRef
  spending_controls: SpendingControls
  /** Stripe Card.metadata. The adapter writes:
   *   - aps_delegation_ref: V2Delegation.id (uuid)
   *   - aps_cancel_at_iso: V2Delegation.policy_context.valid_until
   *   - aps_currency: rail currency (uppercase) — distinct from Stripe's
   *     lowercase `currency` so APS-side comparisons stay strict. */
  metadata: Record<string, string>
  created: number
  last4?: string
  exp_month?: number
  exp_year?: number
  brand?: string
}

// ── Authorization (webhook payload) ───────────────────────────────

export interface MerchantData {
  category: string
  /** MCC code, 4-digit. */
  category_code?: string
  city?: string
  country?: string
  name?: string
  network_id?: string
  postal_code?: string
  state?: string
}

export interface Authorization {
  /** 'iauth_...' */
  id: string
  object: 'issuing.authorization'
  /** Smallest currency unit (positive integer; debit auths from Stripe
   *  arrive as positive — Stripe normalizes sign across rails). */
  amount: number
  /** Lowercase ISO 4217. */
  currency: string
  approved: boolean
  status: 'pending' | 'reversed' | 'closed' | 'expired'
  card: { id: string; cardholder: string | CardholderRef; currency?: string }
  merchant_data: MerchantData
  metadata: Record<string, string>
  created: number
  /** Pending request body for realtime decisioning; present on the
   *  issuing_authorization.request event. */
  pending_request?: {
    amount: number
    currency: string
    merchant_amount?: number
    merchant_currency?: string
  }
}

export interface AuthorizationEvent {
  /** Stripe wraps every webhook in an Event object; we only model the
   *  fields the rail uses. */
  id: string
  type: 'issuing_authorization.request' | 'issuing_authorization.created' | string
  created: number
  data: { object: Authorization }
  livemode: boolean
}

// ── Decision returned by the rail ─────────────────────────────────

import type { PaymentDenial, PaymentReceipt, DenialReason } from '../types.js'

export interface AuthorizationDecision {
  /** True iff the rail told Stripe to approve. */
  approved: boolean
  /** Closed-taxonomy denial reason when approved=false. */
  reason?: DenialReason
  /** Free-form detail string; mirrors PaymentDenial.reason_detail. */
  reason_detail?: string
  /** Signed APS PaymentReceipt when approved=true. */
  receipt?: PaymentReceipt
  /** Signed APS PaymentDenial when approved=false. */
  denial?: PaymentDenial
}

// ── Adapter configuration ─────────────────────────────────────────

/** Caller-injected HTTP client. Defaults to global `fetch` in the
 *  factory. Tests pass a mock to avoid live calls. */
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string },
) => Promise<{
  ok: boolean
  status: number
  text: () => Promise<string>
  json?: () => Promise<unknown>
}>

/** Resolves a Stripe card id to the APS DelegationView that authorized
 *  spending on that card. Returns null when the card is unknown to the
 *  gateway (rail will decline the authorization with rail_error). */
export type DelegationLookup = (cardId: string) => DelegationView | null

/** Mapper from a full V2Delegation to Stripe SpendingControls. The
 *  default implementation reads:
 *    - resource_limits.spend_limit_cents      → spending_limits[0].amount
 *    - constraints.allowed_merchant_categories → allowed_categories
 *  Callers with a richer mapping (per-MCC limits, country restrictions)
 *  pass their own. */
export type SpendingControlsMapper = (
  delegation: import('../../types.js').V2Delegation,
) => SpendingControls

export interface StripeIssuingConfig {
  /** Stripe secret key. MUST start with 'sk_test_' for the reference
   *  adapter; the adapter refuses 'sk_live_' to keep the open-source
   *  surface to test mode. */
  apiKey: string
  /** Stripe webhook signing secret ('whsec_...'). Required for
   *  verifyWebhookSignature(); may be omitted if signature verification
   *  is handled upstream (e.g. by a gateway-side webhook router). */
  webhookSecret?: string
  /** Ed25519 issuer private key (hex) used to sign emitted APS
   *  PaymentReceipt and PaymentDenial. */
  issuerPrivateKeyHex: string
  /** Default rail currency in APS form (uppercase ISO 4217), e.g. 'USD'.
   *  Stored in card metadata as aps_currency and copied into
   *  PaymentReceipt.currency. */
  apsCurrency?: string
  /** Stripe currency in lowercase ISO 4217, e.g. 'usd'. Defaults to the
   *  lowercase form of apsCurrency. */
  stripeCurrency?: string
  /** Cardholder id ('ich_...') the gateway pre-created and reuses for
   *  every agent-bound card. Required for provisionAgentCard. */
  defaultCardholder?: string
  /** Override for the Stripe API base URL (used in tests + on-prem). */
  apiBase?: string
  /** Injected fetch for tests; defaults to global fetch. */
  fetch?: FetchLike
  /** Override the default V2Delegation → SpendingControls mapping. */
  spendingControlsMapper?: SpendingControlsMapper
  /** Resolves a Stripe card id to the APS DelegationView. Defaults to
   *  the in-memory map populated by provisionAgentCard. */
  delegationLookup?: DelegationLookup
  /** Required scope the rail enforces during webhook handling.
   *  Defaults to 'commerce.purchase'. */
  requiredScope?: string
  /** Allowed clock skew (seconds) for webhook signature verification.
   *  Defaults to 300 (Stripe's recommended tolerance). */
  webhookToleranceSec?: number
}
