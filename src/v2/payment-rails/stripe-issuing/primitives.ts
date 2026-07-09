// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Stripe Issuing — protocol primitives (SDK-side)
// ══════════════════════════════════════════════════════════════════
// Pure functions and constants that define the protocol's contract
// with Stripe Issuing: V2Delegation → SpendingControls mapping,
// V2Delegation → DelegationView projection, the form-urlencoding
// scheme that mirrors what the live rail emits, and the webhook
// signature verifier (HMAC-SHA256 over `${t}.${rawBody}` with
// constant-time comparison).
//
// The orchestration class `StripeIssuingRail` (live HTTP client,
// in-memory card↔delegation registry, credential handling) is
// gateway product. It lives at
// `aeoess-gateway/src/payment-rails/stripe-issuing/index.ts` and
// imports these primitives via the public `agent-passport-system`
// package surface. Splitting the file along this boundary keeps the
// SDK transferable to the Linux Foundation without carrying a
// credential-handling runtime.
// ══════════════════════════════════════════════════════════════════

import { createHmac, timingSafeEqual } from 'node:crypto'
import { csvToList } from '../csv.js'
import { resolveSpendLimitCents } from '../scope-resolution.js'
import type { DelegationView } from '../types.js'
import type { V2Delegation } from '../../types.js'
import type { SpendingControls } from './types.js'

export const DEFAULT_API_BASE = 'https://api.stripe.com'
export const DEFAULT_REQUIRED_SCOPE = 'commerce.purchase'
export const DEFAULT_TOLERANCE_SEC = 300
export const RAIL_NAME = 'stripe-issuing'

// ── Default V2Delegation → SpendingControls mapping ──────────────

/**
 * Reads:
 *   - spend cap via resolveSpendLimitCents() — walks
 *     resource_limits.spend_limit_cents → resource_limits['commerce.spend_limit']
 *     AP2 alias → constraints.spend_limit_cents string fallback
 *   - constraints.allowed_merchant_categories (CSV) → allowed_categories
 *   - constraints.allowed_merchant_countries (CSV)  → allowed_merchant_countries
 *
 * Throws if no positive spend limit can be derived. APS scope categories
 * (e.g. 'commerce.purchase') are intentionally NOT mapped to MCCs;
 * MCC mapping is a domain decision the gateway owns.
 */
export function defaultMapDelegationToSpendingControls(
  delegation: V2Delegation,
): SpendingControls {
  const constraints = delegation.scope.constraints ?? {}

  const limit = resolveSpendLimitCents(delegation)
  if (limit === null || limit <= 0) {
    throw new Error(
      'StripeIssuingRail: delegation must define a positive spend cap (resource_limits.spend_limit_cents, commerce.spend_limit, or constraints.spend_limit_cents)',
    )
  }

  const sc: SpendingControls = {
    spending_limits: [{ amount: Math.floor(limit), interval: 'all_time' }],
  }

  const allowedCats = csvToList(constraints.allowed_merchant_categories)
  if (allowedCats.length > 0) sc.allowed_categories = allowedCats

  const allowedCountries = csvToList(constraints.allowed_merchant_countries)
  if (allowedCountries.length > 0) sc.allowed_merchant_countries = allowedCountries

  return sc
}

// ── V2Delegation → DelegationView (the slim shape preAuthorize uses) ──

/**
 * Project a V2Delegation into the slim DelegationView shape that
 * `preAuthorize` consumes. Pure function; throws on missing or
 * non-positive spend cap. Exported as a primitive so the gateway-side
 * orchestration class can consume it via `agent-passport-system`.
 */
export function delegationToView(
  delegation: V2Delegation,
  apsCurrency: string,
  walletId: string,
): DelegationView {
  const cents = resolveSpendLimitCents(delegation)
  if (cents === null || cents <= 0) {
    throw new Error(
      'delegationToView: delegation must declare a positive spend cap (resource_limits.spend_limit_cents, commerce.spend_limit, or constraints.spend_limit_cents)',
    )
  }
  const view: DelegationView = {
    receipt_id: delegation.id,
    scope: delegation.scope.action_categories.slice(),
    spend_limit_base_units: String(Math.floor(cents)),
    wallet_id: walletId,
    currency: apsCurrency,
    delegator: delegation.delegator,
  }
  if (delegation.policy_context.valid_from !== undefined) {
    view.not_before = delegation.policy_context.valid_from
  }
  if (delegation.policy_context.valid_until !== undefined) {
    view.not_after = delegation.policy_context.valid_until
  }
  if (
    delegation.scope.escalation_requirements !== undefined &&
    delegation.scope.escalation_requirements.length > 0
  ) {
    view.escalation_requirements = delegation.scope.escalation_requirements
  }
  return view
}

// ── Form-urlencoded body builder for Stripe API ──────────────────

/** Stripe's API accepts deeply nested params via PHP-style bracket
 *  notation. We support: scalars, arrays of scalars, and one level of
 *  nesting (object → key[subkey]=value). Exported as a primitive so
 *  the gateway-side orchestration class can pin its on-the-wire body
 *  shape against the same encoder the SDK ships. */
export function encodeForm(obj: Record<string, unknown>): string {
  const parts: string[] = []
  const enc = (k: string, v: unknown): void => {
    if (v === undefined || v === null) return
    if (Array.isArray(v)) {
      for (let i = 0; i < v.length; i++) {
        enc(`${k}[${i}]`, v[i])
      }
      return
    }
    if (typeof v === 'object') {
      for (const [sk, sv] of Object.entries(v as Record<string, unknown>)) {
        enc(`${k}[${sk}]`, sv)
      }
      return
    }
    parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
  }
  for (const [k, v] of Object.entries(obj)) enc(k, v)
  return parts.join('&')
}

// ── Webhook signature verification (Stripe scheme=v1) ────────────

/**
 * Verify a Stripe webhook signature. Header format:
 *   t=<unix_ts>,v1=<hex_hmac_sha256>[,v0=...]
 * Signed payload: `${t}.${rawBody}`
 * Algorithm: HMAC-SHA256 with the webhook signing secret.
 *
 * Returns false on missing parts, malformed header, expired timestamp,
 * or signature mismatch. Constant-time comparison via timingSafeEqual.
 *
 * Bytewise output of this function is part of the protocol contract.
 * Conformance tests pin it; do not alter without an RFC + spec bump.
 */
export function verifyStripeSignature(
  rawBody: string,
  signatureHeader: string,
  webhookSecret: string,
  toleranceSec = DEFAULT_TOLERANCE_SEC,
  nowSec: number = Math.floor(Date.now() / 1000),
): boolean {
  if (!signatureHeader || !webhookSecret) return false
  const parts = signatureHeader.split(',').map((p) => p.trim())
  let t: string | undefined
  const v1s: string[] = []
  for (const p of parts) {
    const eq = p.indexOf('=')
    if (eq < 0) continue
    const k = p.slice(0, eq)
    const v = p.slice(eq + 1)
    if (k === 't') t = v
    else if (k === 'v1') v1s.push(v)
  }
  if (t === undefined || v1s.length === 0) return false

  const ts = Number(t)
  if (!Number.isFinite(ts)) return false
  if (Math.abs(nowSec - ts) > toleranceSec) return false

  const signed = `${t}.${rawBody}`
  const expected = createHmac('sha256', webhookSecret).update(signed, 'utf8').digest()

  for (const candidate of v1s) {
    let buf: Buffer
    try {
      buf = Buffer.from(candidate, 'hex')
    } catch {
      continue
    }
    if (buf.length !== expected.length) continue
    if (timingSafeEqual(buf, expected)) return true
  }
  return false
}

// ── Type re-exports for the primitive surface ─────────────────────
// Types stay in ./types.ts (unchanged); this re-export gives the
// primitive surface a single import target.

export type {
  Authorization,
  AuthorizationDecision,
  AuthorizationEvent,
  CardholderRef,
  DelegationLookup,
  FetchLike,
  MerchantData,
  SpendingControls,
  SpendingControlsMapper,
  SpendingLimit,
  SpendingLimitInterval,
  StripeIssuingConfig,
  VirtualCard,
} from './types.js'
