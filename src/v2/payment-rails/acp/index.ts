// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// ACP — Agentic Commerce Protocol adapter (OpenAI + Stripe)
// ══════════════════════════════════════════════════════════════════
// Public functions:
//   preAuthorizeAcpCheckout(req, delegation)  → permit | deny+reason
//   apsToAcpError(reason)                     → AcpErrorType + AcpErrorCode
//   signAcpReceipt(input, privateKeyHex)      → AcpReceipt
//   verifyAcpReceipt(receipt, signerPubHex)   → AcpVerifyResult
//   signAcpDenial(input, privateKeyHex)       → AcpDenial
//   verifyAcpDenial(denial, signerPubHex)     → AcpVerifyResult
//   delegationToAcpAllowed(delegation)        → { allowed_merchants, allowed_currencies, max_total }
//   acpSessionToDelegationHints(session)      → partial V2Delegation derivation
//
// Spec-ambiguity calls (also documented in docs/governance/acp-interop.md):
//   - V2Delegation.scope.action_categories does not map 1:1 to ACP
//     items (ACP is line-item based, APS is action-class based). We
//     surface allowed_merchants and a max_total cents budget; line-
//     item filtering is gateway product, not protocol primitive.
//   - ACP idempotency conflicts produce a deterministic
//     'idempotency_conflict' denial mapped to the ACP error type
//     'request_not_idempotent' with code 'invalid'. Caller maintains
//     the idempotency cache; this adapter only emits the receipt.
//   - Receipt session_state captures whatever the merchant returned;
//     we don't synthesize a session ourselves.
// ══════════════════════════════════════════════════════════════════

import { createHash, randomUUID } from 'node:crypto'
import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { publicKeyFromPrivate, sign, verify as edVerify } from '../../../crypto/keys.js'
import {
  parseDidUri,
  publicKeyHexFromMethod,
  resolveVerificationMethod,
} from '../../../core/did-uri.js'
import type { RotatableDIDDocument } from '../../../types/passport.js'

/** Phase 4.1 / P12 — caller-supplied DID document resolver. */
export type AcpResolveDidDocument = (
  agentId: string,
) => Promise<RotatableDIDDocument | null>

/** Phase 4.1 / P12 — derive the receipt's signer string. When both
 *  agentId and keyRef are supplied, it's a DID URI; otherwise the
 *  legacy raw hex pubkey form. Compatible-superset. */
function _acpSignerFor(
  privateKeyHex: string,
  agentId: string | undefined,
  keyRef: string | undefined,
): string {
  if (agentId && keyRef) {
    if (!agentId.startsWith('did:')) {
      throw new Error(`signAcp*: issuer_agent_id must be a DID, got '${agentId}'`)
    }
    if (keyRef.includes('#')) {
      throw new Error("signAcp*: issuer_key_ref must not contain '#'")
    }
    return `${agentId}#${keyRef}`
  }
  return publicKeyFromPrivate(privateKeyHex)
}
import { verifyOwnerConfirmation } from '../../human-escalation.js'
import type { OwnerConfirmation, V2Delegation } from '../../types.js'
import { csvToList } from '../csv.js'
import { resolveSpendLimitCents } from '../scope-resolution.js'
import type { DenialReason as FoundationDenialReason } from '../types.js'
import {
  ACP_API_VERSION,
} from './types.js'
export { ACP_API_VERSION } from './types.js'
import type {
  AcpCheckoutSession,
  AcpCreateCheckoutSessionRequest,
  AcpDenial,
  AcpDenialReason,
  AcpErrorCode,
  AcpErrorType,
  AcpOp,
  AcpReceipt,
  AcpUpdateCheckoutSessionRequest,
  AcpVerifyResult,
} from './types.js'

// ── Internal canonical helpers ────────────────────────────────────

function sha256Hex(bytes: Uint8Array | string): string {
  const buf = typeof bytes === 'string' ? Buffer.from(bytes, 'utf8') : Buffer.from(bytes)
  return createHash('sha256').update(buf).digest('hex')
}

function canonicalDigest(obj: unknown): string {
  return sha256Hex(canonicalizeJCS(obj))
}

/** Rewrite every present-and-undefined member of a caller-supplied value as an
 *  explicit null, at any depth, returning a copy. canonicalizeJCS() used to
 *  coerce those members to null itself, so the canonical bytes are unchanged;
 *  this exists so the strict canonicalizer of #101 sees the same preimage
 *  instead of throwing on a value the SDK receives rather than builds.
 *
 *  Key presence is preserved exactly: a member that is genuinely absent stays
 *  absent. Rewriting an absent member would ADD "member":null and move bytes.
 *
 *  A top-level undefined is mapped to null too, because the old canonicalizer
 *  returned the four bytes null for it and request_body is typed unknown, so a
 *  caller can pass one. An ARRAY HOLE is deliberately NOT covered: the old
 *  canonicalizer emitted [,1] for a sparse array, which is not valid JSON, so a
 *  hole is now a rejection rather than a preserved byte sequence. */
function _acpNullNormalize<T>(value: T): T {
  if (value === undefined) return null as unknown as T
  if (value === null || typeof value !== 'object') return value
  if (value instanceof Date) return value
  if (Array.isArray(value)) {
    return value.map(v => (v === undefined ? null : _acpNullNormalize(v))) as unknown as T
  }
  const src = value as Record<string, unknown>
  const out: Record<string, unknown> = {}
  for (const key of Object.keys(src)) {
    const v = src[key]
    out[key] = v === undefined ? null : _acpNullNormalize(v)
  }
  return out as T
}


function nowIso(): string {
  return new Date().toISOString()
}

// ── APS ↔ ACP error mapping ───────────────────────────────────────

/**
 * Deterministic mapping from an APS denial reason to the ACP error
 * envelope a merchant would have returned. This is the reverse of
 * the merchant's view: when APS gates an ACP call BEFORE it reaches
 * the merchant, we still emit the ACP-shaped error so the caller can
 * surface it identically to a real merchant response.
 */
export function apsToAcpError(reason: AcpDenialReason): {
  type: AcpErrorType
  code: AcpErrorCode
  /** Optional JSONPath into the ACP request body. */
  param?: string
} {
  switch (reason) {
    case 'spend_limit_exceeded':
      return { type: 'invalid_request', code: 'invalid', param: '$.items' }
    case 'merchant_not_allowed':
      return { type: 'invalid_request', code: 'invalid', param: '$.items[0].id' }
    case 'delegation_expired':
      return { type: 'invalid_request', code: 'requires_sign_in' }
    case 'currency_mismatch':
      return { type: 'invalid_request', code: 'invalid', param: '$.currency' }
    case 'wallet_revoked':
      return { type: 'invalid_request', code: 'payment_declined' }
    case 'no_commerce_scope':
      return { type: 'invalid_request', code: 'requires_sign_in' }
    case 'idempotency_conflict':
      return { type: 'request_not_idempotent', code: 'invalid' }
    case 'invalid_session_state':
      return { type: 'invalid_request', code: 'invalid', param: '$.status' }
    case 'api_version_mismatch':
      return { type: 'service_unavailable', code: 'invalid' }
    case 'requires_owner_confirmation':
      return { type: 'invalid_request', code: 'requires_sign_in' }
  }
}

// ── Tier-2 → Tier-1 vocab crosswalk (Audit B P5) ──────────────────

/**
 * Map an ACP-specific denial reason to the foundation Tier-1
 * DenialReason taxonomy. Generic gateways and audit-log consumers read
 * Tier 1; rail-aware clients can keep reading Tier 2.
 *
 * Mapping policy (also documented in
 * docs/governance/payment-rails-denial-vocabulary.md):
 *   - Direct carryovers stay as themselves
 *     (spend_limit_exceeded, wallet_revoked, no_commerce_scope)
 *   - delegation_expired → time_window_violation
 *     (foundation models all expiry as time-window failures)
 *   - merchant_not_allowed / currency_mismatch / idempotency_conflict
 *     / invalid_session_state / api_version_mismatch
 *     / requires_owner_confirmation → rail_error
 *     (no exact Tier-1 analog; Tier-2 carries the precise reason for
 *     ACP-aware consumers)
 */
export function mapAcpDenialToFoundation(reason: AcpDenialReason): FoundationDenialReason {
  switch (reason) {
    case 'spend_limit_exceeded':
      return 'spend_limit_exceeded'
    case 'wallet_revoked':
      return 'wallet_revoked'
    case 'no_commerce_scope':
      return 'no_commerce_scope'
    case 'delegation_expired':
      return 'time_window_violation'
    case 'merchant_not_allowed':
    case 'currency_mismatch':
    case 'idempotency_conflict':
    case 'invalid_session_state':
    case 'api_version_mismatch':
      return 'rail_error'
    case 'requires_owner_confirmation':
      return 'requires_owner_confirmation'
  }
}

// ── Crosswalk: V2Delegation → ACP authorization envelope ──────────

export interface AcpAllowedFromDelegation {
  /** Merchant identifiers (PSP merchant ids, domains, or platform ids). */
  allowed_merchants: string[]
  /** ISO 4217 lowercase. Empty = no currency constraint. */
  allowed_currencies: string[]
  /** Hard cap in minor units across all line items. null = no cap. */
  max_total: number | null
  /** Token expiry — ISO 8601 of policy_context.valid_until if set. */
  valid_until?: string
}

/**
 * Project a V2Delegation into the subset of ACP context it permits.
 * Used by preAuthorizeAcpCheckout and by callers that want to render
 * a delegation as a buyer-facing summary before initiating a session.
 *
 * Field sourcing (matches AP2 / MPP / Stripe-Issuing conventions):
 *   - max_total ← resolveSpendLimitCents(delegation)
 *     [walks resource_limits.spend_limit_cents → commerce.spend_limit
 *     alias → constraints.spend_limit_cents string]
 *   - allowed_merchants ← scope.constraints.allowed_merchants (CSV)
 *   - allowed_currencies ← scope.constraints.allowed_currencies (CSV)
 *   - valid_until ← policy_context.valid_until
 */
export function delegationToAcpAllowed(delegation: V2Delegation): AcpAllowedFromDelegation {
  const constraints = delegation.scope?.constraints ?? {}

  return {
    allowed_merchants: csvToList(constraints.allowed_merchants),
    allowed_currencies: csvToList(constraints.allowed_currencies).map((s) => s.toLowerCase()),
    max_total: resolveSpendLimitCents(delegation),
    valid_until: delegation.policy_context?.valid_until,
  }
}

// ── Crosswalk: ACP CheckoutSession → V2Delegation hints ───────────

/**
 * One-way derivation: given a CheckoutSession the merchant returned,
 * compute the V2Delegation fields a downstream gateway could pin
 * against. Lossy by design — line-item content does not survive.
 */
export function acpSessionToDelegationHints(session: AcpCheckoutSession): {
  scope: {
    action_categories: string[]
    constraints: {
      allowed_merchants?: string[]
      allowed_currencies: string[]
      spend_limit_cents: number
    }
  }
  notes: string[]
} {
  const totalEntry = session.totals.find((t) => t.type === 'total')
  const totalAmount = totalEntry?.amount ?? 0
  const merchant = session.payment_provider?.provider
  return {
    scope: {
      action_categories: ['commerce'],
      constraints: {
        allowed_merchants: merchant ? [merchant] : undefined,
        allowed_currencies: [session.currency.toLowerCase()],
        spend_limit_cents: totalAmount,
      },
    },
    notes: [
      'lossy: line-item content not preserved in V2Delegation derivation',
      'PSP merchant identifier may differ from settlement merchant id',
    ],
  }
}

// ── Pre-authorization gate ────────────────────────────────────────

export type AcpPreAuthorizeResult =
  | { allow: true }
  | { allow: false; reason: AcpDenialReason; detail?: string }

/** Action class ACP operations slot into for HumanEscalationFlag matching. */
const ACP_ACTION_CLASS = 'commerce' as const

export interface AcpPreAuthorizeOptions {
  /** Owner-signed confirmation, when the delegation declares an
   *  escalation_requirement on action_class 'commerce' with
   *  requires_owner_confirmation: true. The gate runs the full
   *  verifyOwnerConfirmation() chain (signer = delegator, scope
   *  binding, expiry, signature). */
  owner_confirmation?: OwnerConfirmation
  /** Per-action confirmation_scope binds details_hash. ACP defaults
   *  to hashing the canonical request body when omitted. */
  action_details?: Record<string, unknown>
  /** session_id for 'per_session' confirmation scope. */
  session_id?: string | null
  /** Caller-provided clock; defaults to Date.now() in tests/fixtures. */
  now?: Date
}

/**
 * Decide whether a checkout-session request is permitted under a
 * delegation BEFORE the agent calls the merchant. Pure function;
 * no I/O, no side effects, no state. Intended to be the rail-side
 * hook that emits a signed receipt or denial after this returns.
 */
export function preAuthorizeAcpCheckout(
  request: AcpCreateCheckoutSessionRequest | AcpUpdateCheckoutSessionRequest,
  delegation: V2Delegation,
  /** Currency of the merchant's catalog; ACP carries this only on the response. */
  expectedCurrency?: string,
  options: AcpPreAuthorizeOptions = {},
): AcpPreAuthorizeResult {
  // 1. Delegation must include a 'commerce' action category.
  const actionCategories = delegation.scope?.action_categories ?? []
  if (!actionCategories.includes('commerce')) {
    return { allow: false, reason: 'no_commerce_scope', detail: 'delegation lacks commerce scope' }
  }

  // 2. Delegation must not be expired.
  const validUntil = delegation.policy_context?.valid_until
  if (validUntil) {
    const expiresAt = Date.parse(validUntil)
    if (Number.isFinite(expiresAt) && Date.now() > expiresAt) {
      return { allow: false, reason: 'delegation_expired', detail: validUntil }
    }
  }

  // 2.5. HumanEscalationFlag — Audit B P9. If the delegation declares
  // escalation_requirements on the 'commerce' action class with
  // requires_owner_confirmation: true, the caller MUST supply a valid
  // OwnerConfirmation signed by delegator. Without it, deny. With an
  // invalid one, deny too.
  const reqs = delegation.scope?.escalation_requirements
  const matchingReq = reqs?.find(
    (r) => r.action_class === ACP_ACTION_CLASS && r.requires_owner_confirmation,
  )
  if (matchingReq) {
    if (!options.owner_confirmation) {
      return {
        allow: false,
        reason: 'requires_owner_confirmation',
        detail: `action_class '${ACP_ACTION_CLASS}' requires owner confirmation`,
      }
    }
    const verdict = verifyOwnerConfirmation(
      options.owner_confirmation,
      {
        action_class: ACP_ACTION_CLASS,
        action_details: options.action_details ?? (request as Record<string, unknown>),
        session_id: options.session_id ?? null,
      },
      delegation,
      options.now ?? new Date(),
    )
    if (!verdict.valid) {
      return {
        allow: false,
        reason: 'requires_owner_confirmation',
        detail: `invalid owner_confirmation: ${verdict.reason}`,
      }
    }
  }

  const allowed = delegationToAcpAllowed(delegation)

  // 3. Currency check — only if the call provides expectedCurrency.
  if (expectedCurrency && allowed.allowed_currencies.length > 0) {
    if (!allowed.allowed_currencies.includes(expectedCurrency.toLowerCase())) {
      return {
        allow: false,
        reason: 'currency_mismatch',
        detail: `${expectedCurrency} not in [${allowed.allowed_currencies.join(',')}]`,
      }
    }
  }

  // 4. Empty items → invalid session state. Real spend gating runs
  // at session-complete time when authoritative totals are present.
  if ('items' in request && Array.isArray(request.items) && allowed.max_total !== null) {
    const qtyTotal = request.items.reduce((acc, it) => acc + (it.quantity ?? 0), 0)
    if (qtyTotal === 0) {
      return { allow: false, reason: 'invalid_session_state', detail: 'no items' }
    }
  }

  return { allow: true }
}

/**
 * Final spend check, run when a session has been retrieved or
 * completed and authoritative totals are in hand. Separate from
 * preAuthorizeAcpCheckout because totals are a server-side property.
 */
export function checkAcpSessionUnderBudget(
  session: AcpCheckoutSession,
  delegation: V2Delegation,
): AcpPreAuthorizeResult {
  const allowed = delegationToAcpAllowed(delegation)
  if (allowed.max_total === null) return { allow: true }

  const totalEntry = session.totals.find((t) => t.type === 'total')
  if (!totalEntry) {
    return { allow: false, reason: 'invalid_session_state', detail: 'no total entry' }
  }
  if (totalEntry.amount > allowed.max_total) {
    return {
      allow: false,
      reason: 'spend_limit_exceeded',
      detail: `${totalEntry.amount} > ${allowed.max_total}`,
    }
  }

  if (allowed.allowed_currencies.length > 0) {
    if (!allowed.allowed_currencies.includes(session.currency.toLowerCase())) {
      return {
        allow: false,
        reason: 'currency_mismatch',
        detail: `${session.currency} not allowed`,
      }
    }
  }

  return { allow: true }
}

// ── Sign / verify receipts ────────────────────────────────────────

export interface SignAcpReceiptInput {
  op: AcpOp
  session_id: string
  /** Raw ACP request body (will be canonicalized + digested). */
  request_body: unknown
  /** Authoritative session state at receipt mint time. */
  session_state: AcpCheckoutSession
  delegation_ref?: string
  agent_id: string
  /** Phase 4.1 / Q1: opt into the AccountabilityReceiptBase-aligned shape.
   *  When set (or scope_of_claim supplied), the receipt carries
   *  claim_type='rail.acp.v1', timestamp aliasing issued_at, and
   *  scope_of_claim. Default: legacy shape (no new fields). */
  accountability_shape?: boolean
  /** Override the rail's default scope_of_claim. Setting this implies
   *  accountability_shape=true. */
  scope_of_claim?: import('../../accountability/types/base.js').ScopeOfClaim
  /** Phase 4.1 / P12: when supplied alongside `issuer_key_ref`, the
   *  receipt's `signer` field becomes a DID URI of the form
   *  `${issuer_agent_id}#${issuer_key_ref}`. Verifiers resolve this
   *  against the agent's RotatableDIDDocument. When either is omitted,
   *  signer falls back to the legacy raw-hex pubkey form. */
  issuer_agent_id?: string
  issuer_key_ref?: string
  /** Phase 4.1 / Q2: link to the AttributionReceipt this op pays against. */
  attribution_receipt_id?: string
  /** Phase 4.1 / Q2: link to the SettlementRecord whose payment_obligations
   *  declared this payment. */
  settlement_record_id?: string
}

function defaultAcpReceiptScope(): import('../../accountability/types/base.js').ScopeOfClaim {
  return {
    asserts: 'aps:rail.acp:checkout — an ACP checkout-session op was authorized under the cited V2Delegation; request_digest binds the canonical body, session_state the merchant return.',
    does_not_assert: [
      'funds settled (ACP completion can still be reversed)',
      "merchant's legal identity matches payment_provider.provider",
      'goods or services were delivered',
      'idempotency was enforced (caller maintains the cache)',
    ],
    capture_mode: 'gateway_observed',
    completeness: 'complete',
    self_attested: false,
  }
}

export function signAcpReceipt(
  input: SignAcpReceiptInput,
  signerPrivateKeyHex: string,
): AcpReceipt {
  const signerPub = _acpSignerFor(
    signerPrivateKeyHex,
    input.issuer_agent_id,
    input.issuer_key_ref,
  )
  // explicit null: keeps the shipped preimage bytes (#101); omission would change signatures
  const requestDigest = canonicalDigest(_acpNullNormalize(input.request_body))
  const issued_at = nowIso()
  const useAccountabilityShape =
    input.accountability_shape === true || input.scope_of_claim !== undefined

  const unsigned: Omit<AcpReceipt, 'signature'> = {
    receipt_id: `acpr_${randomUUID()}`,
    receipt_kind: 'acp.checkout_session_op',
    acp_version: ACP_API_VERSION,
    op: input.op,
    session_id: input.session_id,
    // explicit null: keeps the shipped preimage bytes (#101); omission would change signatures
    delegation_ref: input.delegation_ref ?? null,
    agent_id: input.agent_id,
    signer: signerPub,
    // explicit null: keeps the shipped preimage bytes (#101); omission would change signatures
    // Returns a rebuilt plain object, so the receipt no longer aliases the
    // caller's session_state. The signed preimage is byte-identical.
    session_state: _acpNullNormalize(input.session_state),
    request_digest: requestDigest,
    issued_at,
  }
  if (useAccountabilityShape) {
    unsigned.claim_type = 'rail.acp.v1'
    unsigned.timestamp = issued_at
    unsigned.scope_of_claim = input.scope_of_claim ?? defaultAcpReceiptScope()
  }
  if (input.attribution_receipt_id !== undefined) {
    unsigned.attribution_receipt_id = input.attribution_receipt_id
  }
  if (input.settlement_record_id !== undefined) {
    unsigned.settlement_record_id = input.settlement_record_id
  }

  const sigBytes = canonicalizeJCS(unsigned)
  const signature = sign(sigBytes, signerPrivateKeyHex)
  return { ...unsigned, signature }
}

const VALID_OPS: ReadonlySet<AcpOp> = new Set([
  'create',
  'update',
  'complete',
  'cancel',
  'retrieve',
])

export interface VerifyAcpReceiptOptions {
  now?: Date
  ttl_seconds?: number
  expected_signer?: string
  /** Phase 4.1 / P12: required when the receipt's `signer` is a DID URI.
   *  The async `verifyAcpReceiptWithDID()` / `verifyAcpDenialWithDID()`
   *  paths invoke this resolver; the sync `verifyAcpReceipt()` ignores it
   *  and returns DID_RESOLVER_MISSING for DID-URI signers. */
  resolveDidDocument?: AcpResolveDidDocument
}

export function verifyAcpReceipt(
  receipt: AcpReceipt,
  options: VerifyAcpReceiptOptions = {},
): AcpVerifyResult {
  const ttl = options.ttl_seconds ?? 24 * 60 * 60

  if (receipt.acp_version !== ACP_API_VERSION) {
    return {
      valid: false,
      reason: 'INVALID_API_VERSION',
      detail: `expected ${ACP_API_VERSION} got ${receipt.acp_version}`,
    }
  }
  if (receipt.receipt_kind !== 'acp.checkout_session_op') {
    return { valid: false, reason: 'INVALID_RECEIPT_KIND', detail: receipt.receipt_kind }
  }
  if (!VALID_OPS.has(receipt.op)) {
    return { valid: false, reason: 'INVALID_OP', detail: receipt.op }
  }
  if (!receipt.session_id || !receipt.agent_id || !receipt.signer) {
    return { valid: false, reason: 'MISSING_REQUIRED_FIELD' }
  }

  if (options.expected_signer && receipt.signer !== options.expected_signer) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'signer mismatch' }
  }

  const issuedMs = Date.parse(receipt.issued_at)
  if (!Number.isFinite(issuedMs)) {
    return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'issued_at' }
  }
  const nowMs = (options.now ?? new Date()).getTime()
  if (nowMs - issuedMs > ttl * 1000) {
    return { valid: false, reason: 'EXPIRED', detail: `older than ${ttl}s` }
  }

  // Phase 4.1 / Q1: when claim_type is set, additionally enforce the
  // accountability-shape invariants. Legacy receipts (no claim_type)
  // skip this block and verify under the existing path.
  if (receipt.claim_type !== undefined) {
    if (receipt.claim_type !== 'rail.acp.v1') {
      return { valid: false, reason: 'INVALID_RECEIPT_KIND', detail: `claim_type=${receipt.claim_type}` }
    }
    if (receipt.timestamp !== receipt.issued_at) {
      return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'timestamp != issued_at' }
    }
    if (
      !receipt.scope_of_claim ||
      typeof receipt.scope_of_claim.asserts !== 'string' ||
      receipt.scope_of_claim.asserts.length === 0
    ) {
      return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'scope_of_claim' }
    }
  }

  // signature verify — strip sig, canonicalize, verify
  const { signature, ...rest } = receipt
  const sigBytes = canonicalizeJCS(rest)
  if (typeof receipt.signer === 'string' && receipt.signer.startsWith('did:')) {
    return {
      valid: false,
      reason: 'DID_RESOLVER_MISSING',
      detail: 'use verifyAcpReceiptWithDID for DID-URI signers',
    }
  }
  if (!edVerify(sigBytes, signature, receipt.signer)) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'Ed25519 verify failed' }
  }
  return { valid: true }
}

/**
 * Phase 4.1 / P12: async verifier that resolves DID URIs against the
 * caller-supplied DID document resolver. Falls back to the legacy
 * raw-hex path when receipt.signer doesn't start with 'did:'.
 */
export async function verifyAcpReceiptWithDID(
  receipt: AcpReceipt,
  options: VerifyAcpReceiptOptions = {},
): Promise<AcpVerifyResult> {
  const sync = verifyAcpReceipt(receipt, options)
  // Reuse the sync function's structural checks (version, op, ttl, …).
  // It returns DID_RESOLVER_MISSING when signer is a DID URI; we replace
  // that with the async resolver path. All other failure reasons we
  // surface as-is.
  if (sync.valid) return sync
  if (sync.reason !== 'DID_RESOLVER_MISSING') return sync

  if (!options.resolveDidDocument) {
    return { valid: false, reason: 'DID_RESOLVER_MISSING' }
  }
  const parsed = parseDidUri(receipt.signer)
  if (!parsed) return { valid: false, reason: 'DID_URI_INVALID' }
  const didDoc = await options.resolveDidDocument(parsed.agentId)
  if (!didDoc) return { valid: false, reason: 'DID_DOC_NOT_FOUND' }
  const issuedMs = Date.parse(receipt.issued_at)
  const result = resolveVerificationMethod(
    didDoc,
    receipt.signer,
    options.now ? options.now.getTime() : undefined,
    Number.isFinite(issuedMs) ? issuedMs : undefined,
  )
  if (!result) return { valid: false, reason: 'DID_KEY_NOT_IN_DOC' }
  if (result.retired) return { valid: false, reason: 'DID_KEY_RETIRED' }
  const pubHex = publicKeyHexFromMethod(result.method)
  const { signature, ...rest } = receipt
  const sigBytes = canonicalizeJCS(rest)
  if (!edVerify(sigBytes, signature, pubHex)) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'Ed25519 verify failed' }
  }
  return { valid: true }
}

// ── Sign / verify denials ─────────────────────────────────────────

export interface SignAcpDenialInput {
  op: AcpOp
  session_id?: string
  request_body: unknown
  reason: AcpDenialReason
  delegation_ref?: string
  agent_id: string
  /** Phase 4.1 / P12: see SignAcpReceiptInput.issuer_agent_id. */
  issuer_agent_id?: string
  issuer_key_ref?: string
}

export function signAcpDenial(
  input: SignAcpDenialInput,
  signerPrivateKeyHex: string,
): AcpDenial {
  const signerPub = _acpSignerFor(
    signerPrivateKeyHex,
    input.issuer_agent_id,
    input.issuer_key_ref,
  )
  // explicit null: keeps the shipped preimage bytes (#101); omission would change signatures
  const requestDigest = canonicalDigest(_acpNullNormalize(input.request_body))
  const mapped = apsToAcpError(input.reason)

  const unsigned: Omit<AcpDenial, 'signature'> = {
    denial_id: `acpd_${randomUUID()}`,
    denial_kind: 'acp.checkout_session_denial',
    acp_version: ACP_API_VERSION,
    op: input.op,
    // explicit null: keeps the shipped preimage bytes (#101); omission would change signatures
    session_id: input.session_id ?? null,
    // explicit null: keeps the shipped preimage bytes (#101); omission would change signatures
    delegation_ref: input.delegation_ref ?? null,
    agent_id: input.agent_id,
    signer: signerPub,
    reason: input.reason,
    acp_error_code: mapped.code,
    acp_error_type: mapped.type,
    // explicit null: keeps the shipped preimage bytes (#101); omission would change signatures
    acp_error_param: mapped.param ?? null,
    request_digest: requestDigest,
    issued_at: nowIso(),
  }

  const sigBytes = canonicalizeJCS(unsigned)
  const signature = sign(sigBytes, signerPrivateKeyHex)
  return { ...unsigned, signature }
}

export function verifyAcpDenial(
  denial: AcpDenial,
  options: VerifyAcpReceiptOptions = {},
): AcpVerifyResult {
  const ttl = options.ttl_seconds ?? 24 * 60 * 60

  if (denial.acp_version !== ACP_API_VERSION) {
    return { valid: false, reason: 'INVALID_API_VERSION' }
  }
  if (denial.denial_kind !== 'acp.checkout_session_denial') {
    return { valid: false, reason: 'INVALID_RECEIPT_KIND' }
  }
  if (!VALID_OPS.has(denial.op)) {
    return { valid: false, reason: 'INVALID_OP' }
  }
  if (!denial.agent_id || !denial.signer || !denial.reason) {
    return { valid: false, reason: 'MISSING_REQUIRED_FIELD' }
  }

  if (options.expected_signer && denial.signer !== options.expected_signer) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'signer mismatch' }
  }

  const issuedMs = Date.parse(denial.issued_at)
  if (!Number.isFinite(issuedMs)) {
    return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'issued_at' }
  }
  const nowMs = (options.now ?? new Date()).getTime()
  if (nowMs - issuedMs > ttl * 1000) {
    return { valid: false, reason: 'EXPIRED' }
  }

  // mapping invariant: stored fields must match deterministic apsToAcpError
  const expected = apsToAcpError(denial.reason)
  if (denial.acp_error_code !== expected.code || denial.acp_error_type !== expected.type) {
    return {
      valid: false,
      reason: 'SIGNATURE_INVALID',
      detail: 'denial mapping mismatch (tampered or version drift)',
    }
  }

  const { signature, ...rest } = denial
  const sigBytes = canonicalizeJCS(rest)
  if (typeof denial.signer === 'string' && denial.signer.startsWith('did:')) {
    return {
      valid: false,
      reason: 'DID_RESOLVER_MISSING',
      detail: 'use verifyAcpDenialWithDID for DID-URI signers',
    }
  }
  if (!edVerify(sigBytes, signature, denial.signer)) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'Ed25519 verify failed' }
  }
  return { valid: true }
}

/**
 * Phase 4.1 / P12: async denial verifier with DID URI support.
 */
export async function verifyAcpDenialWithDID(
  denial: AcpDenial,
  options: VerifyAcpReceiptOptions = {},
): Promise<AcpVerifyResult> {
  const sync = verifyAcpDenial(denial, options)
  if (sync.valid) return sync
  if (sync.reason !== 'DID_RESOLVER_MISSING') return sync

  if (!options.resolveDidDocument) {
    return { valid: false, reason: 'DID_RESOLVER_MISSING' }
  }
  const parsed = parseDidUri(denial.signer)
  if (!parsed) return { valid: false, reason: 'DID_URI_INVALID' }
  const didDoc = await options.resolveDidDocument(parsed.agentId)
  if (!didDoc) return { valid: false, reason: 'DID_DOC_NOT_FOUND' }
  const issuedMs = Date.parse(denial.issued_at)
  const result = resolveVerificationMethod(
    didDoc,
    denial.signer,
    options.now ? options.now.getTime() : undefined,
    Number.isFinite(issuedMs) ? issuedMs : undefined,
  )
  if (!result) return { valid: false, reason: 'DID_KEY_NOT_IN_DOC' }
  if (result.retired) return { valid: false, reason: 'DID_KEY_RETIRED' }
  const pubHex = publicKeyHexFromMethod(result.method)
  const { signature, ...rest } = denial
  const sigBytes = canonicalizeJCS(rest)
  if (!edVerify(sigBytes, signature, pubHex)) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'Ed25519 verify failed' }
  }
  return { valid: true }
}
