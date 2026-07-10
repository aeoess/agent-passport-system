// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// MPP — Machine Payments Protocol adapter (Stripe + Tempo + Visa)
// ══════════════════════════════════════════════════════════════════
// Public functions:
//   preAuthorizeMppPayment(challenge, delegation) → permit | deny+reason
//   apsToMppHttpError(reason)                     → { http_status, www_authenticate_error }
//   delegationToMppAllowed(delegation)            → { allowed_methods, allowed_currencies, max_amount_per_charge, valid_until }
//   signMppReceipt(input, privateKeyHex)          → MppApsReceipt
//   verifyMppReceipt(receipt, options)            → MppVerifyResult
//   signMppDenial(input, privateKeyHex)           → MppDenial
//   verifyMppDenial(denial, options)              → MppVerifyResult
//
// Spec-ambiguity calls (also documented in docs/governance/mpp-interop.md):
//   - MPP is method-agnostic by design; the per-charge cap lives on
//     the APS side. A challenge may carry multiple methods of which
//     only some are allowed — preAuthorizeMppPayment returns allow:
//     true if AT LEAST ONE method matches the delegation.
//   - Tempo currency is a token contract address; card currency is
//     ISO 4217. Currency comparison is exact-string and lower-cased
//     so '0x20C0...' must match 'allowed_currencies' verbatim.
//   - challenge_expired is checked against options.now (default
//     Date.now()) so the gate runs deterministic in tests.
//   - http_status mapping: 402 for retryable payment failures, 403
//     for hard policy denials (scope/method/currency), 410 for
//     expired delegations or wallet revocation, 503 for version drift.
// ══════════════════════════════════════════════════════════════════

import { randomUUID } from 'node:crypto'
import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { publicKeyFromPrivate, sign, verify as edVerify } from '../../../crypto/keys.js'
import {
  parseDidUri,
  publicKeyHexFromMethod,
  resolveVerificationMethod,
} from '../../../core/did-uri.js'
import type { RotatableDIDDocument } from '../../../types/passport.js'
import { verifyOwnerConfirmation } from '../../human-escalation.js'

export type MppResolveDidDocument = (
  agentId: string,
) => Promise<RotatableDIDDocument | null>

function _mppSignerFor(
  privateKeyHex: string,
  agentId: string | undefined,
  keyRef: string | undefined,
): string {
  if (agentId && keyRef) {
    if (!agentId.startsWith('did:')) {
      throw new Error(`signMpp*: issuer_agent_id must be a DID, got '${agentId}'`)
    }
    if (keyRef.includes('#')) {
      throw new Error("signMpp*: issuer_key_ref must not contain '#'")
    }
    return `${agentId}#${keyRef}`
  }
  return publicKeyFromPrivate(privateKeyHex)
}
import type { OwnerConfirmation, V2Delegation } from '../../types.js'
import { csvToList } from '../csv.js'
import { resolveSpendLimitCents } from '../scope-resolution.js'
import type { DenialReason as FoundationDenialReason } from '../types.js'
import { MPP_VERSION } from './types.js'
export { MPP_VERSION } from './types.js'
import type {
  MppApsReceipt,
  MppDenial,
  MppDenialReason,
  MppMethod,
  MppMethodType,
  MppPaymentChallenge,
  MppVerifyResult,
} from './types.js'

// ── Internal helpers ──────────────────────────────────────────────

function nowIso(): string {
  return new Date().toISOString()
}

// ── APS ↔ MPP HTTP error mapping ──────────────────────────────────

/**
 * Deterministic mapping from an APS denial reason to the MPP-side
 * HTTP envelope a resource server would have returned. Status codes
 * follow the IETF draft's split between 402 (retryable payment
 * issue), 403 (hard policy denial), 410 (gone — token/wallet
 * revoked), and 503 (version mismatch / cannot serve).
 *
 * The www_authenticate_error token follows RFC 6750 §3.1 conventions:
 *   - invalid_request : malformed challenge or authorization
 *   - invalid_token   : payment proof or delegation rejected
 *   - insufficient_funds : APS budget exhausted
 *   - expired         : challenge or delegation past valid_until
 */
export function apsToMppHttpError(reason: MppDenialReason): {
  http_status: 402 | 403 | 410 | 503
  www_authenticate_error:
    | 'invalid_request'
    | 'invalid_token'
    | 'insufficient_funds'
    | 'expired'
} {
  switch (reason) {
    case 'spend_limit_exceeded':
      return { http_status: 402, www_authenticate_error: 'insufficient_funds' }
    case 'method_not_allowed':
      return { http_status: 403, www_authenticate_error: 'invalid_request' }
    case 'currency_not_allowed':
      return { http_status: 403, www_authenticate_error: 'invalid_request' }
    case 'delegation_expired':
      return { http_status: 410, www_authenticate_error: 'expired' }
    case 'no_payment_scope':
      return { http_status: 403, www_authenticate_error: 'invalid_token' }
    case 'challenge_expired':
      return { http_status: 402, www_authenticate_error: 'expired' }
    case 'invalid_authorization':
      return { http_status: 402, www_authenticate_error: 'invalid_token' }
    case 'session_replay':
      return { http_status: 403, www_authenticate_error: 'invalid_request' }
    case 'wallet_revoked':
      return { http_status: 410, www_authenticate_error: 'invalid_token' }
    case 'mpp_version_mismatch':
      return { http_status: 503, www_authenticate_error: 'invalid_request' }
    case 'requires_owner_confirmation':
      return { http_status: 403, www_authenticate_error: 'invalid_token' }
  }
}

// ── Tier-2 → Tier-1 vocab crosswalk (Audit B P5) ──────────────────

/**
 * Map an MPP-specific denial reason to the foundation Tier-1
 * DenialReason taxonomy. See
 * docs/governance/payment-rails-denial-vocabulary.md.
 */
export function mapMppDenialToFoundation(reason: MppDenialReason): FoundationDenialReason {
  switch (reason) {
    case 'spend_limit_exceeded':
      return 'spend_limit_exceeded'
    case 'wallet_revoked':
      return 'wallet_revoked'
    case 'no_payment_scope':
      return 'no_commerce_scope'
    case 'delegation_expired':
    case 'challenge_expired':
      return 'time_window_violation'
    case 'method_not_allowed':
    case 'currency_not_allowed':
    case 'invalid_authorization':
    case 'session_replay':
    case 'mpp_version_mismatch':
      return 'rail_error'
    case 'requires_owner_confirmation':
      return 'requires_owner_confirmation'
  }
}

// ── Crosswalk: V2Delegation → MPP allowed envelope ────────────────

export interface MppAllowedFromDelegation {
  /** Allowed method_type values (open string set). */
  allowed_methods: string[]
  /** ISO 4217 lowercase OR token contract addr. Empty = no constraint. */
  allowed_currencies: string[]
  /** Hard cap per single MPP charge in minor units. null = no cap. */
  max_amount_per_charge: number | null
  /** Token expiry — ISO 8601 of policy_context.valid_until if set. */
  valid_until?: string
}

/**
 * Project a V2Delegation into the MPP context it permits. Used by
 * preAuthorizeMppPayment and by callers that want to render the
 * delegation as a method/currency allow-list before the agent
 * touches the resource.
 *
 * Field sourcing (matches AP2 / ACP / Stripe-Issuing conventions):
 *   - max_amount_per_charge ← resolveSpendLimitCents(delegation)
 *     [walks resource_limits.spend_limit_cents → commerce.spend_limit
 *     alias → constraints.spend_limit_cents string]
 *   - allowed_methods ← scope.constraints.allowed_payment_methods (CSV)
 *   - allowed_currencies ← scope.constraints.allowed_currencies (CSV)
 *   - valid_until ← policy_context.valid_until
 */
export function delegationToMppAllowed(delegation: V2Delegation): MppAllowedFromDelegation {
  const constraints = delegation.scope?.constraints ?? {}

  return {
    allowed_methods: csvToList(constraints.allowed_payment_methods),
    allowed_currencies: csvToList(constraints.allowed_currencies).map((s) => s.toLowerCase()),
    max_amount_per_charge: resolveSpendLimitCents(delegation),
    valid_until: delegation.policy_context?.valid_until,
  }
}

// ── Pre-authorization gate ────────────────────────────────────────

/** Action class MPP exchanges slot into for HumanEscalationFlag matching. */
const MPP_ACTION_CLASS = 'payment' as const

export type MppPreAuthorizeResult =
  | { allow: true }
  | { allow: false; reason: MppDenialReason; detail?: string }

export interface PreAuthorizeMppOptions {
  /** Override for deterministic tests of challenge_expired path. */
  now?: Date
  /** Owner-signed confirmation, when the delegation declares an
   *  escalation_requirement on action_class 'payment' with
   *  requires_owner_confirmation: true. The gate runs the full
   *  verifyOwnerConfirmation() chain. */
  owner_confirmation?: OwnerConfirmation
  /** Per-action confirmation_scope binds details_hash. MPP defaults
   *  to hashing the canonical challenge when omitted. */
  action_details?: Record<string, unknown>
  /** session_id for 'per_session' confirmation scope. */
  session_id?: string | null
}

/**
 * Internal: amount associated with a method, in the unit comparable
 * to scope.resource_limits.spend_limit_cents. Returns null for
 * methods that don't carry an amount we can compare (e.g. tempo with
 * no max_amount or non-fiat denominations).
 */
function methodComparableAmount(method: MppMethod): number | null {
  if (method.method_type === 'card') {
    return method.amount_minor_units
  }
  if (method.method_type === 'lightning') {
    return null
  }
  if (method.method_type === 'tempo') {
    return null
  }
  return null
}

function methodCurrency(method: MppMethod): string {
  if (method.method_type === 'card') return method.currency.toLowerCase()
  if (method.method_type === 'tempo') return method.currency.toLowerCase()
  if (method.method_type === 'lightning') return 'btc'
  return ''
}

/**
 * Decide whether a 402 challenge can be satisfied under a delegation.
 * Pure function; no I/O, no side effects, no state. The gate returns
 * allow:true if AT LEAST ONE listed method matches the delegation's
 * method/currency/amount allow-list and neither the challenge nor
 * the delegation has expired.
 *
 * Fail-closed ordering: scope → delegation expiry → challenge expiry
 * → method allow-list → currency allow-list → per-charge cap. The
 * first failing check decides the reason.
 */
export function preAuthorizeMppPayment(
  challenge: MppPaymentChallenge,
  delegation: V2Delegation,
  options: PreAuthorizeMppOptions = {},
): MppPreAuthorizeResult {
  // 1. Delegation must include a 'payment' action category.
  const actionCategories = delegation.scope?.action_categories ?? []
  if (!actionCategories.includes('payment')) {
    return {
      allow: false,
      reason: 'no_payment_scope',
      detail: 'delegation lacks payment scope',
    }
  }

  const nowMs = (options.now ?? new Date()).getTime()

  // 1.5. HumanEscalationFlag — Audit B P9. If the delegation declares
  // escalation_requirements on the 'payment' action class with
  // requires_owner_confirmation: true, the caller MUST supply a valid
  // OwnerConfirmation signed by delegator.
  const reqs = delegation.scope?.escalation_requirements
  const matchingReq = reqs?.find(
    (r) => r.action_class === MPP_ACTION_CLASS && r.requires_owner_confirmation,
  )
  if (matchingReq) {
    if (!options.owner_confirmation) {
      return {
        allow: false,
        reason: 'requires_owner_confirmation',
        detail: `action_class '${MPP_ACTION_CLASS}' requires owner confirmation`,
      }
    }
    const verdict = verifyOwnerConfirmation(
      options.owner_confirmation,
      {
        action_class: MPP_ACTION_CLASS,
        action_details: options.action_details ?? (challenge as unknown as Record<string, unknown>),
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

  // 2. Delegation must not be expired.
  const validUntil = delegation.policy_context?.valid_until
  if (validUntil) {
    const expiresAt = Date.parse(validUntil)
    if (Number.isFinite(expiresAt) && nowMs > expiresAt) {
      return { allow: false, reason: 'delegation_expired', detail: validUntil }
    }
  }

  // 3. Challenge must not be expired.
  const challengeExpires = Date.parse(challenge.expires_at)
  if (Number.isFinite(challengeExpires) && nowMs > challengeExpires) {
    return { allow: false, reason: 'challenge_expired', detail: challenge.expires_at }
  }

  if (!challenge.methods || challenge.methods.length === 0) {
    return { allow: false, reason: 'invalid_authorization', detail: 'no methods in challenge' }
  }

  const allowed = delegationToMppAllowed(delegation)

  // 4. At least one method must satisfy method/currency/amount.
  let methodMatched = false
  let currencyMatched = false
  let lastReason: MppDenialReason | null = null
  let lastDetail = ''

  for (const method of challenge.methods) {
    if (allowed.allowed_methods.length > 0 && !allowed.allowed_methods.includes(method.method_type)) {
      lastReason = 'method_not_allowed'
      lastDetail = `${method.method_type} not in [${allowed.allowed_methods.join(',')}]`
      continue
    }
    methodMatched = true

    if (allowed.allowed_currencies.length > 0) {
      const cur = methodCurrency(method)
      if (cur && !allowed.allowed_currencies.includes(cur)) {
        lastReason = 'currency_not_allowed'
        lastDetail = `${cur} not in [${allowed.allowed_currencies.join(',')}]`
        continue
      }
    }
    currencyMatched = true

    if (allowed.max_amount_per_charge !== null) {
      const amount = methodComparableAmount(method)
      if (amount !== null && amount > allowed.max_amount_per_charge) {
        lastReason = 'spend_limit_exceeded'
        lastDetail = `${amount} > ${allowed.max_amount_per_charge}`
        continue
      }
    }

    return { allow: true }
  }

  if (lastReason) {
    return { allow: false, reason: lastReason, detail: lastDetail }
  }

  // Defensive: a challenge with methods but no resolvable check failure
  // shouldn't occur, but if it does we surface it as method_not_allowed
  // rather than allow.
  if (!methodMatched) {
    return { allow: false, reason: 'method_not_allowed' }
  }
  if (!currencyMatched) {
    return { allow: false, reason: 'currency_not_allowed' }
  }
  return { allow: true }
}

// ── Sign / verify receipts ────────────────────────────────────────

export interface SignMppReceiptInput {
  challenge_id: string
  method_type: MppMethodType
  amount_paid: string
  currency: string
  paid_at: string
  resource: string
  delegation_ref?: string
  agent_id: string
  /** Phase 4.1 / Q1: opt into AccountabilityReceiptBase shape. */
  accountability_shape?: boolean
  /** Override the rail's default scope_of_claim (implies accountability_shape). */
  scope_of_claim?: import('../../accountability/types/base.js').ScopeOfClaim
  /** Phase 4.1 / P12: when supplied alongside `issuer_key_ref`, signer
   *  becomes a DID URI of the form `${issuer_agent_id}#${issuer_key_ref}`.
   *  Compatible-superset; legacy raw-hex signer when either is omitted. */
  issuer_agent_id?: string
  issuer_key_ref?: string
  /** Phase 4.1 / Q2: link to the AttributionReceipt this MPP exchange
   *  pays against. */
  attribution_receipt_id?: string
  /** Phase 4.1 / Q2: link to the SettlementRecord whose payment_obligations
   *  declared this payment. */
  settlement_record_id?: string
}

function defaultMppReceiptScope(): import('../../accountability/types/base.js').ScopeOfClaim {
  return {
    asserts: 'aps:rail.mpp:authorize — an MPP 402 challenge was satisfied under the cited V2Delegation; the chosen method+currency+amount fell inside the delegation allow-list at gate time.',
    does_not_assert: [
      'on-chain or processor-side settlement finality',
      'the resource served matched buyer expectations',
      'replay was prevented (caller maintains the nonce cache)',
      "counterparty's legal identity matches the resource URL",
    ],
    capture_mode: 'gateway_observed',
    completeness: 'complete',
    self_attested: false,
  }
}

export function signMppReceipt(
  input: SignMppReceiptInput,
  signerPrivateKeyHex: string,
): MppApsReceipt {
  const signerPub = _mppSignerFor(
    signerPrivateKeyHex,
    input.issuer_agent_id,
    input.issuer_key_ref,
  )
  const issued_at = nowIso()
  const useAccountabilityShape =
    input.accountability_shape === true || input.scope_of_claim !== undefined

  const unsigned: Omit<MppApsReceipt, 'signature'> = {
    receipt_id: `mppr_${randomUUID()}`,
    receipt_kind: 'mpp.payment_settled',
    mpp_version: MPP_VERSION,
    challenge_id: input.challenge_id,
    method_type: input.method_type,
    amount_paid: input.amount_paid,
    currency: input.currency,
    paid_at: input.paid_at,
    resource: input.resource,
    delegation_ref: input.delegation_ref,
    agent_id: input.agent_id,
    signer: signerPub,
    issued_at,
  }
  if (useAccountabilityShape) {
    unsigned.claim_type = 'rail.mpp.v1'
    unsigned.timestamp = issued_at
    unsigned.scope_of_claim = input.scope_of_claim ?? defaultMppReceiptScope()
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

export interface VerifyMppOptions {
  now?: Date
  ttl_seconds?: number
  expected_signer?: string
  /** Phase 4.1 / P12: required when signer is a DID URI. The async
   *  `verifyMppReceiptWithDID` / `verifyMppDenialWithDID` paths invoke
   *  this resolver. The sync path returns DID_RESOLVER_MISSING. */
  resolveDidDocument?: MppResolveDidDocument
}

export function verifyMppReceipt(
  receipt: MppApsReceipt,
  options: VerifyMppOptions = {},
): MppVerifyResult {
  const ttl = options.ttl_seconds ?? 24 * 60 * 60

  if (receipt.mpp_version !== MPP_VERSION) {
    return {
      valid: false,
      reason: 'INVALID_VERSION',
      detail: `expected ${MPP_VERSION} got ${receipt.mpp_version}`,
    }
  }
  if (receipt.receipt_kind !== 'mpp.payment_settled') {
    return { valid: false, reason: 'INVALID_RECEIPT_KIND', detail: receipt.receipt_kind }
  }
  if (
    !receipt.challenge_id ||
    !receipt.method_type ||
    !receipt.amount_paid ||
    !receipt.currency ||
    !receipt.resource ||
    !receipt.agent_id ||
    !receipt.signer
  ) {
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

  // Phase 4.1 / Q1: when the accountability shape is in use, enforce its
  // invariants. Legacy receipts (no claim_type) skip this block.
  if (receipt.claim_type !== undefined) {
    if (receipt.claim_type !== 'rail.mpp.v1') {
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
      detail: 'use verifyMppReceiptWithDID for DID-URI signers',
    }
  }
  if (!edVerify(sigBytes, signature, receipt.signer)) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'Ed25519 verify failed' }
  }
  return { valid: true }
}

/** Phase 4.1 / P12: async receipt verifier with DID URI support. */
export async function verifyMppReceiptWithDID(
  receipt: MppApsReceipt,
  options: VerifyMppOptions = {},
): Promise<MppVerifyResult> {
  const sync = verifyMppReceipt(receipt, options)
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

export interface SignMppDenialInput {
  challenge_id?: string
  method_type?: MppMethodType
  reason: MppDenialReason
  delegation_ref?: string
  agent_id: string
  /** Phase 4.1 / P12: see SignMppReceiptInput.issuer_agent_id. */
  issuer_agent_id?: string
  issuer_key_ref?: string
}

export function signMppDenial(
  input: SignMppDenialInput,
  signerPrivateKeyHex: string,
): MppDenial {
  const signerPub = _mppSignerFor(
    signerPrivateKeyHex,
    input.issuer_agent_id,
    input.issuer_key_ref,
  )
  const mapped = apsToMppHttpError(input.reason)

  const unsigned: Omit<MppDenial, 'signature'> = {
    denial_id: `mppd_${randomUUID()}`,
    denial_kind: 'mpp.payment_denial',
    mpp_version: MPP_VERSION,
    challenge_id: input.challenge_id,
    method_type: input.method_type,
    delegation_ref: input.delegation_ref,
    agent_id: input.agent_id,
    signer: signerPub,
    reason: input.reason,
    http_status: mapped.http_status,
    www_authenticate_error: mapped.www_authenticate_error,
    issued_at: nowIso(),
  }

  const sigBytes = canonicalizeJCS(unsigned)
  const signature = sign(sigBytes, signerPrivateKeyHex)
  return { ...unsigned, signature }
}

export function verifyMppDenial(
  denial: MppDenial,
  options: VerifyMppOptions = {},
): MppVerifyResult {
  const ttl = options.ttl_seconds ?? 24 * 60 * 60

  if (denial.mpp_version !== MPP_VERSION) {
    return { valid: false, reason: 'INVALID_VERSION' }
  }
  if (denial.denial_kind !== 'mpp.payment_denial') {
    return { valid: false, reason: 'INVALID_RECEIPT_KIND' }
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

  // mapping invariant: stored fields must match deterministic apsToMppHttpError
  const expected = apsToMppHttpError(denial.reason)
  if (
    denial.http_status !== expected.http_status ||
    denial.www_authenticate_error !== expected.www_authenticate_error
  ) {
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
      detail: 'use verifyMppDenialWithDID for DID-URI signers',
    }
  }
  if (!edVerify(sigBytes, signature, denial.signer)) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'Ed25519 verify failed' }
  }
  return { valid: true }
}

/** Phase 4.1 / P12: async denial verifier with DID URI support. */
export async function verifyMppDenialWithDID(
  denial: MppDenial,
  options: VerifyMppOptions = {},
): Promise<MppVerifyResult> {
  const sync = verifyMppDenial(denial, options)
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
