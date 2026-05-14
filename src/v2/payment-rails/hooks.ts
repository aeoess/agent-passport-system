// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Payment Rails — composable governance hooks
// ══════════════════════════════════════════════════════════════════
// preAuthorize, emitReceipt, emitDenial. Pure functions; no DB,
// no event bus, no env. Rails embed these (or a custom GovernanceHooks
// implementation) to satisfy the contract from types.ts.
//
// Verification helpers verifyPaymentReceipt + verifyPaymentDenial
// reproduce the receipt_id and check the Ed25519 signature against
// the stored signer_did. Mirrors the failure-mode taxonomy in
// src/v2/accountability/verify/*.ts: INVALID_CLAIM_TYPE,
// RECEIPT_ID_MISMATCH, SIGNATURE_INVALID, plus payment-specific
// INVALID_DENIAL_REASON for denial verification.
// ══════════════════════════════════════════════════════════════════

import { sign, publicKeyFromPrivate, verify as edVerify } from '../../crypto/keys.js'
import { canonicalize } from '../../core/canonical.js'
import { createHash } from 'node:crypto'
import {
  parseDidUri,
  resolveVerificationMethod,
  publicKeyHexFromMethod,
} from '../../core/did-uri.js'
import type { RotatableDIDDocument } from '../../types/passport.js'
import {
  canonicalizeDenialForId,
  canonicalizeDenialForSig,
  canonicalizeReceiptForId,
  canonicalizeReceiptForSig,
  sha256Hex,
} from './canonicalize.js'
import type {
  DelegationView,
  DenialReason,
  EmitDenialInput,
  EmitReceiptInput,
  GovernanceHooks,
  PaymentDenial,
  PaymentRail,
  PaymentReceipt,
  PreAuthorizeInput,
  PreAuthorizeResult,
} from './types.js'
import type { OwnerConfirmation } from '../types.js'
import type { ScopeOfClaim } from '../accountability/types/base.js'

// Phase 4.1 / Q1 — accountability-aligned claim_type literals. Verifier
// accepts both the legacy 'aps:*:v1' and the new 'rail.*' literals so
// previously-issued receipts continue to verify.
const RAIL_PAYMENT_RECEIPT_CLAIM_TYPE = 'rail.payment.v1' as const
const LEGACY_PAYMENT_RECEIPT_CLAIM_TYPE = 'aps:payment_receipt:v1' as const
const RAIL_PAYMENT_DENIAL_CLAIM_TYPE = 'rail.payment.denial.v1' as const
const LEGACY_PAYMENT_DENIAL_CLAIM_TYPE = 'aps:payment_denial:v1' as const

// budget_reservation namespace (vocab #91, SDK #25). Three lifecycle
// literals confirmed by Cycles (amavashev) and goodmeta (Ectsang).
// Verifier-side acceptance only — no emit path change in this commit.
// permit + release ride the receipt-verify path; denial rides the
// denial-verify path.
const RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE = 'rail.budget_reservation.permit.v1' as const
const RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE = 'rail.budget_reservation.release.v1' as const
const RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE = 'rail.budget_reservation.denial.v1' as const

/** Default scope_of_claim for foundation receipts. Override via
 *  EmitReceiptInput.scope_of_claim when caller has a richer assertion. */
function defaultPaymentReceiptScope(): ScopeOfClaim {
  return {
    asserts: 'aps:rail.payment:emit — a payment instruction was emitted on the rail under the named delegation; tx_proof anchors the rail-side outcome.',
    does_not_assert: [
      'recipient earned the value',
      'underlying contribution validity',
      'settlement finality (rails have dispute/refund/chargeback windows)',
      'counterparty legal identity',
    ],
    capture_mode: 'gateway_observed',
    completeness: 'complete',
    self_attested: false,
  }
}

function defaultPaymentDenialScope(): ScopeOfClaim {
  return {
    asserts: 'aps:rail.payment:deny — a payment instruction was refused on the rail with a closed-taxonomy denial reason.',
    does_not_assert: [
      'the rail itself is unavailable',
      'the agent acted maliciously',
      'the underlying delegation is invalid (denial may flag a single missing constraint)',
    ],
    capture_mode: 'gateway_observed',
    completeness: 'complete',
    self_attested: false,
  }
}

const VALID_DENIAL_REASONS: readonly DenialReason[] = [
  'no_commerce_scope',
  'spend_limit_exceeded',
  'wallet_revoked',
  'time_window_violation',
  'rail_error',
  'requires_owner_confirmation',
]

function _nowIso(): string {
  const d = new Date()
  return d.toISOString()
}

// ── Escalation gate (HumanEscalationFlag, Audit B P9) ─────────────

/** Hash action_details exactly the way human-escalation.ts does so a
 *  confirmation issued via recordOwnerConfirmation matches a foundation-
 *  side per_action verification. Mirrors human-escalation.ts:39. */
function _hashActionDetails(details: Record<string, unknown>): string {
  return createHash('sha256').update(JSON.stringify(details)).digest('hex')
}

/** Slim verifier for the foundation gate. Mirrors the cryptographic
 *  half of verifyOwnerConfirmation in human-escalation.ts but works
 *  with DelegationView (no full V2Delegation): verifies signature,
 *  delegation_id binding, action_class match, expiry, and the
 *  scope-specific binding (per_action details hash, per_session
 *  session_id). ACP and MPP keep using verifyOwnerConfirmation
 *  directly because they have V2Delegation in hand. */
type ConfirmationVerdict = { valid: true } | { valid: false; reason: string }

function _verifyOwnerConfirmationAgainstView(
  confirmation: OwnerConfirmation,
  view: DelegationView,
  action_class: string,
  action_details: Record<string, unknown> | undefined,
  session_id: string | null | undefined,
  now: Date,
): ConfirmationVerdict {
  if (!view.delegator) {
    return { valid: false, reason: 'DelegationView.delegator missing — cannot verify signature' }
  }
  if (confirmation.delegation_id !== view.receipt_id) {
    return { valid: false, reason: 'delegation_id mismatch' }
  }
  if (confirmation.confirmed_by !== view.delegator) {
    return { valid: false, reason: 'confirmed_by is not the delegator' }
  }
  if (now.getTime() > Date.parse(confirmation.expires_at)) {
    return { valid: false, reason: 'confirmation expired' }
  }
  if (confirmation.action_class !== action_class) {
    return { valid: false, reason: 'action_class mismatch' }
  }
  if (confirmation.confirmation_scope === 'per_action') {
    if (action_details === undefined) {
      return { valid: false, reason: 'per_action confirmation requires action_details on input' }
    }
    if (confirmation.action_details_hash !== _hashActionDetails(action_details)) {
      return { valid: false, reason: 'per_action details hash mismatch' }
    }
  } else if (confirmation.confirmation_scope === 'per_session') {
    if (!session_id || confirmation.session_id !== session_id) {
      return { valid: false, reason: 'per_session session_id mismatch' }
    }
  }
  // Signature verify — mirror bridge.ts:verifyObject exactly: strip
  // signature, run canonicalize() (null-stripping, NOT JCS), sha256 hex,
  // ed25519 verify.
  const { signature, ...rest } = confirmation
  const hash = createHash('sha256').update(canonicalize(rest)).digest('hex')
  if (!edVerify(hash, signature, view.delegator)) {
    return { valid: false, reason: 'signature verification failed' }
  }
  return { valid: true }
}

// ── preAuthorize ──────────────────────────────────────────────────

/**
 * Decide whether a delegation may authorize the requested spend on
 * the given rail. Pure function; no I/O.
 *
 * Order of checks (matches the denial_reason taxonomy precedence):
 *   1. wallet_revoked       — rail.isWalletRevoked(delegation.wallet_id)
 *   2. no_commerce_scope    — required_scope not in delegation.scope
 *   3. time_window_violation — outside [not_before, not_after]
 *   4. spend_limit_exceeded — amount > delegation.spend_limit_base_units
 *      OR currency mismatch between delegation and request
 *
 * Currency mismatch maps to spend_limit_exceeded (the spend limit is
 * denominated in delegation.currency; a request in a different
 * currency cannot be measured against it). Rail integrators that
 * want a separate error code can wrap preAuthorize and re-route.
 */
export function preAuthorize(
  input: PreAuthorizeInput,
  rail: PaymentRail,
): PreAuthorizeResult {
  const { delegation, required_scope, amount_base_units, currency } = input

  if (rail.isWalletRevoked(delegation.wallet_id)) {
    return { ok: false, denial_reason: 'wallet_revoked' }
  }

  if (!delegation.scope.includes(required_scope)) {
    return {
      ok: false,
      denial_reason: 'no_commerce_scope',
      reason_detail: `scope '${required_scope}' not in delegation`,
    }
  }

  // HumanEscalationFlag (Audit B P9). Run before time-window and
  // spend-limit so a flagged action surfaces the confirmation request
  // rather than a generic denial. Caller-supplied action_class falls
  // back to required_scope; that lets foundation rails tag scope
  // strings ('commerce.purchase') as the action class without an extra
  // input field.
  const action_class = input.action_class ?? required_scope
  const reqs = delegation.escalation_requirements
  const matchingReq = reqs?.find(
    (r) => r.action_class === action_class && r.requires_owner_confirmation,
  )
  if (matchingReq) {
    if (!input.owner_confirmation) {
      return {
        ok: false,
        denial_reason: 'requires_owner_confirmation',
        reason_detail: `action_class '${action_class}' requires owner confirmation`,
      }
    }
    const verdict = _verifyOwnerConfirmationAgainstView(
      input.owner_confirmation,
      delegation,
      action_class,
      input.action_details,
      input.session_id ?? null,
      input.now ?? new Date(),
    )
    if (!verdict.valid) {
      return {
        ok: false,
        denial_reason: 'requires_owner_confirmation',
        reason_detail: `invalid owner_confirmation: ${verdict.reason}`,
      }
    }
  }

  const now = input.now ?? new Date()
  if (delegation.not_before !== undefined) {
    const nb = Date.parse(delegation.not_before)
    if (!Number.isNaN(nb) && now.getTime() < nb) {
      return {
        ok: false,
        denial_reason: 'time_window_violation',
        reason_detail: `not_before=${delegation.not_before}`,
      }
    }
  }
  if (delegation.not_after !== undefined) {
    const na = Date.parse(delegation.not_after)
    if (!Number.isNaN(na) && now.getTime() > na) {
      return {
        ok: false,
        denial_reason: 'time_window_violation',
        reason_detail: `not_after=${delegation.not_after}`,
      }
    }
  }

  if (delegation.currency !== currency) {
    return {
      ok: false,
      denial_reason: 'spend_limit_exceeded',
      reason_detail: `currency mismatch: delegation=${delegation.currency} request=${currency}`,
    }
  }

  // Compare base-unit strings as BigInt to handle values above 2^53.
  let limit: bigint
  let amount: bigint
  try {
    limit = BigInt(delegation.spend_limit_base_units)
    amount = BigInt(amount_base_units)
  } catch {
    return {
      ok: false,
      denial_reason: 'rail_error',
      reason_detail: 'amount_base_units or spend_limit_base_units not a valid integer string',
    }
  }
  if (amount > limit) {
    return {
      ok: false,
      denial_reason: 'spend_limit_exceeded',
      reason_detail: `amount=${amount} limit=${limit}`,
    }
  }

  return { ok: true }
}

// ── emitReceipt ───────────────────────────────────────────────────

/**
 * Phase 4.1 / P12: when both `issuerAgentId` AND `issuerKeyRef` are
 * supplied on EmitReceiptInput, signer_did takes the form
 * `${issuerAgentId}#${issuerKeyRef}` (a DID URI). The verifier resolves
 * this against the agent's RotatableDIDDocument and checks retiredAt.
 * When either is missing, signer_did falls back to the legacy raw hex
 * pubkey (publicKeyFromPrivate). Compatible-superset.
 */
function _signerDidFor(
  privateKeyHex: string,
  agentId: string | undefined,
  keyRef: string | undefined,
): string {
  if (agentId && keyRef) {
    if (!agentId.startsWith('did:')) {
      throw new Error(
        `_signerDidFor: issuerAgentId must be a DID, got '${agentId}'`,
      )
    }
    if (keyRef.includes('#')) {
      throw new Error("_signerDidFor: issuerKeyRef must not contain '#'")
    }
    return `${agentId}#${keyRef}`
  }
  return publicKeyFromPrivate(privateKeyHex)
}

export function emitReceipt(
  input: EmitReceiptInput,
  issuerPrivateKeyHex: string,
): PaymentReceipt {
  const signer_did = _signerDidFor(
    issuerPrivateKeyHex,
    input.issuer_agent_id,
    input.issuer_key_ref,
  )
  const issued_at = input.issued_at ?? _nowIso()

  // Phase 4.1 / Q1: emit produces byte-stable legacy shape by default to
  // preserve fixture-pinned byte-parity tests. Callers opting into the
  // accountability-aligned shape pass `accountability_shape: true` (or
  // supply a `scope_of_claim`); the resulting receipt carries the new
  // claim_type literal, timestamp alias, and scope_of_claim. The verifier
  // accepts both shapes so the migration is compatible-superset.
  const useAccountabilityShape =
    input.accountability_shape === true || input.scope_of_claim !== undefined

  const draft: PaymentReceipt = {
    claim_type: useAccountabilityShape
      ? RAIL_PAYMENT_RECEIPT_CLAIM_TYPE
      : LEGACY_PAYMENT_RECEIPT_CLAIM_TYPE,
    receipt_id: '',
    signer_did,
    issued_at,
    delegation_ref: input.delegation_ref,
    action_ref: input.action_ref,
    rail_name: input.rail_name,
    amount_base_units: input.amount_base_units,
    currency: input.currency,
    tx_proof: input.tx_proof,
    signature: '',
  }
  if (useAccountabilityShape) {
    draft.timestamp = issued_at
    draft.scope_of_claim = input.scope_of_claim ?? defaultPaymentReceiptScope()
  }
  if (input.invoice_id !== undefined) {
    draft.invoice_id = input.invoice_id
  }
  if (input.attribution_receipt_id !== undefined) {
    draft.attribution_receipt_id = input.attribution_receipt_id
  }
  if (input.settlement_record_id !== undefined) {
    draft.settlement_record_id = input.settlement_record_id
  }

  const receipt_id = sha256Hex(canonicalizeReceiptForId(draft))
  const withId: PaymentReceipt = { ...draft, receipt_id }
  const signature = sign(canonicalizeReceiptForSig(withId), issuerPrivateKeyHex)
  return { ...withId, signature }
}

// ── emitDenial ────────────────────────────────────────────────────

export function emitDenial(
  input: EmitDenialInput,
  issuerPrivateKeyHex: string,
): PaymentDenial {
  if (!VALID_DENIAL_REASONS.includes(input.denial_reason)) {
    throw new Error(
      `emitDenial: denial_reason must be one of ${VALID_DENIAL_REASONS.join(' | ')}, got '${input.denial_reason}'`,
    )
  }
  const signer_did = _signerDidFor(
    issuerPrivateKeyHex,
    input.issuer_agent_id,
    input.issuer_key_ref,
  )
  const issued_at = input.issued_at ?? _nowIso()

  const useAccountabilityShape =
    input.accountability_shape === true || input.scope_of_claim !== undefined

  const draft: PaymentDenial = {
    claim_type: useAccountabilityShape
      ? RAIL_PAYMENT_DENIAL_CLAIM_TYPE
      : LEGACY_PAYMENT_DENIAL_CLAIM_TYPE,
    receipt_id: '',
    signer_did,
    issued_at,
    delegation_ref: input.delegation_ref,
    action_ref: input.action_ref,
    rail_name: input.rail_name,
    amount_base_units: input.amount_base_units,
    currency: input.currency,
    denial_reason: input.denial_reason,
    signature: '',
  }
  if (useAccountabilityShape) {
    draft.timestamp = issued_at
    draft.scope_of_claim = input.scope_of_claim ?? defaultPaymentDenialScope()
  }
  if (input.reason_detail !== undefined) {
    draft.reason_detail = input.reason_detail
  }

  const receipt_id = sha256Hex(canonicalizeDenialForId(draft))
  const withId: PaymentDenial = { ...draft, receipt_id }
  const signature = sign(canonicalizeDenialForSig(withId), issuerPrivateKeyHex)
  return { ...withId, signature }
}

// ── Verification ──────────────────────────────────────────────────

export type ReceiptVerifyReason =
  | 'INVALID_CLAIM_TYPE'
  | 'RECEIPT_ID_MISMATCH'
  | 'SIGNATURE_INVALID'
  | 'DID_RESOLVER_MISSING'
  | 'DID_URI_INVALID'
  | 'DID_DOC_NOT_FOUND'
  | 'DID_KEY_NOT_IN_DOC'
  | 'DID_KEY_RETIRED'

export interface ReceiptVerifyResult {
  valid: boolean
  reason?: ReceiptVerifyReason
}

/** Phase 4.1 / P12: caller-supplied DID document resolver. Verifier
 *  invokes this when `signer_did` is a DID URI; returns the agent's
 *  RotatableDIDDocument or null when the agent is unknown. */
export type ResolveDidDocument = (
  agentId: string,
) => Promise<RotatableDIDDocument | null>

export interface VerifyReceiptOptions {
  /** Required when `receipt.signer_did` is a DID URI. Omit for legacy
   *  raw-hex receipts. */
  resolveDidDocument?: ResolveDidDocument
  /** Verification clock; defaults to Date.now(). */
  now?: Date
}

/**
 * Sync legacy verifier. Kept for backwards compatibility — receipts
 * carrying a raw hex signer_did continue to verify here without any
 * options. When `receipt.signer_did` is a DID URI (starts with 'did:'),
 * this path returns DID_RESOLVER_MISSING; callers must use the async
 * `verifyPaymentReceiptWithDID()` path with a resolveDidDocument.
 */
export function verifyPaymentReceipt(receipt: PaymentReceipt): ReceiptVerifyResult {
  // Phase 4.1 / Q1: accept both legacy and accountability-aligned literals.
  // Vocab #91 / SDK #25: also accept the two budget_reservation receipt
  // literals (permit, release). The denial literal is handled in
  // verifyPaymentDenial; this path is receipt-only.
  if (
    receipt.claim_type !== LEGACY_PAYMENT_RECEIPT_CLAIM_TYPE &&
    receipt.claim_type !== RAIL_PAYMENT_RECEIPT_CLAIM_TYPE &&
    receipt.claim_type !== RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE &&
    receipt.claim_type !== RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE
  ) {
    return { valid: false, reason: 'INVALID_CLAIM_TYPE' }
  }
  // When the new shape is in use, enforce timestamp == issued_at and a
  // non-empty scope_of_claim.asserts. Legacy receipts (without these
  // fields) skip these checks.
  if (receipt.claim_type === RAIL_PAYMENT_RECEIPT_CLAIM_TYPE) {
    if (receipt.timestamp !== receipt.issued_at) {
      return { valid: false, reason: 'INVALID_CLAIM_TYPE' }
    }
    if (
      !receipt.scope_of_claim ||
      typeof receipt.scope_of_claim.asserts !== 'string' ||
      receipt.scope_of_claim.asserts.length === 0
    ) {
      return { valid: false, reason: 'INVALID_CLAIM_TYPE' }
    }
  }
  const expectedId = sha256Hex(canonicalizeReceiptForId(receipt))
  if (receipt.receipt_id !== expectedId) {
    return { valid: false, reason: 'RECEIPT_ID_MISMATCH' }
  }
  if (typeof receipt.signer_did === 'string' && receipt.signer_did.startsWith('did:')) {
    return { valid: false, reason: 'DID_RESOLVER_MISSING' }
  }
  if (!edVerify(canonicalizeReceiptForSig(receipt), receipt.signature, receipt.signer_did)) {
    return { valid: false, reason: 'SIGNATURE_INVALID' }
  }
  return { valid: true }
}

/**
 * Phase 4.1 / P12: async verifier that resolves DID URIs against the
 * caller-supplied DID document resolver. Falls back to the legacy
 * raw-hex path when signer_did doesn't start with 'did:'.
 *
 * Failure reasons:
 *   - DID_RESOLVER_MISSING — signer_did is a DID URI but no resolver supplied
 *   - DID_URI_INVALID      — signer_did is malformed (no `#`, etc.)
 *   - DID_DOC_NOT_FOUND    — resolver returned null for the agentId
 *   - DID_KEY_NOT_IN_DOC   — keyRef not present in verificationMethod[]
 *   - DID_KEY_RETIRED      — key was retired before the receipt was signed
 *   - SIGNATURE_INVALID    — Ed25519 verify failed
 */
export async function verifyPaymentReceiptWithDID(
  receipt: PaymentReceipt,
  options: VerifyReceiptOptions = {},
): Promise<ReceiptVerifyResult> {
  // Vocab #91 / SDK #25: accepted-literal set is harmonized with the
  // sync verifyPaymentReceipt path — legacy + rail.payment.v1 + the two
  // budget_reservation receipt literals (permit, release). Closes the
  // pre-existing sync/async asymmetry where this path previously only
  // accepted the legacy literal.
  if (
    receipt.claim_type !== LEGACY_PAYMENT_RECEIPT_CLAIM_TYPE &&
    receipt.claim_type !== RAIL_PAYMENT_RECEIPT_CLAIM_TYPE &&
    receipt.claim_type !== RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE &&
    receipt.claim_type !== RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE
  ) {
    return { valid: false, reason: 'INVALID_CLAIM_TYPE' }
  }
  const expectedId = sha256Hex(canonicalizeReceiptForId(receipt))
  if (receipt.receipt_id !== expectedId) {
    return { valid: false, reason: 'RECEIPT_ID_MISMATCH' }
  }
  const sigBytes = canonicalizeReceiptForSig(receipt)
  return _verifyDidOrRawHex(
    receipt.signer_did,
    sigBytes,
    receipt.signature,
    receipt.issued_at,
    options,
  )
}

/** Shared DID-or-rawhex verification step used by all rail verifiers. */
async function _verifyDidOrRawHex(
  signerDid: string,
  payload: string,
  signature: string,
  issuedAt: string | undefined,
  options: VerifyReceiptOptions,
): Promise<ReceiptVerifyResult> {
  if (!signerDid.startsWith('did:')) {
    if (!edVerify(payload, signature, signerDid)) {
      return { valid: false, reason: 'SIGNATURE_INVALID' }
    }
    return { valid: true }
  }
  if (!options.resolveDidDocument) {
    return { valid: false, reason: 'DID_RESOLVER_MISSING' }
  }
  const parsed = parseDidUri(signerDid)
  if (!parsed) return { valid: false, reason: 'DID_URI_INVALID' }
  const didDoc = await options.resolveDidDocument(parsed.agentId)
  if (!didDoc) return { valid: false, reason: 'DID_DOC_NOT_FOUND' }
  const issuedAtMs = issuedAt ? Date.parse(issuedAt) : undefined
  const result = resolveVerificationMethod(
    didDoc,
    signerDid,
    options.now ? options.now.getTime() : undefined,
    Number.isFinite(issuedAtMs) ? issuedAtMs : undefined,
  )
  if (!result) return { valid: false, reason: 'DID_KEY_NOT_IN_DOC' }
  if (result.retired) return { valid: false, reason: 'DID_KEY_RETIRED' }
  const pubHex = publicKeyHexFromMethod(result.method)
  if (!edVerify(payload, signature, pubHex)) {
    return { valid: false, reason: 'SIGNATURE_INVALID' }
  }
  return { valid: true }
}

export type DenialVerifyReason =
  | 'INVALID_CLAIM_TYPE'
  | 'INVALID_DENIAL_REASON'
  | 'RECEIPT_ID_MISMATCH'
  | 'SIGNATURE_INVALID'
  | 'DID_RESOLVER_MISSING'
  | 'DID_URI_INVALID'
  | 'DID_DOC_NOT_FOUND'
  | 'DID_KEY_NOT_IN_DOC'
  | 'DID_KEY_RETIRED'

export interface DenialVerifyResult {
  valid: boolean
  reason?: DenialVerifyReason
}

export function verifyPaymentDenial(denial: PaymentDenial): DenialVerifyResult {
  // Vocab #91 / SDK #25: also accept the budget_reservation denial
  // literal. The permit and release receipt literals belong on the
  // receipt-verify path.
  if (
    denial.claim_type !== LEGACY_PAYMENT_DENIAL_CLAIM_TYPE &&
    denial.claim_type !== RAIL_PAYMENT_DENIAL_CLAIM_TYPE &&
    denial.claim_type !== RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE
  ) {
    return { valid: false, reason: 'INVALID_CLAIM_TYPE' }
  }
  if (denial.claim_type === RAIL_PAYMENT_DENIAL_CLAIM_TYPE) {
    if (denial.timestamp !== denial.issued_at) {
      return { valid: false, reason: 'INVALID_CLAIM_TYPE' }
    }
    if (
      !denial.scope_of_claim ||
      typeof denial.scope_of_claim.asserts !== 'string' ||
      denial.scope_of_claim.asserts.length === 0
    ) {
      return { valid: false, reason: 'INVALID_CLAIM_TYPE' }
    }
  }
  if (!VALID_DENIAL_REASONS.includes(denial.denial_reason)) {
    return { valid: false, reason: 'INVALID_DENIAL_REASON' }
  }
  const expectedId = sha256Hex(canonicalizeDenialForId(denial))
  if (denial.receipt_id !== expectedId) {
    return { valid: false, reason: 'RECEIPT_ID_MISMATCH' }
  }
  if (typeof denial.signer_did === 'string' && denial.signer_did.startsWith('did:')) {
    return { valid: false, reason: 'DID_RESOLVER_MISSING' }
  }
  if (!edVerify(canonicalizeDenialForSig(denial), denial.signature, denial.signer_did)) {
    return { valid: false, reason: 'SIGNATURE_INVALID' }
  }
  return { valid: true }
}

export async function verifyPaymentDenialWithDID(
  denial: PaymentDenial,
  options: VerifyReceiptOptions = {},
): Promise<DenialVerifyResult> {
  // Vocab #91 / SDK #25: accepted-literal set is harmonized with the
  // sync verifyPaymentDenial path — legacy + rail.payment.denial.v1 +
  // the budget_reservation denial literal. Closes the pre-existing
  // sync/async asymmetry where this path previously only accepted the
  // legacy literal.
  if (
    denial.claim_type !== LEGACY_PAYMENT_DENIAL_CLAIM_TYPE &&
    denial.claim_type !== RAIL_PAYMENT_DENIAL_CLAIM_TYPE &&
    denial.claim_type !== RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE
  ) {
    return { valid: false, reason: 'INVALID_CLAIM_TYPE' }
  }
  if (!VALID_DENIAL_REASONS.includes(denial.denial_reason)) {
    return { valid: false, reason: 'INVALID_DENIAL_REASON' }
  }
  const expectedId = sha256Hex(canonicalizeDenialForId(denial))
  if (denial.receipt_id !== expectedId) {
    return { valid: false, reason: 'RECEIPT_ID_MISMATCH' }
  }
  const sigBytes = canonicalizeDenialForSig(denial)
  return _verifyDidOrRawHex(
    denial.signer_did,
    sigBytes,
    denial.signature,
    denial.issued_at,
    options,
  )
}

// ── Composable GovernanceHooks bundle ─────────────────────────────

/**
 * Default GovernanceHooks implementation. Rails that want the
 * standard preAuthorize/emit semantics can use this; rails with
 * custom rules implement GovernanceHooks themselves.
 */
export function createDefaultGovernanceHooks(): GovernanceHooks {
  return {
    preAuthorize,
    emitReceipt,
    emitDenial,
  }
}
