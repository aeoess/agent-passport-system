// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// AP2 v0.2 interop — APS ↔ AP2 mandate crosswalk
// ══════════════════════════════════════════════════════════════════
// Maps APS V2Delegation to AP2 mandate dicts and back.
//
// What ships:
//   - apsToAp2IntentMandate(delegation, opts)   → OpenCheckoutMandate
//   - apsToAp2CartMandate(delegation, cart, …)  → CheckoutMandate
//   - apsToAp2PaymentMandate(delegation, …)     → PaymentMandate
//   - apsToAp2OpenPaymentMandate(delegation, …) → OpenPaymentMandate
//   - ap2MandateToApsDelegation(mandate, …)     → partial V2Delegation
//   - signAp2Mandate(mandate, privateKeyHex)    → SignedAP2Mandate
//   - verifyAp2Mandate(signed, …, opts)         → Ap2VerifyResult
//
// What does NOT ship (lives in gateway integration):
//   - SD-JWT / JWS encoding (Google reference impl wire format)
//   - JWT cosign for the merchant-signed checkout_jwt
//   - PISP / payment-instrument live wiring
//
// Limitations are documented in docs/governance/ap2-interop.md.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { publicKeyFromPrivate, sign, verify as edVerify } from '../../../crypto/keys.js'
import {
  parseDidUri,
  publicKeyHexFromMethod,
  resolveVerificationMethod,
} from '../../../core/did-uri.js'
import type { RotatableDIDDocument } from '../../../types/passport.js'

export type Ap2ResolveDidDocument = (
  agentId: string,
) => Promise<RotatableDIDDocument | null>

function _ap2SignerFor(
  privateKeyHex: string,
  agentId: string | undefined,
  keyRef: string | undefined,
): string {
  if (agentId && keyRef) {
    if (!agentId.startsWith('did:')) {
      throw new Error(`signAp2Mandate: issuer_agent_id must be a DID, got '${agentId}'`)
    }
    if (keyRef.includes('#')) {
      throw new Error("signAp2Mandate: issuer_key_ref must not contain '#'")
    }
    return `${agentId}#${keyRef}`
  }
  return publicKeyFromPrivate(privateKeyHex)
}
import { verifyOwnerConfirmation } from '../../human-escalation.js'
import type { OwnerConfirmation, V2Delegation } from '../../types.js'
import { resolveSpendLimitCents } from '../scope-resolution.js'
import {
  AP2_VERSION,
} from './types.js'
import type {
  AP2AllowedMerchantsConstraint,
  AP2AllowedPayeesConstraint,
  AP2AllowedPaymentInstrumentsConstraint,
  AP2Amount,
  AP2BudgetConstraint,
  AP2CheckoutConstraint,
  AP2CheckoutMandate,
  AP2Cnf,
  AP2LineItemRequirement,
  AP2LineItemsConstraint,
  AP2Mandate,
  AP2Merchant,
  AP2OpenCheckoutMandate,
  AP2OpenPaymentMandate,
  AP2PaymentConstraint,
  AP2PaymentInstrument,
  AP2PaymentMandate,
  AP2Pisp,
  Ap2VerifyResult,
  CartDetails,
  SignedAP2Mandate,
} from './types.js'

// Re-export AP2 types so callers can `import { ... } from '.../ap2'`.
export type {
  AP2AllowedMerchantsConstraint,
  AP2AllowedPayeesConstraint,
  AP2AllowedPaymentInstrumentsConstraint,
  AP2Amount,
  AP2AmountRangeConstraint,
  AP2BudgetConstraint,
  AP2CheckoutConstraint,
  AP2CheckoutMandate,
  AP2Cnf,
  AP2Item,
  AP2LineItemRequirement,
  AP2LineItemsConstraint,
  AP2Mandate,
  AP2Merchant,
  AP2OpenCheckoutMandate,
  AP2OpenPaymentMandate,
  AP2PaymentConstraint,
  AP2PaymentInstrument,
  AP2PaymentMandate,
  AP2PaymentReferenceConstraint,
  AP2Pisp,
  AP2VctCheckout,
  AP2VctOpenCheckout,
  AP2VctOpenPayment,
  AP2VctPayment,
  Ap2VerifyReason,
  Ap2VerifyResult,
  CartDetails,
  CartMandate,
  IntentMandate,
  SignedAP2Mandate,
} from './types.js'

export { AP2_VERSION } from './types.js'

// ── Helpers ───────────────────────────────────────────────────────

/** ISO 8601 string → Unix epoch seconds. Returns undefined on parse fail. */
function _isoToUnixSeconds(iso: string | undefined): number | undefined {
  if (iso === undefined) return undefined
  const ms = Date.parse(iso)
  if (Number.isNaN(ms)) return undefined
  return Math.floor(ms / 1000)
}

/** Unix epoch seconds → ISO 8601 with milliseconds + Z. */
function _unixSecondsToIso(s: number | undefined): string | undefined {
  if (s === undefined) return undefined
  return new Date(s * 1000).toISOString()
}

/** Build a cnf claim from an APS Ed25519 hex pubkey. APS pubkeys are
 *  raw 32-byte Ed25519 keys; AP2 uses RFC 7800 cnf with a JWK. We
 *  encode the raw pubkey as `OKP/Ed25519/x = base64url(pubkey_bytes)`. */
function _cnfFromEd25519Pubkey(pubkeyHex: string): AP2Cnf {
  const bytes = Buffer.from(pubkeyHex, 'hex')
  const x = bytes.toString('base64url')
  return { jwk: { kty: 'OKP', crv: 'Ed25519', x } }
}

/** Reverse of _cnfFromEd25519Pubkey. Returns undefined when the cnf
 *  doesn't carry an Ed25519 OKP JWK. */
function _ed25519PubkeyHexFromCnf(cnf: AP2Cnf | undefined): string | undefined {
  const j = cnf?.jwk
  if (j === undefined || j.kty !== 'OKP' || j.crv !== 'Ed25519') return undefined
  if (j.x === undefined) return undefined
  try {
    return Buffer.from(j.x, 'base64url').toString('hex')
  } catch {
    return undefined
  }
}

/** Read APS spend limit for AP2 mandate construction. Routes through
 *  the foundation `resolveSpendLimitCents()` helper so AP2 honors
 *  the same field-name resolution as ACP / MPP / Stripe-Issuing —
 *  a delegation with `resource_limits.spend_limit_cents` works in
 *  AP2 even though AP2's canonical key is `commerce.spend_limit`.
 *
 *  Canonical key for AP2 is `'commerce.spend_limit'` (callers can
 *  override via opts.spendLimitKey). Returns 0 when no cap is found
 *  (caller treats 0 as "no spend permitted") — this preserves the
 *  AP2-specific 0-sentinel that `apsToAp2OpenPaymentMandate` relies on. */
function _spendLimitFromDelegation(
  delegation: V2Delegation,
  spendLimitKey = 'commerce.spend_limit',
): number {
  const v = resolveSpendLimitCents(delegation, { canonicalKey: spendLimitKey })
  return v ?? 0
}

/** Build a sha256 over canonical bytes, return base64url (the AP2
 *  default for hash digests in mandates). */
function _sha256Base64Url(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('base64url')
}

/** Action class AP2 mandate construction slots into for HumanEscalationFlag. */
const AP2_ACTION_CLASS = 'commerce' as const

/** Audit B P9 — gate AP2 mandate construction on escalation_requirements.
 *  AP2 has no denial primitive (mandates either construct or fail), so
 *  this throws when escalation is required and not satisfied. Caller
 *  collects the OwnerConfirmation and re-invokes the apsToAp2*Mandate
 *  call with `owner_confirmation` populated. */
function _assertAp2EscalationOk(
  delegation: V2Delegation,
  action_details: Record<string, unknown>,
  opts: { owner_confirmation?: OwnerConfirmation; session_id?: string | null; now?: Date },
): void {
  const reqs = delegation.scope?.escalation_requirements
  const matchingReq = reqs?.find(
    (r) => r.action_class === AP2_ACTION_CLASS && r.requires_owner_confirmation,
  )
  if (!matchingReq) return
  if (!opts.owner_confirmation) {
    throw new Error(
      `apsToAp2: action_class '${AP2_ACTION_CLASS}' requires_owner_confirmation; provide opts.owner_confirmation`,
    )
  }
  const verdict = verifyOwnerConfirmation(
    opts.owner_confirmation,
    {
      action_class: AP2_ACTION_CLASS,
      action_details,
      session_id: opts.session_id ?? null,
    },
    delegation,
    opts.now ?? new Date(),
  )
  if (!verdict.valid) {
    throw new Error(
      `apsToAp2: invalid owner_confirmation: ${verdict.reason}`,
    )
  }
}

// ── apsToAp2IntentMandate ─────────────────────────────────────────

export interface ApsToAp2IntentOptions {
  /** Currency the budget is denominated in. ISO 4217. */
  currency: string
  /** Optional list of merchants the intent may settle with. When
   *  omitted, the mandate carries no `allowed_merchants` constraint
   *  (the future cart can settle with any merchant). */
  allowed_merchants?: AP2Merchant[]
  /** Optional line-item requirement spec. When omitted, no `line_items`
   *  constraint is included. */
  line_items?: AP2LineItemRequirement[]
  /** Override resource_limits key. Defaults to 'commerce.spend_limit'. */
  spend_limit_key?: string
  /** Audit B P9 — owner confirmation when the delegation declares an
   *  escalation_requirement on action_class 'commerce'. Required when
   *  the requirement is set; otherwise unused. */
  owner_confirmation?: OwnerConfirmation
  /** session_id for 'per_session' confirmation scope. */
  session_id?: string | null
  /** Override clock for tests. */
  now?: Date
}

/**
 * Build an AP2 OpenCheckoutMandate from an APS V2Delegation.
 *
 * APS delegation → AP2 mapping:
 *   delegation.scope.action_categories      → encoded as constraints
 *                                             via opts.allowed_merchants
 *                                             and opts.line_items
 *   delegation.delegatee (Ed25519 hex pubkey)→ cnf.jwk (OKP/Ed25519/x)
 *   delegation.policy_context.valid_from    → iat (Unix epoch seconds)
 *   delegation.policy_context.valid_until   → exp (Unix epoch seconds)
 */
export function apsToAp2IntentMandate(
  delegation: V2Delegation,
  opts: ApsToAp2IntentOptions,
): AP2OpenCheckoutMandate {
  _assertAp2EscalationOk(
    delegation,
    {
      kind: 'apsToAp2IntentMandate',
      currency: opts.currency,
      allowed_merchants: opts.allowed_merchants,
      line_items: opts.line_items,
    },
    opts,
  )
  const constraints: AP2CheckoutConstraint[] = []
  if (opts.allowed_merchants !== undefined && opts.allowed_merchants.length > 0) {
    constraints.push({
      type: 'checkout.allowed_merchants',
      allowed: opts.allowed_merchants,
    })
  }
  if (opts.line_items !== undefined && opts.line_items.length > 0) {
    constraints.push({ type: 'checkout.line_items', items: opts.line_items })
  }

  const mandate: AP2OpenCheckoutMandate = {
    vct: 'mandate.checkout.open.1',
    constraints,
    cnf: _cnfFromEd25519Pubkey(delegation.delegatee),
  }
  const iat = _isoToUnixSeconds(delegation.policy_context.valid_from)
  const exp = _isoToUnixSeconds(delegation.policy_context.valid_until)
  if (iat !== undefined) mandate.iat = iat
  if (exp !== undefined) mandate.exp = exp
  return mandate
}

// ── apsToAp2CartMandate ───────────────────────────────────────────

export interface ApsToAp2CartOptions {
  /** sha256 hash of the merchant-signed JWT, base64url. When the
   *  caller hasn't computed it (no JWT yet), pass an empty string;
   *  the gateway integration layer fills it before wire emit. */
  checkout_hash?: string
  /** base64url-encoded merchant-signed JWT of the checkout payload.
   *  Defaults to '' for SDK-only audit; the gateway populates this
   *  for wire-compatible mandates. */
  checkout_jwt?: string
  /** Audit B P9 — owner confirmation when the delegation declares an
   *  escalation_requirement on action_class 'commerce'. */
  owner_confirmation?: OwnerConfirmation
  session_id?: string | null
  now?: Date
}

/**
 * Build an AP2 CheckoutMandate from an APS V2Delegation + concrete
 * cart details. AP2 CheckoutMandate is one-way: AP2 has additional
 * cart fields (specific items + total) that APS delegations don't
 * encode, so the caller must supply them.
 *
 * The reverse direction (CheckoutMandate → V2Delegation) loses the
 * cart contents — see ap2MandateToApsDelegation.
 */
export function apsToAp2CartMandate(
  delegation: V2Delegation,
  cart: CartDetails,
  opts: ApsToAp2CartOptions = {},
): AP2CheckoutMandate {
  _assertAp2EscalationOk(
    delegation,
    { kind: 'apsToAp2CartMandate', cart: cart as unknown as Record<string, unknown> },
    opts,
  )
  const checkout_jwt = opts.checkout_jwt ?? ''
  // When the caller hasn't supplied a JWT hash, derive from the empty
  // string per the schema's "sha-256 MUST be used" fallback. Real
  // wire mandates always carry a non-empty checkout_jwt; this default
  // exists so SDK-only audit can construct mandates without a JWT.
  const checkout_hash = opts.checkout_hash ?? _sha256Base64Url(checkout_jwt)

  const mandate: AP2CheckoutMandate = {
    vct: 'mandate.checkout.1',
    checkout_jwt,
    checkout_hash,
    payee: cart.payee,
    items: cart.items,
    total: cart.total,
    cnf: _cnfFromEd25519Pubkey(delegation.delegatee),
  }
  const iat = _isoToUnixSeconds(delegation.policy_context.valid_from)
  const exp = _isoToUnixSeconds(delegation.policy_context.valid_until)
  if (iat !== undefined) mandate.iat = iat
  if (exp !== undefined) mandate.exp = exp
  return mandate
}

// ── apsToAp2PaymentMandate (closed) ───────────────────────────────

export interface ApsToAp2PaymentOptions {
  /** Required: payee merchant. */
  payee: AP2Merchant
  /** Required: instrument used. */
  payment_instrument: AP2PaymentInstrument
  /** Required: settlement amount. AP2 PaymentMandate locks a specific
   *  amount; APS delegation carries a spend_limit (cap), so caller
   *  supplies the exact transaction amount here. */
  payment_amount: AP2Amount
  /** Required: base64url-encoded sha256 of the originating checkout_jwt
   *  (or of any unique identifier for the txn when no JWT exists). */
  transaction_id: string
  pisp?: AP2Pisp
  execution_date?: string
  risk_data?: Record<string, unknown>
  /** Audit B P9 — owner confirmation when the delegation declares an
   *  escalation_requirement on action_class 'commerce'. */
  owner_confirmation?: OwnerConfirmation
  session_id?: string | null
  now?: Date
}

export function apsToAp2PaymentMandate(
  delegation: V2Delegation,
  opts: ApsToAp2PaymentOptions,
): AP2PaymentMandate {
  _assertAp2EscalationOk(
    delegation,
    {
      kind: 'apsToAp2PaymentMandate',
      transaction_id: opts.transaction_id,
      payee: opts.payee as unknown as Record<string, unknown>,
      payment_amount: opts.payment_amount as unknown as Record<string, unknown>,
    },
    opts,
  )
  const mandate: AP2PaymentMandate = {
    vct: 'mandate.payment.1',
    transaction_id: opts.transaction_id,
    payee: opts.payee,
    payment_amount: opts.payment_amount,
    payment_instrument: opts.payment_instrument,
    cnf: _cnfFromEd25519Pubkey(delegation.delegatee),
  }
  if (opts.pisp !== undefined) mandate.pisp = opts.pisp
  if (opts.execution_date !== undefined) mandate.execution_date = opts.execution_date
  if (opts.risk_data !== undefined) mandate.risk_data = opts.risk_data
  const iat = _isoToUnixSeconds(delegation.policy_context.valid_from)
  const exp = _isoToUnixSeconds(delegation.policy_context.valid_until)
  if (iat !== undefined) mandate.iat = iat
  if (exp !== undefined) mandate.exp = exp
  return mandate
}

// ── apsToAp2OpenPaymentMandate ────────────────────────────────────

export interface ApsToAp2OpenPaymentOptions {
  currency: string
  /** Override resource_limits key. Defaults to 'commerce.spend_limit'. */
  spend_limit_key?: string
  allowed_payees?: AP2Merchant[]
  allowed_payment_instruments?: AP2PaymentInstrument[]
  payment_reference?: string
  /** Audit B P9 — owner confirmation when the delegation declares an
   *  escalation_requirement on action_class 'commerce'. */
  owner_confirmation?: OwnerConfirmation
  session_id?: string | null
  now?: Date
}

export function apsToAp2OpenPaymentMandate(
  delegation: V2Delegation,
  opts: ApsToAp2OpenPaymentOptions,
): AP2OpenPaymentMandate {
  _assertAp2EscalationOk(
    delegation,
    {
      kind: 'apsToAp2OpenPaymentMandate',
      currency: opts.currency,
      allowed_payees: opts.allowed_payees,
      payment_reference: opts.payment_reference,
    },
    opts,
  )
  const spendLimit = _spendLimitFromDelegation(delegation, opts.spend_limit_key)
  const constraints: AP2PaymentConstraint[] = [
    {
      type: 'payment.budget',
      total: { currency: opts.currency, value: spendLimit },
    },
  ]
  if (opts.allowed_payees !== undefined && opts.allowed_payees.length > 0) {
    constraints.push({ type: 'payment.allowed_payees', allowed: opts.allowed_payees })
  }
  if (
    opts.allowed_payment_instruments !== undefined &&
    opts.allowed_payment_instruments.length > 0
  ) {
    constraints.push({
      type: 'payment.allowed_payment_instruments',
      allowed: opts.allowed_payment_instruments,
    })
  }
  if (opts.payment_reference !== undefined) {
    constraints.push({ type: 'payment.payment_reference', reference: opts.payment_reference })
  }

  const mandate: AP2OpenPaymentMandate = {
    vct: 'mandate.payment.open.1',
    constraints,
    cnf: _cnfFromEd25519Pubkey(delegation.delegatee),
  }
  const iat = _isoToUnixSeconds(delegation.policy_context.valid_from)
  const exp = _isoToUnixSeconds(delegation.policy_context.valid_until)
  if (iat !== undefined) mandate.iat = iat
  if (exp !== undefined) mandate.exp = exp
  return mandate
}

// ── ap2MandateToApsDelegation ─────────────────────────────────────

export interface Ap2ToApsOptions {
  /** Caller supplies the delegator DID (the user / principal who
   *  authorized the mandate). AP2 encodes the holder via cnf, but
   *  the upstream principal isn't standardized in v0.2. */
  delegator_did: string
  /** Caller supplies the delegation id (UUID or content hash). AP2
   *  uses transaction_id / checkout_hash; APS delegations have
   *  their own id space. */
  delegation_id: string
  /** Default policy_context fields for the resulting V2Delegation. */
  policy_version?: string
  values_floor_version?: string
  trust_epoch?: number
  issuer_id?: string
  /** ISO 8601 timestamp; defaults to new Date().toISOString(). */
  created_at?: string
  /** Optional override resource_limits key. */
  spend_limit_key?: string
}

/**
 * Reverse crosswalk: AP2 mandate → partial V2Delegation. The result
 * is a "shape" — issuer/policy fields are filled from opts because
 * AP2 mandates don't carry APS policy provenance. Callers typically
 * pass the result through the SDK's V2Delegation construction
 * pipeline to produce a fully-signed delegation.
 *
 * Rules for which mandate types map back:
 *   OpenCheckoutMandate   → scope.action_categories=['commerce.checkout']
 *                           constraints surface via scope.constraints
 *   OpenPaymentMandate    → scope.action_categories=['commerce.payment'],
 *                           budget constraint → resource_limits[spend_limit_key]
 *   CheckoutMandate       → scope.action_categories=['commerce.checkout'],
 *                           specific cart not preserved (one-way mapping
 *                           on the forward direction)
 *   PaymentMandate        → scope.action_categories=['commerce.payment'],
 *                           specific amount carried as resource_limits
 */
export function ap2MandateToApsDelegation(
  mandate: AP2Mandate,
  opts: Ap2ToApsOptions,
): V2Delegation {
  const spend_limit_key = opts.spend_limit_key ?? 'commerce.spend_limit'
  const delegatee = _ed25519PubkeyHexFromCnf((mandate as { cnf?: AP2Cnf }).cnf) ?? ''

  const valid_from =
    _unixSecondsToIso((mandate as { iat?: number }).iat) ??
    opts.created_at ??
    new Date().toISOString()
  const valid_until =
    _unixSecondsToIso((mandate as { exp?: number }).exp) ?? valid_from

  // Build action_categories + resource_limits from the mandate type.
  let action_categories: string[]
  const resource_limits: Record<string, number> = {}
  const constraints: Record<string, string> = { ap2_vct: mandate.vct }

  switch (mandate.vct) {
    case 'mandate.checkout.open.1': {
      action_categories = ['commerce.checkout']
      const oc = mandate
      // Encode allowed_merchants as a constraint string for round-trip.
      const allowedMerchants = oc.constraints.find(
        (c): c is AP2AllowedMerchantsConstraint => c.type === 'checkout.allowed_merchants',
      )
      if (allowedMerchants !== undefined) {
        constraints.allowed_merchants = allowedMerchants.allowed.map((m) => m.id).join(',')
      }
      const lineItems = oc.constraints.find(
        (c): c is AP2LineItemsConstraint => c.type === 'checkout.line_items',
      )
      if (lineItems !== undefined) {
        constraints.line_items_count = String(lineItems.items.length)
      }
      break
    }
    case 'mandate.checkout.1': {
      action_categories = ['commerce.checkout']
      const cm = mandate
      if (cm.total !== undefined) {
        resource_limits[spend_limit_key] = cm.total.value
        constraints.currency = cm.total.currency
      }
      if (cm.payee !== undefined) constraints.payee_id = cm.payee.id
      break
    }
    case 'mandate.payment.open.1': {
      action_categories = ['commerce.payment']
      const op = mandate
      const budget = op.constraints.find(
        (c): c is AP2BudgetConstraint => c.type === 'payment.budget',
      )
      if (budget !== undefined) {
        resource_limits[spend_limit_key] = budget.total.value
        constraints.currency = budget.total.currency
      }
      const allowedPayees = op.constraints.find(
        (c): c is AP2AllowedPayeesConstraint => c.type === 'payment.allowed_payees',
      )
      if (allowedPayees !== undefined) {
        constraints.allowed_payees = allowedPayees.allowed.map((m) => m.id).join(',')
      }
      const allowedInstruments = op.constraints.find(
        (c): c is AP2AllowedPaymentInstrumentsConstraint =>
          c.type === 'payment.allowed_payment_instruments',
      )
      if (allowedInstruments !== undefined) {
        constraints.allowed_instruments = allowedInstruments.allowed.map((p) => p.id).join(',')
      }
      break
    }
    case 'mandate.payment.1': {
      action_categories = ['commerce.payment']
      const pm = mandate
      resource_limits[spend_limit_key] = pm.payment_amount.value
      constraints.currency = pm.payment_amount.currency
      constraints.payee_id = pm.payee.id
      constraints.payment_instrument_id = pm.payment_instrument.id
      break
    }
    default: {
      // Exhaustive switch: TypeScript narrows mandate to never above.
      const _exhaustive: never = mandate
      throw new Error(`unsupported AP2 mandate vct: ${(_exhaustive as AP2Mandate).vct}`)
    }
  }

  return {
    id: opts.delegation_id,
    version: 1,
    supersedes: null,
    supersession_justification: null,
    delegator: opts.delegator_did,
    delegatee,
    scope: {
      action_categories,
      domain: 'commerce',
      resource_limits: Object.keys(resource_limits).length > 0 ? resource_limits : undefined,
      constraints,
    },
    policy_context: {
      policy_version: opts.policy_version ?? 'v2',
      values_floor_version: opts.values_floor_version ?? 'v1',
      trust_epoch: opts.trust_epoch ?? 0,
      issuer_id: opts.issuer_id ?? opts.delegator_did,
      created_at: opts.created_at ?? new Date().toISOString(),
      valid_from,
      valid_until,
    },
    signature: '',
    status: 'active',
    renewal_reason: null,
    expansion_reviewer: null,
    expansion_review_sig: null,
    assurance_class: 'evidentially_auditable',
  }
}

// ── Sign + verify (APS Ed25519 over RFC 8785 JCS of the dict) ──────

export interface SignAp2MandateOptions {
  /** Phase 4.1 / Q1: opt into the AccountabilityReceiptBase shape on the
   *  outer envelope. The mandate dict itself is unchanged so the signature
   *  remains byte-identical for legacy callers. New envelopes carry
   *  claim_type='rail.ap2.mandate.v1', timestamp, and scope_of_claim. */
  accountability_shape?: boolean
  /** Override the default scope_of_claim (implies accountability_shape). */
  scope_of_claim?: import('../../accountability/types/base.js').ScopeOfClaim
  /** Phase 4.1 / P12: when both supplied, signer_did becomes a DID URI
   *  of the form `${issuer_agent_id}#${issuer_key_ref}`. Otherwise the
   *  legacy raw-hex pubkey form is used. Compatible-superset. */
  issuer_agent_id?: string
  issuer_key_ref?: string
  /** Phase 4.1 / Q2: link to the AttributionReceipt this mandate is
   *  paying against. Sits on the envelope, not the mandate dict, so
   *  the AP2 wire-level signature stays byte-identical to legacy. */
  attribution_receipt_id?: string
  /** Phase 4.1 / Q2: link to the SettlementRecord whose payment_obligations
   *  declared the payment this mandate authorizes. Envelope-side. */
  settlement_record_id?: string
}

function defaultAp2MandateScope(): import('../../accountability/types/base.js').ScopeOfClaim {
  return {
    asserts: 'aps:rail.ap2:mandate — an AP2 mandate dict was issued and signed under the cited V2Delegation; the mandate authority (cnf, iat, exp, vct) is byte-bound by the Ed25519 signature.',
    does_not_assert: [
      'a payment occurred — a mandate is a permission, not a settlement',
      'the merchant accepted the mandate at the wire layer (AP2 v0.2 wire format is SD-JWT)',
      "the buyer's identity is what cnf.jwk claims (cnf is a key, not an identity)",
      'future mandate use will fall inside scope (replay is gateway product)',
    ],
    capture_mode: 'self_attested',
    completeness: 'complete',
    self_attested: true,
  }
}

export function signAp2Mandate<T extends AP2Mandate>(
  mandate: T,
  signerPrivateKeyHex: string,
  options: SignAp2MandateOptions = {},
): SignedAP2Mandate<T> {
  const signer_did = _ap2SignerFor(
    signerPrivateKeyHex,
    options.issuer_agent_id,
    options.issuer_key_ref,
  )
  const canonical = canonicalizeJCS(mandate)
  const signature = sign(canonical, signerPrivateKeyHex)
  const useAccountabilityShape =
    options.accountability_shape === true || options.scope_of_claim !== undefined

  const envelope: SignedAP2Mandate<T> = { mandate, signer_did, signature }
  if (useAccountabilityShape) {
    envelope.claim_type = 'rail.ap2.mandate.v1'
    envelope.timestamp = new Date().toISOString()
    envelope.scope_of_claim = options.scope_of_claim ?? defaultAp2MandateScope()
  }
  if (options.attribution_receipt_id !== undefined) {
    envelope.attribution_receipt_id = options.attribution_receipt_id
  }
  if (options.settlement_record_id !== undefined) {
    envelope.settlement_record_id = options.settlement_record_id
  }
  return envelope
}

export interface VerifyAp2MandateOptions {
  /** Optional clock for ttl checks; defaults to Date.now(). */
  now?: Date
  /** Skew tolerance in seconds (default 60). */
  clock_skew_seconds?: number
  /** When provided, the verifier asserts signed.signer_did === expected_signer_did. */
  expected_signer_did?: string
  /** Phase 4.1 / P12: required when signer_did is a DID URI. The async
   *  `verifyAp2MandateWithDID` path invokes this resolver. */
  resolveDidDocument?: Ap2ResolveDidDocument
}

const VALID_VCTS = new Set([
  'mandate.checkout.1',
  'mandate.checkout.open.1',
  'mandate.payment.1',
  'mandate.payment.open.1',
])

export function verifyAp2Mandate(
  signed: SignedAP2Mandate,
  options: VerifyAp2MandateOptions = {},
): Ap2VerifyResult {
  const { mandate, signer_did, signature } = signed

  // 1. vct check.
  if (!VALID_VCTS.has(mandate.vct)) {
    return { valid: false, reason: 'INVALID_VCT', detail: `vct='${mandate.vct}' not recognized` }
  }

  // 2. expected signer.
  if (options.expected_signer_did !== undefined && options.expected_signer_did !== signer_did) {
    return {
      valid: false,
      reason: 'SIGNATURE_INVALID',
      detail: `signer_did=${signer_did} does not match expected=${options.expected_signer_did}`,
    }
  }

  // 3. ttl checks.
  const now = options.now ?? new Date()
  const skew = options.clock_skew_seconds ?? 60
  const nowSec = Math.floor(now.getTime() / 1000)
  const iat = (mandate as { iat?: number }).iat
  const exp = (mandate as { exp?: number }).exp
  if (iat !== undefined && iat > nowSec + skew) {
    return { valid: false, reason: 'NOT_YET_VALID', detail: `iat=${iat} > now+skew=${nowSec + skew}` }
  }
  if (exp !== undefined && exp < nowSec - skew) {
    return { valid: false, reason: 'EXPIRED', detail: `exp=${exp} < now-skew=${nowSec - skew}` }
  }

  // 4. required-field checks per vct.
  switch (mandate.vct) {
    case 'mandate.checkout.1': {
      const m = mandate as AP2CheckoutMandate
      if (m.checkout_hash === undefined || m.checkout_hash === '') {
        return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'checkout_hash' }
      }
      break
    }
    case 'mandate.payment.1': {
      const m = mandate as AP2PaymentMandate
      if (
        m.transaction_id === undefined ||
        m.payee === undefined ||
        m.payment_amount === undefined ||
        m.payment_instrument === undefined
      ) {
        return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'payment fields' }
      }
      break
    }
    case 'mandate.checkout.open.1':
    case 'mandate.payment.open.1': {
      const m = mandate as { constraints?: unknown[]; cnf?: AP2Cnf }
      if (!Array.isArray(m.constraints)) {
        return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'constraints' }
      }
      if (m.cnf === undefined) {
        return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'cnf' }
      }
      break
    }
  }

  // Phase 4.1 / Q1: when the envelope opts into the accountability shape,
  // enforce its invariants. Legacy envelopes (no claim_type) skip this.
  if (signed.claim_type !== undefined) {
    if (signed.claim_type !== 'rail.ap2.mandate.v1') {
      return {
        valid: false,
        reason: 'MISSING_REQUIRED_FIELD',
        detail: `claim_type=${signed.claim_type}`,
      }
    }
    if (typeof signed.timestamp !== 'string' || signed.timestamp.length === 0) {
      return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'timestamp' }
    }
    if (
      !signed.scope_of_claim ||
      typeof signed.scope_of_claim.asserts !== 'string' ||
      signed.scope_of_claim.asserts.length === 0
    ) {
      return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'scope_of_claim' }
    }
  }

  // 5. signature verify.
  const canonical = canonicalizeJCS(mandate)
  if (typeof signer_did === 'string' && signer_did.startsWith('did:')) {
    return {
      valid: false,
      reason: 'DID_RESOLVER_MISSING',
      detail: 'use verifyAp2MandateWithDID for DID-URI signers',
    }
  }
  if (!edVerify(canonical, signature, signer_did)) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'Ed25519 verify failed' }
  }

  return { valid: true }
}

/** Phase 4.1 / P12: async mandate verifier with DID URI support. */
export async function verifyAp2MandateWithDID(
  signed: SignedAP2Mandate,
  options: VerifyAp2MandateOptions = {},
): Promise<Ap2VerifyResult> {
  const sync = verifyAp2Mandate(signed, options)
  if (sync.valid) return sync
  if (sync.reason !== 'DID_RESOLVER_MISSING') return sync

  if (!options.resolveDidDocument) {
    return { valid: false, reason: 'DID_RESOLVER_MISSING' }
  }
  const parsed = parseDidUri(signed.signer_did)
  if (!parsed) return { valid: false, reason: 'DID_URI_INVALID' }
  const didDoc = await options.resolveDidDocument(parsed.agentId)
  if (!didDoc) return { valid: false, reason: 'DID_DOC_NOT_FOUND' }
  // AP2 mandates carry iat (Unix seconds) for the signing instant.
  const iatSec = (signed.mandate as { iat?: number }).iat
  const issuedAtMs = typeof iatSec === 'number' ? iatSec * 1000 : undefined
  const result = resolveVerificationMethod(
    didDoc,
    signed.signer_did,
    options.now ? options.now.getTime() : undefined,
    issuedAtMs,
  )
  if (!result) return { valid: false, reason: 'DID_KEY_NOT_IN_DOC' }
  if (result.retired) return { valid: false, reason: 'DID_KEY_RETIRED' }
  const pubHex = publicKeyHexFromMethod(result.method)
  const canonical = canonicalizeJCS(signed.mandate)
  if (!edVerify(canonical, signed.signature, pubHex)) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'Ed25519 verify failed' }
  }
  return { valid: true }
}
