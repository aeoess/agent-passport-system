// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Payment-rails governance hooks — preAuthorize, emit, verify, fixtures.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  canonicalizeDenialForId,
  canonicalizeDenialForSig,
  canonicalizeReceiptForId,
  canonicalizeReceiptForSig,
  createDefaultGovernanceHooks,
  createNanoRail,
  emitDenial,
  emitReceipt,
  paymentRailsSha256Hex,
  preAuthorize,
  verifyPaymentDenial,
  verifyPaymentDenialWithDID,
  verifyPaymentReceipt,
  verifyPaymentReceiptWithDID,
  xnoToRaw,
} from '../../../src/v2/payment-rails/index.js'
import type {
  DelegationView,
  PaymentDenial,
  PaymentReceipt,
} from '../../../src/v2/payment-rails/index.js'
import { generateKeyPair, publicKeyFromPrivate, sign } from '../../../src/crypto/keys.js'
import {
  recordOwnerConfirmation,
  requestOwnerConfirmation,
} from '../../../src/v2/human-escalation.js'
import type {
  EscalationRequirement,
  V2Delegation,
} from '../../../src/v2/types.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_DIR = join(__dirname, '..', '..', '..', 'src', 'v2', 'payment-rails', 'fixtures')

const ISSUER_PRIV = '88'.repeat(32)
const ISSUER_PUB = publicKeyFromPrivate(ISSUER_PRIV)
const FIXED_TS = '2026-05-03T20:00:00.000Z'

const ADDR = 'nano_3test1f1xt7r3y6a7z9k1c0nv8d4yhfk93rcd6b1pmce8wkqf6kpunkfxnwd'

function _delegation(overrides: Partial<DelegationView> = {}): DelegationView {
  return {
    receipt_id: 'd'.repeat(64),
    scope: ['commerce.purchase'],
    spend_limit_base_units: xnoToRaw('1'), // 1 XNO
    wallet_id: 'wallet-test-001',
    currency: 'XNO',
    ...overrides,
  }
}

function _rail() {
  return createNanoRail({
    receivingAddress: ADDR,
    fetchHistory: async () => [],
    fetchBlockInfo: async () => ({ confirmed: 'true', amount: '0' }),
  })
}

// ── preAuthorize gate matrix ──────────────────────────────────────

describe('preAuthorize', () => {
  it('returns ok=true when scope matches and amount under limit', () => {
    const result = preAuthorize(
      {
        delegation: _delegation(),
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
      },
      _rail(),
    )
    assert.equal(result.ok, true)
  })

  it('rejects with no_commerce_scope when required_scope is absent', () => {
    const result = preAuthorize(
      {
        delegation: _delegation({ scope: ['commerce.refund'] }),
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
      },
      _rail(),
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'no_commerce_scope')
    assert.match(result.reason_detail ?? '', /commerce\.purchase/)
  })

  it('rejects with spend_limit_exceeded when amount > delegation budget', () => {
    const result = preAuthorize(
      {
        delegation: _delegation({ spend_limit_base_units: xnoToRaw('0.0001') }),
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('1'), // way over the 0.0001 limit
        currency: 'XNO',
      },
      _rail(),
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'spend_limit_exceeded')
  })

  it('rejects with wallet_revoked after rail.revokeWallet on the bound wallet', async () => {
    const rail = _rail()
    await rail.revokeWallet('wallet-test-001')
    const result = preAuthorize(
      {
        delegation: _delegation(),
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
      },
      rail,
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'wallet_revoked')
  })

  it('rejects with time_window_violation when before not_before', () => {
    const result = preAuthorize(
      {
        delegation: _delegation({ not_before: '2099-01-01T00:00:00.000Z' }),
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        now: new Date('2026-05-03T20:00:00.000Z'),
      },
      _rail(),
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'time_window_violation')
    assert.match(result.reason_detail ?? '', /not_before/)
  })

  it('rejects with time_window_violation when after not_after', () => {
    const result = preAuthorize(
      {
        delegation: _delegation({ not_after: '2020-01-01T00:00:00.000Z' }),
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        now: new Date('2026-05-03T20:00:00.000Z'),
      },
      _rail(),
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'time_window_violation')
    assert.match(result.reason_detail ?? '', /not_after/)
  })

  it('rejects with spend_limit_exceeded when currencies do not match', () => {
    const result = preAuthorize(
      {
        delegation: _delegation({ currency: 'USDC' }),
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
      },
      _rail(),
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'spend_limit_exceeded')
    assert.match(result.reason_detail ?? '', /currency mismatch/)
  })

  it('default GovernanceHooks bundle exposes the same preAuthorize behavior', () => {
    const hooks = createDefaultGovernanceHooks()
    const result = hooks.preAuthorize(
      {
        delegation: _delegation(),
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
      },
      _rail(),
    )
    assert.equal(result.ok, true)
  })
})

// ── emitReceipt + verifyPaymentReceipt ────────────────────────────

describe('emitReceipt + verifyPaymentReceipt', () => {
  it('emits a signed receipt that round-trips through verify', () => {
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        invoice_id: 'inv-test-001',
        issued_at: FIXED_TS,
      },
      ISSUER_PRIV,
    )
    assert.equal(r.claim_type, 'aps:payment_receipt:v1')
    assert.equal(r.signer_did, ISSUER_PUB)
    assert.equal(r.receipt_id.length, 64)
    assert.equal(r.signature.length, 128)
    const v = verifyPaymentReceipt(r)
    assert.equal(v.valid, true)
  })

  it('verify returns RECEIPT_ID_MISMATCH when amount is tampered', () => {
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        issued_at: FIXED_TS,
      },
      ISSUER_PRIV,
    )
    const tampered: PaymentReceipt = { ...r, amount_base_units: xnoToRaw('1') }
    const v = verifyPaymentReceipt(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'RECEIPT_ID_MISMATCH')
  })

  it('verify returns SIGNATURE_INVALID when signature byte is flipped', () => {
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        issued_at: FIXED_TS,
      },
      ISSUER_PRIV,
    )
    const last = r.signature.slice(-1)
    const flipped = r.signature.slice(0, -1) + (last === '0' ? '1' : '0')
    const tampered: PaymentReceipt = { ...r, signature: flipped }
    const v = verifyPaymentReceipt(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'SIGNATURE_INVALID')
  })

  it('verify returns INVALID_CLAIM_TYPE for wrong claim_type', () => {
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        issued_at: FIXED_TS,
      },
      ISSUER_PRIV,
    )
    const tampered: PaymentReceipt = { ...r, claim_type: 'aps:other:v1' }
    const v = verifyPaymentReceipt(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'INVALID_CLAIM_TYPE')
  })

  it('two emits with identical inputs produce the same receipt_id and signature', () => {
    const inputs = {
      delegation_ref: 'd'.repeat(64),
      action_ref: 'a'.repeat(64),
      rail_name: 'nano',
      amount_base_units: xnoToRaw('0.001'),
      currency: 'XNO',
      tx_proof: 'b'.repeat(64),
      invoice_id: 'inv-test-001',
      issued_at: FIXED_TS,
    }
    const a = emitReceipt(inputs, ISSUER_PRIV)
    const b = emitReceipt(inputs, ISSUER_PRIV)
    assert.equal(a.receipt_id, b.receipt_id)
    assert.equal(a.signature, b.signature)
  })
})

// ── emitDenial + verifyPaymentDenial ──────────────────────────────

describe('emitDenial + verifyPaymentDenial', () => {
  it('emits a signed denial that round-trips through verify', () => {
    const d = emitDenial(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        denial_reason: 'no_commerce_scope',
        reason_detail: "scope 'commerce.purchase' not in delegation",
        issued_at: FIXED_TS,
      },
      ISSUER_PRIV,
    )
    assert.equal(d.claim_type, 'aps:payment_denial:v1')
    assert.equal(d.denial_reason, 'no_commerce_scope')
    const v = verifyPaymentDenial(d)
    assert.equal(v.valid, true)
  })

  it('verify returns INVALID_DENIAL_REASON for unknown reason', () => {
    const d = emitDenial(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        denial_reason: 'rail_error',
        issued_at: FIXED_TS,
      },
      ISSUER_PRIV,
    )
    const tampered: PaymentDenial = {
      ...d,
      denial_reason: 'made_up_reason' as PaymentDenial['denial_reason'],
    }
    const v = verifyPaymentDenial(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'INVALID_DENIAL_REASON')
  })

  it('emit throws on unknown denial_reason at construction time', () => {
    assert.throws(
      () =>
        emitDenial(
          {
            delegation_ref: 'd'.repeat(64),
            action_ref: 'a'.repeat(64),
            rail_name: 'nano',
            amount_base_units: xnoToRaw('0.001'),
            currency: 'XNO',
            denial_reason: 'made_up' as PaymentDenial['denial_reason'],
            issued_at: FIXED_TS,
          },
          ISSUER_PRIV,
        ),
      /denial_reason must be one of/,
    )
  })
})

// ── HumanEscalationFlag — Audit B P9 ─────────────────────────────

describe('preAuthorize — escalation_requirements', () => {
  /** Build a fully-fleshed V2Delegation just to mint an OwnerConfirmation,
   *  then project it back down into a DelegationView with escalation_requirements
   *  + delegator populated. The fixture mirrors what the gateway-side
   *  delegationToView() projection produces for a real V2Delegation. */
  function _escalatedView(opts: {
    confirmation_ttl_ms?: number
    confirmation_scope?: EscalationRequirement['confirmation_scope']
  } = {}) {
    const ownerKey = generateKeyPair()
    const requirement: EscalationRequirement = {
      action_class: 'commerce.purchase',
      requires_owner_confirmation: true,
      confirmation_ttl_ms: opts.confirmation_ttl_ms ?? 5 * 60 * 1000,
      confirmation_scope: opts.confirmation_scope ?? 'time_window',
    }
    const validUntil = new Date(Date.now() + 60 * 60 * 1000).toISOString()
    const validFrom = new Date(Date.now() - 60 * 1000).toISOString()
    const fullDelegation: V2Delegation = {
      id: 'd'.repeat(64),
      version: 1,
      supersedes: null,
      supersession_justification: null,
      delegator: ownerKey.publicKey,
      delegatee: 'agent-002',
      scope: {
        action_categories: ['commerce'],
        escalation_requirements: [requirement],
      },
      policy_context: {
        policy_version: '2.0.0',
        values_floor_version: '1.0.0',
        trust_epoch: 1,
        issuer_id: ownerKey.publicKey,
        created_at: validFrom,
        valid_from: validFrom,
        valid_until: validUntil,
      },
      signature: 'stub_signature_for_test',
      status: 'active',
      renewal_reason: null,
      expansion_reviewer: null,
      expansion_review_sig: null,
      assurance_class: 'mechanically_enforceable',
    }
    const view: DelegationView = {
      receipt_id: fullDelegation.id,
      scope: ['commerce.purchase'],
      spend_limit_base_units: xnoToRaw('1'),
      wallet_id: 'wallet-test-esc-001',
      currency: 'XNO',
      delegator: ownerKey.publicKey,
      escalation_requirements: [requirement],
    }
    return { view, fullDelegation, ownerKey }
  }

  it('no escalation_requirements: existing behavior unchanged', () => {
    const result = preAuthorize(
      {
        delegation: _delegation(),
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
      },
      _rail(),
    )
    assert.equal(result.ok, true)
  })

  it('escalation matches required_scope, no confirmation: denies with requires_owner_confirmation', () => {
    const { view } = _escalatedView()
    const result = preAuthorize(
      {
        delegation: view,
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
      },
      _rail(),
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'requires_owner_confirmation')
  })

  it('escalation matches, valid time_window confirmation: allows', () => {
    const { view, fullDelegation, ownerKey } = _escalatedView()
    const request = requestOwnerConfirmation(fullDelegation, {
      action_class: 'commerce.purchase',
      action_details: { kind: 'any' },
    })
    const confirmation = recordOwnerConfirmation({
      request,
      delegation: fullDelegation,
      owner_private_key: ownerKey.privateKey,
    })
    const result = preAuthorize(
      {
        delegation: view,
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        owner_confirmation: confirmation,
      },
      _rail(),
    )
    assert.equal(result.ok, true, `expected allow, got ${JSON.stringify(result)}`)
  })

  it('escalation matches, expired confirmation: denies', () => {
    const { view, fullDelegation, ownerKey } = _escalatedView({ confirmation_ttl_ms: 1 })
    const request = requestOwnerConfirmation(fullDelegation, {
      action_class: 'commerce.purchase',
      action_details: { kind: 'any' },
    })
    const confirmation = recordOwnerConfirmation({
      request,
      delegation: fullDelegation,
      owner_private_key: ownerKey.privateKey,
    })
    const future = new Date(Date.now() + 5 * 60 * 1000)
    const result = preAuthorize(
      {
        delegation: view,
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        owner_confirmation: confirmation,
        now: future,
      },
      _rail(),
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'requires_owner_confirmation')
    assert.match(result.reason_detail ?? '', /expired/)
  })

  it('escalation matches, confirmation signed by wrong key: denies', () => {
    const { view, fullDelegation } = _escalatedView()
    const wrongOwner = generateKeyPair()
    const request = requestOwnerConfirmation(fullDelegation, {
      action_class: 'commerce.purchase',
      action_details: { kind: 'any' },
    })
    // Sign with the wrong key. The signed object stores confirmed_by =
    // delegation.delegator (which is the RIGHT pubkey), but the signature
    // comes from the wrong private key — verifyOwnerConfirmation should
    // catch the mismatch via signature verification.
    const confirmation = recordOwnerConfirmation({
      request,
      delegation: fullDelegation,
      owner_private_key: wrongOwner.privateKey,
    })
    const result = preAuthorize(
      {
        delegation: view,
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        owner_confirmation: confirmation,
      },
      _rail(),
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'requires_owner_confirmation')
  })

  it('escalation requirement on different action_class: existing behavior unchanged', () => {
    const ownerKey = generateKeyPair()
    const view: DelegationView = {
      ..._delegation(),
      delegator: ownerKey.publicKey,
      escalation_requirements: [
        {
          action_class: 'org_creation',
          requires_owner_confirmation: true,
          confirmation_ttl_ms: 5 * 60 * 1000,
          confirmation_scope: 'time_window',
        },
      ],
    }
    const result = preAuthorize(
      {
        delegation: view,
        required_scope: 'commerce.purchase',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
      },
      _rail(),
    )
    assert.equal(result.ok, true)
  })
})

// ── Fixture byte-parity ───────────────────────────────────────────

describe('fixtures — byte-parity round trip', () => {
  it('checked-in receipt fixture verifies clean', () => {
    const fixture = JSON.parse(
      readFileSync(join(FIXTURE_DIR, 'receipt-nano-happy.fixture.json'), 'utf8'),
    ) as PaymentReceipt
    const v = verifyPaymentReceipt(fixture)
    assert.equal(v.valid, true, `fixture verify failed: ${v.reason}`)
  })

  it('checked-in denial fixture verifies clean', () => {
    const fixture = JSON.parse(
      readFileSync(join(FIXTURE_DIR, 'denial-no-scope.fixture.json'), 'utf8'),
    ) as PaymentDenial
    const v = verifyPaymentDenial(fixture)
    assert.equal(v.valid, true, `fixture verify failed: ${v.reason}`)
  })
})

// ── Phase 4.1 / Q1 — accountability-aligned shape ─────────────────

describe('Phase 4.1 / Q1 — foundation accountability shape', () => {
  it('new emit path populates claim_type rail.payment.v1, timestamp, scope_of_claim', () => {
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        accountability_shape: true,
      },
      ISSUER_PRIV,
    )
    assert.equal(r.claim_type, 'rail.payment.v1')
    assert.equal(r.timestamp, r.issued_at)
    assert.ok(r.scope_of_claim, 'scope_of_claim must be populated')
    assert.ok(r.scope_of_claim!.asserts.length > 0)
    assert.equal(verifyPaymentReceipt(r).valid, true)
  })

  it('legacy-shape receipt (no claim_type accountability literal) still verifies', () => {
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: '1',
        currency: 'XNO',
        tx_proof: 'c'.repeat(64),
      },
      ISSUER_PRIV,
    )
    assert.equal(r.claim_type, 'aps:payment_receipt:v1')
    assert.equal(r.timestamp, undefined)
    assert.equal(r.scope_of_claim, undefined)
    assert.equal(verifyPaymentReceipt(r).valid, true)
  })

  it('verifier rejects accountability-shape receipt with mismatched timestamp', () => {
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: '1',
        currency: 'XNO',
        tx_proof: 'd'.repeat(64),
        accountability_shape: true,
      },
      ISSUER_PRIV,
    )
    const tampered = { ...r, timestamp: '1999-01-01T00:00:00.000Z' }
    assert.equal(verifyPaymentReceipt(tampered).valid, false)
  })

  it('scope_of_claim override propagates to receipt', () => {
    const custom = {
      asserts: 'custom payment evidence claim',
      does_not_assert: ['custom non-assertion'],
      capture_mode: 'gateway_observed' as const,
      completeness: 'complete' as const,
      self_attested: false,
    }
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: '1',
        currency: 'XNO',
        tx_proof: 'e'.repeat(64),
        scope_of_claim: custom,
      },
      ISSUER_PRIV,
    )
    assert.deepEqual(r.scope_of_claim, custom)
    assert.equal(r.claim_type, 'rail.payment.v1')
  })
})

// ── Vocab #91 / SDK #25 — budget_reservation literal acceptance ───
// Positive-case coverage for the three claim_type literals added by
// PR #27 across the four verifier entry points. Each test mints a
// legacy-shape receipt/denial via the existing emit path, rebrands
// claim_type to the budget_reservation literal, and recomputes
// receipt_id + signature with the same canonicalize/sha256/sign
// helpers the emit path uses. No new fixture shape; the DID-aware
// verifiers exercise their raw-hex branch (same pattern as the
// P12 "legacy raw-hex" case in did-uri-signing.test.ts).

describe('verifier — rail.budget_reservation claim_type acceptance', () => {
  it('verifyPaymentReceipt accepts rail.budget_reservation.permit.v1', () => {
    const base = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        issued_at: FIXED_TS,
      },
      ISSUER_PRIV,
    )
    const draft: PaymentReceipt = {
      ...base,
      claim_type: 'rail.budget_reservation.permit.v1',
      receipt_id: '',
      signature: '',
    }
    const receipt_id = paymentRailsSha256Hex(canonicalizeReceiptForId(draft))
    const withId: PaymentReceipt = { ...draft, receipt_id }
    const signature = sign(canonicalizeReceiptForSig(withId), ISSUER_PRIV)
    const r: PaymentReceipt = { ...withId, signature }
    assert.equal(r.claim_type, 'rail.budget_reservation.permit.v1')
    assert.equal(verifyPaymentReceipt(r).valid, true)
  })

  it('verifyPaymentReceipt accepts rail.budget_reservation.release.v1', () => {
    const base = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        issued_at: FIXED_TS,
      },
      ISSUER_PRIV,
    )
    const draft: PaymentReceipt = {
      ...base,
      claim_type: 'rail.budget_reservation.release.v1',
      receipt_id: '',
      signature: '',
    }
    const receipt_id = paymentRailsSha256Hex(canonicalizeReceiptForId(draft))
    const withId: PaymentReceipt = { ...draft, receipt_id }
    const signature = sign(canonicalizeReceiptForSig(withId), ISSUER_PRIV)
    const r: PaymentReceipt = { ...withId, signature }
    assert.equal(r.claim_type, 'rail.budget_reservation.release.v1')
    assert.equal(verifyPaymentReceipt(r).valid, true)
  })

  it('verifyPaymentReceiptWithDID accepts rail.budget_reservation.permit.v1', async () => {
    const base = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        issued_at: FIXED_TS,
      },
      ISSUER_PRIV,
    )
    const draft: PaymentReceipt = {
      ...base,
      claim_type: 'rail.budget_reservation.permit.v1',
      receipt_id: '',
      signature: '',
    }
    const receipt_id = paymentRailsSha256Hex(canonicalizeReceiptForId(draft))
    const withId: PaymentReceipt = { ...draft, receipt_id }
    const signature = sign(canonicalizeReceiptForSig(withId), ISSUER_PRIV)
    const r: PaymentReceipt = { ...withId, signature }
    const v = await verifyPaymentReceiptWithDID(r)
    assert.equal(v.valid, true, `expected valid, got ${v.reason}`)
  })

  it('verifyPaymentReceiptWithDID accepts rail.budget_reservation.release.v1', async () => {
    const base = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        issued_at: FIXED_TS,
      },
      ISSUER_PRIV,
    )
    const draft: PaymentReceipt = {
      ...base,
      claim_type: 'rail.budget_reservation.release.v1',
      receipt_id: '',
      signature: '',
    }
    const receipt_id = paymentRailsSha256Hex(canonicalizeReceiptForId(draft))
    const withId: PaymentReceipt = { ...draft, receipt_id }
    const signature = sign(canonicalizeReceiptForSig(withId), ISSUER_PRIV)
    const r: PaymentReceipt = { ...withId, signature }
    const v = await verifyPaymentReceiptWithDID(r)
    assert.equal(v.valid, true, `expected valid, got ${v.reason}`)
  })

  it('verifyPaymentDenial accepts rail.budget_reservation.denial.v1', () => {
    const base = emitDenial(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        denial_reason: 'no_commerce_scope',
        issued_at: FIXED_TS,
      },
      ISSUER_PRIV,
    )
    const draft: PaymentDenial = {
      ...base,
      claim_type: 'rail.budget_reservation.denial.v1',
      receipt_id: '',
      signature: '',
    }
    const receipt_id = paymentRailsSha256Hex(canonicalizeDenialForId(draft))
    const withId: PaymentDenial = { ...draft, receipt_id }
    const signature = sign(canonicalizeDenialForSig(withId), ISSUER_PRIV)
    const d: PaymentDenial = { ...withId, signature }
    assert.equal(d.claim_type, 'rail.budget_reservation.denial.v1')
    assert.equal(verifyPaymentDenial(d).valid, true)
  })

  it('verifyPaymentDenialWithDID accepts rail.budget_reservation.denial.v1', async () => {
    const base = emitDenial(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: xnoToRaw('0.001'),
        currency: 'XNO',
        denial_reason: 'no_commerce_scope',
        issued_at: FIXED_TS,
      },
      ISSUER_PRIV,
    )
    const draft: PaymentDenial = {
      ...base,
      claim_type: 'rail.budget_reservation.denial.v1',
      receipt_id: '',
      signature: '',
    }
    const receipt_id = paymentRailsSha256Hex(canonicalizeDenialForId(draft))
    const withId: PaymentDenial = { ...draft, receipt_id }
    const signature = sign(canonicalizeDenialForSig(withId), ISSUER_PRIV)
    const d: PaymentDenial = { ...withId, signature }
    const v = await verifyPaymentDenialWithDID(d)
    assert.equal(v.valid, true, `expected valid, got ${v.reason}`)
  })
})
