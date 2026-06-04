// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// AP2 v0.2 interop — APS ↔ AP2 mandate crosswalk tests.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  AP2_VERSION,
  ap2MandateToApsDelegation,
  apsToAp2CartMandate,
  apsToAp2IntentMandate,
  apsToAp2OpenPaymentMandate,
  apsToAp2PaymentMandate,
  signAp2Mandate,
  verifyAp2Mandate,
} from '../../../src/v2/payment-rails/ap2/index.js'
import type {
  AP2CheckoutMandate,
  AP2OpenCheckoutMandate,
  AP2PaymentMandate,
  SignedAP2Mandate,
} from '../../../src/v2/payment-rails/ap2/index.js'
import { generateKeyPair, publicKeyFromPrivate } from '../../../src/crypto/keys.js'
import {
  recordOwnerConfirmation,
  requestOwnerConfirmation,
} from '../../../src/v2/human-escalation.js'
import type { EscalationRequirement, V2Delegation } from '../../../src/v2/types.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_DIR = join(
  __dirname,
  '..',
  '..',
  '..',
  'src',
  'v2',
  'payment-rails',
  'ap2',
  'fixtures',
)

const SIGNER_PRIV = '99'.repeat(32)
const SIGNER_PUB = publicKeyFromPrivate(SIGNER_PRIV)
const VALID_FROM = '2026-05-03T20:00:00.000Z'
const VALID_UNTIL = '2026-06-03T20:00:00.000Z'
// Fixed verification clock inside the VALID_FROM..VALID_UNTIL window, so the
// mandate ttl tests do not depend on real wall-clock time. Matches the fixed
// clock the fixture tests below already use.
const NOW = new Date('2026-05-10T00:00:00.000Z')

function _delegation(overrides: Partial<V2Delegation> = {}): V2Delegation {
  const base: V2Delegation = {
    id: 'aps-deleg-test',
    version: 1,
    supersedes: null,
    supersession_justification: null,
    delegator: 'did:aps:test-user',
    delegatee: SIGNER_PUB,
    scope: {
      action_categories: ['commerce.checkout'],
      domain: 'commerce',
      resource_limits: { 'commerce.spend_limit': 50_000 },
      constraints: { fixture: 'unit test' },
    },
    policy_context: {
      policy_version: 'v2',
      values_floor_version: 'v1',
      trust_epoch: 0,
      issuer_id: 'did:aps:test-user',
      created_at: VALID_FROM,
      valid_from: VALID_FROM,
      valid_until: VALID_UNTIL,
    },
    signature: '',
    status: 'active',
    renewal_reason: null,
    expansion_reviewer: null,
    expansion_review_sig: null,
    assurance_class: 'evidentially_auditable',
  }
  return { ...base, ...overrides }
}

// ── Module pin ────────────────────────────────────────────────────

describe('AP2 v0.2 interop — module sanity', () => {
  it('AP2_VERSION is pinned to "0.2"', () => {
    assert.equal(AP2_VERSION, '0.2')
  })
})

// ── Spend-cap alternate forms (AP2 resolver) ─────────────────────
// Mirrors the trio in tests/v2/payment-rails/mpp.test.ts.
// AP2 calls resolveSpendLimitCents with canonicalKey='commerce.spend_limit',
// which (per scope-resolution.ts) skips the AP2-alias fallback step and
// goes resource_limits['commerce.spend_limit'] → constraints.spend_limit_cents
// (string). resource_limits.spend_limit_cents (Tier-1 canonical for other
// rails) is NOT picked up by the AP2 path.

describe('AP2 spend-cap resolution — alternate forms', () => {
  it('(a) resource_limits[commerce.spend_limit] surfaces in payment.budget', () => {
    const d = _delegation({
      scope: {
        action_categories: ['commerce.payment'],
        domain: 'commerce',
        resource_limits: { 'commerce.spend_limit': 50_000 },
        constraints: {},
      },
    })
    const m = apsToAp2OpenPaymentMandate(d, { currency: 'USD' })
    const budget = m.constraints.find((c) => c.type === 'payment.budget')
    assert.ok(budget && budget.type === 'payment.budget')
    if (budget?.type !== 'payment.budget') return
    assert.equal(budget.total.value, 50_000)
  })

  it('(b) resource_limits.spend_limit_cents is NOT picked up — AP2 yields 0 sentinel', () => {
    // NOTE: AP2's _spendLimitFromDelegation overrides canonicalKey to
    // 'commerce.spend_limit'. resolveSpendLimitCents then skips the
    // AP2-alias fallback and falls through to constraints (string).
    // Tier-1 canonical 'spend_limit_cents' is invisible to AP2 — by design.
    const d = _delegation({
      scope: {
        action_categories: ['commerce.payment'],
        domain: 'commerce',
        resource_limits: { spend_limit_cents: 50_000 },
        constraints: {},
      },
    })
    const m = apsToAp2OpenPaymentMandate(d, { currency: 'USD' })
    const budget = m.constraints.find((c) => c.type === 'payment.budget')
    assert.ok(budget && budget.type === 'payment.budget')
    if (budget?.type !== 'payment.budget') return
    assert.equal(budget.total.value, 0)
  })

  it('(c) constraints.spend_limit_cents string fallback round-trips to 50000', () => {
    const d = _delegation({
      scope: {
        action_categories: ['commerce.payment'],
        domain: 'commerce',
        resource_limits: {},
        constraints: { spend_limit_cents: '50000' },
      },
    })
    const m = apsToAp2OpenPaymentMandate(d, { currency: 'USD' })
    const budget = m.constraints.find((c) => c.type === 'payment.budget')
    assert.ok(budget && budget.type === 'payment.budget')
    if (budget?.type !== 'payment.budget') return
    assert.equal(budget.total.value, 50_000)
  })
})

// ── apsToAp2IntentMandate (OpenCheckoutMandate) ──────────────────

describe('apsToAp2IntentMandate', () => {
  it('produces an OpenCheckoutMandate with correct vct and cnf', () => {
    const m = apsToAp2IntentMandate(_delegation(), { currency: 'USD' })
    assert.equal(m.vct, 'mandate.checkout.open.1')
    assert.deepEqual(m.cnf.jwk?.kty, 'OKP')
    assert.deepEqual(m.cnf.jwk?.crv, 'Ed25519')
    assert.ok((m.cnf.jwk?.x?.length ?? 0) > 0)
  })

  it('encodes valid_from / valid_until as Unix epoch seconds', () => {
    const m = apsToAp2IntentMandate(_delegation(), { currency: 'USD' })
    assert.equal(m.iat, Math.floor(Date.parse(VALID_FROM) / 1000))
    assert.equal(m.exp, Math.floor(Date.parse(VALID_UNTIL) / 1000))
  })

  it('builds allowed_merchants constraint when option provided', () => {
    const merchant = { id: 'merch:001', name: 'Test Merchant' }
    const m = apsToAp2IntentMandate(_delegation(), {
      currency: 'USD',
      allowed_merchants: [merchant],
    })
    const c = m.constraints.find((c) => c.type === 'checkout.allowed_merchants')
    assert.ok(c)
    if (c?.type !== 'checkout.allowed_merchants') return
    assert.deepEqual(c.allowed, [merchant])
  })

  it('builds line_items constraint when option provided', () => {
    const m = apsToAp2IntentMandate(_delegation(), {
      currency: 'USD',
      line_items: [
        {
          id: 'req-001',
          acceptable_items: [
            {
              id: 'i1',
              name: 'Widget',
              quantity: 1,
              unit_price: { currency: 'USD', value: 999 },
            },
          ],
          quantity: 1,
        },
      ],
    })
    const c = m.constraints.find((c) => c.type === 'checkout.line_items')
    assert.ok(c)
  })

  it('omits constraints[] entries when no options provided', () => {
    const m = apsToAp2IntentMandate(_delegation(), { currency: 'USD' })
    assert.equal(m.constraints.length, 0)
  })
})

// ── ap2MandateToApsDelegation (round-trip) ───────────────────────

describe('ap2MandateToApsDelegation — round-trip', () => {
  it('OpenCheckoutMandate → V2Delegation preserves delegatee, valid_until, scope category', () => {
    const original = _delegation()
    const m = apsToAp2IntentMandate(original, {
      currency: 'USD',
      allowed_merchants: [{ id: 'merch:001', name: 'M1' }],
    })
    const recovered = ap2MandateToApsDelegation(m, {
      delegator_did: original.delegator,
      delegation_id: 'aps-deleg-recovered',
    })
    assert.equal(recovered.delegatee, original.delegatee)
    assert.equal(recovered.policy_context.valid_until, original.policy_context.valid_until)
    assert.deepEqual(recovered.scope.action_categories, ['commerce.checkout'])
    // ap2_vct round-trips through scope.constraints for audit.
    assert.equal(recovered.scope.constraints?.ap2_vct, 'mandate.checkout.open.1')
  })

  it('OpenPaymentMandate budget round-trips into resource_limits', () => {
    const original = _delegation({
      scope: {
        action_categories: ['commerce.payment'],
        domain: 'commerce',
        resource_limits: { 'commerce.spend_limit': 12345 },
        constraints: {},
      },
    })
    const m = apsToAp2OpenPaymentMandate(original, { currency: 'USD' })
    const recovered = ap2MandateToApsDelegation(m, {
      delegator_did: original.delegator,
      delegation_id: 'aps-deleg-recovered',
    })
    assert.deepEqual(recovered.scope.action_categories, ['commerce.payment'])
    assert.equal(recovered.scope.resource_limits?.['commerce.spend_limit'], 12345)
    assert.equal(recovered.scope.constraints?.currency, 'USD')
  })

  it('PaymentMandate (closed) round-trips amount + payee + instrument', () => {
    const m = apsToAp2PaymentMandate(_delegation(), {
      payee: { id: 'merch:m2', name: 'M2' },
      payment_instrument: { type: 'card', id: 'pi:c1' },
      payment_amount: { currency: 'USD', value: 999 },
      transaction_id: 'tx-test',
    })
    const recovered = ap2MandateToApsDelegation(m, {
      delegator_did: 'did:aps:user',
      delegation_id: 'aps-deleg-test',
    })
    assert.equal(recovered.scope.resource_limits?.['commerce.spend_limit'], 999)
    assert.equal(recovered.scope.constraints?.payee_id, 'merch:m2')
    assert.equal(recovered.scope.constraints?.payment_instrument_id, 'pi:c1')
    assert.equal(recovered.scope.constraints?.currency, 'USD')
  })

  it('CheckoutMandate (closed) maps to commerce.checkout but does NOT preserve cart items', () => {
    const m = apsToAp2CartMandate(
      _delegation(),
      {
        payee: { id: 'merch:m', name: 'M' },
        items: [
          {
            id: 'i1',
            name: 'Item',
            quantity: 2,
            unit_price: { currency: 'USD', value: 500 },
          },
        ],
        total: { currency: 'USD', value: 1000 },
      },
      {},
    )
    const recovered = ap2MandateToApsDelegation(m, {
      delegator_did: 'did:aps:user',
      delegation_id: 'recovered',
    })
    assert.deepEqual(recovered.scope.action_categories, ['commerce.checkout'])
    // Total carries forward as resource_limits, payee_id as constraint.
    assert.equal(recovered.scope.resource_limits?.['commerce.spend_limit'], 1000)
    assert.equal(recovered.scope.constraints?.payee_id, 'merch:m')
    // But the items[] array is NOT preserved (one-way limitation).
    assert.equal((recovered.scope as { items?: unknown[] }).items, undefined)
  })
})

// ── signAp2Mandate + verifyAp2Mandate ────────────────────────────

describe('signAp2Mandate + verifyAp2Mandate', () => {
  it('signs and verifies a round-trip mandate', () => {
    const m = apsToAp2IntentMandate(_delegation(), { currency: 'USD' })
    const signed = signAp2Mandate(m, SIGNER_PRIV)
    assert.equal(signed.signer_did, SIGNER_PUB)
    assert.equal(signed.signature.length, 128)
    const v = verifyAp2Mandate(signed, { now: NOW })
    assert.equal(v.valid, true)
  })

  it('rejects mandate with mismatched signature (flipped byte)', () => {
    const m = apsToAp2IntentMandate(_delegation(), { currency: 'USD' })
    const signed = signAp2Mandate(m, SIGNER_PRIV)
    const last = signed.signature.slice(-1)
    const flipped = signed.signature.slice(0, -1) + (last === '0' ? '1' : '0')
    const tampered: SignedAP2Mandate = { ...signed, signature: flipped }
    const v = verifyAp2Mandate(tampered, { now: NOW })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'SIGNATURE_INVALID')
  })

  it('rejects mandate when expected_signer_did mismatches', () => {
    const m = apsToAp2IntentMandate(_delegation(), { currency: 'USD' })
    const signed = signAp2Mandate(m, SIGNER_PRIV)
    const v = verifyAp2Mandate(signed, { expected_signer_did: '0'.repeat(64), now: NOW })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'SIGNATURE_INVALID')
  })

  it('rejects mandate with INVALID_VCT when vct is unknown', () => {
    const m = apsToAp2IntentMandate(_delegation(), { currency: 'USD' })
    const signed = signAp2Mandate(m, SIGNER_PRIV)
    const tampered = {
      ...signed,
      mandate: { ...signed.mandate, vct: 'mandate.unknown.1' as never },
    }
    const v = verifyAp2Mandate(tampered as SignedAP2Mandate, { now: NOW })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'INVALID_VCT')
  })

  it('rejects mandate with EXPIRED reason when exp < now', () => {
    const past = new Date('2020-01-01T00:00:00.000Z').toISOString()
    const expired = _delegation({
      policy_context: {
        ..._delegation().policy_context,
        valid_until: past,
      },
    })
    const m = apsToAp2IntentMandate(expired, { currency: 'USD' })
    const signed = signAp2Mandate(m, SIGNER_PRIV)
    const v = verifyAp2Mandate(signed, { now: new Date('2026-05-03T21:00:00.000Z') })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'EXPIRED')
  })

  it('rejects mandate with NOT_YET_VALID when iat > now', () => {
    const future = new Date('2099-01-01T00:00:00.000Z').toISOString()
    const notYet = _delegation({
      policy_context: {
        ..._delegation().policy_context,
        valid_from: future,
      },
    })
    const m = apsToAp2IntentMandate(notYet, { currency: 'USD' })
    const signed = signAp2Mandate(m, SIGNER_PRIV)
    const v = verifyAp2Mandate(signed, { now: new Date('2026-05-03T21:00:00.000Z') })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'NOT_YET_VALID')
  })

  it('detects MISSING_REQUIRED_FIELD on a CheckoutMandate without checkout_hash', () => {
    const m = apsToAp2CartMandate(
      _delegation(),
      {
        payee: { id: 'm', name: 'M' },
        items: [],
        total: { currency: 'USD', value: 0 },
      },
      {},
    )
    // Force the schema gap.
    const badMandate: AP2CheckoutMandate = { ...m, checkout_hash: '' }
    const signed = signAp2Mandate(badMandate, SIGNER_PRIV)
    const v = verifyAp2Mandate(signed, { now: NOW })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'MISSING_REQUIRED_FIELD')
  })

  it('detects MISSING_REQUIRED_FIELD on a PaymentMandate missing payment_instrument', () => {
    const m = apsToAp2PaymentMandate(_delegation(), {
      payee: { id: 'm', name: 'M' },
      payment_instrument: { type: 'card', id: 'pi:c1' },
      payment_amount: { currency: 'USD', value: 100 },
      transaction_id: 'tx',
    })
    const bad: AP2PaymentMandate = { ...m, payment_instrument: undefined as unknown as AP2PaymentMandate['payment_instrument'] }
    const signed = signAp2Mandate(bad, SIGNER_PRIV)
    const v = verifyAp2Mandate(signed, { now: NOW })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'MISSING_REQUIRED_FIELD')
  })

  it('two emits with identical inputs produce identical signatures', () => {
    const m = apsToAp2IntentMandate(_delegation(), { currency: 'USD' })
    const a = signAp2Mandate(m, SIGNER_PRIV)
    const b = signAp2Mandate(m, SIGNER_PRIV)
    assert.equal(a.signature, b.signature)
  })
})

// ── Fixture byte-parity ──────────────────────────────────────────

describe('AP2 fixtures — byte-parity round trip', () => {
  it('META.json pins ap2_version 0.2', () => {
    const meta = JSON.parse(readFileSync(join(FIXTURE_DIR, 'META.json'), 'utf8'))
    assert.equal(meta.ap2_version, '0.2')
    assert.equal(meta.pairs.length, 3)
  })

  it('intent fixture (001) verifies clean', () => {
    const signed = JSON.parse(
      readFileSync(join(FIXTURE_DIR, 'ap2-intent-mandate-001.json'), 'utf8'),
    ) as SignedAP2Mandate<AP2OpenCheckoutMandate>
    const v = verifyAp2Mandate(signed, { now: NOW })
    assert.equal(v.valid, true, `verify failed: ${v.reason} ${v.detail}`)
  })

  it('cart fixture (002) verifies clean', () => {
    const signed = JSON.parse(
      readFileSync(join(FIXTURE_DIR, 'ap2-cart-mandate-002.json'), 'utf8'),
    ) as SignedAP2Mandate<AP2CheckoutMandate>
    const v = verifyAp2Mandate(signed, { now: NOW })
    assert.equal(v.valid, true, `verify failed: ${v.reason} ${v.detail}`)
  })

  it('payment fixture (003) verifies clean', () => {
    const signed = JSON.parse(
      readFileSync(join(FIXTURE_DIR, 'ap2-payment-mandate-003.json'), 'utf8'),
    ) as SignedAP2Mandate<AP2PaymentMandate>
    const v = verifyAp2Mandate(signed, { now: NOW })
    assert.equal(v.valid, true, `verify failed: ${v.reason} ${v.detail}`)
  })

  it('intent fixture (001) round-trips back into an APS delegation', () => {
    const apsOriginal = JSON.parse(
      readFileSync(join(FIXTURE_DIR, 'aps-delegation-001.json'), 'utf8'),
    ) as V2Delegation
    const signed = JSON.parse(
      readFileSync(join(FIXTURE_DIR, 'ap2-intent-mandate-001.json'), 'utf8'),
    ) as SignedAP2Mandate<AP2OpenCheckoutMandate>
    const recovered = ap2MandateToApsDelegation(signed.mandate, {
      delegator_did: apsOriginal.delegator,
      delegation_id: apsOriginal.id,
    })
    assert.equal(recovered.delegatee, apsOriginal.delegatee)
    assert.equal(
      recovered.policy_context.valid_until,
      apsOriginal.policy_context.valid_until,
    )
    assert.deepEqual(recovered.scope.action_categories, apsOriginal.scope.action_categories)
  })
})

// ── HumanEscalationFlag — Audit B P9 ─────────────────────────────

describe('apsToAp2*Mandate — escalation_requirements', () => {
  /** Build a delegation flagged with action_class 'commerce' and a real
   *  keypair as delegator so a matching OwnerConfirmation can be minted
   *  via recordOwnerConfirmation. */
  function _escalatedDelegation(opts: {
    confirmation_ttl_ms?: number
    confirmation_scope?: EscalationRequirement['confirmation_scope']
  } = {}) {
    const ownerKey = generateKeyPair()
    const requirement: EscalationRequirement = {
      action_class: 'commerce',
      requires_owner_confirmation: true,
      confirmation_ttl_ms: opts.confirmation_ttl_ms ?? 5 * 60 * 1000,
      confirmation_scope: opts.confirmation_scope ?? 'time_window',
    }
    const delegation = _delegation({
      delegator: ownerKey.publicKey,
      scope: {
        action_categories: ['commerce.checkout'],
        resource_limits: { 'commerce.spend_limit': 50_000 },
        escalation_requirements: [requirement],
      },
    })
    return { delegation, ownerKey }
  }

  function _mintConfirmation(
    delegation: V2Delegation,
    ownerKey: ReturnType<typeof generateKeyPair>,
    details: Record<string, unknown>,
  ) {
    const request = requestOwnerConfirmation(delegation, {
      action_class: 'commerce',
      action_details: details,
    })
    return recordOwnerConfirmation({
      request,
      delegation,
      owner_private_key: ownerKey.privateKey,
    })
  }

  it('apsToAp2IntentMandate: no escalation_requirements: existing behavior unchanged', () => {
    const m = apsToAp2IntentMandate(_delegation(), { currency: 'USD' })
    assert.equal(m.vct, 'mandate.checkout.open.1')
  })

  it('apsToAp2IntentMandate: escalation matches commerce, no confirmation: throws', () => {
    const { delegation } = _escalatedDelegation()
    assert.throws(
      () => apsToAp2IntentMandate(delegation, { currency: 'USD' }),
      /requires_owner_confirmation/,
    )
  })

  it('apsToAp2IntentMandate: escalation matches, valid time_window confirmation: builds mandate', () => {
    const { delegation, ownerKey } = _escalatedDelegation()
    const confirmation = _mintConfirmation(delegation, ownerKey, { kind: 'any' })
    const m = apsToAp2IntentMandate(delegation, {
      currency: 'USD',
      owner_confirmation: confirmation,
    })
    assert.equal(m.vct, 'mandate.checkout.open.1')
  })

  it('apsToAp2CartMandate: escalation matches, no confirmation: throws', () => {
    const { delegation } = _escalatedDelegation()
    assert.throws(
      () =>
        apsToAp2CartMandate(delegation, {
          payee: { name: 'merchant', merchant_category_code: '5411' },
          items: [],
          total: { currency: 'USD', value: '10' },
        }),
      /requires_owner_confirmation/,
    )
  })

  it('apsToAp2PaymentMandate: escalation matches, expired confirmation: throws', () => {
    const { delegation, ownerKey } = _escalatedDelegation({ confirmation_ttl_ms: 1 })
    const confirmation = _mintConfirmation(delegation, ownerKey, { kind: 'any' })
    const future = new Date(Date.now() + 5 * 60 * 1000)
    assert.throws(
      () =>
        apsToAp2PaymentMandate(delegation, {
          payee: { name: 'merchant', merchant_category_code: '5411' },
          payment_instrument: { type: 'card', token: 'tok_1' },
          payment_amount: { currency: 'USD', value: '10' },
          transaction_id: 'tx_001',
          owner_confirmation: confirmation,
          now: future,
        }),
      /invalid owner_confirmation/,
    )
  })

  it('apsToAp2OpenPaymentMandate: escalation matches, valid confirmation: builds mandate', () => {
    const { delegation, ownerKey } = _escalatedDelegation()
    const confirmation = _mintConfirmation(delegation, ownerKey, { kind: 'any' })
    const m = apsToAp2OpenPaymentMandate(delegation, {
      currency: 'USD',
      owner_confirmation: confirmation,
    })
    assert.equal(m.vct, 'mandate.payment.open.1')
  })

  it('escalation requirement on different action_class: existing behavior unchanged', () => {
    const ownerKey = generateKeyPair()
    const delegation = _delegation({
      delegator: ownerKey.publicKey,
      scope: {
        action_categories: ['commerce.checkout'],
        resource_limits: { 'commerce.spend_limit': 50_000 },
        escalation_requirements: [
          {
            action_class: 'org_creation',
            requires_owner_confirmation: true,
            confirmation_ttl_ms: 5 * 60 * 1000,
            confirmation_scope: 'time_window',
          },
        ],
      },
    })
    const m = apsToAp2IntentMandate(delegation, { currency: 'USD' })
    assert.equal(m.vct, 'mandate.checkout.open.1')
  })
})

// ── Phase 4.1 / Q1 — accountability shape ─────────────────────────

describe('AP2 Q1 — accountability shape', () => {
  const ownerKey = generateKeyPair()
  function intent(): V2Delegation {
    return {
      id: 'del_ap2_q1',
      version: 1,
      supersedes: null,
      supersession_justification: null,
      delegator: 'did:aps:user',
      delegatee: ownerKey.publicKey,
      scope: {
        action_categories: ['commerce.checkout'],
        resource_limits: { 'commerce.spend_limit': 50000 },
        constraints: {},
      },
      policy_context: {
        policy_version: '2.0.0',
        values_floor_version: '1.0.0',
        trust_epoch: 1,
        issuer_id: 'did:aps:user',
        created_at: '2026-05-04T00:00:00.000Z',
        valid_from: '2026-05-04T00:00:00.000Z',
        valid_until: '2026-12-31T23:59:59.000Z',
      },
      signature: 'stub',
      status: 'active',
      renewal_reason: null,
      expansion_reviewer: null,
      expansion_review_sig: null,
      assurance_class: 'mechanically_enforceable',
    }
  }

  it('signAp2Mandate accountability_shape populates rail.ap2.mandate.v1, timestamp, scope_of_claim', () => {
    const kp = generateKeyPair()
    const m = apsToAp2IntentMandate(intent(), { currency: 'USD' })
    const signed = signAp2Mandate(m, kp.privateKey, { accountability_shape: true })
    assert.equal(signed.claim_type, 'rail.ap2.mandate.v1')
    assert.equal(typeof signed.timestamp, 'string')
    assert.ok(signed.scope_of_claim && signed.scope_of_claim.asserts.length > 0)
    assert.equal(verifyAp2Mandate(signed).valid, true)
  })

  it('legacy-shape SignedAP2Mandate (no claim_type) still verifies', () => {
    const kp = generateKeyPair()
    const m = apsToAp2IntentMandate(intent(), { currency: 'USD' })
    const signed = signAp2Mandate(m, kp.privateKey)
    assert.equal(signed.claim_type, undefined)
    assert.equal(verifyAp2Mandate(signed).valid, true)
  })

  it('SignedAP2Mandate with mismatched claim_type literal rejected', () => {
    const kp = generateKeyPair()
    const m = apsToAp2IntentMandate(intent(), { currency: 'USD' })
    const signed = signAp2Mandate(m, kp.privateKey, { accountability_shape: true })
    const tampered = { ...signed, claim_type: 'rail.payment.v1' as unknown as 'rail.ap2.mandate.v1' }
    assert.equal(verifyAp2Mandate(tampered).valid, false)
  })

  it('scope_of_claim override propagates', () => {
    const kp = generateKeyPair()
    const m = apsToAp2IntentMandate(intent(), { currency: 'USD' })
    const custom = {
      asserts: 'custom ap2 claim',
      does_not_assert: ['custom'],
      capture_mode: 'self_attested' as const,
      completeness: 'complete' as const,
      self_attested: true,
    }
    const signed = signAp2Mandate(m, kp.privateKey, { scope_of_claim: custom })
    assert.deepEqual(signed.scope_of_claim, custom)
  })
})
