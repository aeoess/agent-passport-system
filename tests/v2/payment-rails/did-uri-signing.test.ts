// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Phase 4.1 / P12 — DID URI signer_did across all five rails
// ══════════════════════════════════════════════════════════════════
// Seven cases per rail (foundation, ACP, MPP, AP2, Stripe-Issuing
// inherits foundation):
//
//   1. Sign with DID URI; verify with resolver → pass
//   2. Sign with DID URI; rotate planned (retiredAt > issuedAt);
//      verify post-rotation → pass
//   3. Sign with DID URI; rotate emergency (retiredAt < issuedAt);
//      verify → fail with DID_KEY_RETIRED
//   4. Sign with raw hex (legacy); verify without resolver → pass
//   5. Sign with DID URI; verify without resolver → DID_RESOLVER_MISSING
//   6. Sign with DID URI; resolver returns null → DID_DOC_NOT_FOUND
//   7. Sign with DID URI; keyRef not in returned doc → DID_KEY_NOT_IN_DOC
//
// The dual-bug fix (CC-1 verdict): rotation no longer breaks legitimate
// receipts (case 2) AND a retired key cannot mint passing receipts
// (case 3). Compatible-superset: legacy raw-hex still works (case 4).
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  emitReceipt,
  verifyPaymentReceipt,
  verifyPaymentReceiptWithDID,
} from '../../../src/v2/payment-rails/index.js'
import {
  signAcpReceipt,
  verifyAcpReceipt,
  verifyAcpReceiptWithDID,
} from '../../../src/v2/payment-rails/acp/index.js'
import {
  signMppReceipt,
  verifyMppReceipt,
  verifyMppReceiptWithDID,
} from '../../../src/v2/payment-rails/mpp/index.js'
import {
  apsToAp2IntentMandate,
  signAp2Mandate,
  verifyAp2Mandate,
  verifyAp2MandateWithDID,
} from '../../../src/v2/payment-rails/ap2/index.js'
import { generateKeyPair } from '../../../src/crypto/keys.js'

import type { AcpCheckoutSession } from '../../../src/v2/payment-rails/acp/types.js'
import type { V2Delegation } from '../../../src/v2/types.js'
import {
  docAfterRotation,
  docKey1Active,
  makeResolver,
  makeRotationFixture,
} from './fixtures/did-rotation-fixture.js'

// ── Test helpers ──────────────────────────────────────────────────

const NOW_ISO = '2026-05-04T12:00:00.000Z'
const NOW_MS = Date.parse(NOW_ISO)
const PRE_ROT_ISO = '2026-05-04T11:00:00.000Z' // before NOW_ISO
const POST_ROT_ISO = '2026-05-04T13:00:00.000Z' // after NOW_ISO

function happyAcpSession(): AcpCheckoutSession {
  return {
    id: 'cs_p12',
    status: 'ready_for_payment',
    currency: 'usd',
    line_items: [
      {
        id: 'li_001',
        item: { id: 'item_widget', quantity: 1 },
        base_amount: 1000,
        discount: 0,
        subtotal: 1000,
        tax: 100,
        total: 1100,
      },
    ],
    payment_provider: { provider: 'stripe', supported_payment_methods: ['card'] },
    totals: [
      { type: 'items_base_amount', display_text: 'Items', amount: 1000 },
      { type: 'tax', display_text: 'Tax', amount: 100 },
      { type: 'total', display_text: 'Total', amount: 1100 },
    ],
  }
}

function intent(): V2Delegation {
  return {
    id: 'del_p12',
    version: 1,
    supersedes: null,
    supersession_justification: null,
    delegator: 'did:aps:user',
    delegatee: 'did:aps:agent',
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

// ── Foundation: PaymentReceipt ────────────────────────────────────

describe('P12 — Foundation PaymentReceipt with DID URI signer', () => {
  it('1. DID URI signer + resolver → pass', async () => {
    const fx = makeRotationFixture()
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: '1',
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        issued_at: PRE_ROT_ISO,
        issuer_agent_id: fx.agentId,
        issuer_key_ref: fx.key1.keyRef,
      },
      fx.key1.privateKey,
    )
    assert.equal(r.signer_did, fx.key1.didUri)
    const resolver = makeResolver({
      [fx.agentId]: docKey1Active(fx, '2026-05-04T00:00:00.000Z'),
    })
    const v = await verifyPaymentReceiptWithDID(r, { resolveDidDocument: resolver })
    assert.equal(v.valid, true, `expected valid, got ${v.reason}`)
  })

  it('2. Planned rotation (retiredAt > issuedAt) → pass', async () => {
    const fx = makeRotationFixture()
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: '1',
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        issued_at: PRE_ROT_ISO,
        issuer_agent_id: fx.agentId,
        issuer_key_ref: fx.key1.keyRef,
      },
      fx.key1.privateKey,
    )
    const resolver = makeResolver({
      [fx.agentId]: docAfterRotation(fx, '2026-05-04T00:00:00.000Z', POST_ROT_ISO),
    })
    const v = await verifyPaymentReceiptWithDID(r, {
      resolveDidDocument: resolver,
      now: new Date(NOW_MS),
    })
    assert.equal(v.valid, true, `post-rotation verify should pass; got ${v.reason}`)
  })

  it('3. Emergency rotation (retiredAt < issuedAt) → DID_KEY_RETIRED', async () => {
    const fx = makeRotationFixture()
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: '1',
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        issued_at: NOW_ISO, // signing instant
        issuer_agent_id: fx.agentId,
        issuer_key_ref: fx.key1.keyRef,
      },
      fx.key1.privateKey,
    )
    const resolver = makeResolver({
      // key1 retired BEFORE the signing instant (compromise mode)
      [fx.agentId]: docAfterRotation(fx, '2026-05-04T00:00:00.000Z', PRE_ROT_ISO),
    })
    const v = await verifyPaymentReceiptWithDID(r, { resolveDidDocument: resolver })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_KEY_RETIRED')
  })

  it('4. Legacy raw-hex signer + no resolver → pass', () => {
    const kp = generateKeyPair()
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: '1',
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
      },
      kp.privateKey,
    )
    assert.ok(!r.signer_did.startsWith('did:'))
    assert.equal(verifyPaymentReceipt(r).valid, true)
  })

  it('5. DID URI without resolver → DID_RESOLVER_MISSING', async () => {
    const fx = makeRotationFixture()
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: '1',
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        issuer_agent_id: fx.agentId,
        issuer_key_ref: fx.key1.keyRef,
      },
      fx.key1.privateKey,
    )
    const v = await verifyPaymentReceiptWithDID(r) // no resolver
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_RESOLVER_MISSING')
  })

  it('6. resolver returns null → DID_DOC_NOT_FOUND', async () => {
    const fx = makeRotationFixture()
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: '1',
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        issuer_agent_id: fx.agentId,
        issuer_key_ref: fx.key1.keyRef,
      },
      fx.key1.privateKey,
    )
    const resolver = makeResolver({}) // empty map — agent not found
    const v = await verifyPaymentReceiptWithDID(r, { resolveDidDocument: resolver })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_DOC_NOT_FOUND')
  })

  it('7. keyRef not in returned doc → DID_KEY_NOT_IN_DOC', async () => {
    const fx = makeRotationFixture()
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: '1',
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        // signer claims key-2 but the doc only has key-1
        issuer_agent_id: fx.agentId,
        issuer_key_ref: fx.key2.keyRef,
      },
      fx.key2.privateKey,
    )
    const resolver = makeResolver({
      [fx.agentId]: docKey1Active(fx, '2026-05-04T00:00:00.000Z'),
    })
    const v = await verifyPaymentReceiptWithDID(r, { resolveDidDocument: resolver })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_KEY_NOT_IN_DOC')
  })
})

// ── ACP: AcpReceipt ───────────────────────────────────────────────

describe('P12 — ACP AcpReceipt with DID URI signer', () => {
  function mkAcpReceipt(fx: ReturnType<typeof makeRotationFixture>, opts: {
    useKey2?: boolean
    legacy?: boolean
  } = {}) {
    const kp = opts.useKey2 ? fx.key2 : fx.key1
    const issuer = opts.legacy
      ? {}
      : { issuer_agent_id: fx.agentId, issuer_key_ref: kp.keyRef }
    return signAcpReceipt(
      {
        op: 'create',
        session_id: 'cs_p12',
        request_body: { items: [{ id: 'i', quantity: 1 }] },
        session_state: happyAcpSession(),
        delegation_ref: 'del_p12',
        agent_id: 'agent-001',
        ...issuer,
      },
      kp.privateKey,
    )
  }

  it('1. DID URI signer + resolver → pass', async () => {
    const fx = makeRotationFixture()
    const r = mkAcpReceipt(fx)
    const resolver = makeResolver({
      [fx.agentId]: docKey1Active(fx, '2026-05-04T00:00:00.000Z'),
    })
    const v = await verifyAcpReceiptWithDID(r, { resolveDidDocument: resolver })
    assert.equal(v.valid, true, `expected valid, got ${v.reason}`)
  })

  it('2. Planned rotation (retiredAt > issuedAt) → pass', async () => {
    const fx = makeRotationFixture()
    const r = mkAcpReceipt(fx)
    const future = new Date(Date.parse(r.issued_at) + 60 * 60 * 1000).toISOString()
    const resolver = makeResolver({
      [fx.agentId]: docAfterRotation(fx, '2026-05-04T00:00:00.000Z', future),
    })
    const v = await verifyAcpReceiptWithDID(r, { resolveDidDocument: resolver })
    assert.equal(v.valid, true, `post-rotation should pass; got ${v.reason}`)
  })

  it('3. Emergency rotation → DID_KEY_RETIRED', async () => {
    const fx = makeRotationFixture()
    const r = mkAcpReceipt(fx)
    const past = new Date(Date.parse(r.issued_at) - 60 * 60 * 1000).toISOString()
    const resolver = makeResolver({
      [fx.agentId]: docAfterRotation(fx, '2026-05-04T00:00:00.000Z', past),
    })
    const v = await verifyAcpReceiptWithDID(r, { resolveDidDocument: resolver })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_KEY_RETIRED')
  })

  it('4. Legacy raw-hex signer + no resolver → pass', () => {
    const fx = makeRotationFixture()
    const r = mkAcpReceipt(fx, { legacy: true })
    assert.ok(!r.signer.startsWith('did:'))
    const v = verifyAcpReceipt(r)
    assert.equal(v.valid, true)
  })

  it('5. DID URI without resolver → DID_RESOLVER_MISSING', async () => {
    const fx = makeRotationFixture()
    const r = mkAcpReceipt(fx)
    const v = await verifyAcpReceiptWithDID(r)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_RESOLVER_MISSING')
  })

  it('6. resolver returns null → DID_DOC_NOT_FOUND', async () => {
    const fx = makeRotationFixture()
    const r = mkAcpReceipt(fx)
    const resolver = makeResolver({})
    const v = await verifyAcpReceiptWithDID(r, { resolveDidDocument: resolver })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_DOC_NOT_FOUND')
  })

  it('7. keyRef not in returned doc → DID_KEY_NOT_IN_DOC', async () => {
    const fx = makeRotationFixture()
    const r = mkAcpReceipt(fx, { useKey2: true }) // claims key-2
    const resolver = makeResolver({
      [fx.agentId]: docKey1Active(fx, '2026-05-04T00:00:00.000Z'), // only has key-1
    })
    const v = await verifyAcpReceiptWithDID(r, { resolveDidDocument: resolver })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_KEY_NOT_IN_DOC')
  })
})

// ── MPP: MppApsReceipt ────────────────────────────────────────────

describe('P12 — MPP MppApsReceipt with DID URI signer', () => {
  function mkMppReceipt(fx: ReturnType<typeof makeRotationFixture>, opts: {
    useKey2?: boolean
    legacy?: boolean
  } = {}) {
    const kp = opts.useKey2 ? fx.key2 : fx.key1
    const issuer = opts.legacy
      ? {}
      : { issuer_agent_id: fx.agentId, issuer_key_ref: kp.keyRef }
    return signMppReceipt(
      {
        challenge_id: 'ch_p12',
        method_type: 'card',
        amount_paid: '500',
        currency: 'usd',
        paid_at: NOW_ISO,
        resource: 'https://api.example.com/r',
        delegation_ref: 'del_p12',
        agent_id: 'agent-001',
        ...issuer,
      },
      kp.privateKey,
    )
  }

  it('1. DID URI signer + resolver → pass', async () => {
    const fx = makeRotationFixture()
    const r = mkMppReceipt(fx)
    const resolver = makeResolver({
      [fx.agentId]: docKey1Active(fx, '2026-05-04T00:00:00.000Z'),
    })
    const v = await verifyMppReceiptWithDID(r, { resolveDidDocument: resolver })
    assert.equal(v.valid, true, `got ${v.reason}`)
  })

  it('2. Planned rotation → pass', async () => {
    const fx = makeRotationFixture()
    const r = mkMppReceipt(fx)
    const future = new Date(Date.parse(r.issued_at) + 60 * 60 * 1000).toISOString()
    const resolver = makeResolver({
      [fx.agentId]: docAfterRotation(fx, '2026-05-04T00:00:00.000Z', future),
    })
    const v = await verifyMppReceiptWithDID(r, { resolveDidDocument: resolver })
    assert.equal(v.valid, true)
  })

  it('3. Emergency rotation → DID_KEY_RETIRED', async () => {
    const fx = makeRotationFixture()
    const r = mkMppReceipt(fx)
    const past = new Date(Date.parse(r.issued_at) - 60 * 60 * 1000).toISOString()
    const resolver = makeResolver({
      [fx.agentId]: docAfterRotation(fx, '2026-05-04T00:00:00.000Z', past),
    })
    const v = await verifyMppReceiptWithDID(r, { resolveDidDocument: resolver })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_KEY_RETIRED')
  })

  it('4. Legacy raw-hex signer + no resolver → pass', () => {
    const fx = makeRotationFixture()
    const r = mkMppReceipt(fx, { legacy: true })
    assert.ok(!r.signer.startsWith('did:'))
    assert.equal(verifyMppReceipt(r).valid, true)
  })

  it('5. DID URI without resolver → DID_RESOLVER_MISSING', async () => {
    const fx = makeRotationFixture()
    const r = mkMppReceipt(fx)
    const v = await verifyMppReceiptWithDID(r)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_RESOLVER_MISSING')
  })

  it('6. resolver returns null → DID_DOC_NOT_FOUND', async () => {
    const fx = makeRotationFixture()
    const r = mkMppReceipt(fx)
    const v = await verifyMppReceiptWithDID(r, { resolveDidDocument: makeResolver({}) })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_DOC_NOT_FOUND')
  })

  it('7. keyRef not in returned doc → DID_KEY_NOT_IN_DOC', async () => {
    const fx = makeRotationFixture()
    const r = mkMppReceipt(fx, { useKey2: true })
    const resolver = makeResolver({
      [fx.agentId]: docKey1Active(fx, '2026-05-04T00:00:00.000Z'),
    })
    const v = await verifyMppReceiptWithDID(r, { resolveDidDocument: resolver })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_KEY_NOT_IN_DOC')
  })
})

// ── AP2: SignedAP2Mandate ─────────────────────────────────────────

describe('P12 — AP2 SignedAP2Mandate with DID URI signer', () => {
  // AP2 mandates carry iat (Unix seconds). Pin it for retiredAt comparison.
  const IAT_SEC = Math.floor(NOW_MS / 1000)

  function mkAp2Signed(fx: ReturnType<typeof makeRotationFixture>, opts: {
    useKey2?: boolean
    legacy?: boolean
  } = {}) {
    const kp = opts.useKey2 ? fx.key2 : fx.key1
    const m = apsToAp2IntentMandate(intent(), { currency: 'USD' })
    // Force iat to our test timestamp so retiredAt comparisons are stable.
    ;(m as { iat?: number }).iat = IAT_SEC
    const sigOpts = opts.legacy
      ? {}
      : { issuer_agent_id: fx.agentId, issuer_key_ref: kp.keyRef }
    return signAp2Mandate(m, kp.privateKey, sigOpts)
  }

  it('1. DID URI signer + resolver → pass', async () => {
    const fx = makeRotationFixture()
    const s = mkAp2Signed(fx)
    const resolver = makeResolver({
      [fx.agentId]: docKey1Active(fx, '2026-05-04T00:00:00.000Z'),
    })
    const v = await verifyAp2MandateWithDID(s, {
      resolveDidDocument: resolver,
      now: new Date(NOW_MS),
    })
    assert.equal(v.valid, true, `got ${v.reason}`)
  })

  it('2. Planned rotation → pass', async () => {
    const fx = makeRotationFixture()
    const s = mkAp2Signed(fx)
    const future = new Date(NOW_MS + 60 * 60 * 1000).toISOString()
    const resolver = makeResolver({
      [fx.agentId]: docAfterRotation(fx, '2026-05-04T00:00:00.000Z', future),
    })
    const v = await verifyAp2MandateWithDID(s, {
      resolveDidDocument: resolver,
      now: new Date(NOW_MS),
    })
    assert.equal(v.valid, true)
  })

  it('3. Emergency rotation → DID_KEY_RETIRED', async () => {
    const fx = makeRotationFixture()
    const s = mkAp2Signed(fx)
    const past = new Date(NOW_MS - 60 * 60 * 1000).toISOString()
    const resolver = makeResolver({
      [fx.agentId]: docAfterRotation(fx, '2026-05-04T00:00:00.000Z', past),
    })
    const v = await verifyAp2MandateWithDID(s, {
      resolveDidDocument: resolver,
      now: new Date(NOW_MS),
    })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_KEY_RETIRED')
  })

  it('4. Legacy raw-hex signer + no resolver → pass', () => {
    const fx = makeRotationFixture()
    const s = mkAp2Signed(fx, { legacy: true })
    assert.ok(!s.signer_did.startsWith('did:'))
    const v = verifyAp2Mandate(s, { now: new Date(NOW_MS) })
    assert.equal(v.valid, true)
  })

  it('5. DID URI without resolver → DID_RESOLVER_MISSING', async () => {
    const fx = makeRotationFixture()
    const s = mkAp2Signed(fx)
    const v = await verifyAp2MandateWithDID(s, { now: new Date(NOW_MS) })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_RESOLVER_MISSING')
  })

  it('6. resolver returns null → DID_DOC_NOT_FOUND', async () => {
    const fx = makeRotationFixture()
    const s = mkAp2Signed(fx)
    const v = await verifyAp2MandateWithDID(s, {
      resolveDidDocument: makeResolver({}),
      now: new Date(NOW_MS),
    })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_DOC_NOT_FOUND')
  })

  it('7. keyRef not in returned doc → DID_KEY_NOT_IN_DOC', async () => {
    const fx = makeRotationFixture()
    const s = mkAp2Signed(fx, { useKey2: true })
    const resolver = makeResolver({
      [fx.agentId]: docKey1Active(fx, '2026-05-04T00:00:00.000Z'),
    })
    const v = await verifyAp2MandateWithDID(s, {
      resolveDidDocument: resolver,
      now: new Date(NOW_MS),
    })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_KEY_NOT_IN_DOC')
  })
})

// ── Stripe-Issuing: rides foundation PaymentReceipt ───────────────

describe('P12 — Stripe-Issuing PaymentReceipt with DID URI signer (rides foundation)', () => {
  // Stripe-Issuing emits via foundation emitReceipt with rail_name='stripe-issuing'.
  // The same DID-URI / resolver path applies. We exercise it directly via
  // emitReceipt + verifyPaymentReceiptWithDID since the rail constructor
  // requires sk_test_ keys + a Stripe API base, which is webhook-handler
  // territory. This proves the Stripe-Issuing path inherits the foundation
  // DID-URI semantics correctly.
  function mkStripeReceipt(fx: ReturnType<typeof makeRotationFixture>, opts: {
    useKey2?: boolean
    legacy?: boolean
    issuedAt?: string
  } = {}) {
    const kp = opts.useKey2 ? fx.key2 : fx.key1
    const issuer = opts.legacy
      ? {}
      : { issuer_agent_id: fx.agentId, issuer_key_ref: kp.keyRef }
    return emitReceipt(
      {
        delegation_ref: 'del_stripe_p12',
        action_ref: 'a'.repeat(64),
        rail_name: 'stripe-issuing',
        amount_base_units: '500',
        currency: 'USD',
        tx_proof: 'iauth_test_001',
        issued_at: opts.issuedAt ?? NOW_ISO,
        ...issuer,
      },
      kp.privateKey,
    )
  }

  it('1. DID URI signer + resolver → pass', async () => {
    const fx = makeRotationFixture()
    const r = mkStripeReceipt(fx)
    const resolver = makeResolver({
      [fx.agentId]: docKey1Active(fx, '2026-05-04T00:00:00.000Z'),
    })
    const v = await verifyPaymentReceiptWithDID(r, { resolveDidDocument: resolver })
    assert.equal(v.valid, true, `got ${v.reason}`)
  })

  it('2. Planned rotation → pass', async () => {
    const fx = makeRotationFixture()
    const r = mkStripeReceipt(fx, { issuedAt: PRE_ROT_ISO })
    const resolver = makeResolver({
      [fx.agentId]: docAfterRotation(fx, '2026-05-04T00:00:00.000Z', POST_ROT_ISO),
    })
    const v = await verifyPaymentReceiptWithDID(r, {
      resolveDidDocument: resolver,
      now: new Date(NOW_MS),
    })
    assert.equal(v.valid, true)
  })

  it('3. Emergency rotation → DID_KEY_RETIRED', async () => {
    const fx = makeRotationFixture()
    const r = mkStripeReceipt(fx, { issuedAt: NOW_ISO })
    const resolver = makeResolver({
      [fx.agentId]: docAfterRotation(fx, '2026-05-04T00:00:00.000Z', PRE_ROT_ISO),
    })
    const v = await verifyPaymentReceiptWithDID(r, { resolveDidDocument: resolver })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_KEY_RETIRED')
  })

  it('4. Legacy raw-hex signer + no resolver → pass', () => {
    const fx = makeRotationFixture()
    const r = mkStripeReceipt(fx, { legacy: true })
    assert.ok(!r.signer_did.startsWith('did:'))
    assert.equal(verifyPaymentReceipt(r).valid, true)
  })

  it('5. DID URI without resolver → DID_RESOLVER_MISSING', async () => {
    const fx = makeRotationFixture()
    const r = mkStripeReceipt(fx)
    const v = await verifyPaymentReceiptWithDID(r)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_RESOLVER_MISSING')
  })

  it('6. resolver returns null → DID_DOC_NOT_FOUND', async () => {
    const fx = makeRotationFixture()
    const r = mkStripeReceipt(fx)
    const v = await verifyPaymentReceiptWithDID(r, {
      resolveDidDocument: makeResolver({}),
    })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_DOC_NOT_FOUND')
  })

  it('7. keyRef not in returned doc → DID_KEY_NOT_IN_DOC', async () => {
    const fx = makeRotationFixture()
    const r = mkStripeReceipt(fx, { useKey2: true })
    const resolver = makeResolver({
      [fx.agentId]: docKey1Active(fx, '2026-05-04T00:00:00.000Z'),
    })
    const v = await verifyPaymentReceiptWithDID(r, { resolveDidDocument: resolver })
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'DID_KEY_NOT_IN_DOC')
  })
})
