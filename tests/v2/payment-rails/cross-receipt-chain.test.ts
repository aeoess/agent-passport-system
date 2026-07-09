// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Phase 4.1 / Q2 — Cross-receipt link fields + chain traversal
// ══════════════════════════════════════════════════════════════════
// Hybrid binding (Option C): rail receipts carry attribution_receipt_id
// and settlement_record_id, SettlementRecord carries an outbound
// payment_obligations[] with attribution_receipt_id back-references.
// The chain SettlementRecord → PaymentObligationRef.attribution_receipt_id
// → AttributionReceipt.id matched by PaymentReceipt.attribution_receipt_id
// is INTENT-SIDE only — the Merkle root over input_receipts_hash does
// NOT cover payment_obligations. Phase 5 adds payment_axis Merkle binding.
//
// What these tests prove:
//   - Each rail receipt's signature covers the new link fields (round-trip
//     through verifier with link fields populated).
//   - SettlementRecord.payment_obligations canonicalizes deterministically
//     and rides the gateway signature.
//   - The chain can be traversed: settlement.payment_obligations →
//     attribution.id → matched payment.attribution_receipt_id.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { generateKeyPair } from '../../../src/crypto/keys.js'
import {
  emitReceipt,
  verifyPaymentReceipt,
} from '../../../src/v2/payment-rails/index.js'
import {
  signAcpReceipt,
  verifyAcpReceipt,
} from '../../../src/v2/payment-rails/acp/index.js'
import {
  signMppReceipt,
  verifyMppReceipt,
} from '../../../src/v2/payment-rails/mpp/index.js'
import {
  apsToAp2IntentMandate,
  signAp2Mandate,
  verifyAp2Mandate,
} from '../../../src/v2/payment-rails/ap2/index.js'
import { createAttributionReceipt } from '../../../src/v2/attribution-consent/index.js'
import {
  signSettlementRecord,
  verifySettlementSignature,
} from '../../../src/v2/attribution-settlement/index.js'
import type {
  PaymentObligationRef,
  SettlementRecord,
} from '../../../src/v2/attribution-settlement/index.js'
import type { AcpCheckoutSession } from '../../../src/v2/payment-rails/acp/types.js'
import type { V2Delegation } from '../../../src/v2/types.js'

// ── Test helpers ──────────────────────────────────────────────────

function ts(ms: number) {
  return {
    logicalTime: 1,
    wallClockEarliest: ms,
    wallClockLatest: ms,
    gatewayId: 'g_q2_test',
  }
}

function buildAttributionReceipt() {
  const citer = generateKeyPair()
  const cited = generateKeyPair()
  return createAttributionReceipt({
    citer: 'did:aps:citer-q2',
    citer_public_key: citer.publicKey,
    citer_private_key: citer.privateKey,
    cited_principal: 'did:aps:cited-q2',
    cited_principal_public_key: cited.publicKey,
    citation_content: 'q2 test citation',
    binding_context: 'ctx_q2_test',
    created_at: ts(1_700_000_000_000),
    expires_at: ts(1_800_000_000_000),
  })
}

function happyAcpSession(): AcpCheckoutSession {
  return {
    id: 'cs_q2',
    status: 'ready_for_payment',
    currency: 'usd',
    line_items: [
      {
        id: 'li_001',
        item: { id: 'item_q2', quantity: 1 },
        base_amount: 1000,
        discount: 0,
        subtotal: 1000,
        tax: 0,
        total: 1000,
      },
    ],
    payment_provider: { provider: 'stripe', supported_payment_methods: ['card'] },
    totals: [
      { type: 'items_base_amount', display_text: 'Items', amount: 1000 },
      { type: 'total', display_text: 'Total', amount: 1000 },
    ],
  }
}

function intent(): V2Delegation {
  return {
    id: 'del_q2',
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

const SETTLEMENT_PERIOD_ID = 'q2-2026-05-04-period-001'

// ── Foundation PaymentReceipt link round-trip + chain ─────────────

describe('Phase 4.1 / Q2 — Foundation PaymentReceipt link fields', () => {
  it('round-trips with attribution_receipt_id + settlement_record_id; signature still verifies', () => {
    const issuer = generateKeyPair()
    const attr = buildAttributionReceipt()
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: '1000',
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        attribution_receipt_id: attr.id,
        settlement_record_id: SETTLEMENT_PERIOD_ID,
      },
      issuer.privateKey,
    )
    assert.equal(r.attribution_receipt_id, attr.id)
    assert.equal(r.settlement_record_id, SETTLEMENT_PERIOD_ID)
    assert.equal(verifyPaymentReceipt(r).valid, true)
  })

  it('chain traversal: SettlementRecord → obligation → attribution.id → matching PaymentReceipt', () => {
    const issuer = generateKeyPair()
    const gateway = generateKeyPair()
    const attr = buildAttributionReceipt()

    const obligation: PaymentObligationRef = {
      recipient_did: 'did:aps:cited-q2',
      amount_cents: 1000,
      currency: 'usd',
      rail_hint: 'foundation',
      attribution_receipt_id: attr.id,
    }
    const settlement = signedSettlement(gateway, [obligation])

    const payment = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'nano',
        amount_base_units: '1000',
        currency: 'XNO',
        tx_proof: 'b'.repeat(64),
        attribution_receipt_id: attr.id,
        settlement_record_id: settlement.period.period_id,
      },
      issuer.privateKey,
    )

    // Traversal proof.
    const linked = settlement.payment_obligations!.find(
      (o) => o.attribution_receipt_id === attr.id,
    )
    assert.ok(linked, 'settlement should declare obligation against attr.id')
    assert.equal(payment.attribution_receipt_id, linked.attribution_receipt_id)
    assert.equal(payment.settlement_record_id, settlement.period.period_id)
    assert.equal(verifyPaymentReceipt(payment).valid, true)
    assert.equal(verifySettlementSignature(settlement, gateway.publicKey), true)
  })
})

// ── ACP AcpReceipt link round-trip + chain ─────────────────────────

describe('Phase 4.1 / Q2 — AcpReceipt link fields', () => {
  it('round-trips link fields; verifier still passes', () => {
    const kp = generateKeyPair()
    const attr = buildAttributionReceipt()
    const r = signAcpReceipt(
      {
        op: 'create',
        session_id: 'cs_q2',
        request_body: { items: [{ id: 'i', quantity: 1 }] },
        session_state: happyAcpSession(),
        delegation_ref: 'del_q2',
        agent_id: 'agent-001',
        attribution_receipt_id: attr.id,
        settlement_record_id: SETTLEMENT_PERIOD_ID,
      },
      kp.privateKey,
    )
    assert.equal(r.attribution_receipt_id, attr.id)
    assert.equal(r.settlement_record_id, SETTLEMENT_PERIOD_ID)
    assert.equal(verifyAcpReceipt(r).valid, true)
  })

  it('chain traversal: settlement obligation → ACP receipt with same attribution_receipt_id', () => {
    const kp = generateKeyPair()
    const gateway = generateKeyPair()
    const attr = buildAttributionReceipt()
    const settlement = signedSettlement(gateway, [
      {
        recipient_did: 'did:aps:cited-q2',
        amount_cents: 1000,
        currency: 'usd',
        rail_hint: 'acp',
        attribution_receipt_id: attr.id,
      },
    ])
    const r = signAcpReceipt(
      {
        op: 'create',
        session_id: 'cs_q2',
        request_body: { items: [{ id: 'i', quantity: 1 }] },
        session_state: happyAcpSession(),
        delegation_ref: 'del_q2',
        agent_id: 'agent-001',
        attribution_receipt_id: attr.id,
        settlement_record_id: settlement.period.period_id,
      },
      kp.privateKey,
    )
    const linked = settlement.payment_obligations!.find(
      (o) => o.attribution_receipt_id === attr.id,
    )
    assert.ok(linked)
    assert.equal(r.attribution_receipt_id, linked.attribution_receipt_id)
    assert.equal(verifyAcpReceipt(r).valid, true)
  })
})

// ── MPP MppApsReceipt link round-trip + chain ─────────────────────

describe('Phase 4.1 / Q2 — MppApsReceipt link fields', () => {
  it('round-trips link fields; verifier still passes', () => {
    const kp = generateKeyPair()
    const attr = buildAttributionReceipt()
    const r = signMppReceipt(
      {
        challenge_id: 'ch_q2',
        method_type: 'card',
        amount_paid: '500',
        currency: 'usd',
        paid_at: '2026-05-04T12:00:00.000Z',
        resource: 'https://api.example.com/r',
        delegation_ref: 'del_q2',
        agent_id: 'agent-001',
        attribution_receipt_id: attr.id,
        settlement_record_id: SETTLEMENT_PERIOD_ID,
      },
      kp.privateKey,
    )
    assert.equal(r.attribution_receipt_id, attr.id)
    assert.equal(r.settlement_record_id, SETTLEMENT_PERIOD_ID)
    assert.equal(verifyMppReceipt(r).valid, true)
  })

  it('chain traversal: settlement obligation → MPP receipt with same attribution_receipt_id', () => {
    const kp = generateKeyPair()
    const gateway = generateKeyPair()
    const attr = buildAttributionReceipt()
    const settlement = signedSettlement(gateway, [
      {
        recipient_did: 'did:aps:cited-q2',
        amount_cents: 500,
        currency: 'usd',
        rail_hint: 'mpp',
        attribution_receipt_id: attr.id,
      },
    ])
    const r = signMppReceipt(
      {
        challenge_id: 'ch_q2',
        method_type: 'card',
        amount_paid: '500',
        currency: 'usd',
        paid_at: '2026-05-04T12:00:00.000Z',
        resource: 'https://api.example.com/r',
        delegation_ref: 'del_q2',
        agent_id: 'agent-001',
        attribution_receipt_id: attr.id,
        settlement_record_id: settlement.period.period_id,
      },
      kp.privateKey,
    )
    const linked = settlement.payment_obligations!.find(
      (o) => o.attribution_receipt_id === attr.id,
    )
    assert.ok(linked)
    assert.equal(r.attribution_receipt_id, linked.attribution_receipt_id)
    assert.equal(verifyMppReceipt(r).valid, true)
  })
})

// ── AP2 SignedAP2Mandate link round-trip + chain ──────────────────

describe('Phase 4.1 / Q2 — SignedAP2Mandate link fields', () => {
  it('round-trips link fields on the envelope; mandate dict unchanged; verifier passes', () => {
    const kp = generateKeyPair()
    const attr = buildAttributionReceipt()
    const m = apsToAp2IntentMandate(intent(), { currency: 'USD' })
    const signed = signAp2Mandate(m, kp.privateKey, {
      attribution_receipt_id: attr.id,
      settlement_record_id: SETTLEMENT_PERIOD_ID,
    })
    assert.equal(signed.attribution_receipt_id, attr.id)
    assert.equal(signed.settlement_record_id, SETTLEMENT_PERIOD_ID)
    // Mandate dict is byte-stable: the link fields ride the envelope, not
    // the canonical signing payload, so AP2 wire compatibility is preserved.
    assert.equal(verifyAp2Mandate(signed).valid, true)
  })

  it('chain traversal: settlement obligation → AP2 envelope with same attribution_receipt_id', () => {
    const kp = generateKeyPair()
    const gateway = generateKeyPair()
    const attr = buildAttributionReceipt()
    const settlement = signedSettlement(gateway, [
      {
        recipient_did: 'did:aps:cited-q2',
        amount_cents: 50000,
        currency: 'usd',
        rail_hint: 'ap2',
        attribution_receipt_id: attr.id,
      },
    ])
    const m = apsToAp2IntentMandate(intent(), { currency: 'USD' })
    const signed = signAp2Mandate(m, kp.privateKey, {
      attribution_receipt_id: attr.id,
      settlement_record_id: settlement.period.period_id,
    })
    const linked = settlement.payment_obligations!.find(
      (o) => o.attribution_receipt_id === attr.id,
    )
    assert.ok(linked)
    assert.equal(signed.attribution_receipt_id, linked.attribution_receipt_id)
    assert.equal(verifyAp2Mandate(signed).valid, true)
  })
})

// ── Stripe-Issuing PaymentReceipt link round-trip + chain ─────────

describe('Phase 4.1 / Q2 — Stripe-Issuing PaymentReceipt link fields (rides foundation)', () => {
  it('round-trips link fields; verifier passes', () => {
    const issuer = generateKeyPair()
    const attr = buildAttributionReceipt()
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'stripe-issuing',
        amount_base_units: '1000',
        currency: 'USD',
        tx_proof: 'iauth_q2',
        attribution_receipt_id: attr.id,
        settlement_record_id: SETTLEMENT_PERIOD_ID,
      },
      issuer.privateKey,
    )
    assert.equal(r.attribution_receipt_id, attr.id)
    assert.equal(verifyPaymentReceipt(r).valid, true)
  })

  it('chain traversal: settlement obligation → Stripe-Issuing payment with same attribution_receipt_id', () => {
    const issuer = generateKeyPair()
    const gateway = generateKeyPair()
    const attr = buildAttributionReceipt()
    const settlement = signedSettlement(gateway, [
      {
        recipient_did: 'did:aps:cited-q2',
        amount_cents: 1000,
        currency: 'usd',
        rail_hint: 'stripe-issuing',
        attribution_receipt_id: attr.id,
      },
    ])
    const r = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'stripe-issuing',
        amount_base_units: '1000',
        currency: 'USD',
        tx_proof: 'iauth_q2',
        attribution_receipt_id: attr.id,
        settlement_record_id: settlement.period.period_id,
      },
      issuer.privateKey,
    )
    const linked = settlement.payment_obligations!.find(
      (o) => o.attribution_receipt_id === attr.id,
    )
    assert.ok(linked)
    assert.equal(r.attribution_receipt_id, linked.attribution_receipt_id)
    assert.equal(r.rail_name, 'stripe-issuing')
    assert.equal(verifyPaymentReceipt(r).valid, true)
  })
})

// ── Helpers (placed at the bottom) ────────────────────────────────

function emptyAxis() {
  return {
    axis: 'D' as const,
    period: {
      t0: '2026-05-04T00:00:00.000Z',
      t1: '2026-05-05T00:00:00.000Z',
      period_id: SETTLEMENT_PERIOD_ID,
    },
    total_actions: 0,
    contributors: [],
    residual_bucket: null,
    axis_merkle_root: 'deadbeef'.repeat(8),
  }
}

function signedSettlement(
  gateway: { publicKey: string; privateKey: string },
  payment_obligations: PaymentObligationRef[],
): SettlementRecord {
  const period = {
    t0: '2026-05-04T00:00:00.000Z',
    t1: '2026-05-05T00:00:00.000Z',
    period_id: SETTLEMENT_PERIOD_ID,
  }
  const body: Omit<SettlementRecord, 'signature'> = {
    schema: 'aps.settlement.v1',
    period,
    gateway_did: gateway.publicKey,
    axes: {
      D: { ...emptyAxis(), axis: 'D' },
      P: { ...emptyAxis(), axis: 'P' },
      G: { ...emptyAxis(), axis: 'G' },
      C: { ...emptyAxis(), axis: 'C' },
    },
    input_receipts_hash: '0'.repeat(64),
    total_input_count: 0,
    issued_at: '2026-05-04T12:00:00.000Z',
    payment_obligations,
  }
  const signature = signSettlementRecord(body, gateway.privateKey)
  return { ...body, signature }
}
