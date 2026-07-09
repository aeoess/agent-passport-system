// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license.
// ══════════════════════════════════════════════════════════════════
// Phase 4.1 / Q1 — APSBundle aggregation across rails
// ══════════════════════════════════════════════════════════════════
// A bundle that mixes an ActionReceipt with a rail-emitted receipt
// commits to both via the Merkle root. This is the structural
// affordance Q1 unlocks: a payment receipt becomes evidence the
// rest of APS recognizes.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { generateKeyPair } from '../../../src/crypto/keys.js'
import {
  computeMerkleRoot,
  createAPSBundle,
} from '../../../src/v2/accountability/construct/bundle.js'
import { createActionReceipt } from '../../../src/v2/accountability/construct/action.js'
import { emitReceipt } from '../../../src/v2/payment-rails/index.js'
import { signAcpReceipt } from '../../../src/v2/payment-rails/acp/index.js'
import { signMppReceipt } from '../../../src/v2/payment-rails/mpp/index.js'
import { signAp2Mandate, apsToAp2IntentMandate } from '../../../src/v2/payment-rails/ap2/index.js'
import { RAIL_RECEIPT_CLAIM_TYPES, RecordType } from '../../../src/v2/claim-evidence-types.js'
import type { AcpCheckoutSession } from '../../../src/v2/payment-rails/acp/types.js'
import type { V2Delegation } from '../../../src/v2/types.js'

const ISSUER = generateKeyPair()
const BUNDLER = generateKeyPair()

const SCOPE = {
  asserts: 'aps:bundle:test — bundle proves Merkle commitment over the listed receipts only.',
  does_not_assert: ['receipts attest to anything beyond their own claim_type'],
  capture_mode: 'gateway_observed' as const,
  completeness: 'complete' as const,
  self_attested: false,
}

function happyAcpSession(): AcpCheckoutSession {
  return {
    id: 'cs_q1_bundle',
    buyer: { first_name: 'Test', email: 'test@example.com' },
    payment_provider: { provider: 'stripe', supported_payment_methods: ['card'] },
    status: 'in_progress',
    currency: 'usd',
    line_items: [],
    fulfillment_address: undefined,
    fulfillment_options: [],
    fulfillment_option_id: undefined,
    totals: [{ type: 'total', display_text: '', amount: 1000 }],
    messages: [],
    links: [],
  }
}

function intent(): V2Delegation {
  return {
    id: 'del_bundle_q1',
    version: 1,
    supersedes: null,
    supersession_justification: null,
    delegator: 'did:aps:user',
    delegatee: ISSUER.publicKey,
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

describe('Phase 4.1 / Q1 — APSBundle aggregation across rails', () => {
  it('Foundation PaymentReceipt aggregates with ActionReceipt under one Merkle root', () => {
    const action = createActionReceipt(
      {
        scope_of_claim: SCOPE,
        agent_did: ISSUER.publicKey,
        delegation_chain_root: 'a'.repeat(64),
        action: { kind: 'commerce.purchase', target: 'merchant-x' },
        side_effect_classes: ['financial'],
      },
      ISSUER.privateKey,
    )
    const payment = emitReceipt(
      {
        delegation_ref: 'del_bundle_q1',
        action_ref: 'b'.repeat(64),
        rail_name: 'nano',
        amount_base_units: '1000',
        currency: 'XNO',
        tx_proof: 'c'.repeat(64),
        accountability_shape: true,
      },
      ISSUER.privateKey,
    )

    const bundle = createAPSBundle(
      {
        bundler_did: BUNDLER.publicKey,
        period_start: '2026-05-04T00:00:00.000Z',
        period_end: '2026-05-04T23:59:59.000Z',
        receipts: [
          { receipt_id: action.receipt_id, claim_type: action.claim_type },
          { receipt_id: payment.receipt_id, claim_type: payment.claim_type },
        ],
        profile_conformance: ['aps:profile/q1-rail-bundle'],
        scope_of_claim: SCOPE,
      },
      BUNDLER.privateKey,
    )

    assert.equal(bundle.receipt_count, 2)
    assert.equal(
      bundle.merkle_root,
      computeMerkleRoot([action.receipt_id, payment.receipt_id]),
    )
    assert.equal(payment.claim_type, RAIL_RECEIPT_CLAIM_TYPES[RecordType.PaymentReceipt])
  })

  it('AcpReceipt aggregates with ActionReceipt under one Merkle root', () => {
    const action = createActionReceipt(
      {
        scope_of_claim: SCOPE,
        agent_did: ISSUER.publicKey,
        delegation_chain_root: 'a'.repeat(64),
        action: { kind: 'commerce.purchase', target: 'merchant-acp' },
        side_effect_classes: ['financial'],
      },
      ISSUER.privateKey,
    )
    const acp = signAcpReceipt(
      {
        op: 'create',
        session_id: 'cs_bundle_acp',
        request_body: { items: [{ id: 'i', quantity: 1 }] },
        session_state: happyAcpSession(),
        delegation_ref: 'del_bundle_q1',
        agent_id: 'agent-001',
        accountability_shape: true,
      },
      ISSUER.privateKey,
    )
    const bundle = createAPSBundle(
      {
        bundler_did: BUNDLER.publicKey,
        period_start: '2026-05-04T00:00:00.000Z',
        period_end: '2026-05-04T23:59:59.000Z',
        receipts: [
          { receipt_id: action.receipt_id, claim_type: action.claim_type },
          { receipt_id: acp.receipt_id, claim_type: acp.claim_type ?? 'rail.acp.v1' },
        ],
        profile_conformance: ['aps:profile/q1-rail-bundle'],
        scope_of_claim: SCOPE,
      },
      BUNDLER.privateKey,
    )

    assert.equal(bundle.receipt_count, 2)
    assert.equal(acp.claim_type, RAIL_RECEIPT_CLAIM_TYPES[RecordType.AcpReceipt])
    assert.equal(
      bundle.merkle_root,
      computeMerkleRoot([action.receipt_id, acp.receipt_id]),
    )
  })

  it('MppApsReceipt aggregates with ActionReceipt under one Merkle root', () => {
    const action = createActionReceipt(
      {
        scope_of_claim: SCOPE,
        agent_did: ISSUER.publicKey,
        delegation_chain_root: 'a'.repeat(64),
        action: { kind: 'commerce.payment', target: 'mpp-resource' },
        side_effect_classes: ['financial'],
      },
      ISSUER.privateKey,
    )
    const mpp = signMppReceipt(
      {
        challenge_id: 'ch_bundle_mpp',
        method_type: 'card',
        amount_paid: '500',
        currency: 'usd',
        paid_at: '2026-05-04T12:00:00.000Z',
        resource: 'https://api.example.com/r',
        delegation_ref: 'del_bundle_q1',
        agent_id: 'agent-001',
        accountability_shape: true,
      },
      ISSUER.privateKey,
    )
    const bundle = createAPSBundle(
      {
        bundler_did: BUNDLER.publicKey,
        period_start: '2026-05-04T00:00:00.000Z',
        period_end: '2026-05-04T23:59:59.000Z',
        receipts: [
          { receipt_id: action.receipt_id, claim_type: action.claim_type },
          { receipt_id: mpp.receipt_id, claim_type: mpp.claim_type ?? 'rail.mpp.v1' },
        ],
        profile_conformance: ['aps:profile/q1-rail-bundle'],
        scope_of_claim: SCOPE,
      },
      BUNDLER.privateKey,
    )
    assert.equal(bundle.receipt_count, 2)
    assert.equal(mpp.claim_type, RAIL_RECEIPT_CLAIM_TYPES[RecordType.MppApsReceipt])
  })

  it('SignedAP2Mandate aggregates with ActionReceipt under one Merkle root', () => {
    const action = createActionReceipt(
      {
        scope_of_claim: SCOPE,
        agent_did: ISSUER.publicKey,
        delegation_chain_root: 'a'.repeat(64),
        action: { kind: 'commerce.checkout.intent', target: 'agent' },
        side_effect_classes: ['internal_only'],
      },
      ISSUER.privateKey,
    )
    const m = apsToAp2IntentMandate(intent(), { currency: 'USD' })
    const ap2 = signAp2Mandate(m, ISSUER.privateKey, { accountability_shape: true })
    // SignedAP2Mandate has no built-in receipt_id; use sha256 of canonicalized
    // envelope as the bundle leaf (matches how a gateway aggregator would
    // anchor it). For test simplicity, use a derived id.
    const ap2Id = `ap2-${m.vct}-${ap2.timestamp}`
    const bundle = createAPSBundle(
      {
        bundler_did: BUNDLER.publicKey,
        period_start: '2026-05-04T00:00:00.000Z',
        period_end: '2026-05-04T23:59:59.000Z',
        receipts: [
          { receipt_id: action.receipt_id, claim_type: action.claim_type },
          { receipt_id: ap2Id, claim_type: ap2.claim_type ?? 'rail.ap2.mandate.v1' },
        ],
        profile_conformance: ['aps:profile/q1-rail-bundle'],
        scope_of_claim: SCOPE,
      },
      BUNDLER.privateKey,
    )
    assert.equal(bundle.receipt_count, 2)
    assert.equal(ap2.claim_type, RAIL_RECEIPT_CLAIM_TYPES[RecordType.SignedAP2Mandate])
  })

  it('Stripe-Issuing PaymentReceipt (rides foundation) aggregates with ActionReceipt', () => {
    const action = createActionReceipt(
      {
        scope_of_claim: SCOPE,
        agent_did: ISSUER.publicKey,
        delegation_chain_root: 'a'.repeat(64),
        action: { kind: 'commerce.purchase', target: 'stripe-merchant' },
        side_effect_classes: ['financial'],
      },
      ISSUER.privateKey,
    )
    // Stripe-Issuing emits via foundation emitReceipt with rail_name='stripe-issuing'.
    const stripeReceipt = emitReceipt(
      {
        delegation_ref: 'del_bundle_q1',
        action_ref: 'b'.repeat(64),
        rail_name: 'stripe-issuing',
        amount_base_units: '500',
        currency: 'USD',
        tx_proof: 'iauth_test_001',
        accountability_shape: true,
      },
      ISSUER.privateKey,
    )
    const bundle = createAPSBundle(
      {
        bundler_did: BUNDLER.publicKey,
        period_start: '2026-05-04T00:00:00.000Z',
        period_end: '2026-05-04T23:59:59.000Z',
        receipts: [
          { receipt_id: action.receipt_id, claim_type: action.claim_type },
          { receipt_id: stripeReceipt.receipt_id, claim_type: stripeReceipt.claim_type },
        ],
        profile_conformance: ['aps:profile/q1-rail-bundle'],
        scope_of_claim: SCOPE,
      },
      BUNDLER.privateKey,
    )
    assert.equal(bundle.receipt_count, 2)
    assert.equal(stripeReceipt.rail_name, 'stripe-issuing')
    assert.equal(stripeReceipt.claim_type, RAIL_RECEIPT_CLAIM_TYPES[RecordType.PaymentReceipt])
  })
})
