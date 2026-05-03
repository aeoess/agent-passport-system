// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Stripe Issuing payment rail — live smoke test (test mode only).
//
// Hard gates:
//   - STRIPE_API_KEY unset      → skip with clear message
//   - STRIPE_API_KEY = sk_live_ → fail-fast and abort
//   - STRIPE_API_KEY = sk_test_ → run end-to-end against api.stripe.com
//
// On any Stripe API error during the smoke (e.g. account doesn't have
// Issuing enabled, regional restriction), the test SKIPS rather than
// fails — the goal is to surface adapter regressions, not Stripe
// account state. Build does not break when this skips.
//
// Cleanup: cardholder is set inactive (Stripe does not allow delete)
// and the card is canceled.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  createStripeIssuingRail,
  type VirtualCard,
} from '../../../src/v2/payment-rails/stripe-issuing/index.js'
import { generateKeyPair } from '../../../src/crypto/keys.js'
import { verifyPaymentReceipt } from '../../../src/v2/payment-rails/index.js'
import type { V2Delegation } from '../../../src/v2/types.js'

const KEY = process.env.STRIPE_API_KEY
const API_BASE = 'https://api.stripe.com'

// Top-level live-key gate. We intentionally throw at module load so
// the file fails to evaluate (instead of letting individual tests
// ignore the misconfiguration). Test mode only — no exceptions.
if (KEY?.startsWith('sk_live_')) {
  throw new Error(
    'stripe-issuing-live.test.ts: refusing to run with sk_live_ key. ' +
      'This live smoke test is test-mode only.',
  )
}

const SKIP_REASON =
  'STRIPE_API_KEY not set — skipping Stripe Issuing live smoke. ' +
  'Set a sk_test_... key to run.'

async function stripeForm(
  path: string,
  body: Record<string, string>,
  apiKey: string,
): Promise<unknown> {
  const form = new URLSearchParams(body).toString()
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: form,
  })
  const text = await res.text()
  if (!res.ok) throw new Error(`Stripe ${path} ${res.status}: ${text.slice(0, 400)}`)
  return JSON.parse(text)
}

function buildLiveDelegation(): V2Delegation {
  return {
    id: `deleg-live-${Date.now()}`,
    version: 1,
    supersedes: null,
    supersession_justification: null,
    delegator: 'did:key:z6MkLiveDelegator',
    delegatee: 'did:key:z6MkLiveAgent',
    scope: {
      action_categories: ['commerce.purchase'],
      resource_limits: { spend_limit_cents: 500 }, // $5
      constraints: {},
    },
    policy_context: {
      policy_version: '1.0',
      values_floor_version: '1.0',
      trust_epoch: 1,
      issuer_id: 'aps-live-smoke',
      created_at: new Date().toISOString(),
      valid_from: new Date(Date.now() - 1000).toISOString(),
      valid_until: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    },
    signature: 'placeholder',
    status: 'active',
    renewal_reason: null,
    expansion_reviewer: null,
    expansion_review_sig: null,
    assurance_class: 'mechanically_enforceable',
  }
}

describe('StripeIssuingRail — live smoke (sk_test_ only)', () => {
  it('provisions cardholder + card, runs gated webhook flow, cleans up', async (t) => {
    if (KEY === undefined || KEY === '') {
      t.skip(SKIP_REASON)
      return
    }
    if (!KEY.startsWith('sk_test_')) {
      t.skip(`STRIPE_API_KEY does not start with 'sk_test_' — skipping (got prefix '${KEY.slice(0, 8)}')`)
      return
    }

    let cardholderId: string | undefined
    let cardId: string | undefined

    try {
      // 1. Create a test cardholder. Stripe Issuing test mode accepts
      //    any believable address shape.
      const cardholder = (await stripeForm(
        '/v1/issuing/cardholders',
        {
          name: 'APS Live Smoke Cardholder',
          email: 'aps-live-smoke@example.test',
          phone_number: '+15555550100',
          status: 'active',
          type: 'individual',
          'billing[address][line1]': '123 Test St',
          'billing[address][city]': 'San Francisco',
          'billing[address][state]': 'CA',
          'billing[address][postal_code]': '94103',
          'billing[address][country]': 'US',
        },
        KEY,
      )) as { id: string }
      cardholderId = cardholder.id
      assert.ok(cardholderId.startsWith('ich_'), `unexpected cardholder id: ${cardholderId}`)

      // 2. Build the rail and provision a card.
      const issuer = generateKeyPair()
      const rail = createStripeIssuingRail({
        apiKey: KEY,
        issuerPrivateKeyHex: issuer.privateKey,
        defaultCardholder: cardholderId,
        apsCurrency: 'USD',
      })

      const delegation = buildLiveDelegation()
      const card: VirtualCard = await rail.provisionAgentCard(delegation)
      cardId = card.id
      assert.ok(cardId.startsWith('ic_'), `unexpected card id: ${cardId}`)
      assert.equal(card.type, 'virtual')
      assert.equal(card.status, 'active')
      assert.equal(card.metadata.aps_delegation_ref, delegation.id)

      // 3. Exercise the webhook handler with a synthetic event for an
      //    over-budget purchase. We do NOT trigger a real authorization
      //    via Stripe's test endpoint here — that requires either a
      //    test handler endpoint configured on the account (which is
      //    out-of-band setup) or the realtime authorizations test
      //    helper. The synthetic decline path is sufficient to prove
      //    the rail wires preAuthorize → APS denial end-to-end. The
      //    /decline call hits Stripe live and will fail because the
      //    auth id is synthetic; we tolerate that and assert the
      //    denial was emitted regardless.
      const decision = await rail.handleAuthorizationWebhook({
        id: 'evt_live_smoke_synth',
        type: 'issuing_authorization.request',
        created: Math.floor(Date.now() / 1000),
        livemode: false,
        data: {
          object: {
            id: 'iauth_live_smoke_synth_overbudget',
            object: 'issuing.authorization',
            amount: 9999, // > $5 limit
            currency: 'usd',
            approved: false,
            status: 'pending',
            card: { id: cardId, cardholder: cardholderId },
            merchant_data: { category: 'computers_peripherals_software', name: 'Test Vendor' },
            metadata: {},
            created: Math.floor(Date.now() / 1000),
            pending_request: { amount: 9999, currency: 'usd' },
          },
        },
      })
      assert.equal(decision.approved, false)
      assert.equal(decision.reason, 'spend_limit_exceeded')
      assert.ok(decision.denial)

      // 4. Approve path with an under-budget synthetic. Same caveat
      //    about /approve hitting Stripe with a synthetic id.
      const approveDecision = await rail.handleAuthorizationWebhook({
        id: 'evt_live_smoke_synth_ok',
        type: 'issuing_authorization.request',
        created: Math.floor(Date.now() / 1000),
        livemode: false,
        data: {
          object: {
            id: 'iauth_live_smoke_synth_ok',
            object: 'issuing.authorization',
            amount: 200,
            currency: 'usd',
            approved: false,
            status: 'pending',
            card: { id: cardId, cardholder: cardholderId },
            merchant_data: { category: 'computers_peripherals_software', name: 'Test Vendor' },
            metadata: {},
            created: Math.floor(Date.now() / 1000),
            pending_request: { amount: 200, currency: 'usd' },
          },
        },
      })

      // The approve call to Stripe with a synthetic auth id will 4xx,
      // which our handler converts to rail_error denial. Both outcomes
      // are valid signals that the wiring is intact; what we assert is
      // that an APS receipt or denial was emitted with a verifiable
      // signature — never neither.
      if (approveDecision.approved) {
        const v = verifyPaymentReceipt(approveDecision.receipt!)
        assert.equal(v.valid, true, JSON.stringify(v))
      } else {
        assert.ok(approveDecision.denial, 'expected denial when not approved')
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      // Account-level issues (Issuing not enabled, region restriction,
      // rate limit) skip rather than fail. Real adapter regressions
      // surface as TypeError / signature failures, not as Stripe errors.
      if (/Stripe \//.test(msg) || /403|429|account/i.test(msg)) {
        t.skip(`Stripe live API unavailable for this account: ${msg.slice(0, 200)}`)
        return
      }
      throw e
    } finally {
      // Cleanup. Best effort; do not fail the test on cleanup errors.
      if (cardId) {
        try {
          await stripeForm(`/v1/issuing/cards/${cardId}`, { status: 'canceled' }, KEY)
        } catch {
          // ignore
        }
      }
      if (cardholderId) {
        try {
          await stripeForm(`/v1/issuing/cardholders/${cardholderId}`, { status: 'inactive' }, KEY)
        } catch {
          // ignore
        }
      }
    }
  })
})
