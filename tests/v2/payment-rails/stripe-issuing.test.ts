// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Stripe Issuing payment rail — mocked behavior tests.
//
// Every Stripe HTTP call is mocked. No live API contact. The only
// crypto is the issuer Ed25519 key used to sign emitted APS receipts
// and denials.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  createStripeIssuingRail,
  defaultMapDelegationToSpendingControls,
  verifyStripeSignature,
  type AuthorizationEvent,
  type FetchLike,
  type VirtualCard,
} from '../../../src/v2/payment-rails/stripe-issuing/index.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_DIR = join(
  __dirname, '..', '..', '..',
  'src', 'v2', 'payment-rails', 'stripe-issuing', 'fixtures',
)
import {
  verifyPaymentDenial,
  verifyPaymentReceipt,
} from '../../../src/v2/payment-rails/index.js'
import { generateKeyPair } from '../../../src/crypto/keys.js'
import type { V2Delegation } from '../../../src/v2/types.js'

// ── Test fixtures ─────────────────────────────────────────────────

const TEST_KEY = 'sk_test_mock_1234567890abcdef'
const ISSUER = generateKeyPair()
const ISSUER_PRIV = ISSUER.privateKey
const WEBHOOK_SECRET = 'whsec_test_secret_for_signing_payloads'

const FIXED_NOW_MS = Date.parse('2026-05-03T12:00:00.000Z')
const FIXED_NOW_SEC = Math.floor(FIXED_NOW_MS / 1000)

function buildDelegation(overrides: {
  spend_limit_cents?: number
  action_categories?: string[]
  allowed_merchant_categories?: string
  valid_from?: string
  valid_until?: string
  id?: string
} = {}): V2Delegation {
  return {
    id: overrides.id ?? 'deleg-test-001',
    version: 1,
    supersedes: null,
    supersession_justification: null,
    delegator: 'did:key:z6MkDelegator',
    delegatee: 'did:key:z6MkAgent',
    scope: {
      action_categories: overrides.action_categories ?? ['commerce.purchase'],
      resource_limits: { spend_limit_cents: overrides.spend_limit_cents ?? 5000 },
      constraints: overrides.allowed_merchant_categories
        ? { allowed_merchant_categories: overrides.allowed_merchant_categories }
        : {},
    },
    policy_context: {
      policy_version: '1.0',
      values_floor_version: '1.0',
      trust_epoch: 1,
      issuer_id: 'test-issuer',
      created_at: '2026-05-01T00:00:00.000Z',
      valid_from: overrides.valid_from ?? '2026-05-01T00:00:00.000Z',
      valid_until: overrides.valid_until ?? '2026-12-31T23:59:59.000Z',
    },
    signature: 'fakesig',
    status: 'active',
    renewal_reason: null,
    expansion_reviewer: null,
    expansion_review_sig: null,
    assurance_class: 'mechanically_enforceable',
  }
}

interface FetchCall {
  url: string
  method: string
  headers: Record<string, string>
  body?: string
}

interface MockFetchOpts {
  /** Optional per-path response overrides. Path matches the URL suffix. */
  routes?: Array<{
    match: (url: string, init: { method: string }) => boolean
    respond: (call: FetchCall) => { status?: number; body: unknown }
  }>
  /** Default response when no route matches. */
  fallback?: (call: FetchCall) => { status?: number; body: unknown }
}

function makeMockFetch(opts: MockFetchOpts = {}): { fetch: FetchLike; calls: FetchCall[] } {
  const calls: FetchCall[] = []
  const fetch: FetchLike = async (url, init) => {
    const call: FetchCall = {
      url,
      method: init.method,
      headers: init.headers,
      body: init.body,
    }
    calls.push(call)
    const route = opts.routes?.find((r) => r.match(url, { method: init.method }))
    let resp: { status?: number; body: unknown }
    if (route) {
      resp = route.respond(call)
    } else if (opts.fallback) {
      resp = opts.fallback(call)
    } else {
      resp = { status: 404, body: { error: 'no mock route matched', url } }
    }
    const status = resp.status ?? 200
    const text = JSON.stringify(resp.body)
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => text,
    }
  }
  return { fetch, calls }
}

function decodeForm(body: string | undefined): Record<string, string> {
  if (!body) return {}
  const out: Record<string, string> = {}
  for (const part of body.split('&')) {
    if (!part) continue
    const eq = part.indexOf('=')
    if (eq < 0) continue
    out[decodeURIComponent(part.slice(0, eq))] = decodeURIComponent(part.slice(eq + 1))
  }
  return out
}

function sampleCardResponse(overrides: Partial<VirtualCard> = {}): VirtualCard {
  return {
    id: overrides.id ?? 'ic_test_card_abc',
    object: 'issuing.card',
    type: 'virtual',
    status: 'active',
    currency: 'usd',
    cardholder: 'ich_test_cardholder',
    spending_controls: {
      spending_limits: [{ amount: 5000, interval: 'all_time' }],
      spending_limits_currency: 'usd',
    },
    metadata: {},
    created: FIXED_NOW_SEC,
    last4: '4242',
    exp_month: 12,
    exp_year: 2030,
    brand: 'Visa',
    ...overrides,
  }
}

function sampleAuthorizationEvent(opts: {
  cardId: string
  amountCents: number
  authId?: string
  currency?: string
}): AuthorizationEvent {
  return {
    id: 'evt_test_' + (opts.authId ?? 'iauth_default'),
    type: 'issuing_authorization.request',
    created: FIXED_NOW_SEC,
    livemode: false,
    data: {
      object: {
        id: opts.authId ?? 'iauth_test_default',
        object: 'issuing.authorization',
        amount: opts.amountCents,
        currency: opts.currency ?? 'usd',
        approved: false,
        status: 'pending',
        card: { id: opts.cardId, cardholder: 'ich_test_cardholder', currency: 'usd' },
        merchant_data: { category: 'computers_peripherals_software', name: 'Test Vendor' },
        metadata: {},
        created: FIXED_NOW_SEC,
        pending_request: {
          amount: opts.amountCents,
          currency: opts.currency ?? 'usd',
        },
      },
    },
  }
}

// ── Constructor / config ──────────────────────────────────────────

describe('StripeIssuingRail — constructor', () => {
  it('refuses sk_live_ keys', () => {
    assert.throws(
      () =>
        createStripeIssuingRail({
          apiKey: 'sk_live_anything',
          issuerPrivateKeyHex: ISSUER_PRIV,
        }),
      /sk_live_/,
    )
  })

  it('refuses keys with neither sk_test_ nor sk_live_ prefix', () => {
    assert.throws(
      () =>
        createStripeIssuingRail({
          apiKey: 'pk_test_publishable_not_secret',
          issuerPrivateKeyHex: ISSUER_PRIV,
        }),
      /sk_test_/,
    )
  })

  it('accepts sk_test_ keys and sets name + currency', () => {
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
      apsCurrency: 'EUR',
    })
    assert.equal(rail.name, 'stripe-issuing')
    assert.equal(rail.currency, 'EUR')
  })
})

// ── Default delegation → SpendingControls mapping ────────────────

describe('defaultMapDelegationToSpendingControls', () => {
  it('maps spend_limit_cents to spending_limits[0].amount with all_time interval', () => {
    const sc = defaultMapDelegationToSpendingControls(
      buildDelegation({ spend_limit_cents: 12345 }),
    )
    assert.deepEqual(sc.spending_limits, [{ amount: 12345, interval: 'all_time' }])
    assert.equal(sc.allowed_categories, undefined)
  })

  it('maps allowed_merchant_categories CSV constraint to allowed_categories', () => {
    const sc = defaultMapDelegationToSpendingControls(
      buildDelegation({
        spend_limit_cents: 5000,
        allowed_merchant_categories: 'computers_peripherals_software, office_supplies',
      }),
    )
    assert.deepEqual(sc.allowed_categories, [
      'computers_peripherals_software',
      'office_supplies',
    ])
  })

  it('throws when spend_limit_cents is missing or non-positive', () => {
    assert.throws(
      () => defaultMapDelegationToSpendingControls(buildDelegation({ spend_limit_cents: 0 })),
      /spend_limit_cents/,
    )
  })

  it('floors fractional spend limits to integer cents', () => {
    const sc = defaultMapDelegationToSpendingControls(
      buildDelegation({ spend_limit_cents: 199.7 }),
    )
    assert.equal(sc.spending_limits?.[0]?.amount, 199)
  })
})

// ── provisionAgentCard ────────────────────────────────────────────

describe('StripeIssuingRail — provisionAgentCard', () => {
  it('POSTs to /v1/issuing/cards with mapped SpendingControls + APS metadata', async () => {
    const card = sampleCardResponse({ id: 'ic_provisioned_001' })
    const { fetch, calls } = makeMockFetch({
      fallback: () => ({ status: 200, body: card }),
    })
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
      defaultCardholder: 'ich_test_cardholder',
      fetch,
    })

    const delegation = buildDelegation({
      spend_limit_cents: 7500,
      allowed_merchant_categories: 'computers_peripherals_software',
    })
    const result = await rail.provisionAgentCard(delegation)

    assert.equal(result.id, 'ic_provisioned_001')
    assert.equal(calls.length, 1)
    const call = calls[0]!
    assert.ok(call.url.endsWith('/v1/issuing/cards'))
    assert.equal(call.method, 'POST')
    assert.equal(call.headers.Authorization, `Bearer ${TEST_KEY}`)

    const form = decodeForm(call.body)
    assert.equal(form.cardholder, 'ich_test_cardholder')
    assert.equal(form.currency, 'usd')
    assert.equal(form.type, 'virtual')
    assert.equal(form.status, 'active')
    assert.equal(form['spending_controls[spending_limits][0][amount]'], '7500')
    assert.equal(form['spending_controls[spending_limits][0][interval]'], 'all_time')
    assert.equal(
      form['spending_controls[allowed_categories][0]'],
      'computers_peripherals_software',
    )
    assert.equal(form['spending_controls[spending_limits_currency]'], 'usd')
    assert.equal(form['metadata[aps_delegation_ref]'], delegation.id)
    assert.equal(form['metadata[aps_delegator]'], delegation.delegator)
    assert.equal(form['metadata[aps_currency]'], 'USD')
    assert.equal(
      form['metadata[aps_cancel_at_iso]'],
      delegation.policy_context.valid_until,
    )
  })

  it('refuses to provision without a cardholder', async () => {
    const { fetch } = makeMockFetch({ fallback: () => ({ body: {} }) })
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
      fetch,
    })
    await assert.rejects(
      () => rail.provisionAgentCard(buildDelegation()),
      /cardholder/,
    )
  })

  it('records card → delegation mapping for later webhook lookup', async () => {
    const card = sampleCardResponse({ id: 'ic_tracked_001' })
    const { fetch } = makeMockFetch({ fallback: () => ({ body: card }) })
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
      defaultCardholder: 'ich_test_cardholder',
      fetch,
    })
    await rail.provisionAgentCard(buildDelegation({ id: 'deleg-tracked-001' }))

    // Build a webhook for the same card. handleAuthorizationWebhook
    // should resolve the delegation without an external lookup callback.
    const event = sampleAuthorizationEvent({
      cardId: 'ic_tracked_001',
      amountCents: 1000,
      authId: 'iauth_lookup_test',
    })
    const { fetch: mockApprove, calls } = makeMockFetch({
      fallback: () => ({ body: { id: event.data.object.id, status: 'pending' } }),
    })
    // Swap the rail's fetch via a fresh rail wired to the mockApprove
    // and re-register the same delegation map.
    const rail2 = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
      fetch: mockApprove,
    })
    rail2.registerCardDelegation('ic_tracked_001', {
      receipt_id: 'deleg-tracked-001',
      scope: ['commerce.purchase'],
      spend_limit_base_units: '5000',
      currency: 'USD',
      wallet_id: 'ic_tracked_001',
    })
    const decision = await rail2.handleAuthorizationWebhook(event)
    assert.equal(decision.approved, true)
    assert.equal(calls[0]?.url.endsWith('/approve'), true)
  })
})

// ── handleAuthorizationWebhook ────────────────────────────────────

describe('StripeIssuingRail — handleAuthorizationWebhook (approve path)', () => {
  it('approves a webhook within scope + budget, emits a verifiable PaymentReceipt', async () => {
    const { fetch, calls } = makeMockFetch({
      fallback: ({ url }) => ({
        body: { id: url.split('/').slice(-2, -1)[0] ?? 'iauth_x', status: 'pending' },
      }),
    })
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
      fetch,
    })
    rail.registerCardDelegation('ic_card_ok', {
      receipt_id: 'deleg-ok-001',
      scope: ['commerce.purchase'],
      spend_limit_base_units: '5000',
      currency: 'USD',
      wallet_id: 'ic_card_ok',
    })

    const event = sampleAuthorizationEvent({
      cardId: 'ic_card_ok',
      amountCents: 1234,
      authId: 'iauth_ok_001',
    })
    const decision = await rail.handleAuthorizationWebhook(event)

    assert.equal(decision.approved, true)
    assert.ok(decision.receipt, 'expected receipt on approve path')
    assert.equal(decision.receipt!.rail_name, 'stripe-issuing')
    assert.equal(decision.receipt!.delegation_ref, 'deleg-ok-001')
    assert.equal(decision.receipt!.amount_base_units, '1234')
    assert.equal(decision.receipt!.currency, 'USD')
    assert.equal(decision.receipt!.tx_proof, 'iauth_ok_001')

    const verify = verifyPaymentReceipt(decision.receipt!)
    assert.equal(verify.valid, true, JSON.stringify(verify))

    assert.equal(calls.length, 1)
    assert.ok(calls[0]!.url.endsWith('/v1/issuing/authorizations/iauth_ok_001/approve'))
    const form = decodeForm(calls[0]!.body)
    assert.equal(form['metadata[aps_delegation_ref]'], 'deleg-ok-001')
    assert.ok(form['metadata[aps_action_ref]']?.length === 64) // sha256 hex
  })
})

describe('StripeIssuingRail — handleAuthorizationWebhook (decline paths)', () => {
  it('declines over-budget with spend_limit_exceeded denial', async () => {
    const { fetch, calls } = makeMockFetch({
      fallback: () => ({ body: { id: 'iauth_overbudget_001', status: 'pending' } }),
    })
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
      fetch,
    })
    rail.registerCardDelegation('ic_card_low', {
      receipt_id: 'deleg-low-001',
      scope: ['commerce.purchase'],
      spend_limit_base_units: '500', // $5 cap
      currency: 'USD',
      wallet_id: 'ic_card_low',
    })

    const event = sampleAuthorizationEvent({
      cardId: 'ic_card_low',
      amountCents: 5000, // $50
      authId: 'iauth_overbudget_001',
    })
    const decision = await rail.handleAuthorizationWebhook(event)

    assert.equal(decision.approved, false)
    assert.equal(decision.reason, 'spend_limit_exceeded')
    assert.ok(decision.denial)
    assert.equal(decision.denial!.denial_reason, 'spend_limit_exceeded')
    const v = verifyPaymentDenial(decision.denial!)
    assert.equal(v.valid, true, JSON.stringify(v))
    assert.equal(calls.length, 1)
    assert.ok(calls[0]!.url.endsWith('/v1/issuing/authorizations/iauth_overbudget_001/decline'))
  })

  it('declines a revoked card with wallet_revoked denial', async () => {
    const { fetch, calls } = makeMockFetch({
      fallback: ({ url }) =>
        url.endsWith('/decline')
          ? { body: { id: 'iauth_revoked_001', status: 'closed', approved: false } }
          : { body: { id: 'ic_card_dead', status: 'canceled' } },
    })
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
      fetch,
    })
    rail.registerCardDelegation('ic_card_dead', {
      receipt_id: 'deleg-dead-001',
      scope: ['commerce.purchase'],
      spend_limit_base_units: '50000',
      currency: 'USD',
      wallet_id: 'ic_card_dead',
    })
    await rail.revokeWallet('ic_card_dead')

    const event = sampleAuthorizationEvent({
      cardId: 'ic_card_dead',
      amountCents: 1000,
      authId: 'iauth_revoked_001',
    })
    const decision = await rail.handleAuthorizationWebhook(event)

    assert.equal(decision.approved, false)
    assert.equal(decision.reason, 'wallet_revoked')
    assert.ok(decision.denial)
    const v = verifyPaymentDenial(decision.denial!)
    assert.equal(v.valid, true)

    // Two POSTs: cancel during revokeWallet, then decline.
    assert.ok(calls.some((c) => c.url.endsWith('/decline')))
    assert.ok(calls.some((c) => c.url.endsWith('/v1/issuing/cards/ic_card_dead')))
  })

  it('declines no_commerce_scope when delegation lacks commerce.purchase', async () => {
    const { fetch, calls } = makeMockFetch({
      fallback: () => ({ body: { id: 'iauth_noscope_001', status: 'pending' } }),
    })
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
      fetch,
    })
    rail.registerCardDelegation('ic_card_noscope', {
      receipt_id: 'deleg-noscope-001',
      scope: ['commerce.refund'],
      spend_limit_base_units: '5000',
      currency: 'USD',
      wallet_id: 'ic_card_noscope',
    })
    const event = sampleAuthorizationEvent({
      cardId: 'ic_card_noscope',
      amountCents: 1000,
      authId: 'iauth_noscope_001',
    })
    const decision = await rail.handleAuthorizationWebhook(event)
    assert.equal(decision.approved, false)
    assert.equal(decision.reason, 'no_commerce_scope')
    assert.ok(calls[0]!.url.endsWith('/decline'))
  })

  it('declines unknown card with rail_error', async () => {
    const { fetch, calls } = makeMockFetch({
      fallback: () => ({ body: { id: 'iauth_unknown_001' } }),
    })
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
      fetch,
    })
    const event = sampleAuthorizationEvent({
      cardId: 'ic_card_unregistered',
      amountCents: 1000,
      authId: 'iauth_unknown_001',
    })
    const decision = await rail.handleAuthorizationWebhook(event)
    assert.equal(decision.approved, false)
    assert.equal(decision.reason, 'rail_error')
    assert.match(decision.denial?.reason_detail ?? '', /no delegation registered/)
    assert.ok(calls[0]!.url.endsWith('/decline'))
  })
})

// ── Webhook signature verification ────────────────────────────────

describe('StripeIssuingRail — verifyWebhookSignature', () => {
  function signWebhook(body: string, ts: number): string {
    const sig = createHmac('sha256', WEBHOOK_SECRET)
      .update(`${ts}.${body}`, 'utf8')
      .digest('hex')
    return `t=${ts},v1=${sig}`
  }

  it('accepts a fresh, correctly signed payload', () => {
    const body = '{"hello":"world"}'
    const header = signWebhook(body, FIXED_NOW_SEC)
    assert.equal(
      verifyStripeSignature(body, header, WEBHOOK_SECRET, 300, FIXED_NOW_SEC),
      true,
    )
  })

  it('rejects a payload signed with the wrong secret', () => {
    const body = '{"hello":"world"}'
    const ts = FIXED_NOW_SEC
    const sig = createHmac('sha256', 'whsec_OTHER').update(`${ts}.${body}`).digest('hex')
    const header = `t=${ts},v1=${sig}`
    assert.equal(verifyStripeSignature(body, header, WEBHOOK_SECRET, 300, ts), false)
  })

  it('rejects a payload outside the tolerance window (replay)', () => {
    const body = '{"hello":"world"}'
    const oldTs = FIXED_NOW_SEC - 600 // 10 min old
    const header = signWebhook(body, oldTs)
    assert.equal(verifyStripeSignature(body, header, WEBHOOK_SECRET, 300, FIXED_NOW_SEC), false)
  })

  it('rejects a malformed header (no t=, no v1=)', () => {
    assert.equal(verifyStripeSignature('{}', 'garbage', WEBHOOK_SECRET, 300, FIXED_NOW_SEC), false)
  })

  it('rail.verifyWebhookSignature uses configured secret + tolerance', () => {
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
      webhookSecret: WEBHOOK_SECRET,
      webhookToleranceSec: 60,
    })
    const body = '{"event":"test"}'
    const header = signWebhook(body, FIXED_NOW_SEC)
    assert.equal(rail.verifyWebhookSignature(body, header, FIXED_NOW_SEC), true)
    // Outside tighter tolerance.
    const oldHeader = signWebhook(body, FIXED_NOW_SEC - 120)
    assert.equal(rail.verifyWebhookSignature(body, oldHeader, FIXED_NOW_SEC), false)
  })

  it('rail.verifyWebhookSignature throws when no secret is configured', () => {
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
    })
    assert.throws(() => rail.verifyWebhookSignature('{}', 't=1,v1=ff'), /no webhookSecret/)
  })
})

// ── revokeWallet + isWalletRevoked ────────────────────────────────

describe('StripeIssuingRail — revokeWallet', () => {
  it('POSTs status=canceled and flips isWalletRevoked to true', async () => {
    const { fetch, calls } = makeMockFetch({
      fallback: () => ({ body: { id: 'ic_card_xyz', status: 'canceled' } }),
    })
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
      fetch,
    })
    assert.equal(rail.isWalletRevoked('ic_card_xyz'), false)
    const ok = await rail.revokeWallet('ic_card_xyz')
    assert.equal(ok, true)
    assert.equal(rail.isWalletRevoked('ic_card_xyz'), true)
    assert.equal(calls.length, 1)
    assert.ok(calls[0]!.url.endsWith('/v1/issuing/cards/ic_card_xyz'))
    assert.equal(decodeForm(calls[0]!.body).status, 'canceled')
  })

  it('is idempotent: second revoke skips the HTTP call', async () => {
    const { fetch, calls } = makeMockFetch({
      fallback: () => ({ body: { id: 'ic_card_xyz', status: 'canceled' } }),
    })
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
      fetch,
    })
    await rail.revokeWallet('ic_card_xyz')
    await rail.revokeWallet('ic_card_xyz')
    assert.equal(calls.length, 1)
  })

  it('treats Stripe "already canceled" 400 as success', async () => {
    let n = 0
    const { fetch } = makeMockFetch({
      fallback: () => {
        n++
        return { status: 400, body: { error: { message: 'card already canceled' } } }
      },
    })
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
      fetch,
    })
    const ok = await rail.revokeWallet('ic_card_xyz')
    assert.equal(ok, true)
    assert.equal(n, 1)
  })
})

// ── verifyTransaction ─────────────────────────────────────────────

describe('StripeIssuingRail — verifyTransaction', () => {
  it('returns verified=true when authorization is closed + approved + amount matches', async () => {
    const { fetch } = makeMockFetch({
      fallback: () => ({
        body: {
          id: 'iauth_settle_001',
          object: 'issuing.authorization',
          amount: 1234,
          currency: 'usd',
          approved: true,
          status: 'closed',
          card: { id: 'ic_x', cardholder: 'ich_x' },
          merchant_data: { category: 'x', name: 'Vendor X' },
          metadata: {},
          created: FIXED_NOW_SEC,
        },
      }),
    })
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
      fetch,
    })
    const r = await rail.verifyTransaction('iauth_settle_001', '1234')
    assert.equal(r.verified, true)
    assert.equal(r.amount_base_units, '1234')
    assert.equal(r.sender, 'ich_x')
    assert.equal(r.receiver, 'Vendor X')
  })

  it('returns verified=false on Stripe API error and surfaces error', async () => {
    const { fetch } = makeMockFetch({
      fallback: () => ({ status: 404, body: { error: { message: 'not found' } } }),
    })
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
      fetch,
    })
    const r = await rail.verifyTransaction('iauth_missing')
    assert.equal(r.verified, false)
    assert.match(r.error ?? '', /404/)
  })
})

// ── PaymentRail not-supported surfaces ────────────────────────────

// ── Fixture exercise (synthetic webhook → rail) ───────────────────

describe('StripeIssuingRail — fixture exercise', () => {
  it('approve fixture → rail approves and emits a verifiable receipt', async () => {
    const event: AuthorizationEvent = JSON.parse(
      readFileSync(join(FIXTURE_DIR, 'authorization-approve.fixture.json'), 'utf8'),
    )
    const { fetch } = makeMockFetch({
      fallback: () => ({ body: { id: event.data.object.id, status: 'pending' } }),
    })
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
      fetch,
    })
    rail.registerCardDelegation(event.data.object.card.id, {
      receipt_id: 'deleg-fixture-stripe-001',
      scope: ['commerce.purchase'],
      spend_limit_base_units: '7500',
      currency: 'USD',
      wallet_id: event.data.object.card.id,
    })
    const decision = await rail.handleAuthorizationWebhook(event)
    assert.equal(decision.approved, true)
    assert.equal(verifyPaymentReceipt(decision.receipt!).valid, true)
  })

  it('decline-overbudget fixture → rail declines and emits a verifiable denial', async () => {
    const event: AuthorizationEvent = JSON.parse(
      readFileSync(
        join(FIXTURE_DIR, 'authorization-decline-overbudget.fixture.json'),
        'utf8',
      ),
    )
    const { fetch } = makeMockFetch({
      fallback: () => ({ body: { id: event.data.object.id, status: 'closed' } }),
    })
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
      fetch,
    })
    rail.registerCardDelegation(event.data.object.card.id, {
      receipt_id: 'deleg-fixture-stripe-001',
      scope: ['commerce.purchase'],
      spend_limit_base_units: '7500',
      currency: 'USD',
      wallet_id: event.data.object.card.id,
    })
    const decision = await rail.handleAuthorizationWebhook(event)
    assert.equal(decision.approved, false)
    assert.equal(decision.reason, 'spend_limit_exceeded')
    assert.equal(verifyPaymentDenial(decision.denial!).valid, true)
  })

  it('spending-controls-derived fixture matches the live mapper output', () => {
    const fx = JSON.parse(
      readFileSync(join(FIXTURE_DIR, 'spending-controls-derived.fixture.json'), 'utf8'),
    ) as { source_delegation: import('../../../src/v2/types.js').V2Delegation; derived: unknown }
    const reDerived = defaultMapDelegationToSpendingControls(fx.source_delegation)
    assert.deepEqual(reDerived, fx.derived)
  })
})

describe('StripeIssuingRail — PaymentRail surface (createInvoice/checkStatus)', () => {
  it('createInvoice throws with a guidance message', async () => {
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
    })
    await assert.rejects(
      () => rail.createInvoice({ amount_base_units: '100' }),
      /provisionAgentCard/,
    )
  })

  it('checkStatus throws with a guidance message', async () => {
    const rail = createStripeIssuingRail({
      apiKey: TEST_KEY,
      issuerPrivateKeyHex: ISSUER_PRIV,
    })
    await assert.rejects(() => rail.checkStatus('any'), /verifyTransaction/)
  })
})
