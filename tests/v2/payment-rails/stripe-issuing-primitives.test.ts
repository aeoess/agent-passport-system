// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Stripe Issuing — protocol-primitive tests (SDK-side)
// ══════════════════════════════════════════════════════════════════
// Phase 4.1 boundary split: the orchestration class `StripeIssuingRail`
// moved to the private gateway repo. The class-exercising tests
// (provisionAgentCard, handleAuthorizationWebhook approve/decline/
// escalation paths, revokeWallet, verifyTransaction, fixture exercise,
// PaymentRail surface) moved with it.
//
// The primitive surface stays in the SDK and these tests pin it:
//   - defaultMapDelegationToSpendingControls
//   - verifyStripeSignature (the standalone HMAC verifier; the class
//     instance method `rail.verifyWebhookSignature` is gateway-side)
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'

import {
  defaultMapDelegationToSpendingControls,
  verifyStripeSignature,
} from '../../../src/v2/payment-rails/stripe-issuing/index.js'
import type { V2Delegation } from '../../../src/v2/types.js'

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

// ── defaultMapDelegationToSpendingControls ────────────────────────

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

// ── verifyStripeSignature (standalone primitive) ──────────────────
// The class instance method `rail.verifyWebhookSignature` lives in the
// gateway repo with the rest of the class. These tests pin the
// standalone primitive's bytewise behavior. Conformance-pinning level.

describe('verifyStripeSignature (standalone primitive)', () => {
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
})
