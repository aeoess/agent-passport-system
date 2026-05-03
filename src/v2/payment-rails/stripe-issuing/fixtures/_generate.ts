// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Generates byte-parity fixtures for the stripe-issuing adapter.
// Run: npx tsx src/v2/payment-rails/stripe-issuing/fixtures/_generate.ts
//
// Fixtures captured here:
//   - spending-controls-derived.fixture.json
//       Stripe SpendingControls produced by the default mapper from a
//       canonical sample V2Delegation.
//   - authorization-approve.fixture.json
//       Synthetic issuing_authorization.request webhook payload that
//       passes APS gates (within budget, in scope).
//   - authorization-decline-overbudget.fixture.json
//       Synthetic webhook that should fail with spend_limit_exceeded.
//
// All timestamps fixed; ids use stable strings. Re-run when the
// adapter or upstream Stripe shape changes.

import { writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { defaultMapDelegationToSpendingControls } from '../index.js'
import type { AuthorizationEvent } from '../types.js'
import type { V2Delegation } from '../../../types.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXED_TS_ISO = '2026-05-03T20:00:00.000Z'
const FIXED_TS_SEC = Math.floor(Date.parse(FIXED_TS_ISO) / 1000)

function writeFx(name: string, value: unknown): void {
  const path = resolve(__dirname, name)
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n')
  console.log(`wrote ${name}`)
}

// ── Sample APS delegation ────────────────────────────────────────

const SAMPLE_DELEGATION: V2Delegation = {
  id: 'deleg-fixture-stripe-001',
  version: 1,
  supersedes: null,
  supersession_justification: null,
  delegator: 'did:key:z6MkFixtureDelegator',
  delegatee: 'did:key:z6MkFixtureAgent',
  scope: {
    action_categories: ['commerce.purchase'],
    resource_limits: { spend_limit_cents: 7500 },
    constraints: {
      allowed_merchant_categories: 'computers_peripherals_software,office_supplies',
    },
  },
  policy_context: {
    policy_version: '1.0',
    values_floor_version: '1.0',
    trust_epoch: 1,
    issuer_id: 'aps-fixture-issuer',
    created_at: FIXED_TS_ISO,
    valid_from: FIXED_TS_ISO,
    valid_until: '2026-12-31T23:59:59.000Z',
  },
  signature: 'fixture-signature-placeholder',
  status: 'active',
  renewal_reason: null,
  expansion_reviewer: null,
  expansion_review_sig: null,
  assurance_class: 'mechanically_enforceable',
}

writeFx('spending-controls-derived.fixture.json', {
  source_delegation: SAMPLE_DELEGATION,
  derived: defaultMapDelegationToSpendingControls(SAMPLE_DELEGATION),
})

// ── Approve-case authorization webhook ───────────────────────────

const APPROVE_EVENT: AuthorizationEvent = {
  id: 'evt_fixture_approve_001',
  type: 'issuing_authorization.request',
  created: FIXED_TS_SEC,
  livemode: false,
  data: {
    object: {
      id: 'iauth_fixture_approve_001',
      object: 'issuing.authorization',
      amount: 1234, // $12.34, well under $75 limit
      currency: 'usd',
      approved: false,
      status: 'pending',
      card: {
        id: 'ic_fixture_card_001',
        cardholder: 'ich_fixture_cardholder_001',
        currency: 'usd',
      },
      merchant_data: {
        category: 'computers_peripherals_software',
        category_code: '5734',
        name: 'Test Vendor',
        country: 'US',
      },
      metadata: { aps_delegation_ref: SAMPLE_DELEGATION.id },
      created: FIXED_TS_SEC,
      pending_request: { amount: 1234, currency: 'usd' },
    },
  },
}
writeFx('authorization-approve.fixture.json', APPROVE_EVENT)

// ── Decline-case (over-budget) authorization webhook ─────────────

const DECLINE_EVENT: AuthorizationEvent = {
  id: 'evt_fixture_decline_overbudget_001',
  type: 'issuing_authorization.request',
  created: FIXED_TS_SEC,
  livemode: false,
  data: {
    object: {
      id: 'iauth_fixture_decline_overbudget_001',
      object: 'issuing.authorization',
      amount: 50000, // $500, way over $75 cap
      currency: 'usd',
      approved: false,
      status: 'pending',
      card: {
        id: 'ic_fixture_card_001',
        cardholder: 'ich_fixture_cardholder_001',
        currency: 'usd',
      },
      merchant_data: {
        category: 'computers_peripherals_software',
        category_code: '5734',
        name: 'Test Vendor',
        country: 'US',
      },
      metadata: { aps_delegation_ref: SAMPLE_DELEGATION.id },
      created: FIXED_TS_SEC,
      pending_request: { amount: 50000, currency: 'usd' },
    },
  },
}
writeFx('authorization-decline-overbudget.fixture.json', DECLINE_EVENT)

// ── Meta ─────────────────────────────────────────────────────────

writeFx('META.json', {
  generator: 'src/v2/payment-rails/stripe-issuing/fixtures/_generate.ts',
  generated_at: new Date().toISOString(),
  fixed_timestamp: FIXED_TS_ISO,
  note: 'Synthetic Stripe Issuing fixtures. No real Stripe API call was made; ids and amounts are deterministic. Regenerate when the AuthorizationEvent or SpendingControls shape changes.',
  fixtures: {
    'spending-controls-derived.fixture.json':
      'Stripe SpendingControls produced by defaultMapDelegationToSpendingControls from the sample V2Delegation, plus the source delegation for traceability.',
    'authorization-approve.fixture.json':
      'issuing_authorization.request webhook payload sized to pass the sample delegation ($12.34 vs $75 cap, in commerce.purchase scope).',
    'authorization-decline-overbudget.fixture.json':
      'issuing_authorization.request webhook payload sized to fail spend_limit_exceeded ($500 vs $75 cap).',
  },
})
