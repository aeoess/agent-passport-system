// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Generates byte-parity fixtures for the AP2 interop module.
// Run: npx tsx src/v2/payment-rails/ap2/fixtures/_generate.ts
//
// Three pairs:
//   001 — APS V2Delegation ↔ AP2 OpenCheckoutMandate (intent / open)
//   002 — APS V2Delegation + cart   ↔ AP2 CheckoutMandate (closed)
//   003 — APS V2Delegation + amount ↔ AP2 PaymentMandate (closed)
//
// Pinned signer seed: 64-char hex of 0x99. Pinned timestamps.

import { writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { publicKeyFromPrivate } from '../../../../crypto/keys.js'
import {
  AP2_VERSION,
  apsToAp2CartMandate,
  apsToAp2IntentMandate,
  apsToAp2PaymentMandate,
  signAp2Mandate,
} from '../index.js'
import type { V2Delegation } from '../../../types.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const SIGNER_PRIV = '99'.repeat(32)
const SIGNER_PUB = publicKeyFromPrivate(SIGNER_PRIV)
const VALID_FROM = '2026-05-03T20:00:00.000Z'
const VALID_UNTIL = '2026-06-03T20:00:00.000Z'

function writeFx(name: string, value: unknown) {
  const path = resolve(__dirname, name)
  writeFileSync(path, JSON.stringify(value, null, 2))
  console.log(`wrote ${name}`)
}

// ── Common APS delegation building blocks ────────────────────────

function _delegation(
  id: string,
  action_categories: string[],
  spend_limit?: number,
): V2Delegation {
  // delegatee in AP2 land needs to be a 32-byte Ed25519 hex pubkey for
  // a valid cnf.jwk encoding. Use the signer pubkey for fixture
  // simplicity; production callers use the actual delegatee pubkey.
  return {
    id,
    version: 1,
    supersedes: null,
    supersession_justification: null,
    delegator: 'did:aps:user-fixture-001',
    delegatee: SIGNER_PUB,
    scope: {
      action_categories,
      domain: 'commerce',
      resource_limits:
        spend_limit !== undefined ? { 'commerce.spend_limit': spend_limit } : undefined,
      constraints: { fixture: 'AP2 round-trip' },
    },
    policy_context: {
      policy_version: 'v2',
      values_floor_version: 'v1',
      trust_epoch: 0,
      issuer_id: 'did:aps:user-fixture-001',
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
}

// ── 001: APS delegation → OpenCheckoutMandate (open intent) ──────

const aps001 = _delegation('aps-deleg-001', ['commerce.checkout'], 50_000)
const ap2_001 = apsToAp2IntentMandate(aps001, {
  currency: 'USD',
  allowed_merchants: [
    { id: 'merch:acme-001', name: 'Acme Goods', url: 'https://acme.example' },
  ],
  line_items: [
    {
      id: 'req-001',
      acceptable_items: [
        {
          id: 'item-widget-001',
          name: 'Widget',
          quantity: 1,
          unit_price: { currency: 'USD', value: 4999 },
        },
      ],
      quantity: 1,
    },
  ],
})
const signed_001 = signAp2Mandate(ap2_001, SIGNER_PRIV)
writeFx('aps-delegation-001.json', aps001)
writeFx('ap2-intent-mandate-001.json', signed_001)

// ── 002: APS delegation + cart → CheckoutMandate (closed) ─────────

const aps002 = _delegation('aps-deleg-002', ['commerce.checkout'], 27999)
const ap2_002 = apsToAp2CartMandate(
  aps002,
  {
    payee: { id: 'merch:store-002', name: 'Specific Store', url: 'https://store.example' },
    items: [
      {
        id: 'item-shirt-l',
        name: 'Large Shirt',
        quantity: 1,
        unit_price: { currency: 'USD', value: 27999 },
      },
    ],
    total: { currency: 'USD', value: 27999 },
  },
  // No JWT yet — the gateway integration layer fills these for wire
  // emit. The fixture demonstrates the SDK-only audit shape.
  {},
)
const signed_002 = signAp2Mandate(ap2_002, SIGNER_PRIV)
writeFx('aps-delegation-002.json', aps002)
writeFx('ap2-cart-mandate-002.json', signed_002)

// ── 003: APS delegation + amount → PaymentMandate (closed) ────────

const aps003 = _delegation('aps-deleg-003', ['commerce.payment'], 27999)
const ap2_003 = apsToAp2PaymentMandate(aps003, {
  payee: { id: 'merch:store-002', name: 'Specific Store' },
  payment_instrument: { type: 'card', id: 'pi:card-1234', display: '**** **** **** 1234' },
  payment_amount: { currency: 'USD', value: 27999 },
  transaction_id: 'tx-fixture-003',
})
const signed_003 = signAp2Mandate(ap2_003, SIGNER_PRIV)
writeFx('aps-delegation-003.json', aps003)
writeFx('ap2-payment-mandate-003.json', signed_003)

// ── META.json ─────────────────────────────────────────────────────

writeFx('META.json', {
  generator: 'src/v2/payment-rails/ap2/fixtures/_generate.ts',
  ap2_version: AP2_VERSION,
  generated_at: new Date().toISOString(),
  signer_seed_hex: SIGNER_PRIV,
  signer_did_hex: SIGNER_PUB,
  fixed_valid_from: VALID_FROM,
  fixed_valid_until: VALID_UNTIL,
  pairs: [
    {
      id: '001',
      kind: 'open_checkout_mandate',
      aps: 'aps-delegation-001.json',
      ap2: 'ap2-intent-mandate-001.json',
      note: 'APS delegation → AP2 OpenCheckoutMandate (intent / open). Round-trips back via ap2MandateToApsDelegation.',
    },
    {
      id: '002',
      kind: 'checkout_mandate',
      aps: 'aps-delegation-002.json',
      ap2: 'ap2-cart-mandate-002.json',
      note: 'APS delegation + cart → AP2 CheckoutMandate (closed). One-way: cart contents not in APS delegation, so reverse trip loses items + total.',
    },
    {
      id: '003',
      kind: 'payment_mandate',
      aps: 'aps-delegation-003.json',
      ap2: 'ap2-payment-mandate-003.json',
      note: 'APS delegation + transaction-specific amount → AP2 PaymentMandate (closed). Reverse trip carries amount + payee + instrument back into delegation.scope.constraints.',
    },
  ],
  notes: {
    signing: 'APS Ed25519 over RFC 8785 JCS of the mandate dict. The cross-impl APS audit path. Wire-level SD-JWT/JWS encoding lives in the gateway integration layer.',
    cnf_encoding: 'AP2 cnf.jwk encodes the APS delegatee pubkey as OKP/Ed25519 with x = base64url(pubkey_bytes).',
    iat_exp: 'Unix epoch seconds derived from policy_context.valid_from / valid_until.',
  },
})
