// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Generates canonical conformance fixtures for the payment-rails
// conformance harness.
// Run: npx tsx src/v2/payment-rails/conformance/fixtures/_generate.ts
//
// Pinned signer key, pinned timestamp, pinned refs. The point of
// these fixtures is byte-stable: third-party adapter authors pin to
// a specific schema_version under META.json and re-run the harness
// to confirm their implementation produces the same emitted bytes.
// Re-run when the receipt/denial canonical shape changes; bump the
// schema_version in META.json on every change.

import { writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { publicKeyFromPrivate } from '../../../../crypto/keys.js'
import { emitDenial, emitReceipt } from '../../hooks.js'
import {
  HARNESS_FIXED_NOW,
  HARNESS_ISSUER_PRIV,
  STANDARD_SCENARIOS,
} from '../harness.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const SIGNER_PUB = publicKeyFromPrivate(HARNESS_ISSUER_PRIV)
const NOW_ISO = HARNESS_FIXED_NOW.toISOString()

const DELEGATION_REF = 'd'.repeat(64)
const ACTION_REF = 'a'.repeat(64)
const TX_PROOF = 'b'.repeat(64)
const FIXED_WALLET = 'wallet-conformance-fixed'
const FIXED_RAIL = 'nano'
const FIXED_CURRENCY = 'XNO'

function writeFx(name: string, value: unknown) {
  const path = resolve(__dirname, name)
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n')
  console.log(`wrote ${name}`)
}

// ── Pre-authorize fixtures (SCN-001..SCN-005) ─────────────────────

function preAuthFixture(
  id: string,
  description: string,
  delegationOverrides: Record<string, unknown>,
  amount: string,
  expected: Record<string, unknown>,
  required_scope = 'commerce.purchase',
) {
  return {
    scenario_id: id,
    description,
    kind: 'pre_authorize',
    input: {
      delegation: {
        receipt_id: DELEGATION_REF,
        scope: ['commerce.purchase'],
        spend_limit_base_units: '1000000000000000000000000000000',
        wallet_id: FIXED_WALLET,
        currency: FIXED_CURRENCY,
        ...delegationOverrides,
      },
      required_scope,
      amount_base_units: amount,
      currency: FIXED_CURRENCY,
      now: NOW_ISO,
    },
    expected,
  }
}

writeFx(
  'SCN-001.fixture.json',
  preAuthFixture(
    'SCN-001',
    'preAuthorize accepts when delegation has commerce scope and amount within budget',
    {},
    '1000',
    { ok: true },
  ),
)

writeFx(
  'SCN-002.fixture.json',
  preAuthFixture(
    'SCN-002',
    "preAuthorize rejects with 'no_commerce_scope' when required_scope absent",
    { scope: ['commerce.refund'] },
    '1000',
    { ok: false, denial_reason: 'no_commerce_scope' },
  ),
)

writeFx(
  'SCN-003.fixture.json',
  preAuthFixture(
    'SCN-003',
    "preAuthorize rejects with 'spend_limit_exceeded' when amount exceeds budget",
    { spend_limit_base_units: '1000' },
    '10000',
    { ok: false, denial_reason: 'spend_limit_exceeded' },
  ),
)

writeFx(
  'SCN-004.fixture.json',
  {
    scenario_id: 'SCN-004',
    description:
      "preAuthorize rejects with 'wallet_revoked' when bound wallet is revoked",
    kind: 'pre_authorize_with_revocation',
    setup: {
      revoke_wallet_id: FIXED_WALLET,
    },
    input: {
      delegation: {
        receipt_id: DELEGATION_REF,
        scope: ['commerce.purchase'],
        spend_limit_base_units: '1000000000000000000000000000000',
        wallet_id: FIXED_WALLET,
        currency: FIXED_CURRENCY,
      },
      required_scope: 'commerce.purchase',
      amount_base_units: '1000',
      currency: FIXED_CURRENCY,
      now: NOW_ISO,
    },
    expected: { ok: false, denial_reason: 'wallet_revoked' },
  },
)

writeFx(
  'SCN-005.fixture.json',
  preAuthFixture(
    'SCN-005',
    "preAuthorize rejects with 'time_window_violation' after delegation.not_after expired",
    { not_after: new Date(HARNESS_FIXED_NOW.getTime() - 60_000).toISOString() },
    '1000',
    { ok: false, denial_reason: 'time_window_violation' },
  ),
)

// ── Emit fixtures (SCN-006, SCN-007, SCN-008, SCN-010) ────────────

const receipt006 = emitReceipt(
  {
    delegation_ref: DELEGATION_REF,
    action_ref: ACTION_REF,
    rail_name: FIXED_RAIL,
    amount_base_units: '1000',
    currency: FIXED_CURRENCY,
    tx_proof: TX_PROOF,
    invoice_id: 'inv-conformance-006',
    issued_at: NOW_ISO,
  },
  HARNESS_ISSUER_PRIV,
)
writeFx('SCN-006.fixture.json', {
  scenario_id: 'SCN-006',
  description: 'emitReceipt produces a PaymentReceipt with valid Ed25519 signature',
  kind: 'emit_receipt',
  input: {
    delegation_ref: DELEGATION_REF,
    action_ref: ACTION_REF,
    rail_name: FIXED_RAIL,
    amount_base_units: '1000',
    currency: FIXED_CURRENCY,
    tx_proof: TX_PROOF,
    invoice_id: 'inv-conformance-006',
    issued_at: NOW_ISO,
  },
  issuer_private_key_hex: HARNESS_ISSUER_PRIV,
  expected: receipt006,
})

const receipt007 = emitReceipt(
  {
    delegation_ref: DELEGATION_REF,
    action_ref: ACTION_REF,
    rail_name: FIXED_RAIL,
    amount_base_units: '1000',
    currency: FIXED_CURRENCY,
    tx_proof: TX_PROOF,
    issued_at: NOW_ISO,
  },
  HARNESS_ISSUER_PRIV,
)
writeFx('SCN-007.fixture.json', {
  scenario_id: 'SCN-007',
  description: 'emitReceipt output round-trips through JSON canonicalization',
  kind: 'emit_receipt_roundtrip',
  input: {
    delegation_ref: DELEGATION_REF,
    action_ref: ACTION_REF,
    rail_name: FIXED_RAIL,
    amount_base_units: '1000',
    currency: FIXED_CURRENCY,
    tx_proof: TX_PROOF,
    issued_at: NOW_ISO,
  },
  issuer_private_key_hex: HARNESS_ISSUER_PRIV,
  expected: receipt007,
})

const denial008 = emitDenial(
  {
    delegation_ref: DELEGATION_REF,
    action_ref: ACTION_REF,
    rail_name: FIXED_RAIL,
    amount_base_units: '1000',
    currency: FIXED_CURRENCY,
    denial_reason: 'no_commerce_scope',
    reason_detail: "scope 'commerce.purchase' not in delegation",
    issued_at: NOW_ISO,
  },
  HARNESS_ISSUER_PRIV,
)
writeFx('SCN-008.fixture.json', {
  scenario_id: 'SCN-008',
  description: 'emitDenial produces a PaymentDenial with valid Ed25519 signature',
  kind: 'emit_denial',
  input: {
    delegation_ref: DELEGATION_REF,
    action_ref: ACTION_REF,
    rail_name: FIXED_RAIL,
    amount_base_units: '1000',
    currency: FIXED_CURRENCY,
    denial_reason: 'no_commerce_scope',
    reason_detail: "scope 'commerce.purchase' not in delegation",
    issued_at: NOW_ISO,
  },
  issuer_private_key_hex: HARNESS_ISSUER_PRIV,
  expected: denial008,
})

// ── Revocation sequence (SCN-009) ─────────────────────────────────

writeFx('SCN-009.fixture.json', {
  scenario_id: 'SCN-009',
  description: 'revokeWallet halts subsequent preAuthorize calls bound to that wallet',
  kind: 'revocation_sequence',
  wallet_id: FIXED_WALLET,
  operations: [
    {
      op: 'preAuthorize',
      input: {
        delegation: {
          receipt_id: DELEGATION_REF,
          scope: ['commerce.purchase'],
          spend_limit_base_units: '1000000000000000000000000000000',
          wallet_id: FIXED_WALLET,
          currency: FIXED_CURRENCY,
        },
        required_scope: 'commerce.purchase',
        amount_base_units: '1000',
        currency: FIXED_CURRENCY,
        now: NOW_ISO,
      },
      expected: { ok: true },
    },
    { op: 'revokeWallet', wallet_id: FIXED_WALLET, expected: true },
    { op: 'isWalletRevoked', wallet_id: FIXED_WALLET, expected: true },
    { op: 'revokeWallet', wallet_id: FIXED_WALLET, expected: true },
    {
      op: 'preAuthorize',
      input: {
        delegation: {
          receipt_id: DELEGATION_REF,
          scope: ['commerce.purchase'],
          spend_limit_base_units: '1000000000000000000000000000000',
          wallet_id: FIXED_WALLET,
          currency: FIXED_CURRENCY,
        },
        required_scope: 'commerce.purchase',
        amount_base_units: '1000',
        currency: FIXED_CURRENCY,
        now: NOW_ISO,
      },
      expected: { ok: false, denial_reason: 'wallet_revoked' },
    },
  ],
})

// ── delegation_ref binding (SCN-010) ──────────────────────────────

const REF_010 = 'c'.repeat(64)
const receipt010 = emitReceipt(
  {
    delegation_ref: REF_010,
    action_ref: ACTION_REF,
    rail_name: FIXED_RAIL,
    amount_base_units: '1000',
    currency: FIXED_CURRENCY,
    tx_proof: TX_PROOF,
    issued_at: NOW_ISO,
  },
  HARNESS_ISSUER_PRIV,
)
writeFx('SCN-010.fixture.json', {
  scenario_id: 'SCN-010',
  description: "emitted receipt.delegation_ref equals the input delegation receipt_id",
  kind: 'emit_receipt',
  input: {
    delegation_ref: REF_010,
    action_ref: ACTION_REF,
    rail_name: FIXED_RAIL,
    amount_base_units: '1000',
    currency: FIXED_CURRENCY,
    tx_proof: TX_PROOF,
    issued_at: NOW_ISO,
  },
  issuer_private_key_hex: HARNESS_ISSUER_PRIV,
  expected: receipt010,
})

// ── META ──────────────────────────────────────────────────────────

writeFx('META.json', {
  generator: 'src/v2/payment-rails/conformance/fixtures/_generate.ts',
  generated_at: new Date().toISOString(),
  schema_version: '1.0.0',
  signer_seed_hex: HARNESS_ISSUER_PRIV,
  signer_did_hex: SIGNER_PUB,
  fixed_timestamp: NOW_ISO,
  scenarios: STANDARD_SCENARIOS.map((s) => ({ id: s.id, description: s.description })),
  note:
    'Canonical inputs + expected outputs for the payment-rails conformance harness. ' +
    'Third-party adapters pin to schema_version and re-run the harness to claim conformance. ' +
    'Bump schema_version on any breaking shape change.',
})
