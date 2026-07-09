// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Generates byte-parity fixtures for the x402 payment rail.
// Run: npx tsx src/v2/payment-rails/x402/fixtures/_generate.ts
//
// Pinned signer seed (66 repeated): keeps signed receipts/denials
// deterministic. Pinned tx hash and EIP-3009 nonce: keeps
// PaymentRequirements/PaymentPayload byte-stable.

import { writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { publicKeyFromPrivate } from '../../../../crypto/keys.js'
import { emitDenial, emitReceipt } from '../../hooks.js'
import {
  X402_VERSION,
  type EIP3009Authorization,
  type X402PaymentPayload,
  type X402PaymentRequirements,
} from '../types.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const SIGNER_PRIV = '66'.repeat(32)
const SIGNER_PUB = publicKeyFromPrivate(SIGNER_PRIV)
const FIXED_TS = '2026-05-03T20:00:00.000Z'

const DELEGATION_REF = 'd'.repeat(64)
const ACTION_REF = 'a'.repeat(64)
const TX_HASH = '0x' + 'c'.repeat(64)

const PAY_TO = '0x000000000000000000000000000000000000beef'
const PAYER = '0x000000000000000000000000000000000000cafe'
const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'

function writeFx(name: string, value: unknown) {
  const path = resolve(__dirname, name)
  writeFileSync(path, JSON.stringify(value, null, 2))
  console.log(`wrote ${name}`)
}

// ── PaymentRequirements (1.00 USDC = 1_000_000 atomic) ───────────

const requirements: X402PaymentRequirements = {
  scheme: 'exact',
  network: 'base',
  maxAmountRequired: '1000000',
  asset: USDC_BASE,
  payTo: PAY_TO,
  resource: 'https://example.com/api/premium-data',
  description: 'Premium API endpoint — 1 request',
  maxTimeoutSeconds: 60,
  extra: {
    name: 'USD Coin',
    version: '2',
  },
}
writeFx('payment-requirements.fixture.json', requirements)

// ── PaymentPayload ───────────────────────────────────────────────

const authorization: EIP3009Authorization = {
  from: PAYER,
  to: PAY_TO,
  value: '1000000',
  validAfter: '0',
  validBefore: '1893456000', // 2030-01-01 UTC
  nonce: '0x' + 'e'.repeat(64),
}

const payload: X402PaymentPayload = {
  x402Version: X402_VERSION,
  scheme: 'exact',
  network: 'base',
  payload: {
    signature: '0x' + 'f'.repeat(130),
    authorization,
  },
}
writeFx('payment-payload.fixture.json', payload)

// ── Settled receipt (x402-base-USDC rail) ────────────────────────

const receipt = emitReceipt(
  {
    delegation_ref: DELEGATION_REF,
    action_ref: ACTION_REF,
    rail_name: 'x402-base-USDC',
    amount_base_units: '1000000',
    currency: 'USDC',
    tx_proof: TX_HASH,
    invoice_id: 'inv-x402-fixture-001',
    issued_at: FIXED_TS,
  },
  SIGNER_PRIV,
)
writeFx('settled-receipt.fixture.json', receipt)

// ── Denied receipt (rail_error from facilitator) ─────────────────

const denial = emitDenial(
  {
    delegation_ref: DELEGATION_REF,
    action_ref: ACTION_REF,
    rail_name: 'x402-base-USDC',
    amount_base_units: '1000000',
    currency: 'USDC',
    denial_reason: 'rail_error',
    reason_detail: 'facilitator: invalid_signature',
    issued_at: FIXED_TS,
  },
  SIGNER_PRIV,
)
writeFx('denied-receipt.fixture.json', denial)

// ── Meta ─────────────────────────────────────────────────────────

writeFx('META.json', {
  generator: 'src/v2/payment-rails/x402/fixtures/_generate.ts',
  generated_at: new Date().toISOString(),
  signer_seed_hex: SIGNER_PRIV,
  signer_did_hex: SIGNER_PUB,
  fixed_timestamp: FIXED_TS,
  pinned: {
    delegation_ref: DELEGATION_REF,
    action_ref: ACTION_REF,
    tx_hash: TX_HASH,
    payer: PAYER,
    pay_to: PAY_TO,
    usdc_base_mainnet: USDC_BASE,
  },
  rail_name: 'x402-base-USDC',
  network: 'base',
  scheme: 'exact',
  x402_version: X402_VERSION,
  note: 'Byte-parity fixtures for the x402 reference adapter. Regenerate when the wire shapes (PaymentRequirements / PaymentPayload) or the signed APS receipt/denial canonical bytes change.',
})
