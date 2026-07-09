// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Generates byte-parity fixtures for the payment-rails module.
// Run: npx tsx src/v2/payment-rails/fixtures/_generate.ts
//
// Pinned signer seed: 64-char hex of 0x77 to keep outputs deterministic.
// All timestamps fixed. action_ref / delegation_ref / tx_proof are
// stable hex strings. Re-run when the canonical shape changes.

import { writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { publicKeyFromPrivate } from '../../../crypto/keys.js'
import {
  emitDenial,
  emitReceipt,
} from '../hooks.js'
import { canonicalizeInvoice } from '../canonicalize.js'
import { createNanoRail, xnoToRaw } from '../nano.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const SIGNER_PRIV = '77'.repeat(32)
const SIGNER_PUB = publicKeyFromPrivate(SIGNER_PRIV)
const FIXED_TS = '2026-05-03T20:00:00.000Z'

const DELEGATION_REF = 'd'.repeat(64)
const ACTION_REF = 'a'.repeat(64)
const TX_PROOF = 'b'.repeat(64)

function writeFx(name: string, value: unknown) {
  const path = resolve(__dirname, name)
  writeFileSync(path, JSON.stringify(value, null, 2))
  console.log(`wrote ${name}`)
}

// ── PaymentReceipt fixture (Nano happy path) ─────────────────────

const receipt = emitReceipt(
  {
    delegation_ref: DELEGATION_REF,
    action_ref: ACTION_REF,
    rail_name: 'nano',
    amount_base_units: xnoToRaw('0.001'),
    currency: 'XNO',
    tx_proof: TX_PROOF,
    invoice_id: 'inv-fixture-001',
    issued_at: FIXED_TS,
  },
  SIGNER_PRIV,
)
writeFx('receipt-nano-happy.fixture.json', receipt)

// ── PaymentDenial fixture (no_commerce_scope) ────────────────────

const denial = emitDenial(
  {
    delegation_ref: DELEGATION_REF,
    action_ref: ACTION_REF,
    rail_name: 'nano',
    amount_base_units: xnoToRaw('0.001'),
    currency: 'XNO',
    denial_reason: 'no_commerce_scope',
    reason_detail: "scope 'commerce.purchase' not in delegation",
    issued_at: FIXED_TS,
  },
  SIGNER_PRIV,
)
writeFx('denial-no-scope.fixture.json', denial)

// ── PaymentInvoice round-trip fixture ────────────────────────────
//
// The Nano adapter's createInvoice adds a random raw offset for
// uniqueness, so to produce a deterministic invoice we monkey-patch
// Math.random for one call and capture the result.

const _origRandom = Math.random
Math.random = () => 0.5 // → offset = 5000 raw

const rail = createNanoRail({
  receivingAddress: 'nano_3test1f1xt7r3y6a7z9k1c0nv8d4yhfk93rcd6b1pmce8wkqf6kpunkfxnwd',
  fetchHistory: async () => [],
  fetchBlockInfo: async () => ({ confirmed: 'true', amount: '0' }),
})

const invoice = await rail.createInvoice({
  amount_base_units: xnoToRaw('0.001'),
  settlement_id: 'set-fixture-001',
  agent_id: 'agent-fixture-001',
  memo: 'unit test invoice',
  expires_in_seconds: 3600,
})

Math.random = _origRandom

// Override the random invoice_id and timestamps so the canonical bytes
// are deterministic. A "real" invoice would not need this; the fixture
// captures the shape, not the entropy.
const stable = {
  ...invoice,
  invoice_id: 'inv-fixture-001',
  created_at: FIXED_TS,
  expires_at: '2026-05-03T21:00:00.000Z',
}
writeFx('invoice-roundtrip.fixture.json', stable)

// ── Meta ─────────────────────────────────────────────────────────

writeFx('META.json', {
  generator: 'src/v2/payment-rails/fixtures/_generate.ts',
  generated_at: new Date().toISOString(),
  signer_seed_hex: SIGNER_PRIV,
  signer_did_hex: SIGNER_PUB,
  fixed_timestamp: FIXED_TS,
  note: 'Byte-parity fixtures for payment-rails. Regenerate when receipt/denial/invoice shape changes.',
})
