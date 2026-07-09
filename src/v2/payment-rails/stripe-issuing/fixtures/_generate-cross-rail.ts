// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Cross-rail fixture generator (stripe/ai#356 — Mycelium / Asqav)
// ══════════════════════════════════════════════════════════════════
// Produces permit-receipt-cross-rail.fixture.json: three signed
// rail events demonstrating the permit / revocation / re-issue
// lifecycle with cross-rail linking keys.
//
// All three events are emitted by the live SDK code paths
// (emitReceipt, emitDenial) under a fixed issuer key, with fixed
// timestamps and content-addressed identifiers. Re-running this
// script MUST produce a byte-identical fixture.
//
// Cross-rail keys consumed downstream:
//   - receipt_id   (sha256 over JCS-canonical receipt)
//                  → Mycelium TrailRecord.payment_hash
//   - action_ref   (top-level, content-addressed; per-event)
//                  → both rails' action_ref linking key
//   - delegation_ref (lineage between permit + revocation; new D'
//                     for re-issue) → both rails' lineage link
//
// Run: npx tsx src/v2/payment-rails/stripe-issuing/fixtures/_generate-cross-rail.ts
// ══════════════════════════════════════════════════════════════════

import { writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { emitReceipt, emitDenial } from '../../hooks.js'
import { publicKeyFromPrivate } from '../../../../crypto/keys.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

// ── Fixed issuer key (fixture-only; do not use in production) ────
const ISSUER_PRIV_HEX =
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
const ISSUER_PUB_HEX = publicKeyFromPrivate(ISSUER_PRIV_HEX)

// ── Fixed identifiers ────────────────────────────────────────────
// 64-hex placeholders for the original delegation D and the
// superseding delegation D' (re-issue chain).
const DELEGATION_REF_D = 'd'.repeat(64)
const DELEGATION_REF_D_PRIME = 'e'.repeat(64)
// 64-hex action_ref values for the three events. R0 = permit,
// R1 = denied attempt under revoked D (revocation evidence on rail),
// R2 = re-issue under D'. action_ref is content-addressed per event.
const ACTION_REF_R0 = '0'.repeat(64)
const ACTION_REF_R1 = '1'.repeat(64)
const ACTION_REF_R2 = '2'.repeat(64)

// ── Fixed timestamps (60s apart, deterministic) ───────────────────
const TS_PERMIT = '2026-05-06T20:00:00.000Z'
const TS_REVOCATION = '2026-05-06T20:01:00.000Z'
const TS_REISSUE = '2026-05-06T20:02:00.000Z'

// ── Three rail events ────────────────────────────────────────────

// 1. Permit: PaymentReceipt under delegation D, action_ref R0.
const permit = emitReceipt(
  {
    delegation_ref: DELEGATION_REF_D,
    action_ref: ACTION_REF_R0,
    rail_name: 'stripe-issuing',
    amount_base_units: '1234',
    currency: 'usd',
    tx_proof: 'iauth_fixture_permit_001',
    issued_at: TS_PERMIT,
    accountability_shape: true,
  },
  ISSUER_PRIV_HEX,
)

// 2. Revocation evidence: PaymentDenial under same D after off-rail
//    revocation. denial_reason='wallet_revoked' is the closest
//    available rail-level signal that delegation/wallet authority
//    no longer holds. action_ref R1 (per-event content-addressed),
//    delegation_ref still D (the cross-rail linking key for
//    revocation against the original permit).
const revocation = emitDenial(
  {
    delegation_ref: DELEGATION_REF_D,
    action_ref: ACTION_REF_R1,
    rail_name: 'stripe-issuing',
    amount_base_units: '1234',
    currency: 'usd',
    denial_reason: 'wallet_revoked',
    reason_detail: 'delegation D revoked off-rail; subsequent payment attempt denied',
    issued_at: TS_REVOCATION,
    accountability_shape: true,
  },
  ISSUER_PRIV_HEX,
)

// 3. Re-issue: PaymentReceipt under new delegation D' (which
//    supersedes D off-rail). action_ref R2, delegation_ref D'.
//    Lineage to permit goes through D'.supersedes=hash(D) on the
//    delegation object; the receipt itself just declares D' as
//    the authorizing delegation.
const reissue = emitReceipt(
  {
    delegation_ref: DELEGATION_REF_D_PRIME,
    action_ref: ACTION_REF_R2,
    rail_name: 'stripe-issuing',
    amount_base_units: '1234',
    currency: 'usd',
    tx_proof: 'iauth_fixture_reissue_001',
    issued_at: TS_REISSUE,
    accountability_shape: true,
  },
  ISSUER_PRIV_HEX,
)

// ── Cross-rail keys summary ──────────────────────────────────────
// Top-level summary block so verifiers can grep the linking keys
// without re-canonicalizing the receipts. Authoritative source is
// each event object itself; this block is a convenience view.
const cross_rail_keys = {
  permit: {
    receipt_id: permit.receipt_id,
    action_ref: permit.action_ref,
    delegation_ref: permit.delegation_ref,
    role: 'permit',
    notes:
      'Mycelium TrailRecord(permit).payment_hash = receipt_id. action_ref = R0 = both rails\' linking key for the permit event.',
  },
  revocation: {
    receipt_id: revocation.receipt_id,
    action_ref: revocation.action_ref,
    delegation_ref: revocation.delegation_ref,
    role: 'revocation',
    notes:
      'Same delegation_ref as permit (cross-rail lineage link). action_ref = R1, distinct per content. denial_reason=wallet_revoked is the rail-level signal that off-rail revocation took effect.',
  },
  reissue: {
    receipt_id: reissue.receipt_id,
    action_ref: reissue.action_ref,
    delegation_ref: reissue.delegation_ref,
    role: 'reissue',
    notes:
      'New delegation_ref (D\') that supersedes the original D off-rail. Lineage to permit goes through D\'.supersedes=hash(D) on the delegation object.',
  },
}

const fixture = {
  fixture_metadata: {
    name: 'permit-receipt-cross-rail',
    issue: 'stripe/ai#356',
    purpose:
      'Three-event lifecycle (permit / revocation / re-issue) demonstrating cross-rail interop with Mycelium TrailRecord (Arbitrum One + Base mainnet dual-chain anchored) and Asqav protectmcp:lifecycle (RFC 3161 + OTS anchored).',
    deterministic: true,
    issuer: {
      pub_hex: ISSUER_PUB_HEX,
      priv_hex_disclosure:
        'fixture-only deterministic key; do not use in production. Disclosed for byte-parity test reproduction.',
      priv_hex: ISSUER_PRIV_HEX,
    },
    canonicalization: 'JCS (RFC 8785)',
    signature_alg: 'EdDSA / Ed25519',
    receipt_id_derivation:
      'sha256 hex over canonicalize({...event, receipt_id: \'\', signature: \'\'})',
  },
  events: {
    permit,
    revocation,
    reissue,
  },
  cross_rail_keys,
}

const path = resolve(__dirname, 'permit-receipt-cross-rail.fixture.json')
writeFileSync(path, JSON.stringify(fixture, null, 2) + '\n')
console.log(`wrote ${path}`)
console.log('')
console.log('cross-rail keys:')
console.log(`  permit.receipt_id    = ${permit.receipt_id}`)
console.log(`  revocation.receipt_id = ${revocation.receipt_id}`)
console.log(`  reissue.receipt_id   = ${reissue.receipt_id}`)
console.log(`  delegation D (permit + revocation) = ${DELEGATION_REF_D}`)
console.log(`  delegation D' (reissue)            = ${DELEGATION_REF_D_PRIME}`)
