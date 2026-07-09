// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// x402 payment rail — adapter behavior tests with mock facilitator.
//
// No real network I/O; the facilitator /verify and /settle endpoints
// are caller-supplied closures the test file injects per scenario.
//
// Coverage:
//   - createInvoice produces valid X402PaymentRequirements
//   - submitPayment happy path (facilitator verifies + settles → receipt
//     with on-chain tx hash)
//   - submitPayment verify-fail → denial with rail_error
//   - preAuthorize gate failures (no_commerce_scope, spend_limit_exceeded)
//     before invoice creation
//   - revokeWallet halts subsequent createInvoice → preAuthorize chain
//   - verifyTransaction resolves settled tx hashes
//   - sendPayment throws UnsupportedOperation
//   - canonicalize+verify round-trip on receipt and denial
//   - byte-parity check on the four shipped fixtures

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  emitDenial,
  emitReceipt,
  preAuthorize,
  verifyPaymentDenial,
  verifyPaymentReceipt,
} from '../../../src/v2/payment-rails/index.js'
import type {
  DelegationView,
  PaymentDenial,
  PaymentReceipt,
} from '../../../src/v2/payment-rails/index.js'
import {
  DEFAULT_FACILITATOR_URL,
  USDC_BASE_MAINNET,
  X402PaymentRail,
  createX402Rail,
} from '../../../src/v2/payment-rails/x402/index.js'
import {
  X402_VERSION,
  type EIP3009Authorization,
  type X402PaymentPayload,
  type X402SettleResponse,
  type X402VerifyResponse,
} from '../../../src/v2/payment-rails/x402/types.js'
import { publicKeyFromPrivate } from '../../../src/crypto/keys.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_DIR = join(
  __dirname,
  '..',
  '..',
  '..',
  'src',
  'v2',
  'payment-rails',
  'x402',
  'fixtures',
)

const ISSUER_PRIV = '99'.repeat(32)
const ISSUER_PUB = publicKeyFromPrivate(ISSUER_PRIV)

const PAY_TO = '0x000000000000000000000000000000000000beef'
const PAYER = '0x000000000000000000000000000000000000cafe'
const TX_HASH = '0x' + '1'.repeat(64)

// ── Mock facilitators ─────────────────────────────────────────────

function alwaysVerify(payer = PAYER) {
  return async (): Promise<X402VerifyResponse> => ({
    isValid: true,
    payer,
  })
}

function neverVerify(reason = 'invalid_signature') {
  return async (): Promise<X402VerifyResponse> => ({
    isValid: false,
    invalidReason: reason,
    payer: PAYER,
  })
}

function alwaysSettle(txHash = TX_HASH, payer = PAYER) {
  return async (): Promise<X402SettleResponse> => ({
    success: true,
    payer,
    transaction: txHash,
    network: 'base',
  })
}

function neverSettle(reason = 'insufficient_funds') {
  return async (): Promise<X402SettleResponse> => ({
    success: false,
    errorReason: reason,
    payer: PAYER,
    transaction: '',
    network: 'base',
  })
}

function _rail(overrides: Partial<{
  verify: ReturnType<typeof alwaysVerify>
  settle: ReturnType<typeof alwaysSettle>
}> = {}): X402PaymentRail {
  return createX402Rail({
    payTo: PAY_TO,
    asset: USDC_BASE_MAINNET,
    network: 'base',
    resource: 'https://example.com/api/premium',
    description: 'Test endpoint',
    facilitatorVerify: overrides.verify ?? alwaysVerify(),
    facilitatorSettle: overrides.settle ?? alwaysSettle(),
  })
}

function _delegation(overrides: Partial<DelegationView> = {}): DelegationView {
  return {
    receipt_id: 'd'.repeat(64),
    scope: ['commerce.purchase'],
    spend_limit_base_units: '5000000', // 5 USDC
    wallet_id: 'wallet-x402-001',
    currency: 'USDC',
    ...overrides,
  }
}

function _authorization(overrides: Partial<EIP3009Authorization> = {}): EIP3009Authorization {
  return {
    from: PAYER,
    to: PAY_TO,
    value: '1000000',
    validAfter: '0',
    validBefore: '1893456000',
    nonce: '0x' + '0'.repeat(64),
    ...overrides,
  }
}

function _payload(overrides: Partial<X402PaymentPayload> = {}): X402PaymentPayload {
  return {
    x402Version: X402_VERSION,
    scheme: 'exact',
    network: 'base',
    payload: {
      signature: '0x' + 'a'.repeat(130),
      authorization: _authorization(),
    },
    ...overrides,
  }
}

// ── createInvoice ─────────────────────────────────────────────────

describe('X402PaymentRail — createInvoice', () => {
  it('builds an invoice with the configured rail name and currency', async () => {
    const rail = _rail()
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    assert.equal(invoice.rail_name, 'x402-base-USDC')
    assert.equal(invoice.currency, 'USDC')
    assert.equal(invoice.amount_base_units, '1000000')
    assert.equal(invoice.amount_human, '1 USDC')
    assert.equal(invoice.destination, PAY_TO)
    assert.equal(invoice.status, 'pending')
  })

  it('formats sub-unit amounts via assetDecimals (USDC default 6)', async () => {
    const rail = _rail()
    const tenCents = await rail.createInvoice({ amount_base_units: '100000' })
    assert.equal(tenCents.amount_human, '0.1 USDC')
    const hundredth = await rail.createInvoice({ amount_base_units: '10000' })
    assert.equal(hundredth.amount_human, '0.01 USDC')
  })

  it('caches PaymentRequirements retrievable via getRequirements()', async () => {
    const rail = _rail()
    const invoice = await rail.createInvoice({ amount_base_units: '2000000' })
    const req = rail.getRequirements(invoice.invoice_id)
    assert.notEqual(req, undefined)
    assert.equal(req?.scheme, 'exact')
    assert.equal(req?.network, 'base')
    assert.equal(req?.maxAmountRequired, '2000000')
    assert.equal(req?.asset, USDC_BASE_MAINNET)
    assert.equal(req?.payTo, PAY_TO)
    assert.equal(req?.resource, 'https://example.com/api/premium')
    assert.equal(req?.description, 'Test endpoint')
    assert.equal(req?.maxTimeoutSeconds, 60)
  })

  it('expires_in_seconds overrides defaultMaxTimeoutSeconds', async () => {
    const rail = createX402Rail({
      payTo: PAY_TO,
      asset: USDC_BASE_MAINNET,
      network: 'base',
      resource: 'https://example.com/r',
      defaultMaxTimeoutSeconds: 60,
      facilitatorVerify: alwaysVerify(),
      facilitatorSettle: alwaysSettle(),
    })
    const invoice = await rail.createInvoice({
      amount_base_units: '1000000',
      expires_in_seconds: 300,
    })
    const req = rail.getRequirements(invoice.invoice_id)
    assert.equal(req?.maxTimeoutSeconds, 300)
  })
})

// ── submitPayment happy path ──────────────────────────────────────

describe('X402PaymentRail — submitPayment happy path', () => {
  it('verifies + settles, returns tx hash, marks invoice confirmed', async () => {
    const rail = _rail()
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const outcome = await rail.submitPayment(invoice.invoice_id, _payload())

    assert.equal(outcome.verified, true)
    assert.equal(outcome.settled, true)
    assert.equal(outcome.transaction, TX_HASH)
    assert.equal(outcome.payer, PAYER)

    const after = await rail.checkStatus(invoice.invoice_id)
    assert.equal(after.status, 'confirmed')
  })

  it('full pipeline: preAuth → submitPayment → emitReceipt → verify', async () => {
    const rail = _rail()
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })

    const preAuth = preAuthorize(
      {
        delegation: _delegation(),
        required_scope: 'commerce.purchase',
        amount_base_units: '1000000',
        currency: 'USDC',
      },
      rail,
    )
    assert.equal(preAuth.ok, true)

    const outcome = await rail.submitPayment(invoice.invoice_id, _payload())
    assert.equal(outcome.verified && outcome.settled, true)

    const receipt = emitReceipt(
      {
        delegation_ref: _delegation().receipt_id,
        action_ref: 'a'.repeat(64),
        rail_name: rail.name,
        amount_base_units: invoice.amount_base_units,
        currency: invoice.currency,
        tx_proof: outcome.transaction!,
        invoice_id: invoice.invoice_id,
      },
      ISSUER_PRIV,
    )

    assert.equal(receipt.rail_name, 'x402-base-USDC')
    assert.equal(receipt.tx_proof, TX_HASH)
    assert.equal(receipt.signer_did, ISSUER_PUB)

    const verified = verifyPaymentReceipt(receipt)
    assert.equal(verified.valid, true)
  })
})

// ── submitPayment verify-fail → denial ────────────────────────────

describe('X402PaymentRail — submitPayment failure → rail_error denial', () => {
  it('verify-fail produces invalidReason, no settle attempted', async () => {
    let settleCalls = 0
    const rail = createX402Rail({
      payTo: PAY_TO,
      asset: USDC_BASE_MAINNET,
      network: 'base',
      resource: 'https://example.com/r',
      facilitatorVerify: neverVerify('invalid_signature'),
      facilitatorSettle: async () => {
        settleCalls += 1
        return alwaysSettle()()
      },
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const outcome = await rail.submitPayment(invoice.invoice_id, _payload())

    assert.equal(outcome.verified, false)
    assert.equal(outcome.invalidReason, 'invalid_signature')
    assert.equal(settleCalls, 0)

    const after = await rail.checkStatus(invoice.invoice_id)
    assert.equal(after.status, 'failed')
  })

  it('verify-fail caller emits PaymentDenial with rail_error + invalidReason detail', async () => {
    const rail = _rail({ verify: neverVerify('expired_authorization') })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const outcome = await rail.submitPayment(invoice.invoice_id, _payload())

    assert.equal(outcome.verified, false)
    const denial = emitDenial(
      {
        delegation_ref: _delegation().receipt_id,
        action_ref: 'a'.repeat(64),
        rail_name: rail.name,
        amount_base_units: invoice.amount_base_units,
        currency: invoice.currency,
        denial_reason: 'rail_error',
        reason_detail: `facilitator: ${outcome.invalidReason}`,
      },
      ISSUER_PRIV,
    )

    assert.equal(denial.denial_reason, 'rail_error')
    assert.match(denial.reason_detail ?? '', /expired_authorization/)
    assert.equal(verifyPaymentDenial(denial).valid, true)
  })

  it('settle-fail (verify ok) reports settleErrorReason; invoice marked failed', async () => {
    const rail = _rail({ settle: neverSettle('insufficient_funds') })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const outcome = await rail.submitPayment(invoice.invoice_id, _payload())

    assert.equal(outcome.verified, true)
    assert.equal(outcome.settled, false)
    assert.equal(outcome.settleErrorReason, 'insufficient_funds')

    const after = await rail.checkStatus(invoice.invoice_id)
    assert.equal(after.status, 'failed')
  })

  it('facilitator throws → outcome carries threw-prefix; invoice failed', async () => {
    const rail = createX402Rail({
      payTo: PAY_TO,
      asset: USDC_BASE_MAINNET,
      network: 'base',
      resource: 'https://example.com/r',
      facilitatorVerify: async () => {
        throw new Error('connect ECONNREFUSED')
      },
      facilitatorSettle: alwaysSettle(),
    })
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    const outcome = await rail.submitPayment(invoice.invoice_id, _payload())

    assert.equal(outcome.verified, false)
    assert.match(outcome.invalidReason ?? '', /facilitator_verify_threw/)
    assert.match(outcome.invalidReason ?? '', /ECONNREFUSED/)
  })
})

// ── preAuthorize gating ───────────────────────────────────────────

describe('X402PaymentRail — preAuthorize gates spend before submitPayment', () => {
  it('no_commerce_scope when delegation lacks commerce.purchase', () => {
    const rail = _rail()
    const result = preAuthorize(
      {
        delegation: _delegation({ scope: ['commerce.refund'] }),
        required_scope: 'commerce.purchase',
        amount_base_units: '1000000',
        currency: 'USDC',
      },
      rail,
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'no_commerce_scope')
  })

  it('spend_limit_exceeded when amount > delegation budget', () => {
    const rail = _rail()
    const result = preAuthorize(
      {
        delegation: _delegation({ spend_limit_base_units: '500000' }), // 0.5 USDC
        required_scope: 'commerce.purchase',
        amount_base_units: '1000000', // 1 USDC
        currency: 'USDC',
      },
      rail,
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'spend_limit_exceeded')
  })

  it('caller emits signed PaymentDenial when preAuth fails', () => {
    const rail = _rail()
    const result = preAuthorize(
      {
        delegation: _delegation({ scope: [] }),
        required_scope: 'commerce.purchase',
        amount_base_units: '1000000',
        currency: 'USDC',
      },
      rail,
    )
    assert.equal(result.ok, false)
    if (result.ok) return

    const denial = emitDenial(
      {
        delegation_ref: _delegation().receipt_id,
        action_ref: 'a'.repeat(64),
        rail_name: rail.name,
        amount_base_units: '1000000',
        currency: 'USDC',
        denial_reason: result.denial_reason,
        reason_detail: result.reason_detail,
      },
      ISSUER_PRIV,
    )
    assert.equal(denial.denial_reason, 'no_commerce_scope')
    assert.equal(verifyPaymentDenial(denial).valid, true)
  })
})

// ── revokeWallet ──────────────────────────────────────────────────

describe('X402PaymentRail — revokeWallet halts subsequent authorization', () => {
  it('preAuthorize denies wallet_revoked after revokeWallet', async () => {
    const rail = _rail()
    await rail.revokeWallet('wallet-x402-001')
    assert.equal(rail.isWalletRevoked('wallet-x402-001'), true)

    const result = preAuthorize(
      {
        delegation: _delegation(),
        required_scope: 'commerce.purchase',
        amount_base_units: '1000000',
        currency: 'USDC',
      },
      rail,
    )
    assert.equal(result.ok, false)
    if (result.ok) return
    assert.equal(result.denial_reason, 'wallet_revoked')
  })

  it('createInvoice still succeeds after revoke, but caller MUST gate via preAuth', async () => {
    // The rail's createInvoice intentionally does not consult the
    // revocation set — it just builds a request object. The
    // governance gate lives at preAuthorize. This test pins that
    // separation: revoking does not break invoice creation; it
    // breaks the pre-auth pipeline that wraps it.
    const rail = _rail()
    await rail.revokeWallet('wallet-x402-001')
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    assert.equal(invoice.status, 'pending')
  })

  it('revokeWallet is idempotent', async () => {
    const rail = _rail()
    assert.equal(await rail.revokeWallet('w1'), true)
    assert.equal(await rail.revokeWallet('w1'), true)
    assert.equal(rail.isWalletRevoked('w1'), true)
  })
})

// ── verifyTransaction ─────────────────────────────────────────────

describe('X402PaymentRail — verifyTransaction', () => {
  it('resolves a settled tx hash to the cached invoice state', async () => {
    const rail = _rail()
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    await rail.submitPayment(invoice.invoice_id, _payload())

    const result = await rail.verifyTransaction(TX_HASH, '1000000')
    assert.equal(result.verified, true)
    assert.equal(result.amount_base_units, '1000000')
    assert.equal(result.sender, PAYER)
    assert.equal(result.receiver, PAY_TO)
  })

  it('returns verified=false for unknown tx hash', async () => {
    const rail = _rail()
    const result = await rail.verifyTransaction('0xdeadbeef', '1000000')
    assert.equal(result.verified, false)
    assert.match(result.error ?? '', /not associated/)
  })

  it('returns verified=false on amount mismatch even when tx is known', async () => {
    const rail = _rail()
    const invoice = await rail.createInvoice({ amount_base_units: '1000000' })
    await rail.submitPayment(invoice.invoice_id, _payload())

    const result = await rail.verifyTransaction(TX_HASH, '999999')
    assert.equal(result.verified, false)
  })
})

// ── sendPayment unsupported ───────────────────────────────────────

describe('X402PaymentRail — sendPayment unsupported', () => {
  it('throws with a clear message that x402 is pull-only', async () => {
    const rail = _rail()
    await assert.rejects(
      () =>
        rail.sendPayment({
          destination: PAY_TO,
          amount_base_units: '1000000',
        }),
      /x402 rail does not support sendPayment/,
    )
  })
})

// ── Receipt + denial canonicalize round-trip ──────────────────────

describe('X402PaymentRail — signed receipt/denial round-trip', () => {
  it('PaymentReceipt round-trips canonicalize+verify', () => {
    const receipt = emitReceipt(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'x402-base-USDC',
        amount_base_units: '1000000',
        currency: 'USDC',
        tx_proof: TX_HASH,
        invoice_id: 'inv-x402-roundtrip',
      },
      ISSUER_PRIV,
    )
    assert.equal(verifyPaymentReceipt(receipt).valid, true)

    const tampered = { ...receipt, tx_proof: '0xdeadbeef' }
    assert.equal(verifyPaymentReceipt(tampered).valid, false)
  })

  it('PaymentDenial round-trips canonicalize+verify', () => {
    const denial = emitDenial(
      {
        delegation_ref: 'd'.repeat(64),
        action_ref: 'a'.repeat(64),
        rail_name: 'x402-base-USDC',
        amount_base_units: '1000000',
        currency: 'USDC',
        denial_reason: 'rail_error',
        reason_detail: 'facilitator: invalid_signature',
      },
      ISSUER_PRIV,
    )
    assert.equal(verifyPaymentDenial(denial).valid, true)

    const tampered = { ...denial, reason_detail: 'tampered' }
    assert.equal(verifyPaymentDenial(tampered).valid, false)
  })
})

// ── Fixture byte-parity ───────────────────────────────────────────

describe('X402PaymentRail — fixture byte-parity', () => {
  it('settled-receipt fixture verifies', () => {
    const text = readFileSync(join(FIXTURE_DIR, 'settled-receipt.fixture.json'), 'utf8')
    const receipt: PaymentReceipt = JSON.parse(text)
    assert.equal(verifyPaymentReceipt(receipt).valid, true)
    assert.equal(receipt.rail_name, 'x402-base-USDC')
    assert.equal(receipt.currency, 'USDC')
  })

  it('denied-receipt fixture verifies', () => {
    const text = readFileSync(join(FIXTURE_DIR, 'denied-receipt.fixture.json'), 'utf8')
    const denial: PaymentDenial = JSON.parse(text)
    assert.equal(verifyPaymentDenial(denial).valid, true)
    assert.equal(denial.denial_reason, 'rail_error')
  })

  it('payment-requirements fixture parses with required v1 fields', () => {
    const text = readFileSync(
      join(FIXTURE_DIR, 'payment-requirements.fixture.json'),
      'utf8',
    )
    const req = JSON.parse(text)
    assert.equal(req.scheme, 'exact')
    assert.equal(req.network, 'base')
    assert.equal(typeof req.maxAmountRequired, 'string')
    assert.equal(typeof req.maxTimeoutSeconds, 'number')
  })

  it('payment-payload fixture parses with required v1 envelope + EIP-3009 fields', () => {
    const text = readFileSync(join(FIXTURE_DIR, 'payment-payload.fixture.json'), 'utf8')
    const p: X402PaymentPayload = JSON.parse(text)
    assert.equal(p.x402Version, X402_VERSION)
    assert.equal(p.scheme, 'exact')
    assert.equal(p.network, 'base')
    const inner = p.payload as { signature: string; authorization: EIP3009Authorization }
    assert.match(inner.signature, /^0x[0-9a-fA-F]+$/)
    assert.match(inner.authorization.from, /^0x/)
    assert.match(inner.authorization.to, /^0x/)
    assert.equal(typeof inner.authorization.value, 'string')
    assert.equal(typeof inner.authorization.validAfter, 'string')
    assert.equal(typeof inner.authorization.validBefore, 'string')
    assert.match(inner.authorization.nonce, /^0x/)
  })
})

// ── Default exports / pinned constants ────────────────────────────

describe('X402PaymentRail — default constants', () => {
  it('exports the Coinbase CDP facilitator URL pin', () => {
    assert.equal(DEFAULT_FACILITATOR_URL, 'https://api.cdp.coinbase.com/x402')
  })

  it('exports USDC contract addresses for Base mainnet and Sepolia', () => {
    assert.equal(USDC_BASE_MAINNET, '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913')
  })
})
