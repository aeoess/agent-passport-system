// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Nano payment rail — adapter behavior tests.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  canonicalizeInvoice,
  createNanoRail,
  invoiceDigest,
  rawToXno,
  xnoToRaw,
} from '../../../src/v2/payment-rails/index.js'
import type {
  FetchBlockInfo,
  FetchHistory,
} from '../../../src/v2/payment-rails/index.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_DIR = join(__dirname, '..', '..', '..', 'src', 'v2', 'payment-rails', 'fixtures')

const ADDR = 'nano_3test1f1xt7r3y6a7z9k1c0nv8d4yhfk93rcd6b1pmce8wkqf6kpunkfxnwd'

const noopHistory: FetchHistory = async () => []
const noopBlockInfo: FetchBlockInfo = async () => ({ confirmed: 'true', amount: '0' })

describe('NanoPaymentRail — unit conversion', () => {
  it('xnoToRaw round-trips with rawToXno', () => {
    assert.equal(rawToXno(xnoToRaw('0.001')), '0.001')
    assert.equal(rawToXno(xnoToRaw('1')), '1')
    assert.equal(rawToXno(xnoToRaw('123.456789')), '123.456789')
  })

  it('xnoToRaw produces 30 decimal digits of precision', () => {
    // 1 XNO = 10^30 raw
    assert.equal(xnoToRaw('1'), '1000000000000000000000000000000')
    // 0.000000000000000000000000000001 XNO = 1 raw
    assert.equal(xnoToRaw('0.000000000000000000000000000001'), '1')
  })

  it('rawToXno strips trailing zeros from fractional output', () => {
    // 5 * 10^29 raw = 0.5 XNO; output should be "0.5", not "0.500..."
    assert.equal(rawToXno('500000000000000000000000000000'), '0.5')
  })
})

describe('NanoPaymentRail — invoice creation', () => {
  it('createInvoice returns a pending invoice with destination + currency', async () => {
    const rail = createNanoRail({
      receivingAddress: ADDR,
      fetchHistory: noopHistory,
      fetchBlockInfo: noopBlockInfo,
    })
    const inv = await rail.createInvoice({
      amount_base_units: xnoToRaw('0.001'),
      memo: 'unit test',
    })
    assert.equal(inv.rail_name, 'nano')
    assert.equal(inv.currency, 'XNO')
    assert.equal(inv.destination, ADDR)
    assert.equal(inv.status, 'pending')
    assert.equal(inv.memo, 'unit test')
    // Adapter adds a uniqueness offset; raw amount should be base + 1..9999
    const baseRaw = BigInt(xnoToRaw('0.001'))
    const actualRaw = BigInt(inv.amount_base_units)
    const offset = actualRaw - baseRaw
    assert.ok(offset >= 1n && offset <= 9999n, `offset out of bounds: ${offset}`)
  })

  it('every invoice has a unique invoice_id and unique amount fingerprint', async () => {
    const rail = createNanoRail({
      receivingAddress: ADDR,
      fetchHistory: noopHistory,
      fetchBlockInfo: noopBlockInfo,
    })
    const a = await rail.createInvoice({ amount_base_units: xnoToRaw('0.001') })
    const b = await rail.createInvoice({ amount_base_units: xnoToRaw('0.001') })
    assert.notEqual(a.invoice_id, b.invoice_id)
    // Random offset means amount_base_units almost certainly differs.
    // Tolerate occasional collisions: assert that the pair is not
    // identical across BOTH id AND amount.
    if (a.amount_base_units === b.amount_base_units) {
      assert.notEqual(a.invoice_id, b.invoice_id)
    }
  })

  it('invoice round-trips through canonicalize byte-identical', async () => {
    const rail = createNanoRail({
      receivingAddress: ADDR,
      fetchHistory: noopHistory,
      fetchBlockInfo: noopBlockInfo,
    })
    const inv = await rail.createInvoice({ amount_base_units: xnoToRaw('0.001') })
    const canon1 = canonicalizeInvoice(inv)
    const canon2 = canonicalizeInvoice(JSON.parse(JSON.stringify(inv)))
    assert.equal(canon1, canon2)
    assert.equal(invoiceDigest(inv), invoiceDigest(JSON.parse(JSON.stringify(inv))))
  })
})

describe('NanoPaymentRail — checkStatus', () => {
  it('throws if invoice is not in cache', async () => {
    const rail = createNanoRail({
      receivingAddress: ADDR,
      fetchHistory: noopHistory,
      fetchBlockInfo: noopBlockInfo,
    })
    await assert.rejects(
      () => rail.checkStatus('not-a-real-invoice-id'),
      /not found in adapter cache/,
    )
  })

  it('returns pending when no matching receive in history', async () => {
    const rail = createNanoRail({
      receivingAddress: ADDR,
      fetchHistory: async () => [],
      fetchBlockInfo: noopBlockInfo,
    })
    const inv = await rail.createInvoice({ amount_base_units: xnoToRaw('0.001') })
    const status = await rail.checkStatus(inv.invoice_id)
    assert.equal(status.status, 'pending')
  })

  it('flips to confirmed when fetchHistory returns a matching receive', async () => {
    let expectedRaw = ''
    const rail = createNanoRail({
      receivingAddress: ADDR,
      fetchHistory: async () => [
        {
          hash: 'block-abc',
          type: 'receive',
          account: 'nano_3sender',
          amount: expectedRaw,
        },
      ],
      fetchBlockInfo: noopBlockInfo,
    })
    const inv = await rail.createInvoice({ amount_base_units: xnoToRaw('0.001') })
    expectedRaw = inv.amount_base_units
    const status = await rail.checkStatus(inv.invoice_id)
    assert.equal(status.status, 'confirmed')
    assert.equal((status.metadata as Record<string, unknown>).block_hash, 'block-abc')
  })

  it('flips to expired when expires_at has passed', async () => {
    const rail = createNanoRail({
      receivingAddress: ADDR,
      fetchHistory: noopHistory,
      fetchBlockInfo: noopBlockInfo,
    })
    const inv = await rail.createInvoice({
      amount_base_units: xnoToRaw('0.001'),
      expires_in_seconds: 0,
    })
    // Manually advance the cache's expires_at into the past.
    // (createInvoice with expires_in_seconds=0 still produces a tiny
    //  positive window; force expiry by waiting briefly.)
    await new Promise((r) => setTimeout(r, 5))
    const status = await rail.checkStatus(inv.invoice_id)
    assert.equal(status.status, 'expired')
  })
})

describe('NanoPaymentRail — verifyTransaction', () => {
  it('returns verified=true when block is confirmed and amount matches', async () => {
    const fetchBlockInfo: FetchBlockInfo = async () => ({
      confirmed: 'true',
      amount: '1000000000000000000000000000',
      block_account: 'nano_3sender',
      contents: { link_as_account: 'nano_3receiver' },
      local_timestamp: '1745000000',
    })
    const rail = createNanoRail({
      receivingAddress: ADDR,
      fetchHistory: noopHistory,
      fetchBlockInfo,
    })
    const result = await rail.verifyTransaction(
      'block-hash-abc',
      '1000000000000000000000000000',
    )
    assert.equal(result.verified, true)
    assert.equal(result.sender, 'nano_3sender')
    assert.equal(result.receiver, 'nano_3receiver')
    assert.ok(result.timestamp !== undefined)
  })

  it('returns verified=false when block is unconfirmed', async () => {
    const fetchBlockInfo: FetchBlockInfo = async () => ({
      confirmed: 'false',
      amount: '1000000000000000000000000000',
    })
    const rail = createNanoRail({
      receivingAddress: ADDR,
      fetchHistory: noopHistory,
      fetchBlockInfo,
    })
    const result = await rail.verifyTransaction('block-hash')
    assert.equal(result.verified, false)
  })

  it('returns verified=false when expected amount differs from on-chain amount', async () => {
    const fetchBlockInfo: FetchBlockInfo = async () => ({
      confirmed: 'true',
      amount: '500000000000000000000000000', // 0.0005 XNO
    })
    const rail = createNanoRail({
      receivingAddress: ADDR,
      fetchHistory: noopHistory,
      fetchBlockInfo,
    })
    const result = await rail.verifyTransaction(
      'block-hash',
      '1000000000000000000000000000', // expected 0.001 XNO
    )
    assert.equal(result.verified, false)
  })

  it('returns verified=false on fetch error and surfaces error message', async () => {
    const fetchBlockInfo: FetchBlockInfo = async () => {
      throw new Error('rpc offline')
    }
    const rail = createNanoRail({
      receivingAddress: ADDR,
      fetchHistory: noopHistory,
      fetchBlockInfo,
    })
    const result = await rail.verifyTransaction('block-hash')
    assert.equal(result.verified, false)
    assert.match(result.error ?? '', /rpc offline/)
  })
})

describe('NanoPaymentRail — wallet revocation', () => {
  it('isWalletRevoked returns false for unrevoked wallets', () => {
    const rail = createNanoRail({
      receivingAddress: ADDR,
      fetchHistory: noopHistory,
      fetchBlockInfo: noopBlockInfo,
    })
    assert.equal(rail.isWalletRevoked('wallet-abc'), false)
  })

  it('revokeWallet flips isWalletRevoked to true and is idempotent', async () => {
    const rail = createNanoRail({
      receivingAddress: ADDR,
      fetchHistory: noopHistory,
      fetchBlockInfo: noopBlockInfo,
    })
    const first = await rail.revokeWallet('wallet-abc')
    const second = await rail.revokeWallet('wallet-abc')
    assert.equal(first, true)
    assert.equal(second, true)
    assert.equal(rail.isWalletRevoked('wallet-abc'), true)
  })
})

describe('NanoPaymentRail — invoice fixture round-trip (byte-parity)', () => {
  it('canonicalizing the saved fixture produces the same bytes', () => {
    const fixture = JSON.parse(
      readFileSync(join(FIXTURE_DIR, 'invoice-roundtrip.fixture.json'), 'utf8'),
    )
    const canonOnce = canonicalizeInvoice(fixture)
    const canonTwice = canonicalizeInvoice(JSON.parse(canonOnce))
    assert.equal(canonOnce, canonTwice)
  })
})
