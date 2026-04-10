// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createPassport,
  computeIdempotencyKey, computeActionRef,
  commercePreflight, createCommerceDelegation,
} from '../src/index.js'
import type { IdempotencyStore, CommercePreflightResult } from '../src/index.js'

function makePassport() {
  const { signedPassport } = createPassport({
    agentId: `agent-idemp-${Date.now()}`,
    agentName: 'Idempotency Test Agent',
    ownerAlias: 'test',
    mission: 'Test idempotency',
    capabilities: ['commerce'],
    runtime: { platform: 'node', models: ['test'], toolsCount: 1, memoryType: 'session' },
  })
  return signedPassport
}

function makeDelegation(agentId: string) {
  return createCommerceDelegation({
    agentId,
    delegationId: `del-idemp-${Date.now()}`,
    spendLimit: 100000,
    currency: 'usd',
    approvedMerchants: ['TestMerchant'],
  })
}

function makeInMemoryStore(): IdempotencyStore & { _entries: Map<string, { receiptId: string; recordedAt: number }> } {
  const entries = new Map<string, { receiptId: string; recordedAt: number }>()
  return {
    _entries: entries,
    async check(key: string, windowSeconds: number) {
      const entry = entries.get(key)
      if (!entry) return { duplicate: false }
      const age = (Date.now() - entry.recordedAt) / 1000
      if (age > windowSeconds) return { duplicate: false }
      return { duplicate: true, existingReceiptId: entry.receiptId }
    },
    async record(key: string, receiptId: string) {
      entries.set(key, { receiptId, recordedAt: Date.now() })
    },
  }
}

describe('computeIdempotencyKey', () => {
  it('same inputs produce same idempotency key', () => {
    const params = { agentId: 'agent-1', scope: 'commerce:checkout', target: 'https://shop.example/checkout', amount: { amount: 5000, currency: 'usd' } }
    const key1 = computeIdempotencyKey(params)
    const key2 = computeIdempotencyKey(params)
    assert.equal(key1, key2)
    assert.equal(key1.length, 64) // SHA-256 hex
  })

  it('different amounts produce different keys', () => {
    const base = { agentId: 'agent-1', scope: 'commerce:checkout', target: 'https://shop.example/checkout' }
    const key1 = computeIdempotencyKey({ ...base, amount: { amount: 5000, currency: 'usd' } })
    const key2 = computeIdempotencyKey({ ...base, amount: { amount: 7500, currency: 'usd' } })
    assert.notEqual(key1, key2)
  })

  it('different agents produce different keys', () => {
    const base = { scope: 'commerce:checkout', target: 'https://shop.example/checkout', amount: { amount: 5000, currency: 'usd' } }
    const key1 = computeIdempotencyKey({ ...base, agentId: 'agent-1' })
    const key2 = computeIdempotencyKey({ ...base, agentId: 'agent-2' })
    assert.notEqual(key1, key2)
  })

  it('same inputs at different times produce SAME key (contrast with action_ref)', () => {
    const params = { agentId: 'agent-1', scope: 'commerce:checkout', target: 'https://shop.example/checkout', amount: { amount: 5000, currency: 'usd' } }

    const key1 = computeIdempotencyKey(params)
    // Simulate "different time" by computing action_ref with different timestamps
    const ref1 = computeActionRef({ agentId: 'agent-1', action: { type: 'commerce:checkout', scopeRequired: 'commerce:checkout' }, createdAt: '2026-04-01T00:00:00Z' })
    const ref2 = computeActionRef({ agentId: 'agent-1', action: { type: 'commerce:checkout', scopeRequired: 'commerce:checkout' }, createdAt: '2026-04-01T00:01:00Z' })

    // Idempotency key is stable across time
    const key2 = computeIdempotencyKey(params)
    assert.equal(key1, key2)

    // Action refs differ with different timestamps
    assert.notEqual(ref1, ref2)
  })

  it('different currencies produce different keys', () => {
    const base = { agentId: 'agent-1', scope: 'commerce:checkout', target: 'https://shop.example/checkout' }
    const key1 = computeIdempotencyKey({ ...base, amount: { amount: 5000, currency: 'usd' } })
    const key2 = computeIdempotencyKey({ ...base, amount: { amount: 5000, currency: 'eur' } })
    assert.notEqual(key1, key2)
  })

  it('with and without amount produce different keys', () => {
    const base = { agentId: 'agent-1', scope: 'commerce:checkout', target: 'https://shop.example/checkout' }
    const key1 = computeIdempotencyKey(base)
    const key2 = computeIdempotencyKey({ ...base, amount: { amount: 5000, currency: 'usd' } })
    assert.notEqual(key1, key2)
  })

  it('different targets produce different keys', () => {
    const base = { agentId: 'agent-1', scope: 'commerce:checkout', amount: { amount: 5000, currency: 'usd' } }
    const key1 = computeIdempotencyKey({ ...base, target: 'https://shop-a.example/checkout' })
    const key2 = computeIdempotencyKey({ ...base, target: 'https://shop-b.example/checkout' })
    assert.notEqual(key1, key2)
  })
})

describe('commercePreflight with idempotency', () => {
  it('returns duplicate when idempotency store has match', async () => {
    const sp = makePassport()
    const delegation = makeDelegation(sp.passport.agentId)
    const store = makeInMemoryStore()

    const key = computeIdempotencyKey({
      agentId: sp.passport.agentId,
      scope: 'commerce:checkout',
      target: 'TestMerchant',
      amount: { amount: 2000, currency: 'usd' },
    })

    // Record a previous receipt
    await store.record(key, 'rcpt-existing-123')

    const result = await commercePreflight({
      signedPassport: sp,
      delegation,
      merchantName: 'TestMerchant',
      estimatedTotal: { amount: 2000, currency: 'usd' },
      idempotencyKey: key,
      idempotencyStore: store,
      idempotencyWindowSeconds: 300,
    }) as CommercePreflightResult

    assert.equal(result.permitted, false)
    assert.equal(result.existingReceiptId, 'rcpt-existing-123')
    const idempCheck = result.checks.find(c => c.check === 'idempotency')
    assert.ok(idempCheck)
    assert.equal(idempCheck!.passed, false)
    assert.ok(idempCheck!.detail.includes('Duplicate'))
  })

  it('permits when idempotency store has no match', async () => {
    const sp = makePassport()
    const delegation = makeDelegation(sp.passport.agentId)
    const store = makeInMemoryStore()

    const key = computeIdempotencyKey({
      agentId: sp.passport.agentId,
      scope: 'commerce:checkout',
      target: 'TestMerchant',
      amount: { amount: 2000, currency: 'usd' },
    })

    const result = await commercePreflight({
      signedPassport: sp,
      delegation,
      merchantName: 'TestMerchant',
      estimatedTotal: { amount: 2000, currency: 'usd' },
      idempotencyKey: key,
      idempotencyStore: store,
      idempotencyWindowSeconds: 300,
    }) as CommercePreflightResult

    assert.equal(result.permitted, true)
    const idempCheck = result.checks.find(c => c.check === 'idempotency')
    assert.ok(idempCheck)
    assert.equal(idempCheck!.passed, true)
  })

  it('without idempotency key works exactly as before (backward compat)', () => {
    const sp = makePassport()
    const delegation = makeDelegation(sp.passport.agentId)

    const result = commercePreflight({
      signedPassport: sp,
      delegation,
      merchantName: 'TestMerchant',
      estimatedTotal: { amount: 2000, currency: 'usd' },
    }) as CommercePreflightResult

    // Synchronous return, no idempotency check in checks
    assert.equal(result.permitted, true)
    assert.ok(!result.checks.some(c => c.check === 'idempotency'))
  })

  it('window expiry: key recorded, window passes, same key is allowed again', async () => {
    const sp = makePassport()
    const delegation = makeDelegation(sp.passport.agentId)
    const store = makeInMemoryStore()

    const key = computeIdempotencyKey({
      agentId: sp.passport.agentId,
      scope: 'commerce:checkout',
      target: 'TestMerchant',
      amount: { amount: 2000, currency: 'usd' },
    })

    // Record with timestamp in the past (beyond window)
    store._entries.set(key, { receiptId: 'rcpt-old', recordedAt: Date.now() - 400_000 })

    const result = await commercePreflight({
      signedPassport: sp,
      delegation,
      merchantName: 'TestMerchant',
      estimatedTotal: { amount: 2000, currency: 'usd' },
      idempotencyKey: key,
      idempotencyStore: store,
      idempotencyWindowSeconds: 300,
    }) as CommercePreflightResult

    assert.equal(result.permitted, true)
    const idempCheck = result.checks.find(c => c.check === 'idempotency')
    assert.ok(idempCheck)
    assert.equal(idempCheck!.passed, true)
  })

  it('uses default 300s window when idempotencyWindowSeconds not specified', async () => {
    const sp = makePassport()
    const delegation = makeDelegation(sp.passport.agentId)
    const store = makeInMemoryStore()

    const key = computeIdempotencyKey({
      agentId: sp.passport.agentId,
      scope: 'commerce:checkout',
      target: 'TestMerchant',
      amount: { amount: 2000, currency: 'usd' },
    })

    await store.record(key, 'rcpt-default-window')

    const result = await commercePreflight({
      signedPassport: sp,
      delegation,
      merchantName: 'TestMerchant',
      estimatedTotal: { amount: 2000, currency: 'usd' },
      idempotencyKey: key,
      idempotencyStore: store,
      // no idempotencyWindowSeconds — should default to 300
    }) as CommercePreflightResult

    assert.equal(result.permitted, false)
    assert.equal(result.existingReceiptId, 'rcpt-default-window')
  })
})
