// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// SDK side: only the pure key derivation. The "commercePreflight with
// idempotency" describe block moved to gateway commerce-preflight.test.ts
// alongside the orchestrator implementation.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  computeIdempotencyKey, computeActionRef,
} from '../src/index.js'

describe('computeIdempotencyKey', () => {
  it('same inputs produce same idempotency key', () => {
    const params = { agentId: 'agent-1', scope: 'commerce:checkout', target: 'https://shop.example/checkout', amount: { amount: 5000, currency: 'usd' } }
    const key1 = computeIdempotencyKey(params)
    const key2 = computeIdempotencyKey(params)
    assert.equal(key1, key2)
    assert.equal(key1.length, 64)
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
    const ref1 = computeActionRef({ agentId: 'agent-1', action: { type: 'commerce:checkout', scopeRequired: 'commerce:checkout' }, createdAt: '2026-04-01T00:00:00Z' })
    const ref2 = computeActionRef({ agentId: 'agent-1', action: { type: 'commerce:checkout', scopeRequired: 'commerce:checkout' }, createdAt: '2026-04-01T00:01:00Z' })

    const key2 = computeIdempotencyKey(params)
    assert.equal(key1, key2)
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
