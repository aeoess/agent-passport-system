// ══════════════════════════════════════════════════════════════════
// Layer 7 — Agentic Commerce: Test Suite
// ══════════════════════════════════════════════════════════════════

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  createPassport,
  sign as signFn, canonicalize,
} from '../src/index.js'
import {
  commercePreflight, createCommerceDelegation,
  getSpendSummary, requestHumanApproval, verifyCommerceReceipt,
} from '../src/core/commerce.js'
import type { SignedPassport } from '../src/types/passport.js'
import type { CommerceDelegation, ACPMoney } from '../src/types/commerce.js'

function makeFixtures() {
  const { signedPassport, keyPair } = createPassport({
    agentId: 'shopper-001',
    agentName: 'ShopperAgent',
    ownerAlias: 'tima',
    mission: 'Find and purchase products within delegated budget',
    capabilities: ['commerce', 'web-search', 'product-comparison'],
    runtime: { platform: 'node', models: ['claude-sonnet-4-20250514'], toolsCount: 5, memoryType: 'session' },
    metadata: { beneficiaryPrincipalId: 'tima-principal-001' },
  })

  const delegation = createCommerceDelegation({
    agentId: 'shopper-001',
    delegationId: 'del-commerce-001',
    spendLimit: 50000,  // $500.00 in cents
    currency: 'usd',
    approvedMerchants: ['Cartsy', 'TechStore', 'BookShelf'],
    requireHumanApproval: true,
    humanApprovalThreshold: 25000,  // $250.00
  })

  return { keys: keyPair, passport: signedPassport, delegation }
}

describe('Layer 7 — Agentic Commerce', () => {

  describe('createCommerceDelegation', () => {
    it('creates a delegation with commerce scopes', () => {
      const { delegation } = makeFixtures()
      assert.ok(delegation.scope.includes('commerce:checkout'))
      assert.ok(delegation.scope.includes('commerce:browse'))
      assert.equal(delegation.spendLimit, 50000)
      assert.equal(delegation.spentAmount, 0)
      assert.equal(delegation.currency, 'usd')
      assert.deepEqual(delegation.approvedMerchants, ['Cartsy', 'TechStore', 'BookShelf'])
      assert.equal(delegation.requireHumanApproval, true)
      assert.equal(delegation.humanApprovalThreshold, 25000)
    })

    it('defaults to usd and human approval required', () => {
      const d = createCommerceDelegation({
        agentId: 'test',
        delegationId: 'del-test',
        spendLimit: 10000,
      })
      assert.equal(d.currency, 'usd')
      assert.equal(d.requireHumanApproval, true)
    })
  })

  describe('commercePreflight', () => {
    it('passes all gates when everything is valid', () => {
      const { passport, delegation } = makeFixtures()
      const result = commercePreflight({
        signedPassport: passport,
        delegation,
        merchantName: 'Cartsy',
        estimatedTotal: { amount: 2600, currency: 'usd' },
      })
      assert.equal(result.permitted, true)
      assert.equal(result.blockedReason, undefined)
      assert.ok(result.checks.every(c => c.passed))
    })

    it('blocks when agent lacks commerce scope', () => {
      const { passport } = makeFixtures()
      const badDelegation = createCommerceDelegation({
        agentId: 'shopper-001',
        delegationId: 'del-bad',
        spendLimit: 50000,
      })
      // Override scopes to remove commerce
      badDelegation.scope = ['web:search', 'web:fetch']

      const result = commercePreflight({
        signedPassport: passport,
        delegation: badDelegation,
        merchantName: 'Cartsy',
        estimatedTotal: { amount: 1000, currency: 'usd' },
      })
      assert.equal(result.permitted, false)
      assert.ok(result.blockedReason?.includes('commerce:checkout'))
    })

    it('blocks when purchase exceeds spend limit', () => {
      const { passport, delegation } = makeFixtures()
      // Set spent amount close to limit
      delegation.spentAmount = 49000

      const result = commercePreflight({
        signedPassport: passport,
        delegation,
        merchantName: 'Cartsy',
        estimatedTotal: { amount: 2000, currency: 'usd' },  // $20, only $10 remaining
      })
      assert.equal(result.permitted, false)
      assert.ok(result.blockedReason?.includes('exceeds'))
    })

    it('blocks when merchant is not on approved list', () => {
      const { passport, delegation } = makeFixtures()
      const result = commercePreflight({
        signedPassport: passport,
        delegation,
        merchantName: 'ShadyStore',
        estimatedTotal: { amount: 1000, currency: 'usd' },
      })
      assert.equal(result.permitted, false)
      assert.ok(result.blockedReason?.includes('NOT on approved list'))
    })

    it('warns when human approval threshold exceeded', () => {
      const { passport, delegation } = makeFixtures()
      const result = commercePreflight({
        signedPassport: passport,
        delegation,
        merchantName: 'TechStore',
        estimatedTotal: { amount: 30000, currency: 'usd' },  // $300 > $250 threshold
      })
      // Still permitted at preflight, but with warnings
      assert.equal(result.permitted, true)
      assert.ok(result.warnings.length > 0)
      assert.ok(result.warnings[0].includes('approval threshold'))
    })

    it('passes with commerce:* wildcard scope', () => {
      const { passport } = makeFixtures()
      const wildcardDelegation = createCommerceDelegation({
        agentId: 'shopper-001',
        delegationId: 'del-wildcard',
        spendLimit: 100000,
      })
      wildcardDelegation.scope = ['commerce:*']

      const result = commercePreflight({
        signedPassport: passport,
        delegation: wildcardDelegation,
        merchantName: 'AnyStore',
        estimatedTotal: { amount: 5000, currency: 'usd' },
      })
      assert.equal(result.permitted, true)
    })
  })

  describe('getSpendSummary', () => {
    it('calculates spend analytics correctly', () => {
      const { delegation } = makeFixtures()
      delegation.spentAmount = 35000  // $350 of $500

      const summary = getSpendSummary(delegation)
      assert.equal(summary.limit, 50000)
      assert.equal(summary.spent, 35000)
      assert.equal(summary.remaining, 15000)
      assert.equal(summary.currency, 'usd')
      assert.equal(summary.utilizationPercent, 70)
      assert.equal(summary.nearLimit, false)
    })

    it('flags nearLimit at 80%+', () => {
      const { delegation } = makeFixtures()
      delegation.spentAmount = 42000  // 84%

      const summary = getSpendSummary(delegation)
      assert.equal(summary.nearLimit, true)
      assert.equal(summary.utilizationPercent, 84)
    })

    it('handles zero spend limit', () => {
      const d = createCommerceDelegation({
        agentId: 'test',
        delegationId: 'del-zero',
        spendLimit: 0,
      })
      const summary = getSpendSummary(d)
      assert.equal(summary.utilizationPercent, 0)
      assert.equal(summary.remaining, 0)
    })
  })

  describe('requestHumanApproval', () => {
    it('creates a pending approval request', () => {
      const request = requestHumanApproval({
        agentId: 'shopper-001',
        delegationId: 'del-commerce-001',
        merchantName: 'TechStore',
        items: [{
          id: 'item-1', skuId: 'sku-laptop-001', name: 'Laptop Stand',
          quantity: 1,
          unitPrice: { amount: 5125, currency: 'usd' },
          totalPrice: { amount: 5125, currency: 'usd' },
        }],
        totalAmount: { amount: 30000, currency: 'usd' },
        reason: 'Purchase exceeds human approval threshold of $250.00',
        expiresInMinutes: 15,
      })

      assert.ok(request.requestId.startsWith('approval-'))
      assert.equal(request.status, 'pending')
      assert.equal(request.agentId, 'shopper-001')
      assert.equal(request.merchantName, 'TechStore')
      assert.equal(request.totalAmount.amount, 30000)
      assert.ok(new Date(request.expiresAt) > new Date(request.createdAt))
    })

    it('defaults to 30 minute expiry', () => {
      const request = requestHumanApproval({
        agentId: 'test',
        delegationId: 'del-test',
        merchantName: 'Store',
        items: [],
        totalAmount: { amount: 1000, currency: 'usd' },
        reason: 'test',
      })
      const created = new Date(request.createdAt).getTime()
      const expires = new Date(request.expiresAt).getTime()
      const diffMinutes = (expires - created) / (60 * 1000)
      assert.equal(diffMinutes, 30)
    })
  })

  describe('verifyCommerceReceipt', () => {
    it('verifies a valid receipt signature', () => {
      const { keys } = makeFixtures()

      const receiptData = {
        receiptId: 'rcpt-commerce-test123',
        version: '1.0',
        timestamp: new Date().toISOString(),
        agentId: 'shopper-001',
        delegationId: 'del-commerce-001',
        action: {
          type: 'commerce:complete_checkout' as const,
          target: 'https://cartsy.com/checkout_sessions/cs-123/complete',
          method: 'POST',
          scopeUsed: 'commerce:checkout',
          spend: { amount: 2600, currency: 'usd' },
        },
        checkout: {
          sessionId: 'cs-123',
          merchantName: 'Cartsy',
          items: [{ skuId: 'sku-shirt-001', name: 'Deluxe Shirt', quantity: 1, unitPrice: 2600 }],
          totalAmount: 2600,
          totalCurrency: 'usd',
          status: 'completed',
        },
        delegationChain: [keys.publicKey],
        beneficiary: 'tima-principal-001',
      }

      const sig = signFn(canonicalize(receiptData), keys.privateKey)
      const receipt = { ...receiptData, signature: sig }

      const result = verifyCommerceReceipt(receipt, keys.publicKey)
      assert.equal(result.valid, true)
      assert.equal(result.errors.length, 0)
    })

    it('rejects a tampered receipt', () => {
      const { keys } = makeFixtures()

      const receiptData = {
        receiptId: 'rcpt-commerce-tampered',
        version: '1.0',
        timestamp: new Date().toISOString(),
        agentId: 'shopper-001',
        delegationId: 'del-commerce-001',
        action: {
          type: 'commerce:complete_checkout' as const,
          target: 'https://cartsy.com/checkout_sessions/cs-456/complete',
          method: 'POST',
          scopeUsed: 'commerce:checkout',
          spend: { amount: 2600, currency: 'usd' },
        },
        checkout: {
          sessionId: 'cs-456',
          merchantName: 'Cartsy',
          items: [{ skuId: 'sku-1', name: 'Item', quantity: 1, unitPrice: 2600 }],
          totalAmount: 2600,
          totalCurrency: 'usd',
          status: 'completed',
        },
        delegationChain: [keys.publicKey],
        beneficiary: 'tima-principal-001',
      }

      const sig = signFn(canonicalize(receiptData), keys.privateKey)
      // Tamper with the amount after signing
      const tampered = { ...receiptData, signature: sig }
      tampered.action = { ...tampered.action, spend: { amount: 999999, currency: 'usd' } }

      const result = verifyCommerceReceipt(tampered, keys.publicKey)
      assert.equal(result.valid, false)
      assert.ok(result.errors.some(e => e.includes('invalid')))
    })
  })

  describe('Passport enforcement integration', () => {
    it('blocks a non-commerce agent from preflight', () => {
      // Create a research-only agent
      const { signedPassport: researchPassport } = createPassport({
        agentId: 'researcher-001',
        agentName: 'ResearchAgent',
        ownerAlias: 'tima',
        mission: 'Research only — no commerce',
        capabilities: ['web-search', 'document-analysis'],
        runtime: { platform: 'node', models: ['claude-sonnet-4-20250514'], toolsCount: 3, memoryType: 'session' },
      })

      // Give it research-only scopes
      const researchDelegation = createCommerceDelegation({
        agentId: 'researcher-001',
        delegationId: 'del-research',
        spendLimit: 0,
      })
      researchDelegation.scope = ['web:search', 'web:fetch']  // no commerce scope

      const result = commercePreflight({
        signedPassport: researchPassport,
        delegation: researchDelegation,
        merchantName: 'Cartsy',
        estimatedTotal: { amount: 100, currency: 'usd' },
      })

      assert.equal(result.permitted, false)
      assert.ok(result.blockedReason?.includes('commerce:checkout'))
    })

    it('tracks spend across multiple preflight checks', () => {
      const { passport, delegation } = makeFixtures()

      // First purchase: $100
      delegation.spentAmount = 0
      const first = commercePreflight({
        signedPassport: passport, delegation,
        merchantName: 'Cartsy',
        estimatedTotal: { amount: 10000, currency: 'usd' },
      })
      assert.equal(first.permitted, true)

      // Simulate spending
      delegation.spentAmount = 10000

      // Second purchase: $350 (would bring total to $450, under $500 limit)
      const second = commercePreflight({
        signedPassport: passport, delegation,
        merchantName: 'TechStore',
        estimatedTotal: { amount: 35000, currency: 'usd' },
      })
      assert.equal(second.permitted, true)

      // Simulate spending
      delegation.spentAmount = 45000

      // Third purchase: $100 (would bring total to $550, OVER $500 limit)
      const third = commercePreflight({
        signedPassport: passport, delegation,
        merchantName: 'BookShelf',
        estimatedTotal: { amount: 10000, currency: 'usd' },
      })
      assert.equal(third.permitted, false)
      assert.ok(third.blockedReason?.includes('exceeds'))
    })
  })
})
