// ══════════════════════════════════════════════════════════════════
// Layer 7 — Agentic Commerce: SDK Primitive Tests
// ══════════════════════════════════════════════════════════════════
// commercePreflight + ACP fetch wrapper tests moved to gateway
// (test/sdk-migrated/core/commerce-preflight.test.ts) along with the
// orchestrator implementation. SDK keeps gate predicates and signing.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createPassport,
  sign as signFn, canonicalize,
} from '../src/index.js'
import {
  createCommerceDelegation,
  getSpendSummary, requestHumanApproval, verifyCommerceReceipt,
  checkPassportGate, checkScopeGate, checkSpendGate,
  checkHumanApprovalThreshold, checkMerchantGate,
  hasCommerceScope, commercePreflight,
} from '../src/core/commerce.js'

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
    spendLimit: 50000,
    currency: 'usd',
    approvedMerchants: ['Cartsy', 'TechStore', 'BookShelf'],
    requireHumanApproval: true,
    humanApprovalThreshold: 25000,
  })

  return { keys: keyPair, passport: signedPassport, delegation }
}

describe('Layer 7 — Commerce Primitives', () => {

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

  describe('gate predicates', () => {
    it('checkPassportGate passes for valid passport', () => {
      const { passport } = makeFixtures()
      const c = checkPassportGate(passport)
      assert.equal(c.check, 'passport_valid')
      assert.equal(c.passed, true)
    })

    it('checkScopeGate passes when delegation has commerce:checkout', () => {
      const { delegation } = makeFixtures()
      const c = checkScopeGate(delegation)
      assert.equal(c.check, 'delegation_scope')
      assert.equal(c.passed, true)
    })

    it('checkScopeGate fails when delegation lacks commerce:checkout', () => {
      const { delegation } = makeFixtures()
      delegation.scope = ['web:search']
      const c = checkScopeGate(delegation)
      assert.equal(c.passed, false)
      assert.ok(c.detail.includes('commerce:checkout'))
    })

    it('checkSpendGate enforces remaining budget', () => {
      const { delegation } = makeFixtures()
      delegation.spentAmount = 49000
      const ok = checkSpendGate(delegation, { amount: 500, currency: 'usd' })
      const blocked = checkSpendGate(delegation, { amount: 5000, currency: 'usd' })
      assert.equal(ok.passed, true)
      assert.equal(blocked.passed, false)
      assert.ok(blocked.detail.includes('exceeds'))
    })

    it('checkHumanApprovalThreshold returns warning when total exceeds threshold', () => {
      const { delegation } = makeFixtures()
      const warning = checkHumanApprovalThreshold(delegation, { amount: 30000, currency: 'usd' })
      const noWarning = checkHumanApprovalThreshold(delegation, { amount: 10000, currency: 'usd' })
      assert.ok(warning && warning.includes('approval threshold'))
      assert.equal(noWarning, null)
    })

    it('checkMerchantGate enforces allowlist when configured', () => {
      const { delegation } = makeFixtures()
      const ok = checkMerchantGate(delegation, 'Cartsy')
      const blocked = checkMerchantGate(delegation, 'ShadyStore')
      assert.equal(ok!.passed, true)
      assert.equal(blocked!.passed, false)
    })

    it('checkMerchantGate returns null when no allowlist configured', () => {
      const open = createCommerceDelegation({ agentId: 'a', delegationId: 'd', spendLimit: 1000 })
      assert.equal(checkMerchantGate(open, 'AnyStore'), null)
    })

    it('hasCommerceScope honors wildcards', () => {
      const wild = createCommerceDelegation({ agentId: 'a', delegationId: 'd', spendLimit: 1000 })
      wild.scope = ['commerce:*']
      assert.equal(hasCommerceScope(wild, 'commerce:checkout'), true)
    })
  })

  describe('migration stubs', () => {
    it('commercePreflight throws with migration message', () => {
      assert.throws(() => commercePreflight({} as any), /moved to @aeoess\/gateway/)
    })
  })

  describe('getSpendSummary', () => {
    it('calculates spend analytics correctly', () => {
      const { delegation } = makeFixtures()
      delegation.spentAmount = 35000
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
      delegation.spentAmount = 42000
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
      const tampered = { ...receiptData, signature: sig }
      tampered.action = { ...tampered.action, spend: { amount: 999999, currency: 'usd' } }

      const result = verifyCommerceReceipt(tampered, keys.publicKey)
      assert.equal(result.valid, false)
      assert.ok(result.errors.some(e => e.includes('invalid')))
    })
  })
})
