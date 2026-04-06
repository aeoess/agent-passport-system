// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Tests for @aeoess/stripe-governance

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createPassport,
  createCommerceDelegation,
} from 'agent-passport-system'

import {
  governMPPPayment,
  getAgentBudgetStatus,
  type GovernedStripeConfig,
  type StripeGovernanceReceipt,
} from '../src/index.js'

function makeConfig(overrides?: Partial<GovernedStripeConfig>): GovernedStripeConfig {
  const { signedPassport } = createPassport({
    agentId: 'agent-stripe-test-001',
    agentName: 'Stripe Test Agent',
    ownerAlias: 'tima',
    mission: 'Test stripe governance adapter',
    capabilities: ['commerce'],
    runtime: { platform: 'node', version: process.version },
  })

  const delegation = createCommerceDelegation({
    agentId: signedPassport.passport.agentId,
    delegationId: 'del-stripe-test-001',
    spendLimit: 50000,
    currency: 'usd',
    approvedMerchants: ['api.openai.com', 'browserbase.com', 'vercel.com'],
    requireHumanApproval: true,
    humanApprovalThreshold: 10000,
  })

  return {
    passport: signedPassport,
    delegation,
    ...overrides,
  }
}

describe('@aeoess/stripe-governance', () => {
  describe('MPP Payment — auto-approved', () => {
    it('permits payment within budget and approved merchant', async () => {
      const receipts: StripeGovernanceReceipt[] = []
      const config = makeConfig({ onReceipt: (r) => receipts.push(r) })

      const result = await governMPPPayment(config, {
        amount: 4999, currency: 'usd',
        merchant: 'api.openai.com',
        resource: 'GPT-4 API credits',
        paymentMethod: 'spt',
      })

      assert.equal(result.authorized, true)
      assert.ok(result.receipt)
      assert.equal(result.receipt!.action, 'mpp_payment')
      assert.equal(receipts.length, 1)
      assert.ok(result.remainingBudget > 0)
    })
  })

  describe('MPP Payment — human approval', () => {
    it('calls onHumanApprovalRequired for large transactions', async () => {
      let approvalCalled = false
      const config = makeConfig({
        onHumanApprovalRequired: async () => {
          approvalCalled = true
          return true
        },
      })

      const result = await governMPPPayment(config, {
        amount: 20000, currency: 'usd',
        merchant: 'browserbase.com',
        resource: 'Browser sessions',
        paymentMethod: 'x402',
      })

      assert.equal(result.authorized, true)
      assert.equal(approvalCalled, true)
    })

    it('denies when human declines', async () => {
      const config = makeConfig({
        onHumanApprovalRequired: async () => false,
      })

      const result = await governMPPPayment(config, {
        amount: 20000, currency: 'usd',
        merchant: 'browserbase.com',
        resource: 'Browser sessions',
        paymentMethod: 'x402',
      })

      assert.equal(result.authorized, false)
      assert.ok(result.error?.includes('declined'))
    })
  })

  describe('MPP Payment — merchant block', () => {
    it('blocks unauthorized merchant', async () => {
      const config = makeConfig()

      const result = await governMPPPayment(config, {
        amount: 1500, currency: 'usd',
        merchant: 'sketchy-gpu-rental.io',
        resource: 'GPU compute',
        paymentMethod: 'card',
      })

      assert.equal(result.authorized, false)
      assert.ok(result.error)
    })
  })

  describe('MPP Payment — budget block', () => {
    it('blocks transaction exceeding remaining budget', async () => {
      const config = makeConfig()
      // Spend most of the budget first
      config.delegation.spentAmount = 48000

      const result = await governMPPPayment(config, {
        amount: 5000, currency: 'usd',
        merchant: 'api.openai.com',
        resource: 'API credits',
        paymentMethod: 'spt',
      })

      assert.equal(result.authorized, false)
      assert.ok(result.error)
    })
  })

  describe('Budget status', () => {
    it('returns correct budget summary', () => {
      const config = makeConfig()
      config.delegation.spentAmount = 12500

      const status = getAgentBudgetStatus(config)
      assert.equal(status.agentId, 'agent-stripe-test-001')
      assert.equal(status.spendLimit, 500)
      assert.equal(status.spentAmount, 125)
      assert.equal(status.remainingBudget, 375)
      assert.equal(status.utilizationPercent, 25)
      assert.deepStrictEqual(status.approvedMerchants, ['api.openai.com', 'browserbase.com', 'vercel.com'])
    })
  })
})
