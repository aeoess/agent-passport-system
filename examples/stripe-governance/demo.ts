/**
 * Demo: APS Governance + Stripe Agent Payments
 * Run: npx tsx examples/stripe-governance/demo.ts
 */

import {
  createPassport,
  createCommerceDelegation,
} from 'agent-passport-system'

import {
  governMPPPayment,
  getAgentBudgetStatus,
  type GovernedStripeConfig,
} from './stripe-governance-adapter.js'

async function main() {
  const { signedPassport } = createPassport({
    agentId: 'agent-procurement-001',
    agentName: 'procurement-agent',
    ownerAlias: 'tima',
    mission: 'Purchase API credits and infrastructure services',
    capabilities: ['commerce', 'api_provisioning'],
    runtime: { platform: 'node', version: process.version },
  })

  const delegation = createCommerceDelegation({
    agentId: signedPassport.passport.agentId,
    delegationId: 'del-commerce-001',
    spendLimit: 50000,
    currency: 'usd',
    approvedMerchants: ['api.openai.com', 'browserbase.com', 'vercel.com'],
    requireHumanApproval: true,
    humanApprovalThreshold: 10000,
  })

  const config: GovernedStripeConfig = {
    passport: signedPassport,
    delegation,
    verbose: true,
    onHumanApprovalRequired: async (request) => {
      console.log('\n  [HUMAN APPROVAL REQUIRED]')
      console.log(`    Agent: ${request.agentId}`)
      console.log(`    Amount: $${request.totalAmount.amount / 100} ${request.totalAmount.currency}`)
      console.log(`    Merchant: ${request.merchantName}`)
      return true
    },
    onReceipt: (receipt) => {
      console.log(`  [RECEIPT] ${receipt.receiptId} — $${(receipt as any).amount?.amount / 100 || '?'}`)
    },
  }

  console.log('═══ APS + Stripe Governance Demo ═══\n')

  console.log('1. API credits ($49.99, auto-approved)')
  const r1 = await governMPPPayment(config, {
    amount: 4999, currency: 'usd',
    merchant: 'api.openai.com',
    resource: 'GPT-4 API credits (100K tokens)',
    paymentMethod: 'spt',
  })
  console.log(`   → ${r1.authorized ? '✓ Authorized' : '✗ Denied: ' + r1.error}\n`)

  console.log('2. Browser infra ($200, needs human approval)')
  const r2 = await governMPPPayment(config, {
    amount: 20000, currency: 'usd',
    merchant: 'browserbase.com',
    resource: 'Headless browser sessions (1000)',
    paymentMethod: 'x402',
  })
  console.log(`   → ${r2.authorized ? '✓ Authorized' : '✗ Denied: ' + r2.error}\n`)

  console.log('3. Unauthorized merchant (should block)')
  const r3 = await governMPPPayment(config, {
    amount: 1500, currency: 'usd',
    merchant: 'sketchy-gpu-rental.io',
    resource: 'GPU compute hours',
    paymentMethod: 'card',
  })
  console.log(`   → ${r3.authorized ? '✓ Authorized' : '✗ Denied: ' + r3.error}\n`)

  console.log('4. Exceeds remaining budget (should block)')
  const r4 = await governMPPPayment(config, {
    amount: 30000, currency: 'usd',
    merchant: 'vercel.com',
    resource: 'Pro plan upgrade (annual)',
    paymentMethod: 'spt',
  })
  console.log(`   → ${r4.authorized ? '✓ Authorized' : '✗ Denied: ' + r4.error}\n`)

  console.log('═══ Budget Status ═══')
  const s = getAgentBudgetStatus(config)
  console.log(`  Spent: $${s.spentAmount} / $${s.spendLimit} (${s.utilizationPercent}%)`)
  console.log(`  Remaining: $${s.remainingBudget}`)
  console.log(`  Merchants: ${JSON.stringify(s.approvedMerchants)}`)
}

main().catch(console.error)
