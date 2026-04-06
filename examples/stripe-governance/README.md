# APS Governance Adapter for Stripe Agent Payments

**The authorization layer between your agent and Stripe.**

Stripe handles money movement. APS handles who authorized it, within what limits, and produces the audit trail. Neither replaces the other.

## The Problem

Stripe's Agent Toolkit gives agents access to payment tools. Stripe's Restricted API Keys (RAKs) control which Stripe APIs the agent can call. But RAKs don't answer:

- **Who authorized this specific agent** to make this specific purchase?
- **What's the spending ceiling** for this task, not just this API key?
- **Which merchants** is this agent allowed to transact with?
- **Does a human need to approve** transactions above a threshold?
- **Can we trace** this payment back to the human principal who delegated authority?

APS commerce delegation answers all five.

## How It Works

```
Agent wants to pay for API credits
       │
       ▼
┌─────────────────────────┐
│  APS 4-Gate Preflight   │
│                         │
│  1. Passport valid?     │  ← Agent identity (Ed25519)
│  2. Scope authorized?   │  ← Delegation includes commerce
│  3. Budget remaining?   │  ← Spend tracking per delegation
│  4. Merchant allowed?   │  ← Allowlist check
│                         │
│  All gates pass? ──────►│──── Stripe processes payment
│  Any gate fails? ──────►│──── Payment blocked, receipt emitted
└─────────────────────────┘
       │
       ▼
  Signed ActionReceipt
  (links payment → delegation → human principal)
```

## Works With

- **Stripe Agent Toolkit** — wraps LangChain/CrewAI/Vercel AI SDK tools
- **Stripe MPP** (Machine Payments Protocol) — governs agent-to-service payments
- **Stripe x402** — governs USDC micropayments on Base
- **Stripe SPTs** (Shared Payment Tokens) — governs agentic network tokens

## Quick Start

```bash
npm install agent-passport-system
```

```typescript
import { governMPPPayment } from './stripe-governance-adapter'
import { generateKeys, issuePassport, createCommerceDelegation } from 'agent-passport-system'

// Human principal sets up agent with commerce authority
const delegation = createCommerceDelegation({
  delegatorKeys: humanKeys,
  agentPublicKey: agentKeys.publicKey,
  spendLimit: 50000,                    // $500.00
  currency: 'usd',
  allowedMerchants: ['api.openai.com'], // only approved vendors
  requireHumanApproval: true,
  humanApprovalThreshold: 10000,        // human approves above $100
})

// Agent receives MPP payment request from a service
const result = await governMPPPayment(config, {
  amount: 4999,
  currency: 'usd',
  merchant: 'api.openai.com',
  resource: 'GPT-4 API credits',
  paymentMethod: 'spt',
})

// result.authorized === true
// result.receipt links this payment to the delegation chain
// result.remainingBudget === 45001 ($450.01)
```

## Integration with Stripe Agent Toolkit

```typescript
import { createStripeAgentToolkit } from '@stripe/agent-toolkit/langchain'
import { governStripeTools } from './stripe-governance-adapter'

// Standard Stripe setup
const toolkit = await createStripeAgentToolkit({
  secretKey: process.env.STRIPE_SECRET_KEY
})

// Wrap with APS governance
const governedTools = governStripeTools(toolkit.getTools(), {
  passport: agentPassport,
  delegation: commerceDelegation,
  onHumanApprovalRequired: async (request) => {
    // Send Slack notification, wait for human response
    return await notifyHumanViaSlack(request)
  },
  onReceipt: (receipt) => {
    // Log to your audit system
    await auditLogger.log(receipt)
  },
})

// Use governedTools with your LangChain agent
// Every payment tool call goes through APS preflight first
```

## Financial Observability

```typescript
import { getAgentBudgetStatus } from './stripe-governance-adapter'

const status = getAgentBudgetStatus(config)
// {
//   agentId: 'agent-procurement-abc123',
//   spendLimit: 500.00,
//   spentAmount: 249.99,
//   remainingBudget: 250.01,
//   utilizationPercent: 49.99,
//   humanApprovalThreshold: 100.00,
//   approvedMerchants: ['api.openai.com', 'vercel.com']
// }
```

## Run the Demo

```bash
npx tsx examples/stripe-governance/demo.ts
```

Shows four scenarios: auto-approved payment, human-approval-required payment, unauthorized merchant (blocked), and budget exhaustion (blocked).

## Architecture

APS provides the **authorization layer**. Stripe provides the **settlement layer**.

| Concern | Who Handles It |
|---------|---------------|
| Agent identity | APS (Ed25519 passport) |
| Spend authorization | APS (commerce delegation) |
| Merchant allowlisting | APS (delegation scope) |
| Human escalation | APS (approval threshold) |
| Audit trail | APS (signed receipts) |
| Money movement | Stripe (MPP/SPT/x402) |
| Payment processing | Stripe (PaymentIntents API) |
| Fraud detection | Stripe (Radar) |
| Tax calculation | Stripe (Tax) |

## License

Apache-2.0. Part of the [Agent Passport System](https://github.com/aeoess/agent-passport-system).
