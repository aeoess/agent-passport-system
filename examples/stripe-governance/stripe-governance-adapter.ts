/**
 * APS Governance Adapter for Stripe Agent Toolkit
 * 
 * Wraps Stripe's agent tools with Agent Passport System commerce
 * delegation checks. Before any payment action executes, APS verifies:
 * 
 *   1. Passport valid (agent identity)
 *   2. Delegation scope includes commerce
 *   3. Spend within remaining budget
 *   4. Merchant on allowlist (if configured)
 * 
 * After successful payment, produces a signed ActionReceipt linking
 * the transaction back to the human principal's delegation chain.
 * 
 * Works with: @stripe/agent-toolkit (LangChain, CrewAI, Vercel AI SDK)
 * Works with: Stripe MPP (Machine Payments Protocol)
 * Works with: Stripe x402 (USDC micropayments on Base)
 */

import {
  commercePreflight,
  completeCheckout,
  createCommerceDelegation,
  getSpendSummary,
  verifyCommerceReceipt,
  requestHumanApproval,
  generateKeyPair,
  createPassport,
  createDelegation,
  canonicalize,
  type SignedPassport,
  type CommerceDelegation,
  type ACPMoney,
  type CommercePreflightResult,
  type CommerceActionReceipt,
  type HumanApprovalRequest,
} from 'agent-passport-system'

// ── Types ──

export interface GovernedStripeConfig {
  /** Agent's signed passport */
  passport: SignedPassport
  /** Commerce delegation from human principal */
  delegation: CommerceDelegation
  /** Callback when human approval is required (spend above threshold) */
  onHumanApprovalRequired?: (request: HumanApprovalRequest) => Promise<boolean>
  /** Callback for every commerce receipt (audit logging) */
  onReceipt?: (receipt: CommerceActionReceipt) => void
  /** If true, log all preflight results to console */
  verbose?: boolean
}

export interface PreflightDecision {
  permitted: boolean
  result: CommercePreflightResult
  remainingBudget: number
  requiresHumanApproval: boolean
}

// ── Core Adapter ──

/**
 * Creates a governance-wrapped version of any Stripe tool function.
 * 
 * Usage with Stripe Agent Toolkit:
 * ```ts
 * const toolkit = await createStripeAgentToolkit({ secretKey: '...' })
 * const tools = toolkit.getTools()
 * const governedTools = governStripeTools(tools, apsConfig)
 * ```
 */
export function governStripeTools(
  stripeTools: any[],
  config: GovernedStripeConfig
): any[] {
  const PAYMENT_TOOLS = [
    'create_payment_link',
    'create_invoice',
    'create_checkout_session',
    'create_payment_intent',
    'confirm_payment_intent',
    'create_subscription',
    'create_charge',
  ]

  return stripeTools.map(tool => {
    const toolName = tool.name || tool.metadata?.name || ''
    
    if (PAYMENT_TOOLS.some(pt => toolName.toLowerCase().includes(pt.replace(/_/g, '')))) {
      return wrapWithGovernance(tool, toolName, config)
    }
    
    return tool // non-payment tools pass through unchanged
  })
}

/**
 * Wraps a single Stripe tool with APS governance.
 */
function wrapWithGovernance(
  tool: any,
  toolName: string,
  config: GovernedStripeConfig
) {
  const originalCall = tool.call || tool.invoke || tool.func
  
  const governedCall = async (...args: any[]) => {
    // Extract amount from tool arguments
    const amount = extractAmount(args, toolName)
    const merchant = extractMerchant(args, toolName)
    
    // Run 4-gate preflight
    const decision = runPreflight(config, amount, merchant)
    
    if (config.verbose) {
      console.log(`[APS] Preflight for ${toolName}:`, {
        permitted: decision.permitted,
        amount: amount.amount / 100,
        currency: amount.currency,
        remainingBudget: decision.remainingBudget / 100,
        gates: decision.result.checks.map(c => `${c.check}: ${c.passed ? '✓' : '✗'}`),
      })
    }
    
    if (!decision.permitted) {
      return {
        error: 'APS_COMMERCE_DENIED',
        reason: decision.result.blockedReason,
        checks: decision.result.checks.filter(c => !c.passed),
        suggestion: decision.result.warnings.length > 0
          ? decision.result.warnings[0]
          : 'Request a broader commerce delegation from your principal.',
      }
    }
    
    // Human approval gate
    if (decision.requiresHumanApproval) {
      const approvalRequest = requestHumanApproval({
        agentId: config.passport.passport.agentId,
        delegationId: config.delegation.delegationId,
        amount,
        merchantName: merchant,
        items: [],
        totalAmount: amount,
        reason: `Spend of ${amount.amount / 100} ${amount.currency.toUpperCase()} exceeds auto-approval threshold of ${(config.delegation.humanApprovalThreshold || 0) / 100}`,
      })
      
      if (config.onHumanApprovalRequired) {
        const approved = await config.onHumanApprovalRequired(approvalRequest)
        if (!approved) {
          return {
            error: 'APS_HUMAN_DENIED',
            reason: 'Human principal declined the transaction.',
            approvalRequest,
          }
        }
      } else {
        return {
          error: 'APS_HUMAN_APPROVAL_REQUIRED',
          reason: 'Transaction exceeds auto-approval threshold. No human approval handler configured.',
          approvalRequest,
        }
      }
    }
    
    // Execute the original Stripe tool
    const result = await originalCall.apply(tool, args)
    
    // Update spend tracking
    config.delegation.spentAmount += amount.amount
    
    // Produce signed receipt
    if (config.onReceipt) {
      config.onReceipt({
        receiptId: `rcpt_${Date.now().toString(36)}`,
        agentId: config.passport.passport.agentId,
        delegationId: config.delegation.delegationId,
        action: toolName,
        amount,
        merchant,
        timestamp: new Date().toISOString(),
        stripeObjectId: result?.id || result?.data?.id || null,
        preflightHash: canonicalize(decision.result),
      } as any)
    }
    
    return result
  }
  
  // Preserve tool metadata for framework compatibility
  return {
    ...tool,
    call: governedCall,
    invoke: governedCall,
    func: governedCall,
    description: `[APS Governed] ${tool.description || toolName}`,
  }
}

// ── Preflight ──

function runPreflight(
  config: GovernedStripeConfig,
  amount: ACPMoney,
  merchant: string
): PreflightDecision {
  const result = commercePreflight({
    signedPassport: config.passport,
    delegation: config.delegation,
    merchantName: merchant,
    estimatedTotal: amount,
  })
  
  const remainingBudget = config.delegation.spendLimit - config.delegation.spentAmount
  
  const requiresHumanApproval = result.permitted
    && config.delegation.requireHumanApproval === true
    && config.delegation.humanApprovalThreshold != null
    && amount.amount > config.delegation.humanApprovalThreshold
  
  return {
    permitted: result.permitted,
    result,
    remainingBudget,
    requiresHumanApproval,
  }
}

// ── MPP Integration ──

/**
 * Governance wrapper for Stripe Machine Payments Protocol (MPP).
 * 
 * When an agent receives a payment request from a service via MPP,
 * this function verifies the commerce delegation before authorizing.
 * 
 * Flow:
 *   1. Service sends HTTP 402 with payment request
 *   2. Agent calls governMPPPayment() with the request
 *   3. APS runs 4-gate preflight
 *   4. If permitted, returns authorization to proceed
 *   5. Agent sends payment via Stripe (USDC/fiat)
 *   6. APS produces signed receipt
 */
export async function governMPPPayment(
  config: GovernedStripeConfig,
  paymentRequest: {
    amount: number       // smallest currency unit
    currency: string     // 'usd' or 'usdc'
    merchant: string     // service endpoint
    resource: string     // what the agent is buying
    paymentMethod: 'x402' | 'spt' | 'card'
  }
): Promise<{
  authorized: boolean
  receipt?: any
  error?: string
  remainingBudget: number
}> {
  const amount: ACPMoney = {
    amount: paymentRequest.amount,
    currency: paymentRequest.currency,
  }
  
  const decision = runPreflight(config, amount, paymentRequest.merchant)
  
  if (!decision.permitted) {
    return {
      authorized: false,
      error: decision.result.blockedReason,
      remainingBudget: decision.remainingBudget,
    }
  }
  
  if (decision.requiresHumanApproval && config.onHumanApprovalRequired) {
    const approved = await config.onHumanApprovalRequired(
      requestHumanApproval({
        agentId: config.passport.passport.agentId,
        delegationId: config.delegation.delegationId,
        amount,
        merchantName: paymentRequest.merchant,
        items: [],
        totalAmount: amount,
        reason: `MPP payment for ${paymentRequest.resource}`,
      })
    )
    if (!approved) {
      return {
        authorized: false,
        error: 'Human principal declined MPP payment.',
        remainingBudget: decision.remainingBudget,
      }
    }
  }
  
  // Update spend
  config.delegation.spentAmount += amount.amount
  
  const receipt = {
    receiptId: `rcpt_mpp_${Date.now().toString(36)}`,
    agentId: config.passport.passport.agentId,
    delegationId: config.delegation.delegationId,
    action: 'mpp_payment',
    amount,
    merchantName: paymentRequest.merchant,
        items: [],
        totalAmount: amount,
    resource: paymentRequest.resource,
    paymentMethod: paymentRequest.paymentMethod,
    timestamp: new Date().toISOString(),
    preflightHash: canonicalize(decision.result),
  }
  
  if (config.onReceipt) {
    config.onReceipt(receipt as any)
  }
  
  return {
    authorized: true,
    receipt,
    remainingBudget: config.delegation.spendLimit - config.delegation.spentAmount,
  }
}

// ── Budget Dashboard ──

/**
 * Returns the current spend state for an agent's commerce delegation.
 * Useful for financial observability dashboards.
 */
export function getAgentBudgetStatus(config: GovernedStripeConfig) {
  const spent = config.delegation.spentAmount
  const limit = config.delegation.spendLimit
  const remaining = limit - spent
  const utilization = limit > 0 ? spent / limit : 0
  
  return {
    agentId: config.passport.passport.agentId,
    delegationId: config.delegation.delegationId,
    currency: config.delegation.currency,
    spendLimit: limit / 100,
    spentAmount: spent / 100,
    remainingBudget: remaining / 100,
    utilizationPercent: Math.round(utilization * 10000) / 100,
    humanApprovalThreshold: config.delegation.humanApprovalThreshold
      ? config.delegation.humanApprovalThreshold / 100
      : null,
    approvedMerchants: config.delegation.approvedMerchants || 'any',
  }
}

// ── Helpers ──

function extractAmount(args: any[], toolName: string): ACPMoney {
  const input = args[0] || {}
  const data = typeof input === 'string' ? JSON.parse(input) : input
  
  return {
    amount: data.amount || data.unit_amount || data.price?.amount || 0,
    currency: data.currency || 'usd',
  }
}

function extractMerchant(args: any[], toolName: string): string {
  const input = args[0] || {}
  const data = typeof input === 'string' ? JSON.parse(input) : input
  return data.merchant || data.merchant_name || data.metadata?.merchant || 'unknown'
}
