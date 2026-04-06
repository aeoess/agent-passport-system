// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS Governance Adapter for Stripe Agent Payments
 *
 * Wraps Stripe's agent tools with Agent Passport System commerce
 * delegation checks. Before any payment action executes, APS verifies:
 *   1. Passport valid (agent identity)
 *   2. Delegation scope includes commerce
 *   3. Spend within remaining budget
 *   4. Merchant on allowlist (if configured)
 *
 * Works with: @stripe/agent-toolkit, Stripe MPP, x402, SPT
 */

import {
  commercePreflight,
  requestHumanApproval,
  canonicalize,
  type ACPMoney,
  type CommercePreflightResult,
} from 'agent-passport-system'

import type {
  GovernedStripeConfig,
  PreflightDecision,
  MPPPaymentRequest,
  MPPPaymentResult,
  StripeGovernanceReceipt,
} from './types.js'

// ── Tool interface for Stripe Agent Toolkit compatibility ──

interface StripeToolLike {
  name?: string
  metadata?: { name?: string }
  description?: string
  call?: (...args: unknown[]) => Promise<unknown>
  invoke?: (...args: unknown[]) => Promise<unknown>
  func?: (...args: unknown[]) => Promise<unknown>
  [key: string]: unknown
}

// ── Preflight ──

function runPreflight(
  config: GovernedStripeConfig,
  amount: ACPMoney,
  merchant: string,
): PreflightDecision {
  const result: CommercePreflightResult = commercePreflight({
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

  return { permitted: result.permitted, result, remainingBudget, requiresHumanApproval }
}

// ── Core Adapter ──

const PAYMENT_TOOLS = [
  'create_payment_link', 'create_invoice', 'create_checkout_session',
  'create_payment_intent', 'confirm_payment_intent', 'create_subscription', 'create_charge',
]

/**
 * Wraps Stripe Agent Toolkit tools with APS governance.
 * Non-payment tools pass through unchanged.
 */
export function governStripeTools(
  stripeTools: StripeToolLike[],
  config: GovernedStripeConfig,
): StripeToolLike[] {
  return stripeTools.map(tool => {
    const toolName = (tool.name || tool.metadata?.name || '') as string
    if (PAYMENT_TOOLS.some(pt => toolName.toLowerCase().includes(pt.replace(/_/g, '')))) {
      return wrapWithGovernance(tool, toolName, config)
    }
    return tool
  })
}

function wrapWithGovernance(
  tool: StripeToolLike,
  toolName: string,
  config: GovernedStripeConfig,
): StripeToolLike {
  const originalCall = (tool.call || tool.invoke || tool.func) as ((...args: unknown[]) => Promise<unknown>) | undefined

  const governedCall = async (...args: unknown[]) => {
    const amount = extractAmount(args)
    const merchant = extractMerchant(args)

    const decision = runPreflight(config, amount, merchant)

    if (config.verbose) {
      console.log(`[APS] Preflight for ${toolName}:`, {
        permitted: decision.permitted,
        amount: amount.amount / 100,
        currency: amount.currency,
        remainingBudget: decision.remainingBudget / 100,
        gates: decision.result.checks.map((c: { check: string; passed: boolean }) =>
          `${c.check}: ${c.passed ? '\u2713' : '\u2717'}`),
      })
    }

    if (!decision.permitted) {
      return {
        error: 'APS_COMMERCE_DENIED',
        reason: decision.result.blockedReason,
        checks: decision.result.checks.filter((c: { passed: boolean }) => !c.passed),
        suggestion: decision.result.warnings.length > 0
          ? decision.result.warnings[0]
          : 'Request a broader commerce delegation from your principal.',
      }
    }

    if (decision.requiresHumanApproval) {
      const approvalRequest = requestHumanApproval({
        agentId: config.passport.passport.agentId,
        delegationId: config.delegation.delegationId,
        merchantName: merchant,
        items: [],
        totalAmount: amount,
        reason: `Spend of ${amount.amount / 100} ${amount.currency.toUpperCase()} exceeds auto-approval threshold of ${(config.delegation.humanApprovalThreshold || 0) / 100}`,
      })

      if (config.onHumanApprovalRequired) {
        const approved = await config.onHumanApprovalRequired(approvalRequest)
        if (!approved) {
          return { error: 'APS_HUMAN_DENIED', reason: 'Human principal declined the transaction.', approvalRequest }
        }
      } else {
        return { error: 'APS_HUMAN_APPROVAL_REQUIRED', reason: 'Transaction exceeds auto-approval threshold. No handler configured.', approvalRequest }
      }
    }

    const result = originalCall ? await originalCall.apply(tool, args) : undefined
    config.delegation.spentAmount += amount.amount

    if (config.onReceipt) {
      const receipt: StripeGovernanceReceipt = {
        receiptId: `rcpt_${Date.now().toString(36)}`,
        agentId: config.passport.passport.agentId,
        delegationId: config.delegation.delegationId,
        action: toolName,
        amount,
        merchant,
        timestamp: new Date().toISOString(),
        stripeObjectId: ((result as Record<string, unknown>)?.id || null) as string | null,
        preflightHash: canonicalize(decision.result),
      }
      config.onReceipt(receipt)
    }

    return result
  }

  return {
    ...tool,
    call: governedCall,
    invoke: governedCall,
    func: governedCall,
    description: `[APS Governed] ${tool.description || toolName}`,
  }
}

/**
 * Governance wrapper for Stripe Machine Payments Protocol (MPP).
 */
export async function governMPPPayment(
  config: GovernedStripeConfig,
  paymentRequest: MPPPaymentRequest,
): Promise<MPPPaymentResult> {
  const amount: ACPMoney = { amount: paymentRequest.amount, currency: paymentRequest.currency }
  const decision = runPreflight(config, amount, paymentRequest.merchant)

  if (!decision.permitted) {
    return { authorized: false, error: decision.result.blockedReason, remainingBudget: decision.remainingBudget }
  }

  if (decision.requiresHumanApproval && config.onHumanApprovalRequired) {
    const approved = await config.onHumanApprovalRequired(
      requestHumanApproval({
        agentId: config.passport.passport.agentId,
        delegationId: config.delegation.delegationId,
        merchantName: paymentRequest.merchant,
        items: [],
        totalAmount: amount,
        reason: `MPP payment for ${paymentRequest.resource}`,
      })
    )
    if (!approved) {
      return { authorized: false, error: 'Human principal declined MPP payment.', remainingBudget: decision.remainingBudget }
    }
  }

  config.delegation.spentAmount += amount.amount

  const receipt: StripeGovernanceReceipt = {
    receiptId: `rcpt_mpp_${Date.now().toString(36)}`,
    agentId: config.passport.passport.agentId,
    delegationId: config.delegation.delegationId,
    action: 'mpp_payment',
    amount,
    merchantName: paymentRequest.merchant,
    resource: paymentRequest.resource,
    paymentMethod: paymentRequest.paymentMethod,
    timestamp: new Date().toISOString(),
    preflightHash: canonicalize(decision.result),
  }

  if (config.onReceipt) {
    config.onReceipt(receipt)
  }

  return {
    authorized: true,
    receipt: receipt as MPPPaymentResult['receipt'],
    remainingBudget: config.delegation.spendLimit - config.delegation.spentAmount,
  }
}

// ── Helpers ──

function extractAmount(args: unknown[]): ACPMoney {
  const input = args[0] || {}
  const data: Record<string, unknown> = typeof input === 'string' ? JSON.parse(input) : input as Record<string, unknown>
  return {
    amount: (data.amount || data.unit_amount || 0) as number,
    currency: (data.currency || 'usd') as string,
  }
}

function extractMerchant(args: unknown[]): string {
  const input = args[0] || {}
  const data: Record<string, unknown> = typeof input === 'string' ? JSON.parse(input) : input as Record<string, unknown>
  return (data.merchant || data.merchant_name || (data.metadata as Record<string, unknown>)?.merchant || 'unknown') as string
}
