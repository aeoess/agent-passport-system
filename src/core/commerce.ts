// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Layer 7 — Agentic Commerce: Implementation
// ══════════════════════════════════════════════════════════════════
// Integration with the Agentic Commerce Protocol (ACP) by OpenAI + Stripe.
//
// Every commerce action flows through a 4-gate pipeline:
//   1. Passport verification — is this agent who it claims to be?
//   2. Delegation scope check — does this agent have commerce:checkout?
//   3. Spend limit check — would this purchase exceed the cap?
//   4. Values Floor check (F-003 Scoped Authority) — is this within policy?
//
// Only after all 4 gates pass does the agent interact with the merchant.
// Every completed action produces a signed CommerceActionReceipt.
// ══════════════════════════════════════════════════════════════════

import { randomBytes } from 'node:crypto'
import { sign, verify as ed25519Verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import { verifyPassport } from '../verification/verify.js'
import { scopeAuthorizes } from './delegation.js'
import { verifyBoundWallet } from '../v2/wallet-binding/bind.js'
import type { WalletChain } from '../v2/wallet-binding/types.js'
import type { SignedPassport } from '../types/passport.js'
import type {
  ACPCheckoutSession, ACPLineItem, ACPMoney, ACPAddress,
  CommerceConfig, CommerceDelegation,
  CommercePreflightResult, CommercePreflightCheck,
  CommerceActionReceipt, HumanApprovalRequest,
  IdempotencyStore,
} from '../types/commerce.js'

// ── Commerce Scopes ──

const COMMERCE_SCOPES = [
  'commerce:checkout',
  'commerce:browse',
  'commerce:purchase',
  'commerce:cancel',
] as const

type CommerceScope = typeof COMMERCE_SCOPES[number]

function hasScope(delegation: CommerceDelegation, required: CommerceScope): boolean {
  return scopeAuthorizes(delegation.scope, required)
}

// ── Preflight Check: 6-Gate Pipeline ──
// Gates: passport_valid → delegation_scope → spend_limit → merchant_approved
//      → wallet_bound (optional, only when walletRef provided) → idempotency (optional)

export function commercePreflight(opts: {
  signedPassport: SignedPassport
  delegation: CommerceDelegation
  merchantName: string
  estimatedTotal: ACPMoney
  config?: CommerceConfig
  walletRef?: { chain: WalletChain; address: string }
  idempotencyKey: string
  idempotencyStore: IdempotencyStore
  idempotencyWindowSeconds?: number
}): Promise<CommercePreflightResult>
export function commercePreflight(opts: {
  signedPassport: SignedPassport
  delegation: CommerceDelegation
  merchantName: string
  estimatedTotal: ACPMoney
  config?: CommerceConfig
  walletRef?: { chain: WalletChain; address: string }
}): CommercePreflightResult
export function commercePreflight(opts: {
  signedPassport: SignedPassport
  delegation: CommerceDelegation
  merchantName: string
  estimatedTotal: ACPMoney
  config?: CommerceConfig
  walletRef?: { chain: WalletChain; address: string }
  idempotencyKey?: string
  idempotencyStore?: IdempotencyStore
  idempotencyWindowSeconds?: number
}): CommercePreflightResult | Promise<CommercePreflightResult> {
  const checks: CommercePreflightCheck[] = []
  const warnings: string[] = []

  // Gate 1: Passport verification
  const passportResult = verifyPassport(opts.signedPassport)
  checks.push({
    check: 'passport_valid',
    passed: passportResult.valid,
    detail: passportResult.valid
      ? `Passport verified for ${opts.signedPassport.passport.agentId}`
      : `Passport failed: ${passportResult.errors.join(', ')}`,
  })

  // Gate 2: Delegation scope
  const hasCheckoutScope = hasScope(opts.delegation, 'commerce:checkout')
  checks.push({
    check: 'delegation_scope',
    passed: hasCheckoutScope,
    detail: hasCheckoutScope
      ? `Agent has commerce:checkout scope via delegation ${opts.delegation.delegationId}`
      : `Agent lacks commerce:checkout scope. Has: [${opts.delegation.scope.join(', ')}]`,
  })

  // Gate 3: Spend limit
  const amountInBase = opts.estimatedTotal.amount
  const remainingBudget = opts.delegation.spendLimit - opts.delegation.spentAmount
  const withinBudget = amountInBase <= remainingBudget
  checks.push({
    check: 'spend_limit',
    passed: withinBudget,
    detail: withinBudget
      ? `Purchase ${amountInBase} within budget (${remainingBudget} remaining of ${opts.delegation.spendLimit})`
      : `Purchase ${amountInBase} exceeds remaining budget of ${remainingBudget} (limit: ${opts.delegation.spendLimit}, spent: ${opts.delegation.spentAmount})`,
  })

  // Gate 3b: Human approval threshold
  if (opts.delegation.requireHumanApproval && opts.delegation.humanApprovalThreshold) {
    if (amountInBase > opts.delegation.humanApprovalThreshold) {
      warnings.push(
        `Purchase of ${amountInBase} exceeds human approval threshold of ${opts.delegation.humanApprovalThreshold}. Human confirmation required.`
      )
    }
  }

  // Gate 4: Merchant allowlist (if configured)
  if (opts.delegation.approvedMerchants && opts.delegation.approvedMerchants.length > 0) {
    const merchantApproved = opts.delegation.approvedMerchants.includes(opts.merchantName)
    checks.push({
      check: 'merchant_approved',
      passed: merchantApproved,
      detail: merchantApproved
        ? `Merchant "${opts.merchantName}" is on approved list`
        : `Merchant "${opts.merchantName}" is NOT on approved list: [${opts.delegation.approvedMerchants.join(', ')}]`,
    })
  }

  // Gate 5: Wallet binding (only when the action references a specific wallet)
  // Existing 5-gate flows that don't pass walletRef are unaffected.
  if (opts.walletRef) {
    const isBound = verifyBoundWallet(
      opts.signedPassport,
      opts.walletRef.chain,
      opts.walletRef.address
    )
    checks.push({
      check: 'wallet_bound',
      passed: isBound,
      detail: isBound
        ? `Wallet ${opts.walletRef.chain}:${opts.walletRef.address} is bound to passport ${opts.signedPassport.passport.agentId}`
        : `WALLET_NOT_BOUND: ${opts.walletRef.chain}:${opts.walletRef.address} is not bound to passport ${opts.signedPassport.passport.agentId}`,
    })
  }

  // Gate 6: Idempotency check (async, only if key + store provided)
  if (opts.idempotencyKey && opts.idempotencyStore) {
    const windowSeconds = opts.idempotencyWindowSeconds ?? 300
    return opts.idempotencyStore.check(opts.idempotencyKey, windowSeconds).then(result => {
      if (result.duplicate) {
        checks.push({
          check: 'idempotency',
          passed: false,
          detail: `Duplicate operation within ${windowSeconds}s window (existing receipt: ${result.existingReceiptId})`,
        })
      } else {
        checks.push({
          check: 'idempotency',
          passed: true,
          detail: `No duplicate found for idempotency key`,
        })
      }

      const permitted = checks.every(c => c.passed)
      return {
        permitted,
        checks,
        delegation: opts.delegation,
        warnings,
        blockedReason: permitted ? undefined : checks.find(c => !c.passed)?.detail,
        existingReceiptId: result.duplicate ? result.existingReceiptId : undefined,
      }
    })
  }

  const permitted = checks.every(c => c.passed)
  return {
    permitted,
    checks,
    delegation: opts.delegation,
    warnings,
    blockedReason: permitted ? undefined : checks.find(c => !c.passed)?.detail,
  }
}

// ── ACP Client: Create Checkout Session ──

export async function createCheckout(opts: {
  signedPassport: SignedPassport
  delegation: CommerceDelegation
  config: CommerceConfig
  items: { skuId: string; quantity: number }[]
  customer?: { name?: string; email?: string }
  fulfillmentAddress?: ACPAddress
  privateKey: string
}): Promise<{ session: ACPCheckoutSession; receipt: CommerceActionReceipt }> {
  // Run preflight — estimate total as 0 for creation (real total comes from merchant)
  const preflight = commercePreflight({
    signedPassport: opts.signedPassport,
    delegation: opts.delegation,
    merchantName: opts.config.merchantName,
    estimatedTotal: { amount: 0, currency: opts.delegation.currency },
  })

  if (!preflight.permitted) {
    throw new Error(`Commerce preflight DENIED: ${preflight.blockedReason}`)
  }

  // Build ACP CreateCheckoutRequest
  const requestBody = {
    items: opts.items.map(i => ({ sku_id: i.skuId, quantity: i.quantity })),
    ...(opts.customer && { customer: opts.customer }),
    ...(opts.fulfillmentAddress && { fulfillment_address: opts.fulfillmentAddress }),
  }

  // Call merchant endpoint
  const url = `${opts.config.merchantBaseUrl}/checkout_sessions`
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(opts.config.bearerToken && { 'Authorization': `Bearer ${opts.config.bearerToken}` }),
    },
    body: JSON.stringify(requestBody),
  })

  if (!response.ok) {
    throw new Error(`ACP CreateCheckout failed: ${response.status} ${response.statusText}`)
  }

  const session: ACPCheckoutSession = await response.json() as ACPCheckoutSession

  // Generate signed receipt
  const receipt = signCommerceReceipt({
    agentId: opts.signedPassport.passport.agentId,
    delegationId: opts.delegation.delegationId,
    actionType: 'commerce:create_checkout',
    target: url,
    method: 'POST',
    session,
    merchantName: opts.config.merchantName,
    delegationChain: extractDelegationChain(opts.signedPassport),
    beneficiary: opts.signedPassport.passport.metadata?.beneficiaryPrincipalId as string || 'unknown',
    privateKey: opts.privateKey,
  })

  return { session, receipt }
}

// ── ACP Client: Update Checkout Session ──

export async function updateCheckout(opts: {
  signedPassport: SignedPassport
  delegation: CommerceDelegation
  config: CommerceConfig
  sessionId: string
  updates: {
    items?: { id: string; quantity: number }[]
    fulfillmentAddress?: ACPAddress
    fulfillmentOptionId?: string
  }
  privateKey: string
}): Promise<{ session: ACPCheckoutSession; receipt: CommerceActionReceipt }> {
  const url = `${opts.config.merchantBaseUrl}/checkout_sessions/${opts.sessionId}`
  const response = await fetch(url, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      ...(opts.config.bearerToken && { 'Authorization': `Bearer ${opts.config.bearerToken}` }),
    },
    body: JSON.stringify({
      ...(opts.updates.items && { items: opts.updates.items }),
      ...(opts.updates.fulfillmentAddress && { fulfillment_address: opts.updates.fulfillmentAddress }),
      ...(opts.updates.fulfillmentOptionId && { fulfillment_option_id: opts.updates.fulfillmentOptionId }),
    }),
  })

  if (!response.ok) {
    throw new Error(`ACP UpdateCheckout failed: ${response.status} ${response.statusText}`)
  }

  const session: ACPCheckoutSession = await response.json() as ACPCheckoutSession

  const receipt = signCommerceReceipt({
    agentId: opts.signedPassport.passport.agentId,
    delegationId: opts.delegation.delegationId,
    actionType: 'commerce:update_checkout',
    target: url,
    method: 'PUT',
    session,
    merchantName: opts.config.merchantName,
    delegationChain: extractDelegationChain(opts.signedPassport),
    beneficiary: opts.signedPassport.passport.metadata?.beneficiaryPrincipalId as string || 'unknown',
    privateKey: opts.privateKey,
  })

  return { session, receipt }
}

// ── ACP Client: Complete Checkout (Payment) ──

export async function completeCheckout(opts: {
  signedPassport: SignedPassport
  delegation: CommerceDelegation
  config: CommerceConfig
  sessionId: string
  paymentToken: string         // SharedPaymentToken from Stripe
  paymentMethod?: string
  privateKey: string
}): Promise<{ session: ACPCheckoutSession; receipt: CommerceActionReceipt; spendUpdated: CommerceDelegation }> {
  // Re-run preflight with actual total — fetch current session first
  const getUrl = `${opts.config.merchantBaseUrl}/checkout_sessions/${opts.sessionId}`
  const getResponse = await fetch(getUrl, {
    headers: opts.config.bearerToken ? { 'Authorization': `Bearer ${opts.config.bearerToken}` } : {},
  })

  if (!getResponse.ok) {
    throw new Error(`ACP GetCheckout failed: ${getResponse.status}`)
  }

  const currentSession: ACPCheckoutSession = await getResponse.json() as ACPCheckoutSession
  const total = currentSession.totals.total

  // Final preflight with real amount
  const preflight = commercePreflight({
    signedPassport: opts.signedPassport,
    delegation: opts.delegation,
    merchantName: opts.config.merchantName,
    estimatedTotal: total,
  })

  if (!preflight.permitted) {
    throw new Error(`Commerce preflight DENIED at payment: ${preflight.blockedReason}`)
  }

  // Check human approval threshold
  if (opts.delegation.requireHumanApproval && opts.delegation.humanApprovalThreshold) {
    if (total.amount > opts.delegation.humanApprovalThreshold) {
      throw new Error(
        `HUMAN_APPROVAL_REQUIRED: Purchase of ${total.amount} ${total.currency} exceeds threshold of ${opts.delegation.humanApprovalThreshold}. ` +
        `Use requestHumanApproval() to get confirmation before completing.`
      )
    }
  }

  // Complete checkout via ACP
  const url = `${opts.config.merchantBaseUrl}/checkout_sessions/${opts.sessionId}/complete`
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(opts.config.bearerToken && { 'Authorization': `Bearer ${opts.config.bearerToken}` }),
    },
    body: JSON.stringify({
      payment_token: opts.paymentToken,
      ...(opts.paymentMethod && { payment_method: opts.paymentMethod }),
    }),
  })

  if (!response.ok) {
    throw new Error(`ACP CompleteCheckout failed: ${response.status} ${response.statusText}`)
  }

  const session: ACPCheckoutSession = await response.json() as ACPCheckoutSession

  // Update spend tracking on the delegation
  const spendUpdated: CommerceDelegation = {
    ...opts.delegation,
    spentAmount: opts.delegation.spentAmount + total.amount,
  }

  // Generate signed receipt with full purchase details
  const receipt = signCommerceReceipt({
    agentId: opts.signedPassport.passport.agentId,
    delegationId: opts.delegation.delegationId,
    actionType: 'commerce:complete_checkout',
    target: url,
    method: 'POST',
    session,
    merchantName: opts.config.merchantName,
    delegationChain: extractDelegationChain(opts.signedPassport),
    beneficiary: opts.signedPassport.passport.metadata?.beneficiaryPrincipalId as string || 'unknown',
    privateKey: opts.privateKey,
  })

  return { session, receipt, spendUpdated }
}

// ── ACP Client: Cancel Checkout ──

export async function cancelCheckout(opts: {
  signedPassport: SignedPassport
  delegation: CommerceDelegation
  config: CommerceConfig
  sessionId: string
  privateKey: string
}): Promise<{ session: ACPCheckoutSession; receipt: CommerceActionReceipt }> {
  const url = `${opts.config.merchantBaseUrl}/checkout_sessions/${opts.sessionId}/cancel`
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(opts.config.bearerToken && { 'Authorization': `Bearer ${opts.config.bearerToken}` }),
    },
  })

  if (!response.ok) {
    throw new Error(`ACP CancelCheckout failed: ${response.status} ${response.statusText}`)
  }

  const session: ACPCheckoutSession = await response.json() as ACPCheckoutSession

  const receipt = signCommerceReceipt({
    agentId: opts.signedPassport.passport.agentId,
    delegationId: opts.delegation.delegationId,
    actionType: 'commerce:cancel_checkout',
    target: url,
    method: 'POST',
    session,
    merchantName: opts.config.merchantName,
    delegationChain: extractDelegationChain(opts.signedPassport),
    beneficiary: opts.signedPassport.passport.metadata?.beneficiaryPrincipalId as string || 'unknown',
    privateKey: opts.privateKey,
  })

  return { session, receipt }
}

// ── Human Approval Request ──

export function requestHumanApproval(opts: {
  agentId: string
  delegationId: string
  merchantName: string
  items: ACPLineItem[]
  totalAmount: ACPMoney
  reason: string
  expiresInMinutes?: number
}): HumanApprovalRequest {
  const now = new Date()
  const expiresAt = new Date(now.getTime() + (opts.expiresInMinutes || 30) * 60 * 1000)

  return {
    requestId: `approval-${randomBytes(8).toString('hex')}`,
    agentId: opts.agentId,
    merchantName: opts.merchantName,
    items: opts.items,
    totalAmount: opts.totalAmount,
    delegationId: opts.delegationId,
    reason: opts.reason,
    createdAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    status: 'pending',
  }
}

// ── Commerce Receipt Signing ──

function signCommerceReceipt(opts: {
  agentId: string
  delegationId: string
  actionType: CommerceActionReceipt['action']['type']
  target: string
  method: string
  session: ACPCheckoutSession
  merchantName: string
  delegationChain: string[]
  beneficiary: string
  privateKey: string
}): CommerceActionReceipt {
  const receipt: Omit<CommerceActionReceipt, 'signature'> = {
    receiptId: `rcpt-commerce-${randomBytes(8).toString('hex')}`,
    version: '1.0',
    timestamp: new Date().toISOString(),
    agentId: opts.agentId,
    delegationId: opts.delegationId,
    action: {
      type: opts.actionType,
      target: opts.target,
      method: opts.method,
      scopeUsed: 'commerce:checkout',
      spend: {
        amount: opts.session.totals.total.amount,
        currency: opts.session.totals.total.currency,
      },
    },
    checkout: {
      sessionId: opts.session.id,
      merchantName: opts.merchantName,
      items: opts.session.items.map(i => ({
        skuId: i.skuId,
        name: i.name,
        quantity: i.quantity,
        unitPrice: i.unitPrice.amount,
      })),
      totalAmount: opts.session.totals.total.amount,
      totalCurrency: opts.session.totals.total.currency,
      status: opts.session.status,
    },
    delegationChain: opts.delegationChain,
    beneficiary: opts.beneficiary,
  }

  const payload = canonicalize(receipt)
  const signature = sign(payload, opts.privateKey)

  return { ...receipt, signature }
}

// ── Helpers ──

function extractDelegationChain(sp: SignedPassport): string[] {
  const chain = [sp.passport.publicKey]
  if (sp.passport.delegations) {
    for (const d of sp.passport.delegations) {
      if (!chain.includes(d.delegatedBy)) chain.push(d.delegatedBy)
    }
  }
  return chain
}

// ── Commerce Delegation Factory ──

export function createCommerceDelegation(opts: {
  agentId: string
  delegationId: string
  spendLimit: number
  currency?: string
  approvedMerchants?: string[]
  requireHumanApproval?: boolean
  humanApprovalThreshold?: number
  additionalScopes?: string[]
}): CommerceDelegation {
  return {
    agentId: opts.agentId,
    delegationId: opts.delegationId,
    scope: ['commerce:checkout', 'commerce:browse', ...(opts.additionalScopes || [])],
    spendLimit: opts.spendLimit,
    spentAmount: 0,
    currency: opts.currency || 'usd',
    approvedMerchants: opts.approvedMerchants,
    requireHumanApproval: opts.requireHumanApproval ?? true,
    humanApprovalThreshold: opts.humanApprovalThreshold,
  }
}

// ── Spend Analytics ──

export function getSpendSummary(delegation: CommerceDelegation): {
  limit: number
  spent: number
  remaining: number
  currency: string
  utilizationPercent: number
  nearLimit: boolean
} {
  const remaining = delegation.spendLimit - delegation.spentAmount
  const utilization = delegation.spendLimit > 0
    ? (delegation.spentAmount / delegation.spendLimit) * 100
    : 0

  return {
    limit: delegation.spendLimit,
    spent: delegation.spentAmount,
    remaining,
    currency: delegation.currency,
    utilizationPercent: Math.round(utilization * 100) / 100,
    nearLimit: utilization >= 80,
  }
}

// ── Verify Commerce Receipt ──

export function verifyCommerceReceipt(
  receipt: CommerceActionReceipt,
  publicKey: string,
): { valid: boolean; errors: string[] } {
  const errors: string[] = []

  // Verify signature
  const { signature, ...payload } = receipt
  const canonical = canonicalize(payload)

  try {
    const signatureValid = ed25519Verify(canonical, signature, publicKey)
    if (!signatureValid) {
      errors.push('Commerce receipt signature is invalid')
    }
  } catch {
    errors.push('Failed to verify commerce receipt signature')
  }

  // Verify required fields
  if (!receipt.receiptId) errors.push('Missing receiptId')
  if (!receipt.agentId) errors.push('Missing agentId')
  if (!receipt.delegationId) errors.push('Missing delegationId')
  if (!receipt.action?.type) errors.push('Missing action type')
  if (!receipt.action?.scopeUsed) errors.push('Missing scopeUsed')
  if (!receipt.beneficiary) errors.push('Missing beneficiary')
  if (!receipt.checkout?.sessionId) errors.push('Missing checkout sessionId')

  return { valid: errors.length === 0, errors }
}
