// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Layer 7 — Agentic Commerce: Pure Primitives
// ══════════════════════════════════════════════════════════════════
// Migrated 2026-04-17. The 6-gate orchestrator (commercePreflight) and
// the ACP fetch wrappers (createCheckout/updateCheckout/completeCheckout/
// cancelCheckout) moved to @aeoess/gateway as product workflow.
//
// What stays in the SDK:
//   • Gate predicates — each pure, returning {check, passed, detail}
//   • Receipt signing primitive (signCommerceReceipt) and verifier
//   • Delegation factory + spend summary
//   • Human approval request struct
//   • extractDelegationChain helper
//
// Callers compose these themselves, or use the gateway's commerce-preflight.
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
  CommerceConfig, CommerceDelegation, CommercePreflightCheck,
  CommercePreflightResult, CommerceActionReceipt,
  HumanApprovalRequest, IdempotencyStore,
} from '../types/commerce.js'

// ── Commerce Scopes ──

const COMMERCE_SCOPES = [
  'commerce:checkout',
  'commerce:browse',
  'commerce:purchase',
  'commerce:cancel',
] as const

type CommerceScope = typeof COMMERCE_SCOPES[number]

export function hasCommerceScope(delegation: CommerceDelegation, required: CommerceScope): boolean {
  return scopeAuthorizes(delegation.scope, required)
}

// ── Gate Predicates ──
// Each predicate is pure: same inputs → same output, no I/O, no mutation.
// The gateway composes these into the 6-gate commercePreflight pipeline.

export function checkPassportGate(signedPassport: SignedPassport): CommercePreflightCheck {
  const result = verifyPassport(signedPassport)
  return {
    check: 'passport_valid',
    passed: result.valid,
    detail: result.valid
      ? `Passport verified for ${signedPassport.passport.agentId}`
      : `Passport failed: ${result.errors.join(', ')}`,
  }
}

export function checkScopeGate(delegation: CommerceDelegation): CommercePreflightCheck {
  const ok = hasCommerceScope(delegation, 'commerce:checkout')
  return {
    check: 'delegation_scope',
    passed: ok,
    detail: ok
      ? `Agent has commerce:checkout scope via delegation ${delegation.delegationId}`
      : `Agent lacks commerce:checkout scope. Has: [${delegation.scope.join(', ')}]`,
  }
}

export function checkSpendGate(
  delegation: CommerceDelegation,
  estimatedTotal: ACPMoney,
): CommercePreflightCheck {
  const remaining = delegation.spendLimit - delegation.spentAmount
  const ok = estimatedTotal.amount <= remaining
  return {
    check: 'spend_limit',
    passed: ok,
    detail: ok
      ? `Purchase ${estimatedTotal.amount} within budget (${remaining} remaining of ${delegation.spendLimit})`
      : `Purchase ${estimatedTotal.amount} exceeds remaining budget of ${remaining} (limit: ${delegation.spendLimit}, spent: ${delegation.spentAmount})`,
  }
}

export function checkHumanApprovalThreshold(
  delegation: CommerceDelegation,
  estimatedTotal: ACPMoney,
): string | null {
  if (!delegation.requireHumanApproval || !delegation.humanApprovalThreshold) return null
  if (estimatedTotal.amount <= delegation.humanApprovalThreshold) return null
  return (
    `Purchase of ${estimatedTotal.amount} exceeds human approval threshold of ${delegation.humanApprovalThreshold}. ` +
    `Human confirmation required.`
  )
}

export function checkMerchantGate(
  delegation: CommerceDelegation,
  merchantName: string,
): CommercePreflightCheck | null {
  if (!delegation.approvedMerchants || delegation.approvedMerchants.length === 0) return null
  const ok = delegation.approvedMerchants.includes(merchantName)
  return {
    check: 'merchant_approved',
    passed: ok,
    detail: ok
      ? `Merchant "${merchantName}" is on approved list`
      : `Merchant "${merchantName}" is NOT on approved list: [${delegation.approvedMerchants.join(', ')}]`,
  }
}

export function checkWalletGate(
  signedPassport: SignedPassport,
  walletRef: { chain: WalletChain; address: string },
): CommercePreflightCheck {
  const bound = verifyBoundWallet(signedPassport, walletRef.chain, walletRef.address)
  return {
    check: 'wallet_bound',
    passed: bound,
    detail: bound
      ? `Wallet ${walletRef.chain}:${walletRef.address} is bound to passport ${signedPassport.passport.agentId}`
      : `WALLET_NOT_BOUND: ${walletRef.chain}:${walletRef.address} is not bound to passport ${signedPassport.passport.agentId}`,
  }
}

// ── Removed Orchestrator Stubs ──
// commercePreflight, createCheckout, updateCheckout, completeCheckout, cancelCheckout
// moved to @aeoess/gateway src/sdk-migrated/core/commerce-preflight.ts.

const MIGRATED_MSG =
  'commerce orchestration moved to @aeoess/gateway src/sdk-migrated/core/commerce-preflight.ts. ' +
  'Use the gate predicate helpers (checkPassportGate, checkScopeGate, checkSpendGate, ' +
  'checkMerchantGate, checkWalletGate) plus signCommerceReceipt, or import the gateway module.'

// Stubs preserve original return-type signatures so consumers continue
// to typecheck; calling them at runtime throws.

export function commercePreflight(_opts: {
  signedPassport: SignedPassport
  delegation: CommerceDelegation
  merchantName: string
  estimatedTotal: ACPMoney
  config?: CommerceConfig
  walletRef?: { chain: WalletChain; address: string }
  idempotencyKey?: string
  idempotencyStore?: IdempotencyStore
  idempotencyWindowSeconds?: number
}): CommercePreflightResult {
  throw new Error(MIGRATED_MSG)
}

export function createCheckout(_opts: {
  signedPassport: SignedPassport
  delegation: CommerceDelegation
  config: CommerceConfig
  items: { skuId: string; quantity: number }[]
  customer?: { name?: string; email?: string }
  fulfillmentAddress?: ACPAddress
  privateKey: string
}): Promise<{ session: ACPCheckoutSession; receipt: CommerceActionReceipt }> {
  throw new Error(MIGRATED_MSG)
}

export function updateCheckout(_opts: {
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
  throw new Error(MIGRATED_MSG)
}

export function completeCheckout(_opts: {
  signedPassport: SignedPassport
  delegation: CommerceDelegation
  config: CommerceConfig
  sessionId: string
  paymentToken: string
  paymentMethod?: string
  privateKey: string
}): Promise<{ session: ACPCheckoutSession; receipt: CommerceActionReceipt; spendUpdated: CommerceDelegation }> {
  throw new Error(MIGRATED_MSG)
}

export function cancelCheckout(_opts: {
  signedPassport: SignedPassport
  delegation: CommerceDelegation
  config: CommerceConfig
  sessionId: string
  privateKey: string
}): Promise<{ session: ACPCheckoutSession; receipt: CommerceActionReceipt }> {
  throw new Error(MIGRATED_MSG)
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

export function signCommerceReceipt(opts: {
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

export function extractDelegationChain(sp: SignedPassport): string[] {
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

  if (!receipt.receiptId) errors.push('Missing receiptId')
  if (!receipt.agentId) errors.push('Missing agentId')
  if (!receipt.delegationId) errors.push('Missing delegationId')
  if (!receipt.action?.type) errors.push('Missing action type')
  if (!receipt.action?.scopeUsed) errors.push('Missing scopeUsed')
  if (!receipt.beneficiary) errors.push('Missing beneficiary')
  if (!receipt.checkout?.sessionId) errors.push('Missing checkout sessionId')

  return { valid: errors.length === 0, errors }
}
