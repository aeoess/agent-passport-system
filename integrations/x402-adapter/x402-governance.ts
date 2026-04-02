// ══════════════════════════════════════════════════════════════════
// x402 Governance Adapter — APS Commerce Pipeline for HTTP 402
// ══════════════════════════════════════════════════════════════════
// Wraps x402 payment flow (Coinbase/Cloudflare) with APS 4-gate
// commerce enforcement. Before an agent pays, the governance
// layer checks: identity, delegation scope, merchant approval,
// and spend limits.
//
// x402 handles "how to pay" (HTTP 402 → USDC on Solana/Base).
// APS handles "who is allowed to pay how much to whom."
//
// Source: ecosystem convergence on x402 as dominant payment rail
// (119M+ tx on Base, 35M+ on Solana, Stripe integration Feb 2026)
// ══════════════════════════════════════════════════════════════════

import { canonicalize } from 'agent-passport-system'
import type { Delegation } from 'agent-passport-system'

// ── x402 Types (from x402 protocol spec) ──

/** x402 payment details returned in HTTP 402 response */
export interface X402PaymentDetails {
  /** Price in human-readable format (e.g., "$0.01") */
  price: string
  /** Price in smallest unit (e.g., 10000 for $0.01 USDC) */
  maxAmountRequired: string
  /** Token address or identifier */
  token: string
  /** Network identifier (e.g., "eip155:8453" for Base, "solana:mainnet") */
  network: string
  /** Payment scheme (e.g., "exact") */
  scheme: string
  /** Recipient address */
  payTo: string
  /** Endpoint description */
  description?: string
}

/** Result of APS governance check on an x402 payment */
export interface X402GovernanceResult {
  /** Whether the payment is authorized */
  authorized: boolean
  /** Which gate blocked (if unauthorized) */
  blockedBy?: 'identity' | 'delegation' | 'merchant' | 'spend'
  /** Human-readable reason */
  reason: string
  /** Remaining budget after this payment (if authorized) */
  remainingBudget?: number
  /** Signed policy receipt ID */
  receiptId?: string
  /** The payment details that were evaluated */
  payment: X402PaymentDetails
  /** Timestamp of evaluation */
  evaluatedAt: string
}

// ── Adapter Configuration ──

export interface X402GovernanceConfig {
  /** Agent's passport ID */
  agentId: string
  /** Agent's Ed25519 public key (for identity gate) */
  agentPublicKey: string
  /** Commerce delegations — scope, budget, approved merchants */
  delegations: X402CommerceDelegation[]
}

export interface X402CommerceDelegation {
  /** Delegation ID */
  id: string
  /** Who granted this delegation */
  principalId: string
  /** Allowed payment scopes (e.g., ["api_access", "compute", "*"]) */
  scopes: string[]
  /** Maximum spend in USD */
  spendLimit: number
  /** Amount already spent */
  spentAmount: number
  /** Approved merchant addresses (payTo whitelist). Empty = all allowed */
  approvedMerchants: string[]
  /** Approved networks (e.g., ["eip155:8453", "solana:mainnet"]). Empty = all */
  approvedNetworks: string[]
  /** Expiry timestamp */
  expiresAt: string
}

// ── x402 Governance Adapter ──

export class X402GovernanceAdapter {
  private config: X402GovernanceConfig
  private receipts: X402GovernanceResult[] = []

  constructor(config: X402GovernanceConfig) {
    this.config = config
  }

  /**
   * Evaluate an x402 payment against the APS 4-gate commerce pipeline.
   * Call this when an HTTP 402 response is received, BEFORE signing
   * the payment payload.
   *
   * Returns authorized=true if all 4 gates pass.
   * Returns authorized=false with blockedBy indicating which gate failed.
   */
  evaluate(payment: X402PaymentDetails): X402GovernanceResult {
    const now = new Date().toISOString()
    const priceUsd = this.parsePrice(payment.price)

    // ── Gate 1: Identity ──
    // Agent must have a valid passport (public key present)
    if (!this.config.agentPublicKey) {
      return this.deny(payment, 'identity', 'No agent identity configured', now)
    }

    // ── Gate 2: Delegation ──
    // Find a delegation that covers this payment
    const delegation = this.findDelegation(payment, priceUsd)
    if (!delegation) {
      return this.deny(payment, 'delegation',
        'No active delegation covers this payment scope/network', now)
    }

    // Check delegation expiry
    if (new Date(delegation.expiresAt) < new Date()) {
      return this.deny(payment, 'delegation',
        `Delegation ${delegation.id} expired at ${delegation.expiresAt}`, now)
    }

    // ── Gate 3: Merchant ──
    // If delegation has an approved merchant list, payTo must be on it
    if (delegation.approvedMerchants.length > 0 &&
        !delegation.approvedMerchants.includes(payment.payTo)) {
      return this.deny(payment, 'merchant',
        `Merchant ${payment.payTo} not in approved list`, now)
    }

    // ── Gate 4: Spend ──
    // Amount must be within delegation budget
    if (delegation.spentAmount + priceUsd > delegation.spendLimit) {
      return this.deny(payment, 'spend',
        `Payment $${priceUsd} would exceed budget ($${delegation.spentAmount + priceUsd} > $${delegation.spendLimit})`, now)
    }

    // ── All 4 gates passed ──
    // Update spend tracking
    delegation.spentAmount += priceUsd
    const remaining = delegation.spendLimit - delegation.spentAmount

    const result: X402GovernanceResult = {
      authorized: true,
      reason: `Authorized: $${priceUsd} to ${payment.payTo} via delegation ${delegation.id}`,
      remainingBudget: remaining,
      receiptId: `x402_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      payment,
      evaluatedAt: now,
    }

    this.receipts.push(result)
    return result
  }

  /**
   * Governed fetch — wraps a standard fetch call with x402 governance.
   * If the server returns HTTP 402, evaluates the payment through the
   * 4-gate pipeline before authorizing.
   *
   * Usage:
   *   const adapter = new X402GovernanceAdapter(config)
   *   const response = await adapter.governedFetch('https://api.example.com/data', {
   *     paymentSigner: async (details) => signX402Payment(details, wallet)
   *   })
   */
  async governedFetch(
    url: string,
    options: {
      fetchOptions?: RequestInit
      paymentSigner: (details: X402PaymentDetails) => Promise<string>
    }
  ): Promise<{ response: Response; governance: X402GovernanceResult | null }> {
    // First request — may return 402
    const initial = await fetch(url, options.fetchOptions)

    if (initial.status !== 402) {
      return { response: initial, governance: null }
    }

    // Parse x402 payment details from 402 response
    const paymentHeader = initial.headers.get('X-PAYMENT') || initial.headers.get('x-payment')
    let payment: X402PaymentDetails

    if (paymentHeader) {
      payment = JSON.parse(paymentHeader)
    } else {
      // Try body
      const body = await initial.json().catch(() => null)
      if (!body?.accepts?.[0]) {
        return { response: initial, governance: null }
      }
      payment = body.accepts[0] as X402PaymentDetails
    }

    // ── Run 4-gate governance check ──
    const governance = this.evaluate(payment)

    if (!governance.authorized) {
      // Blocked — return the 402 response unchanged + governance denial
      return { response: initial, governance }
    }

    // ── Authorized — sign and retry ──
    const signedPayment = await options.paymentSigner(payment)

    const retryHeaders = new Headers(options.fetchOptions?.headers)
    retryHeaders.set('X-PAYMENT', signedPayment)

    const retried = await fetch(url, {
      ...options.fetchOptions,
      headers: retryHeaders,
    })

    return { response: retried, governance }
  }

  /** Get all governance receipts */
  getReceipts(): X402GovernanceResult[] {
    return [...this.receipts]
  }

  /** Get spend summary per delegation */
  getSpendSummary(): { delegationId: string; spent: number; limit: number; remaining: number }[] {
    return this.config.delegations.map(d => ({
      delegationId: d.id,
      spent: d.spentAmount,
      limit: d.spendLimit,
      remaining: d.spendLimit - d.spentAmount,
    }))
  }

  // ── Private helpers ──

  private deny(payment: X402PaymentDetails, gate: X402GovernanceResult['blockedBy'], reason: string, now: string): X402GovernanceResult {
    const result: X402GovernanceResult = { authorized: false, blockedBy: gate, reason, payment, evaluatedAt: now }
    this.receipts.push(result)
    return result
  }

  private findDelegation(payment: X402PaymentDetails, priceUsd: number): X402CommerceDelegation | undefined {
    return this.config.delegations.find(d => {
      // Scope match: delegation scopes include the payment scheme or wildcard
      const scopeMatch = d.scopes.includes('*') ||
        d.scopes.includes(payment.scheme) ||
        d.scopes.includes('x402') ||
        d.scopes.includes('api_access')
      // Network match: delegation networks include this network or empty (all)
      const networkMatch = d.approvedNetworks.length === 0 ||
        d.approvedNetworks.includes(payment.network)

      // Not expired
      const notExpired = new Date(d.expiresAt) > new Date()

      // Has budget
      const hasBudget = d.spentAmount + priceUsd <= d.spendLimit

      return scopeMatch && networkMatch && notExpired && hasBudget
    })
  }

  private parsePrice(price: string): number {
    // Handle "$0.01" format
    const cleaned = price.replace(/[^0-9.]/g, '')
    const parsed = parseFloat(cleaned)
    return isNaN(parsed) ? 0 : parsed
  }
}

// ── Factory ──

export function createX402GovernanceAdapter(config: X402GovernanceConfig): X402GovernanceAdapter {
  return new X402GovernanceAdapter(config)
}
