// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// x402 payment rail — public reference adapter (Base + USDC)
// ══════════════════════════════════════════════════════════════════
// Implements PaymentRail over the x402 v1 protocol on Base mainnet
// with USDC as the asset. Settlement runs through a caller-supplied
// facilitator (Coinbase's public CDP facilitator at
// https://api.cdp.coinbase.com/x402 by default, or any compatible
// implementation).
//
// Flow:
//   1. createInvoice(opts) builds an X402PaymentRequirements suitable
//      for the resource server's 402 response body and caches it.
//   2. The resource server returns the requirements to the client.
//   3. The client signs an EIP-3009 transferWithAuthorization, sends
//      back the X-PAYMENT header carrying an X402PaymentPayload.
//   4. The resource server passes (invoice_id, payload) to
//      submitPayment(); the rail calls facilitator /verify, then
//      /settle, then resolves the X402SubmitOutcome.
//   5. Caller emits a signed APS PaymentReceipt with tx_proof set to
//      X402SubmitOutcome.transaction (the on-chain tx hash). Failure
//      paths emit a signed PaymentDenial with denial_reason 'rail_error'
//      and reason_detail carrying the facilitator's invalidReason or
//      errorReason.
//
// Rail does NOT:
//   - Sign EIP-3009 authorizations (sender does that off-chain)
//   - Submit on-chain transactions directly (facilitator does at /settle)
//   - Send outbound payments (sendPayment throws UnsupportedOperation —
//     x402 is a pull protocol from the resource server's perspective)
//   - Implement the HTTP transport (X-PAYMENT header encoding, base64
//     framing). Resource servers wire that themselves; the rail
//     produces and consumes the schema-typed bodies.
// ══════════════════════════════════════════════════════════════════

import { randomUUID } from 'node:crypto'
import type {
  CreateInvoiceOpts,
  PaymentInvoice,
  PaymentRail,
  SendPaymentOpts,
  VerifyTransactionResult,
} from '../types.js'
import {
  X402_VERSION,
  type X402Network,
  type X402PaymentPayload,
  type X402PaymentRequirements,
  type X402Scheme,
  type X402SettleRequest,
  type X402SettleResponse,
  type X402SubmitOutcome,
  type X402VerifyRequest,
  type X402VerifyResponse,
} from './types.js'

// ── Caller-injected facilitator I/O ───────────────────────────────

/** Caller wraps the facilitator HTTP /verify call. */
export type FacilitatorVerify = (
  req: X402VerifyRequest,
) => Promise<X402VerifyResponse>

/** Caller wraps the facilitator HTTP /settle call. */
export type FacilitatorSettle = (
  req: X402SettleRequest,
) => Promise<X402SettleResponse>

// ── Configuration ─────────────────────────────────────────────────

export interface X402RailConfig {
  /** Recipient wallet address used as PaymentRequirements.payTo. */
  payTo: string
  /** Token contract address (USDC by default). */
  asset: string
  /** Network identifier per x402 v1. */
  network: X402Network
  /** Default scheme. Currently only 'exact' is widely deployed. */
  scheme?: X402Scheme
  /** Default protected-resource URL. createInvoice can override per
   *  invoice via opts. */
  resource: string
  /** Default human-readable description. createInvoice can override. */
  description?: string
  /** Default maxTimeoutSeconds applied to every invoice unless
   *  the caller-supplied expires_in_seconds overrides it. */
  defaultMaxTimeoutSeconds?: number
  /** Optional currency code displayed in PaymentInvoice.amount_human
   *  and recorded on PaymentReceipt.currency. Defaults to 'USDC'. */
  currency?: string
  /** Decimals on the configured asset; used only to format
   *  amount_human. Defaults to 6 (USDC). The wire-level atomic units
   *  (maxAmountRequired, value) are always integer strings. */
  assetDecimals?: number
  /** Optional rail name override. Defaults to
   *  'x402-{network}-{currency}'. */
  name?: string
  /** Optional EIP-712 domain extra (passed through to PaymentRequirements.extra). */
  extra?: Record<string, unknown>
  /** Caller-supplied facilitator /verify implementation. */
  facilitatorVerify: FacilitatorVerify
  /** Caller-supplied facilitator /settle implementation. */
  facilitatorSettle: FacilitatorSettle
}

// ── Cached invoice ────────────────────────────────────────────────

interface CachedInvoice extends PaymentInvoice {
  /** The X402PaymentRequirements served back to the client. */
  requirements: X402PaymentRequirements
  /** PaymentPayload received via submitPayment, when present. */
  receivedPayload?: X402PaymentPayload
  /** Settle response, when settled. */
  settled?: X402SettleResponse
}

// ── Rail ──────────────────────────────────────────────────────────

export class X402PaymentRail implements PaymentRail {
  readonly name: string
  readonly currency: string

  private readonly config: X402RailConfig
  private readonly invoices = new Map<string, CachedInvoice>()
  /** Tx hash → invoice id, populated on settle. Lets verifyTransaction
   *  resolve a previously-settled invoice from a tx hash. */
  private readonly txIndex = new Map<string, string>()
  private readonly revokedWallets = new Set<string>()

  constructor(config: X402RailConfig) {
    this.config = config
    this.currency = config.currency ?? 'USDC'
    this.name = config.name ?? `x402-${config.network}-${this.currency}`
  }

  // ── PaymentRail surface ─────────────────────────────────────────

  async createInvoice(opts: CreateInvoiceOpts): Promise<PaymentInvoice> {
    const scheme = this.config.scheme ?? 'exact'
    const decimals = this.config.assetDecimals ?? 6
    const maxTimeoutSeconds =
      opts.expires_in_seconds ?? this.config.defaultMaxTimeoutSeconds ?? 60

    const requirements: X402PaymentRequirements = {
      scheme,
      network: this.config.network,
      maxAmountRequired: opts.amount_base_units,
      asset: this.config.asset,
      payTo: this.config.payTo,
      resource: this.config.resource,
      description: this.config.description ?? this.config.resource,
      maxTimeoutSeconds,
    }
    if (this.config.extra !== undefined) {
      requirements.extra = this.config.extra
    }

    const invoiceId = randomUUID()
    const now = new Date()
    const expiresAt = new Date(now.getTime() + maxTimeoutSeconds * 1000).toISOString()

    const metadata: Record<string, unknown> = {
      x402_requirements: requirements,
      x402_version: X402_VERSION,
    }
    if (opts.settlement_id !== undefined) metadata.settlement_id = opts.settlement_id
    if (opts.agent_id !== undefined) metadata.agent_id = opts.agent_id

    const invoice: PaymentInvoice = {
      invoice_id: invoiceId,
      rail_name: this.name,
      amount_base_units: opts.amount_base_units,
      amount_human: `${_formatAtomic(opts.amount_base_units, decimals)} ${this.currency}`,
      currency: this.currency,
      destination: this.config.payTo,
      status: 'pending',
      created_at: now.toISOString(),
      expires_at: expiresAt,
      metadata,
    }
    if (opts.memo !== undefined) invoice.memo = opts.memo

    this.invoices.set(invoiceId, { ...invoice, requirements })
    return invoice
  }

  async checkStatus(invoiceId: string): Promise<PaymentInvoice> {
    const cached = this.invoices.get(invoiceId)
    if (cached === undefined) {
      throw new Error(`invoice ${invoiceId} not found in adapter cache`)
    }

    if (cached.status === 'pending' && cached.expires_at !== undefined) {
      if (new Date(cached.expires_at) < new Date()) {
        cached.status = 'expired'
        this.invoices.set(invoiceId, cached)
      }
    }

    return _stripInternal(cached)
  }

  async verifyTransaction(
    txProof: string,
    expectedAmountBaseUnits?: string,
  ): Promise<VerifyTransactionResult> {
    // x402's facilitator /verify takes a PaymentPayload, not a tx hash;
    // the on-chain transaction itself comes from /settle. Verification
    // by tx hash here resolves the cached settled invoice and confirms
    // the tx hash matches.
    const invoiceId = this.txIndex.get(txProof)
    if (invoiceId === undefined) {
      return {
        verified: false,
        amount_base_units: '0',
        error: `tx ${txProof} not associated with any settled invoice on this rail`,
      }
    }
    const cached = this.invoices.get(invoiceId)
    if (cached === undefined || cached.settled === undefined) {
      return {
        verified: false,
        amount_base_units: '0',
        error: `invoice ${invoiceId} no longer cached or never settled`,
      }
    }

    let amountMatches = true
    if (expectedAmountBaseUnits !== undefined) {
      try {
        amountMatches =
          BigInt(cached.amount_base_units) === BigInt(expectedAmountBaseUnits)
      } catch {
        amountMatches = false
      }
    }

    return {
      verified: amountMatches && cached.settled.success,
      amount_base_units: cached.amount_base_units,
      sender: cached.settled.payer,
      receiver: cached.requirements.payTo,
      timestamp: cached.created_at,
    }
  }

  async revokeWallet(walletId: string): Promise<boolean> {
    this.revokedWallets.add(walletId)
    return true
  }

  isWalletRevoked(walletId: string): boolean {
    return this.revokedWallets.has(walletId)
  }

  // ── x402-specific extras ────────────────────────────────────────

  /** x402 is a pull protocol from the resource server's perspective:
   *  the server collects payment by serving 402 + requirements, then
   *  settling the client's signed authorization. There is no outbound
   *  send. Callers that try this on x402 are misusing the rail. */
  async sendPayment(_opts: SendPaymentOpts): Promise<never> {
    throw new Error(
      'x402 rail does not support sendPayment: the protocol settles ' +
        'client-signed EIP-3009 authorizations through the facilitator ' +
        '(pull). Use submitPayment(invoiceId, payload) on the resource ' +
        'server when an X-PAYMENT header arrives.',
    )
  }

  /**
   * Drive verify-then-settle for a PaymentPayload that arrived on
   * the resource server (decoded from X-PAYMENT). On success, the
   * cached invoice flips to 'confirmed' with the on-chain tx hash
   * recorded; the caller passes outcome.transaction to emitReceipt
   * as tx_proof. On verification failure, the invoice flips to
   * 'failed' and outcome.invalidReason carries the facilitator's
   * reason; caller passes that to emitDenial with denial_reason
   * 'rail_error'.
   *
   * The rail does not sign or emit APS receipts itself — that stays
   * the caller's responsibility, so the issuer key never leaves the
   * caller's process.
   */
  async submitPayment(
    invoiceId: string,
    payload: X402PaymentPayload,
  ): Promise<X402SubmitOutcome> {
    const cached = this.invoices.get(invoiceId)
    if (cached === undefined) {
      throw new Error(`invoice ${invoiceId} not found in adapter cache`)
    }
    if (cached.status !== 'pending') {
      throw new Error(
        `invoice ${invoiceId} not pending (status=${cached.status}); ` +
          'submitPayment expects a fresh invoice',
      )
    }

    // Verify
    const verifyReq: X402VerifyRequest = {
      x402Version: X402_VERSION,
      paymentPayload: payload,
      paymentRequirements: cached.requirements,
    }
    let verifyResp: X402VerifyResponse
    try {
      verifyResp = await this.config.facilitatorVerify(verifyReq)
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      cached.status = 'failed'
      cached.receivedPayload = payload
      this.invoices.set(invoiceId, cached)
      return {
        verified: false,
        invalidReason: `facilitator_verify_threw: ${msg}`,
      }
    }
    if (!verifyResp.isValid) {
      cached.status = 'failed'
      cached.receivedPayload = payload
      this.invoices.set(invoiceId, cached)
      const out: X402SubmitOutcome = {
        verified: false,
        invalidReason: verifyResp.invalidReason ?? 'invalid_payment_payload',
      }
      if (verifyResp.payer !== undefined) out.payer = verifyResp.payer
      return out
    }

    // Settle
    const settleReq: X402SettleRequest = {
      x402Version: X402_VERSION,
      paymentPayload: payload,
      paymentRequirements: cached.requirements,
    }
    let settleResp: X402SettleResponse
    try {
      settleResp = await this.config.facilitatorSettle(settleReq)
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      cached.status = 'failed'
      cached.receivedPayload = payload
      this.invoices.set(invoiceId, cached)
      const out: X402SubmitOutcome = {
        verified: true,
        settled: false,
        settleErrorReason: `facilitator_settle_threw: ${msg}`,
      }
      if (verifyResp.payer !== undefined) out.payer = verifyResp.payer
      return out
    }

    if (!settleResp.success) {
      cached.status = 'failed'
      cached.receivedPayload = payload
      this.invoices.set(invoiceId, cached)
      const out: X402SubmitOutcome = {
        verified: true,
        settled: false,
        settleErrorReason: settleResp.errorReason ?? 'settlement_failed',
        payer: settleResp.payer,
      }
      return out
    }

    // Confirmed
    cached.status = 'confirmed'
    cached.receivedPayload = payload
    cached.settled = settleResp
    cached.metadata = {
      ...cached.metadata,
      tx_hash: settleResp.transaction,
      payer: settleResp.payer,
      confirmed_at: new Date().toISOString(),
    }
    this.invoices.set(invoiceId, cached)
    if (settleResp.transaction !== '') {
      this.txIndex.set(settleResp.transaction, invoiceId)
    }
    return {
      verified: true,
      settled: true,
      transaction: settleResp.transaction,
      payer: settleResp.payer,
    }
  }

  /** Returns the X402PaymentRequirements cached for an invoice. Used
   *  by the resource server to assemble the 402 response body. */
  getRequirements(invoiceId: string): X402PaymentRequirements | undefined {
    return this.invoices.get(invoiceId)?.requirements
  }
}

// ── Helpers ───────────────────────────────────────────────────────

function _stripInternal(c: CachedInvoice): PaymentInvoice {
  const {
    requirements: _r,
    receivedPayload: _p,
    settled: _s,
    ...rest
  } = c
  return rest
}

/** Format an atomic-units string as a decimal string with `decimals`
 *  fractional digits. Trailing zeros stripped. Used only for human
 *  display in PaymentInvoice.amount_human. */
function _formatAtomic(atomic: string, decimals: number): string {
  if (decimals <= 0) return atomic
  const big = BigInt(atomic)
  const div = BigInt(10) ** BigInt(decimals)
  const whole = big / div
  const frac = big % div
  if (frac === 0n) return whole.toString()
  const fracStr = frac.toString().padStart(decimals, '0').replace(/0+$/, '')
  return `${whole}.${fracStr}`
}

// ── Factory ───────────────────────────────────────────────────────

export function createX402Rail(config: X402RailConfig): X402PaymentRail {
  return new X402PaymentRail(config)
}

/** Default Coinbase CDP facilitator endpoint. The free public tier
 *  supports verification on the EIP-3009 USDC scheme without an API
 *  key (subject to Coinbase's published rate limits, currently
 *  ~1K tx/mo). For higher throughput or non-USDC assets a CDP API key
 *  is required and the caller should wire authorization headers
 *  inside their FacilitatorVerify / FacilitatorSettle implementations.
 *  The rail accepts any compatible facilitator URL — pin via the
 *  closure, do not embed in the rail. */
export const DEFAULT_FACILITATOR_URL = 'https://api.cdp.coinbase.com/x402'

/** USDC contract on Base mainnet (eip155:8453). */
export const USDC_BASE_MAINNET = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'

/** USDC contract on Base Sepolia. */
export const USDC_BASE_SEPOLIA = '0x036CbD53842c5426634e7929541eC2318f3dCF7e'
