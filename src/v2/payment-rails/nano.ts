// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Nano payment rail — public reference adapter
// ══════════════════════════════════════════════════════════════════
// Ported from aeoess-gateway/src/payment-rails/nano.ts. The gateway
// version embeds custodial wallet + DB persistence + event bus. This
// reference adapter ships:
//
//   - Unit conversion: xnoToRaw / rawToXno (BigInt-safe)
//   - createInvoice: amount-uniqueness fingerprint via random raw offset
//   - checkStatus: in-memory invoice cache + poll-once caller-supplied
//                  account history (no built-in RPC — caller injects)
//   - verifyTransaction: caller-supplied block_info (no built-in RPC)
//   - revokeWallet / isWalletRevoked: in-memory revocation set
//
// What this adapter DOES NOT do:
//   - Custodial wallet (master seed, HD derivation) — gateway only
//   - Outbound sendPayment — requires wallet credentials, gateway only
//   - DB persistence — gateway routes own this
//   - Network I/O — caller injects nanoRpc and walletStatus callables
//
// The contract is: rails are pure adapters over caller-injected I/O.
// Every state-changing call must go through the GovernanceHooks
// (see hooks.ts) before the rail-side state changes.
// ══════════════════════════════════════════════════════════════════

import { randomUUID } from 'node:crypto'
import type {
  CreateInvoiceOpts,
  PaymentInvoice,
  PaymentRail,
  VerifyTransactionResult,
} from './types.js'

// ── Unit conversion ───────────────────────────────────────────────

const RAW_PER_XNO = BigInt('1000000000000000000000000000000') // 10^30

/** Convert XNO (decimal string or number) to raw (integer string). */
export function xnoToRaw(xno: string | number): string {
  const parts = String(xno).split('.')
  const whole = BigInt(parts[0] || '0') * RAW_PER_XNO
  if (!parts[1]) return whole.toString()
  const decStr = parts[1].padEnd(30, '0').slice(0, 30)
  return (whole + BigInt(decStr)).toString()
}

/** Convert raw (integer string) to XNO (decimal string). */
export function rawToXno(raw: string): string {
  const bigRaw = BigInt(raw)
  const whole = bigRaw / RAW_PER_XNO
  const frac = bigRaw % RAW_PER_XNO
  if (frac === 0n) return whole.toString()
  const fracStr = frac.toString().padStart(30, '0').replace(/0+$/, '')
  return `${whole}.${fracStr}`
}

// ── Caller-injected I/O ───────────────────────────────────────────

/**
 * Read-only callback the rail uses to fetch recent receive blocks
 * for the configured receiving address. The shape mirrors what the
 * Nano JSON-RPC `account_history` action returns; callers can wrap
 * any RPC client (public node, internal node, mock for tests).
 */
export interface NanoHistoryEntry {
  hash: string
  type?: string
  subtype?: string
  account?: string
  /** Raw amount as string. */
  amount: string
  local_timestamp?: string
}

export type FetchHistory = (
  address: string,
  count: number,
) => Promise<NanoHistoryEntry[]>

/**
 * Read-only callback for `verifyTransaction`. Wraps `block_info`.
 */
export interface NanoBlockInfo {
  /** 'true' | 'false' from RPC; rail interprets as boolean. */
  confirmed?: string
  /** Raw amount as string. */
  amount?: string
  block_account?: string
  contents?: { link_as_account?: string }
  local_timestamp?: string
}

export type FetchBlockInfo = (txProof: string) => Promise<NanoBlockInfo>

// ── Invoice cache (in-memory only) ────────────────────────────────

interface CachedInvoice extends PaymentInvoice {
  /** Expected raw amount including the uniqueness offset. */
  expected_raw: string
}

// ── NanoPaymentRail ───────────────────────────────────────────────

export interface NanoRailConfig {
  /** Receiving Nano address (xrb_... or nano_...) the gateway controls. */
  receivingAddress: string
  /** Caller-supplied history fetcher. Required for checkStatus. */
  fetchHistory: FetchHistory
  /** Caller-supplied block_info fetcher. Required for verifyTransaction. */
  fetchBlockInfo: FetchBlockInfo
  /** Optional uniqueness-offset bound (default 9999 raw). The rail adds
   *  a random raw offset in [1, offsetBound] to each invoice so distinct
   *  invoices have distinct on-chain fingerprints. */
  offsetBound?: number
}

export class NanoPaymentRail implements PaymentRail {
  readonly name = 'nano'
  readonly currency = 'XNO'

  private readonly config: NanoRailConfig
  private readonly invoices = new Map<string, CachedInvoice>()
  private readonly revokedWallets = new Set<string>()
  private readonly offsetBound: number

  constructor(config: NanoRailConfig) {
    this.config = config
    this.offsetBound = config.offsetBound ?? 9999
  }

  async createInvoice(opts: CreateInvoiceOpts): Promise<PaymentInvoice> {
    const baseRaw = BigInt(opts.amount_base_units)
    const offset = BigInt(Math.floor(Math.random() * this.offsetBound) + 1)
    const uniqueRaw = (baseRaw + offset).toString()

    const invoiceId = randomUUID()
    const now = new Date()
    const expiresMs = (opts.expires_in_seconds ?? 3600) * 1000
    const expiresAt = new Date(now.getTime() + expiresMs).toISOString()

    // RFC 8785 / canonicalize_jcs preserves null for object values.
    // JSON.stringify(...) drops undefined entirely. To keep an invoice's
    // canonical form round-trippable across JSON encode/decode, we omit
    // optional keys when the caller didn't supply them rather than
    // setting them to undefined.
    const metadata: Record<string, unknown> = {
      amount_raw: uniqueRaw,
      amount_xno_human: rawToXno(uniqueRaw),
    }
    if (opts.settlement_id !== undefined) metadata.settlement_id = opts.settlement_id
    if (opts.agent_id !== undefined) metadata.agent_id = opts.agent_id

    const invoice: PaymentInvoice = {
      invoice_id: invoiceId,
      rail_name: this.name,
      amount_base_units: uniqueRaw,
      amount_human: `${rawToXno(uniqueRaw)} XNO`,
      currency: this.currency,
      destination: this.config.receivingAddress,
      status: 'pending',
      created_at: now.toISOString(),
      expires_at: expiresAt,
      metadata,
    }
    if (opts.memo !== undefined) invoice.memo = opts.memo

    this.invoices.set(invoiceId, { ...invoice, expected_raw: uniqueRaw })
    return invoice
  }

  async checkStatus(invoiceId: string): Promise<PaymentInvoice> {
    const cached = this.invoices.get(invoiceId)
    if (cached === undefined) {
      throw new Error(`invoice ${invoiceId} not found in adapter cache`)
    }

    if (cached.status !== 'pending') return _stripExpected(cached)

    if (cached.expires_at !== undefined && new Date(cached.expires_at) < new Date()) {
      cached.status = 'expired'
      this.invoices.set(invoiceId, cached)
      return _stripExpected(cached)
    }

    let history: NanoHistoryEntry[] = []
    try {
      history = await this.config.fetchHistory(this.config.receivingAddress, 50)
    } catch (e) {
      // Network/transient errors are non-fatal; invoice stays pending.
      // The rail does not surface a 'failed' status on a single transient
      // RPC error — that's a caller-side policy.
      return _stripExpected(cached)
    }

    for (const block of history) {
      const isReceive = block.type === 'receive' || block.subtype === 'receive'
      if (isReceive && block.amount === cached.expected_raw) {
        cached.status = 'confirmed'
        cached.metadata = {
          ...cached.metadata,
          block_hash: block.hash,
          sender: block.account,
          confirmed_at: new Date().toISOString(),
          confirmation_time_ms:
            Date.now() - new Date(cached.created_at).getTime(),
        }
        this.invoices.set(invoiceId, cached)
        break
      }
    }

    return _stripExpected(cached)
  }

  async verifyTransaction(
    txProof: string,
    expectedAmountBaseUnits?: string,
  ): Promise<VerifyTransactionResult> {
    let info: NanoBlockInfo
    try {
      info = await this.config.fetchBlockInfo(txProof)
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      return { verified: false, amount_base_units: '0', error: msg }
    }

    const amountRaw = info.amount ?? '0'
    const confirmed = info.confirmed === 'true'

    let amountMatches = true
    if (expectedAmountBaseUnits !== undefined) {
      try {
        amountMatches = BigInt(amountRaw) === BigInt(expectedAmountBaseUnits)
      } catch {
        amountMatches = false
      }
    }

    const verified = confirmed && amountMatches

    let timestamp: string | undefined
    if (info.local_timestamp !== undefined) {
      const epoch = Number(info.local_timestamp)
      if (!Number.isNaN(epoch)) {
        timestamp = new Date(epoch * 1000).toISOString()
      }
    }

    return {
      verified,
      amount_base_units: amountRaw,
      sender: info.block_account,
      receiver: info.contents?.link_as_account,
      timestamp,
    }
  }

  async revokeWallet(walletId: string): Promise<boolean> {
    this.revokedWallets.add(walletId)
    return true
  }

  isWalletRevoked(walletId: string): boolean {
    return this.revokedWallets.has(walletId)
  }
}

function _stripExpected(c: CachedInvoice): PaymentInvoice {
  const { expected_raw: _ignored, ...rest } = c
  return rest
}

// ── Factory ───────────────────────────────────────────────────────

export function createNanoRail(config: NanoRailConfig): NanoPaymentRail {
  return new NanoPaymentRail(config)
}
