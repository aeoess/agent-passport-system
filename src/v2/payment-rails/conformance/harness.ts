// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Payment Rails — conformance harness
// ══════════════════════════════════════════════════════════════════
// Any third-party PaymentRail adapter MAY claim conformance to the
// APS governance contract by passing the standard scenarios in this
// module against runConformance(). Equivalent in spirit to the
// byte-parity verifier scripts under scripts/verify-* — but for
// payment rails: we don't pin signed bytes (rail adapters wrap
// different settlement substrates), we pin behavior.
//
// Each scenario is a pure async predicate. A scenario passes when its
// run() returns { ok: true } and fails with { ok: false, reason } on
// any deviation. The harness runs every scenario in isolation:
//
//   - Each scenario receives a fresh wallet_id so the revocation
//     state from earlier scenarios never bleeds in.
//   - Time-sensitive scenarios receive a fixed `now` so adapter
//     clocks don't drift the test.
//   - The harness never mutates the input rail beyond calling its
//     public methods. Adapters that hold persistent state across
//     scenarios are still safe because each scenario keys off its
//     own wallet_id.
//
// Closed taxonomy of denial reasons matches the foundation
// (no_commerce_scope, spend_limit_exceeded, wallet_revoked,
// time_window_violation, rail_error). See ../types.ts.
// ══════════════════════════════════════════════════════════════════

import { verifyPaymentDenial, verifyPaymentReceipt } from '../hooks.js'
import type {
  DelegationView,
  GovernanceHooks,
  PaymentRail,
  PreAuthorizeInput,
} from '../types.js'

// ── Public types ──────────────────────────────────────────────────

export interface ConformanceContext {
  rail: PaymentRail
  hooks: GovernanceHooks
  /** Ed25519 private key (hex) the harness uses to sign receipts and
   *  denials in scenarios that exercise emitReceipt / emitDenial. */
  issuerPrivateKeyHex: string
  /** Fixed clock all scenarios share; deterministic time-window
   *  evaluation depends on this. ISO ms-precision UTC. */
  now: Date
  /** Scenario-scoped wallet identifier. Distinct per scenario so
   *  revocation state from one scenario cannot affect another. */
  walletId: string
}

export type ScenarioOutcome =
  | { ok: true }
  | { ok: false; reason: string }

export interface ConformanceScenario {
  /** Stable scenario id (e.g. 'SCN-001'). Used for filtering and
   *  for cross-implementation report comparison. */
  id: string
  description: string
  run(ctx: ConformanceContext): Promise<ScenarioOutcome>
}

export interface ScenarioReport {
  id: string
  description: string
  pass: boolean
  reason?: string
  duration_ms: number
}

export interface ConformanceReport {
  rail_name: string
  rail_currency: string
  /** ISO 8601 UTC ms timestamp the run started. */
  started_at: string
  finished_at: string
  total: number
  passed: number
  failed: number
  all_pass: boolean
  scenarios: ScenarioReport[]
}

export interface RunConformanceOpts {
  /** Override scenarios. Defaults to STANDARD_SCENARIOS. */
  scenarios?: ConformanceScenario[]
  /** Override issuer private key (hex). Defaults to a pinned test
   *  key so scenario byte output is deterministic across runs. */
  issuerPrivateKeyHex?: string
  /** Override the harness clock. Defaults to '2026-05-03T20:00:00.000Z'. */
  now?: Date
}

// ── Pinned test parameters ────────────────────────────────────────

/** Pinned issuer key for the harness. Adapters MUST NOT use this in
 *  production; it is published in this module on purpose so any
 *  reviewer can reproduce a conformance run byte-for-byte. */
export const HARNESS_ISSUER_PRIV = 'aa'.repeat(32)

export const HARNESS_FIXED_NOW = new Date('2026-05-03T20:00:00.000Z')

const DELEGATION_REF = 'd'.repeat(64)
const ACTION_REF = 'a'.repeat(64)
const TX_PROOF = 'b'.repeat(64)

// ── Helpers ───────────────────────────────────────────────────────

function _baseDelegation(walletId: string, currency: string): DelegationView {
  return {
    receipt_id: DELEGATION_REF,
    scope: ['commerce.purchase'],
    spend_limit_base_units: '1000000000000000000000000000000', // 1 unit
    wallet_id: walletId,
    currency,
  }
}

function _input(
  ctx: ConformanceContext,
  delegation: DelegationView,
  amount: string,
  required_scope = 'commerce.purchase',
): PreAuthorizeInput {
  return {
    delegation,
    required_scope,
    amount_base_units: amount,
    currency: ctx.rail.currency,
    now: ctx.now,
  }
}

// ── Standard scenarios ────────────────────────────────────────────

const SCN_001: ConformanceScenario = {
  id: 'SCN-001',
  description:
    'preAuthorize accepts when delegation has commerce scope and amount within budget',
  async run(ctx) {
    const delegation = _baseDelegation(ctx.walletId, ctx.rail.currency)
    const result = ctx.hooks.preAuthorize(_input(ctx, delegation, '1000'), ctx.rail)
    if (!result.ok) {
      return { ok: false, reason: `expected ok=true, got denial=${result.denial_reason}` }
    }
    return { ok: true }
  },
}

const SCN_002: ConformanceScenario = {
  id: 'SCN-002',
  description:
    "preAuthorize rejects with 'no_commerce_scope' when required_scope absent from delegation",
  async run(ctx) {
    const delegation: DelegationView = {
      ..._baseDelegation(ctx.walletId, ctx.rail.currency),
      scope: ['commerce.refund'], // no purchase
    }
    const result = ctx.hooks.preAuthorize(_input(ctx, delegation, '1000'), ctx.rail)
    if (result.ok) return { ok: false, reason: 'expected denial, got ok' }
    if (result.denial_reason !== 'no_commerce_scope') {
      return {
        ok: false,
        reason: `expected denial_reason=no_commerce_scope, got ${result.denial_reason}`,
      }
    }
    return { ok: true }
  },
}

const SCN_003: ConformanceScenario = {
  id: 'SCN-003',
  description:
    "preAuthorize rejects with 'spend_limit_exceeded' when amount exceeds budget",
  async run(ctx) {
    const delegation: DelegationView = {
      ..._baseDelegation(ctx.walletId, ctx.rail.currency),
      spend_limit_base_units: '1000',
    }
    // Request 10x the limit.
    const result = ctx.hooks.preAuthorize(_input(ctx, delegation, '10000'), ctx.rail)
    if (result.ok) return { ok: false, reason: 'expected denial, got ok' }
    if (result.denial_reason !== 'spend_limit_exceeded') {
      return {
        ok: false,
        reason: `expected denial_reason=spend_limit_exceeded, got ${result.denial_reason}`,
      }
    }
    return { ok: true }
  },
}

const SCN_004: ConformanceScenario = {
  id: 'SCN-004',
  description:
    "preAuthorize rejects with 'wallet_revoked' when the bound wallet has been revoked",
  async run(ctx) {
    await ctx.rail.revokeWallet(ctx.walletId)
    if (!ctx.rail.isWalletRevoked(ctx.walletId)) {
      return { ok: false, reason: 'isWalletRevoked returned false after revokeWallet' }
    }
    const delegation = _baseDelegation(ctx.walletId, ctx.rail.currency)
    const result = ctx.hooks.preAuthorize(_input(ctx, delegation, '1000'), ctx.rail)
    if (result.ok) return { ok: false, reason: 'expected denial, got ok' }
    if (result.denial_reason !== 'wallet_revoked') {
      return {
        ok: false,
        reason: `expected denial_reason=wallet_revoked, got ${result.denial_reason}`,
      }
    }
    return { ok: true }
  },
}

const SCN_005: ConformanceScenario = {
  id: 'SCN-005',
  description:
    "preAuthorize rejects with 'time_window_violation' after delegation.not_after has expired",
  async run(ctx) {
    const expired = new Date(ctx.now.getTime() - 60_000).toISOString()
    const delegation: DelegationView = {
      ..._baseDelegation(ctx.walletId, ctx.rail.currency),
      not_after: expired,
    }
    const result = ctx.hooks.preAuthorize(_input(ctx, delegation, '1000'), ctx.rail)
    if (result.ok) return { ok: false, reason: 'expected denial, got ok' }
    if (result.denial_reason !== 'time_window_violation') {
      return {
        ok: false,
        reason: `expected denial_reason=time_window_violation, got ${result.denial_reason}`,
      }
    }
    return { ok: true }
  },
}

const SCN_006: ConformanceScenario = {
  id: 'SCN-006',
  description: 'emitReceipt produces a PaymentReceipt with a valid Ed25519 signature',
  async run(ctx) {
    const receipt = ctx.hooks.emitReceipt(
      {
        delegation_ref: DELEGATION_REF,
        action_ref: ACTION_REF,
        rail_name: ctx.rail.name,
        amount_base_units: '1000',
        currency: ctx.rail.currency,
        tx_proof: TX_PROOF,
        invoice_id: `inv-${ctx.walletId}`,
        issued_at: ctx.now.toISOString(),
      },
      ctx.issuerPrivateKeyHex,
    )
    if (receipt.claim_type !== 'aps:payment_receipt:v1') {
      return { ok: false, reason: `claim_type=${receipt.claim_type}` }
    }
    if (receipt.signature.length !== 128) {
      return { ok: false, reason: `signature length=${receipt.signature.length}, expected 128` }
    }
    if (receipt.receipt_id.length !== 64) {
      return { ok: false, reason: `receipt_id length=${receipt.receipt_id.length}, expected 64` }
    }
    const v = verifyPaymentReceipt(receipt)
    if (!v.valid) return { ok: false, reason: `verifyPaymentReceipt failed: ${v.reason}` }
    return { ok: true }
  },
}

const SCN_007: ConformanceScenario = {
  id: 'SCN-007',
  description:
    'emitReceipt output round-trips through JSON canonicalization and verifies clean',
  async run(ctx) {
    const receipt = ctx.hooks.emitReceipt(
      {
        delegation_ref: DELEGATION_REF,
        action_ref: ACTION_REF,
        rail_name: ctx.rail.name,
        amount_base_units: '1000',
        currency: ctx.rail.currency,
        tx_proof: TX_PROOF,
        issued_at: ctx.now.toISOString(),
      },
      ctx.issuerPrivateKeyHex,
    )
    // Force a JSON round-trip — receipts may cross transport boundaries
    // (HTTP body, file, queue) before they are verified. The signed
    // bytes MUST survive that round-trip.
    const roundTripped = JSON.parse(JSON.stringify(receipt))
    const v = verifyPaymentReceipt(roundTripped)
    if (!v.valid) {
      return { ok: false, reason: `round-trip verify failed: ${v.reason}` }
    }
    return { ok: true }
  },
}

const SCN_008: ConformanceScenario = {
  id: 'SCN-008',
  description: 'emitDenial produces a PaymentDenial with a valid Ed25519 signature',
  async run(ctx) {
    const denial = ctx.hooks.emitDenial(
      {
        delegation_ref: DELEGATION_REF,
        action_ref: ACTION_REF,
        rail_name: ctx.rail.name,
        amount_base_units: '1000',
        currency: ctx.rail.currency,
        denial_reason: 'no_commerce_scope',
        reason_detail: "scope 'commerce.purchase' not in delegation",
        issued_at: ctx.now.toISOString(),
      },
      ctx.issuerPrivateKeyHex,
    )
    if (denial.claim_type !== 'aps:payment_denial:v1') {
      return { ok: false, reason: `claim_type=${denial.claim_type}` }
    }
    if (denial.signature.length !== 128) {
      return { ok: false, reason: `signature length=${denial.signature.length}, expected 128` }
    }
    const v = verifyPaymentDenial(denial)
    if (!v.valid) return { ok: false, reason: `verifyPaymentDenial failed: ${v.reason}` }
    return { ok: true }
  },
}

const SCN_009: ConformanceScenario = {
  id: 'SCN-009',
  description:
    'revokeWallet() halts subsequent preAuthorize calls bound to that wallet',
  async run(ctx) {
    // Pre-revocation: a baseline call MUST succeed.
    const before = ctx.hooks.preAuthorize(
      _input(ctx, _baseDelegation(ctx.walletId, ctx.rail.currency), '1000'),
      ctx.rail,
    )
    if (!before.ok) {
      return {
        ok: false,
        reason: `pre-revocation preAuthorize unexpectedly denied: ${before.denial_reason}`,
      }
    }

    const revoked = await ctx.rail.revokeWallet(ctx.walletId)
    if (revoked !== true) {
      return { ok: false, reason: 'revokeWallet did not return true' }
    }

    // Idempotency: calling revokeWallet a second time MUST still succeed.
    const second = await ctx.rail.revokeWallet(ctx.walletId)
    if (second !== true) {
      return { ok: false, reason: 'revokeWallet not idempotent (second call returned non-true)' }
    }

    const after = ctx.hooks.preAuthorize(
      _input(ctx, _baseDelegation(ctx.walletId, ctx.rail.currency), '1000'),
      ctx.rail,
    )
    if (after.ok) {
      return { ok: false, reason: 'preAuthorize accepted after revokeWallet' }
    }
    if (after.denial_reason !== 'wallet_revoked') {
      return {
        ok: false,
        reason: `expected denial_reason=wallet_revoked, got ${after.denial_reason}`,
      }
    }
    return { ok: true }
  },
}

const SCN_010: ConformanceScenario = {
  id: 'SCN-010',
  description: 'emitted receipt.delegation_ref equals the input delegation receipt_id',
  async run(ctx) {
    const inputRef = 'c'.repeat(64)
    const receipt = ctx.hooks.emitReceipt(
      {
        delegation_ref: inputRef,
        action_ref: ACTION_REF,
        rail_name: ctx.rail.name,
        amount_base_units: '1000',
        currency: ctx.rail.currency,
        tx_proof: TX_PROOF,
        issued_at: ctx.now.toISOString(),
      },
      ctx.issuerPrivateKeyHex,
    )
    if (receipt.delegation_ref !== inputRef) {
      return {
        ok: false,
        reason: `delegation_ref mismatch: got ${receipt.delegation_ref}, expected ${inputRef}`,
      }
    }
    return { ok: true }
  },
}

export const STANDARD_SCENARIOS: readonly ConformanceScenario[] = Object.freeze([
  SCN_001,
  SCN_002,
  SCN_003,
  SCN_004,
  SCN_005,
  SCN_006,
  SCN_007,
  SCN_008,
  SCN_009,
  SCN_010,
])

// ── Runner ────────────────────────────────────────────────────────

/**
 * Run a list of conformance scenarios against a PaymentRail + hooks.
 * Each scenario receives an isolated wallet_id so revocation state
 * never leaks between scenarios. Returns a structured report; never
 * throws on scenario failure (failures land inside the report).
 */
export async function runConformance(
  rail: PaymentRail,
  hooks: GovernanceHooks,
  opts: RunConformanceOpts = {},
): Promise<ConformanceReport> {
  const scenarios = opts.scenarios ?? [...STANDARD_SCENARIOS]
  const issuerPrivateKeyHex = opts.issuerPrivateKeyHex ?? HARNESS_ISSUER_PRIV
  const now = opts.now ?? HARNESS_FIXED_NOW
  const started = new Date()
  const reports: ScenarioReport[] = []

  for (const scenario of scenarios) {
    const ctx: ConformanceContext = {
      rail,
      hooks,
      issuerPrivateKeyHex,
      now,
      walletId: `harness-${scenario.id.toLowerCase()}-${started.getTime()}`,
    }
    const t0 = Date.now()
    let outcome: ScenarioOutcome
    try {
      outcome = await scenario.run(ctx)
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      outcome = { ok: false, reason: `threw: ${msg}` }
    }
    const duration_ms = Date.now() - t0
    if (outcome.ok) {
      reports.push({
        id: scenario.id,
        description: scenario.description,
        pass: true,
        duration_ms,
      })
    } else {
      reports.push({
        id: scenario.id,
        description: scenario.description,
        pass: false,
        reason: outcome.reason,
        duration_ms,
      })
    }
  }

  const finished = new Date()
  const passed = reports.filter((r) => r.pass).length
  const failed = reports.length - passed
  return {
    rail_name: rail.name,
    rail_currency: rail.currency,
    started_at: started.toISOString(),
    finished_at: finished.toISOString(),
    total: reports.length,
    passed,
    failed,
    all_pass: failed === 0,
    scenarios: reports,
  }
}
