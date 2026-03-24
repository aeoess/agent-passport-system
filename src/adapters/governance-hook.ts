// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Generic Governance Hook — framework-agnostic adapter interface.
 *
 * Any agent framework (CrewAI, ADK, LangChain, AutoGen, A2A) implements
 * this interface to get APS governance for free.
 *
 * The hook wraps the framework's action lifecycle:
 *   beforeAction → policy evaluation → action execution → afterAction → receipt
 */

import { createHash, randomBytes } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from '../core/canonical.js'
import { generateKeyPair } from '../crypto/keys.js'
import type { ActionIntent, PolicyDecision, PolicyReceipt } from '../types/policy.js'

// ═══════════════════════════════════════
// Types
// ═══════════════════════════════════════

export interface GovernanceHookConfig {
  agentId: string
  agentPublicKey: string
  agentPrivateKey: string
  delegationId: string
  /** Scopes this agent is authorized for */
  allowedScopes: string[]
  /** Values floor principles to enforce (default: all 8) */
  enforcedPrinciples?: string[]
  /** Maximum spend per action (for commerce) */
  spendLimitPerAction?: number
  /** Whether to generate receipts for read-only actions */
  receiptForReads?: boolean
}

export interface ActionDescriptor {
  /** What the agent wants to do */
  type: string
  /** What it's acting on */
  target: string
  /** Required scope */
  scopeRequired: string
  /** Framework-specific metadata */
  metadata?: Record<string, unknown>
  /** Estimated cost (for commerce actions) */
  estimatedCost?: number
}

export type GovernanceVerdict = 'permit' | 'deny' | 'narrow' | 'audit'

export interface GovernanceResult {
  verdict: GovernanceVerdict
  intentId: string
  decisionId: string
  reason: string
  /** Narrowed scope if verdict is 'narrow' */
  narrowedScope?: string[]
  /** Policy violations if verdict is 'deny' */
  violations?: string[]
}

export interface GovernanceReceipt {
  receiptId: string
  intentId: string
  decisionId: string
  agentId: string
  action: ActionDescriptor
  verdict: GovernanceVerdict
  executionResult: 'success' | 'failure' | 'partial'
  startedAt: string
  completedAt: string
  durationMs: number
  signature: string
}

// ═══════════════════════════════════════
// GovernanceHook — the core adapter class
// ═══════════════════════════════════════

export class GovernanceHook {
  private config: GovernanceHookConfig
  private actionLog: GovernanceReceipt[] = []
  private totalSpend = 0

  constructor(config: GovernanceHookConfig) {
    this.config = config
  }

  /**
   * STEP 1: Before action — evaluate policy.
   * Call this before the agent executes anything.
   * Returns permit/deny/narrow/audit.
   */
  beforeAction(action: ActionDescriptor): GovernanceResult {
    const intentId = 'intent_' + randomBytes(8).toString('hex')
    const decisionId = 'dec_' + randomBytes(8).toString('hex')
    const violations: string[] = []

    // Check 1: Scope authorization
    const scopeMatch = this.config.allowedScopes.some(s =>
      s === action.scopeRequired || s === '*' ||
      (s.endsWith(':*') && action.scopeRequired.startsWith(s.slice(0, -1)))
    )
    if (!scopeMatch) {
      violations.push(`Scope "${action.scopeRequired}" not in allowed: [${this.config.allowedScopes.join(', ')}]`)
    }

    // Check 2: Spend limit
    if (action.estimatedCost && this.config.spendLimitPerAction) {
      if (action.estimatedCost > this.config.spendLimitPerAction) {
        violations.push(`Cost $${action.estimatedCost} exceeds limit $${this.config.spendLimitPerAction}`)
      }
    }

    // Check 3: Delegation active (placeholder for revocation check)
    if (!this.config.delegationId) {
      violations.push('No active delegation')
    }

    const verdict: GovernanceVerdict = violations.length > 0 ? 'deny' : 'permit'

    return {
      verdict,
      intentId,
      decisionId,
      reason: violations.length > 0
        ? `Denied: ${violations.join('; ')}`
        : `Permitted: scope "${action.scopeRequired}" authorized`,
      violations: violations.length > 0 ? violations : undefined,
    }
  }

  /**
   * STEP 2: After action — generate signed receipt.
   * Call this after the action completes (success or failure).
   */
  afterAction(
    result: GovernanceResult,
    action: ActionDescriptor,
    executionResult: 'success' | 'failure' | 'partial',
    startedAt: string,
  ): GovernanceReceipt {
    const completedAt = new Date().toISOString()
    const startMs = new Date(startedAt).getTime()
    const endMs = new Date(completedAt).getTime()

    const receiptPayload = {
      receiptId: 'rcpt_' + randomBytes(8).toString('hex'),
      intentId: result.intentId,
      decisionId: result.decisionId,
      agentId: this.config.agentId,
      action,
      verdict: result.verdict,
      executionResult,
      startedAt,
      completedAt,
      durationMs: endMs - startMs,
    }

    const sig = sign(canonicalize(receiptPayload), this.config.agentPrivateKey)
    const receipt: GovernanceReceipt = { ...receiptPayload, signature: sig }

    if (action.estimatedCost && executionResult === 'success') {
      this.totalSpend += action.estimatedCost
    }
    this.actionLog.push(receipt)
    return receipt
  }

  /**
   * CONVENIENCE: Wrap an async action with full governance lifecycle.
   * beforeAction → execute → afterAction → receipt
   */
  async wrap<T>(
    action: ActionDescriptor,
    execute: () => Promise<T>,
  ): Promise<{ result: T | null; receipt: GovernanceReceipt; governance: GovernanceResult }> {
    const governance = this.beforeAction(action)

    if (governance.verdict === 'deny') {
      const receipt = this.afterAction(governance, action, 'failure', new Date().toISOString())
      return { result: null, receipt, governance }
    }

    const startedAt = new Date().toISOString()
    let executionResult: 'success' | 'failure' = 'failure'
    let result: T | null = null

    try {
      result = await execute()
      executionResult = 'success'
    } catch {
      executionResult = 'failure'
    }

    const receipt = this.afterAction(governance, action, executionResult, startedAt)
    return { result, receipt, governance }
  }

  /** Get all receipts from this session */
  getReceipts(): GovernanceReceipt[] { return [...this.actionLog] }

  /** Get total spend this session */
  getTotalSpend(): number { return this.totalSpend }

  /** Verify a receipt signature */
  verifyReceipt(receipt: GovernanceReceipt): boolean {
    const { signature, ...payload } = receipt
    return verify(canonicalize(payload), signature, this.config.agentPublicKey)
  }

  /** Get the agent's governance config (for framework registration) */
  getConfig(): GovernanceHookConfig { return { ...this.config } }
}
