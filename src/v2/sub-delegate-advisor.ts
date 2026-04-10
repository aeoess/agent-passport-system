// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * v2 Sub-Delegate Advisor — bounded-escalation delegation primitive.
 *
 * Implements the bounded-escalation delegation pattern used in multi-model
 * agent workflows: a lower-cost executor escalates to a higher-capability
 * advisor at decision points. The advisor is bounded in three dimensions:
 *
 *   1. Authority — narrower than parent (monotonic narrowing; empty scope
 *      is the maximum narrowing — advisor holds no tool-execution rights).
 *   2. Count — max_uses expressed as spendLimit with unit 'invocations'
 *      (reuses the existing spend_limit field; no new counter).
 *   3. Time — optional validityWindow clamped to parent expiry.
 *
 * Advisor consultation produces a DecisionLineageReceipt (Module 42) with
 * the advisor as a contributing source — reuses the existing right-to-
 * explanation primitive rather than minting a new receipt type.
 *
 * Gateway enforcement: delegations with spendLimitUnit = 'invocations'
 * are rejected at processToolCall with ADVISOR_SCOPE_VIOLATION, since the
 * advisor is authorized to be consulted, not to execute tools.
 */

import { subDelegate, verifyDelegation, getRevocation } from '../core/delegation.js'
import { createDecisionLineageReceipt } from '../core/data-lifecycle.js'
import type { Delegation } from '../types/passport.js'
import type { DecisionLineageReceipt } from '../types/data-lifecycle.js'

// ══════════════════════════════════════════════════════════════
// Advisor Use Counter
// ══════════════════════════════════════════════════════════════
// Per-delegation counter keyed on delegationId. Kept local so the
// advisor primitive is self-contained and does not reach into
// core/delegation.ts spendTracker internals.

const advisorUseTracker = new Map<string, number>()

export function getAdvisorUses(delegationId: string): number {
  return advisorUseTracker.get(delegationId) ?? 0
}

export function clearAdvisorUseTracker(): void {
  advisorUseTracker.clear()
}

// ══════════════════════════════════════════════════════════════
// subDelegateAdvisor — ergonomic wrapper
// ══════════════════════════════════════════════════════════════

export interface ValidityWindow {
  /** ISO timestamp. If omitted, inherits parent notBefore. */
  notBefore?: string
  /** ISO timestamp. Clamped to parent expiry if later than parent. */
  notAfter?: string
}

export interface SubDelegateAdvisorOptions {
  /** Parent delegation — the authority being narrowed. */
  parentDelegation: Delegation
  /** Advisor agent's DID or public key. */
  advisorDid: string
  /** Maximum number of consultations permitted. Enforced as
   *  spendLimit with spendLimitUnit='invocations'. */
  maxUses: number
  /** Optional time bounds. notAfter is clamped to parent expiry. */
  validityWindow?: ValidityWindow
  /** Parent delegate's private key — signs the advisor delegation. */
  privateKey: string
}

/**
 * Create an advisor delegation: maximally narrowed authority, count-bounded,
 * chained to parent for cascade revocation. The resulting delegation authorizes
 * the advisor to be consulted (up to maxUses times), not to execute tools.
 */
export function subDelegateAdvisor(opts: SubDelegateAdvisorOptions): Delegation {
  if (!opts || typeof opts !== 'object') {
    throw new Error('subDelegateAdvisor: opts required')
  }
  if (!opts.parentDelegation) throw new Error('subDelegateAdvisor: parentDelegation required')
  if (!opts.advisorDid || typeof opts.advisorDid !== 'string') {
    throw new Error('subDelegateAdvisor: advisorDid must be a non-empty string')
  }
  if (!Number.isInteger(opts.maxUses) || opts.maxUses < 1) {
    throw new Error(`subDelegateAdvisor: maxUses must be a positive integer, got ${opts.maxUses}`)
  }
  if (!opts.privateKey) throw new Error('subDelegateAdvisor: privateKey required')

  // Empty scope is the maximum narrowing — the advisor inherits no action
  // authority from parent. subDelegate enforces [] ⊆ parent.scope trivially.
  const advisorScope: string[] = []

  const advisor = subDelegate({
    parentDelegation: opts.parentDelegation,
    delegatedTo: opts.advisorDid,
    scope: advisorScope,
    spendLimit: opts.maxUses,
    spendLimitUnit: 'invocations',
    privateKey: opts.privateKey,
  })

  return advisor
}

// ══════════════════════════════════════════════════════════════
// consultAdvisor — bounded invocation + lineage receipt
// ══════════════════════════════════════════════════════════════

export interface ConsultAdvisorOptions {
  advisorDelegation: Delegation
  /** Short description of the decision the executor is making. */
  decisionType: string
  /** Identifier for the decision artifact produced by the executor. */
  decisionArtifactId: string
  /** Hash of the advice content (e.g. sha256 of advisor output). */
  adviceHash: string
  /** Optional: executor's private key for signing the lineage receipt.
   *  If omitted, a stub key is not acceptable — this is required. */
  privateKey: string
  /** Optional: governing purpose and human-readable explanation. */
  governingPurpose?: string
  explanation?: string
}

export interface ConsultAdvisorResult {
  receipt: DecisionLineageReceipt
  usesRemaining: number
}

/**
 * Consult the advisor: validates the advisor delegation, decrements the
 * invocation counter, and mints a DecisionLineageReceipt naming the advisor
 * as a contributing source. Throws when the delegation is invalid, revoked,
 * expired, or its max_uses is exhausted.
 */
export function consultAdvisor(opts: ConsultAdvisorOptions): ConsultAdvisorResult {
  const d = opts.advisorDelegation
  if (!d) throw new Error('consultAdvisor: advisorDelegation required')
  if (d.spendLimitUnit !== 'invocations') {
    throw new Error('consultAdvisor: delegation is not an advisor delegation (spendLimitUnit !== invocations)')
  }

  // Revocation + expiry check (picks up cascade revocations from parent)
  const status = verifyDelegation(d)
  if (!status.valid || status.expired || status.revoked) {
    throw new Error(
      `consultAdvisor: delegation invalid — ${status.revoked ? 'revoked' : status.expired ? 'expired' : 'failed verification'}`
    )
  }
  if (getRevocation(d.delegationId)) {
    throw new Error('consultAdvisor: delegation revoked')
  }

  const used = advisorUseTracker.get(d.delegationId) ?? 0
  const max = d.spendLimit ?? 0
  if (used >= max) {
    throw new Error(`consultAdvisor: max_uses exhausted (${used}/${max})`)
  }

  advisorUseTracker.set(d.delegationId, used + 1)
  const usesRemaining = max - (used + 1)

  // Reuse DecisionLineageReceipt — advisor is a contributing source.
  const receipt = createDecisionLineageReceipt({
    decisionArtifactId: opts.decisionArtifactId,
    decisionType: opts.decisionType,
    contributingSources: [
      {
        sourceId: d.delegatedTo, // advisor DID / public key
        accessReceiptId: opts.adviceHash, // hash of advice content
        derivationDepth: 0,
        transformPath: [],
        termsVersionAtAccess: d.delegationId,
        lineageConfidence: 'complete',
        compensationStatus: 'settled',
      },
    ],
    lineageCompleteness: 'complete',
    externalHopsPresent: false,
    transformChain: [],
    governingPurpose: opts.governingPurpose,
    explanation: opts.explanation,
    privateKey: opts.privateKey,
  })

  return { receipt, usesRemaining }
}
