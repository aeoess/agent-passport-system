// ══════════════════════════════════════════════════════════════════
// Layer Integration — Wiring isolated modules into a unified protocol
// ══════════════════════════════════════════════════════════════════
// P1: Connect layers that were developed in isolation.
//
// This module bridges:
//   Commerce → Intent/Policy (require declaration before checkout)
//   Commerce → Attribution   (commerce receipts feed attribution)
//   Commerce → Delegation    (use real delegation verification)
//   Coordination → Agora     (auto-post lifecycle events)
//
// Design principle: bridge functions only — no modifications to
// existing layer implementations. All 182 tests stay untouched.
// ══════════════════════════════════════════════════════════════════

import { createActionIntent, evaluateIntent } from './policy.js'
import { commercePreflight } from './commerce.js'
import { createAgoraMessage, appendToFeed } from './agora.js'
import { verifyDelegation, getRevocation, scopeAuthorizes } from './delegation.js'
import type { SignedPassport, ActionReceipt, Delegation } from '../types/passport.js'
import type { ActionIntent, PolicyDecision, PolicyValidator, ValidationContext } from '../types/policy.js'
import type {
  CommerceDelegation, CommerceActionReceipt,
  ACPMoney, CommercePreflightResult,
} from '../types/commerce.js'
import type { AgoraFeed, AgoraMessage, AgoraRegistry } from '../types/agora.js'
import type { TaskBrief, ReviewDecision, TaskCompletion } from '../types/coordination.js'

// ══════════════════════════════════════
// 1. COMMERCE → INTENT/POLICY
// ══════════════════════════════════════
// Before any commerce action, the agent must declare intent
// and get policy approval. This is the 3-signature chain
// applied to spending money.

export interface CommerceIntentResult {
  intent: ActionIntent
  decision: PolicyDecision
  preflight: CommercePreflightResult
  permitted: boolean
  blockedAt?: 'policy' | 'preflight'
  reason?: string
}

/**
 * Full commerce flow: Intent → Policy → Preflight
 *
 * The agent declares "I want to buy X" (intent),
 * the policy engine checks floor principles (decision),
 * then commerce preflight checks merchant/spend gates.
 *
 * All three must pass. This is the protocol working as designed.
 */
export function commerceWithIntent(opts: {
  // Agent identity
  signedPassport: SignedPassport
  agentPrivateKey: string
  // Delegation (real protocol delegation)
  delegation: Delegation
  commerceDelegation: CommerceDelegation
  // What they want to buy
  merchantName: string
  estimatedTotal: ACPMoney
  actionDescription: string
  // Policy engine
  validator: PolicyValidator
  validationContext: ValidationContext
  evaluatorId: string
  evaluatorPublicKey: string
  evaluatorPrivateKey: string
}): CommerceIntentResult {
  // Step 1: Agent declares intent
  const intent = createActionIntent({
    agentId: opts.signedPassport.passport.agentId,
    agentPublicKey: opts.signedPassport.passport.publicKey,
    delegationId: opts.delegation.delegationId,
    action: {
      type: 'commerce:checkout',
      scopeRequired: 'commerce:checkout',
      target: opts.merchantName,
      spend: { amount: opts.estimatedTotal.amount, currency: opts.estimatedTotal.currency },
    },
    context: `Commerce: ${opts.merchantName} — ${opts.estimatedTotal.amount} ${opts.estimatedTotal.currency}. ${opts.actionDescription}`,
    privateKey: opts.agentPrivateKey,
  })

  // Step 2: Policy engine evaluates
  const decision = evaluateIntent({
    intent,
    validator: opts.validator,
    validationContext: opts.validationContext,
    evaluatorId: opts.evaluatorId,
    evaluatorPublicKey: opts.evaluatorPublicKey,
    evaluatorPrivateKey: opts.evaluatorPrivateKey,
  })

  // If policy denied, stop here
  if (decision.verdict !== 'permit') {
    return {
      intent,
      decision,
      preflight: {
        permitted: false,
        checks: [],
        delegation: opts.commerceDelegation,
        warnings: [],
        blockedReason: `Policy denied: ${decision.verdict} — ${decision.reason}`,
      },
      permitted: false,
      blockedAt: 'policy',
      reason: decision.reason,
    }
  }

  // Step 3: Commerce preflight (merchant, spend, passport gates)
  const preflight = commercePreflight({
    signedPassport: opts.signedPassport,
    delegation: opts.commerceDelegation,
    merchantName: opts.merchantName,
    estimatedTotal: opts.estimatedTotal,
  })

  return {
    intent,
    decision,
    preflight,
    permitted: preflight.permitted,
    blockedAt: preflight.permitted ? undefined : 'preflight',
    reason: preflight.permitted ? undefined : preflight.blockedReason,
  }
}

// ══════════════════════════════════════
// 2. COMMERCE → ATTRIBUTION
// ══════════════════════════════════════
// Commerce receipts must feed into the attribution system.
// This bridge converts CommerceActionReceipt → ActionReceipt
// so computeAttribution() and traceBeneficiary() just work.

/**
 * Convert a CommerceActionReceipt into a standard ActionReceipt.
 *
 * The attribution system doesn't care *what* the agent did —
 * it cares about scope, spend, result, and delegation chain.
 * Commerce receipts have all of that; they just need reshaping.
 */
export function commerceReceiptToActionReceipt(
  commerceReceipt: CommerceActionReceipt,
  resultStatus: 'success' | 'failure' | 'partial' = 'success',
): ActionReceipt {
  return {
    receiptId: commerceReceipt.receiptId,
    version: commerceReceipt.version,
    timestamp: commerceReceipt.timestamp,
    agentId: commerceReceipt.agentId,
    delegationId: commerceReceipt.delegationId,
    action: {
      type: commerceReceipt.action.type,
      target: commerceReceipt.action.target,
      method: commerceReceipt.action.method,
      scopeUsed: commerceReceipt.action.scopeUsed,
      spend: commerceReceipt.action.spend,
    },
    result: {
      status: resultStatus,
      summary: `${commerceReceipt.checkout.merchantName}: ${commerceReceipt.checkout.items.length} items, ` +
        `${commerceReceipt.checkout.totalAmount} ${commerceReceipt.checkout.totalCurrency} — ` +
        `${commerceReceipt.checkout.status}`,
    },
    delegationChain: commerceReceipt.delegationChain,
    signature: commerceReceipt.signature,
  }
}

// ══════════════════════════════════════
// 3. COMMERCE → DELEGATION
// ══════════════════════════════════════
// Commerce has its own CommerceDelegation type.
// This bridge validates it against a real protocol Delegation.

export interface DelegationValidationResult {
  valid: boolean
  errors: string[]
  scopeMatch: boolean
  withinSpendLimit: boolean
  notRevoked: boolean
}

/**
 * Validate a CommerceDelegation against its backing protocol Delegation.
 *
 * CommerceDelegation is a convenience type for commerce flows.
 * But the source of truth is the real Delegation from Layer 1.
 * This function checks that the commerce delegation is consistent
 * with the protocol delegation it claims to represent.
 */
export function validateCommerceDelegation(
  commerceDelegation: CommerceDelegation,
  protocolDelegation: Delegation,
): DelegationValidationResult {
  const errors: string[] = []

  // 1. Delegation IDs must match
  if (commerceDelegation.delegationId !== protocolDelegation.delegationId) {
    errors.push(`Delegation ID mismatch: commerce=${commerceDelegation.delegationId}, protocol=${protocolDelegation.delegationId}`)
  }

  // 2. Check delegation is still valid (not revoked)
  const revocation = getRevocation(protocolDelegation.delegationId)
  const notRevoked = !revocation
  if (revocation) {
    errors.push(`Delegation revoked at ${revocation.revokedAt}: ${revocation.reason || 'no reason'}`)
  }

  // 3. Verify delegation signature
  const verifyResult = verifyDelegation(protocolDelegation)
  if (!verifyResult.valid) {
    errors.push(...verifyResult.errors)
  }

  // 4. Commerce scopes should be within protocol delegation scope
  const scopeMatch = commerceDelegation.scope.every(
    s => scopeAuthorizes(protocolDelegation.scope, s)
  )
  if (!scopeMatch) {
    errors.push(`Commerce scopes [${commerceDelegation.scope.join(', ')}] not within protocol scopes [${protocolDelegation.scope.join(', ')}]`)
  }

  // 5. Spend limit should not exceed protocol limit
  const protocolLimit = protocolDelegation.spendLimit ?? Infinity
  const withinSpendLimit = commerceDelegation.spendLimit <= protocolLimit
  if (!withinSpendLimit) {
    errors.push(`Commerce spend limit ${commerceDelegation.spendLimit} exceeds protocol limit ${protocolLimit}`)
  }

  return {
    valid: errors.length === 0,
    errors,
    scopeMatch,
    withinSpendLimit,
    notRevoked,
  }
}

// ══════════════════════════════════════
// 4. COORDINATION → AGORA
// ══════════════════════════════════════
// Coordination lifecycle events auto-post to the Agora feed.
// Every task brief, evidence submission, review, and completion
// becomes a signed, public message. Humans can follow along.

export type CoordinationEventType =
  | 'task_created'
  | 'task_assigned'
  | 'evidence_submitted'
  | 'review_completed'
  | 'evidence_handed_off'
  | 'deliverable_submitted'
  | 'task_completed'

/**
 * Post a coordination lifecycle event to the Agora.
 *
 * This is how the protocol's coordination becomes transparent.
 * Every state transition is a signed message that anyone can read.
 */
export function coordinationToAgora(opts: {
  event: CoordinationEventType
  taskId: string
  agentId: string
  agentName: string
  publicKey: string
  privateKey: string
  feed: AgoraFeed
  registry: AgoraRegistry
  detail: string
}): { message: AgoraMessage; feed: AgoraFeed } {
  const subjects: Record<CoordinationEventType, string> = {
    task_created: `📋 New task: ${opts.taskId}`,
    task_assigned: `👤 Agent assigned to ${opts.taskId}`,
    evidence_submitted: `📎 Evidence submitted for ${opts.taskId}`,
    review_completed: `✅ Review completed on ${opts.taskId}`,
    evidence_handed_off: `🤝 Evidence handed off in ${opts.taskId}`,
    deliverable_submitted: `📦 Deliverable submitted for ${opts.taskId}`,
    task_completed: `🏁 Task completed: ${opts.taskId}`,
  }

  const message = createAgoraMessage({
    agentId: opts.agentId,
    agentName: opts.agentName,
    publicKey: opts.publicKey,
    privateKey: opts.privateKey,
    topic: `coordination:${opts.taskId}`,
    type: 'announcement',
    subject: subjects[opts.event],
    content: opts.detail,
  })

  const updatedFeed = appendToFeed(opts.feed, message)

  return { message, feed: updatedFeed }
}

// ── Convenience: Post task brief creation ──

export function postTaskCreated(opts: {
  brief: TaskBrief
  agentId: string
  agentName: string
  publicKey: string
  privateKey: string
  feed: AgoraFeed
  registry: AgoraRegistry
}): { message: AgoraMessage; feed: AgoraFeed } {
  return coordinationToAgora({
    event: 'task_created',
    taskId: opts.brief.taskId,
    agentId: opts.agentId,
    agentName: opts.agentName,
    publicKey: opts.publicKey,
    privateKey: opts.privateKey,
    feed: opts.feed,
    registry: opts.registry,
    detail: `Task "${opts.brief.title}" created with ${opts.brief.roles.length} roles and ${opts.brief.deliverables.length} deliverables. ${opts.brief.description}`,
  })
}

// ── Convenience: Post review decision ──

export function postReviewCompleted(opts: {
  review: ReviewDecision
  agentId: string
  agentName: string
  publicKey: string
  privateKey: string
  feed: AgoraFeed
  registry: AgoraRegistry
}): { message: AgoraMessage; feed: AgoraFeed } {
  return coordinationToAgora({
    event: 'review_completed',
    taskId: opts.review.taskId,
    agentId: opts.agentId,
    agentName: opts.agentName,
    publicKey: opts.publicKey,
    privateKey: opts.privateKey,
    feed: opts.feed,
    registry: opts.registry,
    detail: `Review verdict: ${opts.review.verdict} (score: ${opts.review.score}/${opts.review.threshold}). ${opts.review.rationale}`,
  })
}

// ── Convenience: Post task completion ──

export function postTaskCompleted(opts: {
  completion: TaskCompletion
  agentId: string
  agentName: string
  publicKey: string
  privateKey: string
  feed: AgoraFeed
  registry: AgoraRegistry
}): { message: AgoraMessage; feed: AgoraFeed } {
  return coordinationToAgora({
    event: 'task_completed',
    taskId: opts.completion.taskId,
    agentId: opts.agentId,
    agentName: opts.agentName,
    publicKey: opts.publicKey,
    privateKey: opts.privateKey,
    feed: opts.feed,
    registry: opts.registry,
    detail: `Status: ${opts.completion.status}. Agents: ${opts.completion.metrics.agentCount}, ` +
      `Duration: ${opts.completion.metrics.totalDuration}s, ` +
      `Rework cycles: ${opts.completion.metrics.reworkCount}. ` +
      (opts.completion.retrospective || ''),
  })
}
