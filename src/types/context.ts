// ══════════════════════════════════════════════════════════════════
// Agent Context — Type Definitions
// ══════════════════════════════════════════════════════════════════
// The context is the enforcement boundary. Everything that goes
// through an AgentContext is automatically policy-checked.
// ══════════════════════════════════════════════════════════════════

import type { ValuesFloor, FloorAttestation, Delegation, ActionReceipt } from './passport.js'
import type { ActionIntent, PolicyDecision, PolicyReceipt, PolicyValidator } from './policy.js'

// ── Context Configuration ──

export type EnforcementLevel = 'auto' | 'manual' | 'strict'

/**
 * auto   — Every execute() call runs the 3-signature chain automatically.
 *           Agent can still call protocol functions directly if needed.
 * manual — Agent must explicitly call requestAction() themselves.
 *           Context tracks state but doesn't enforce.
 *           (This is how the protocol works today.)
 * strict — Like auto, but also blocks direct protocol calls that bypass
 *           the context. Only context.execute() can create receipts.
 */

export interface AgentContextConfig {
  /** Enforcement level. Default: 'auto' */
  enforcement: EnforcementLevel

  /** Custom validator. Default: FloorValidatorV1 */
  validator?: PolicyValidator

  /** Evaluator identity (who signs policy decisions).
   *  Default: the agent itself (self-evaluation).
   *  In production, this should be a separate evaluator agent. */
  evaluator?: {
    id: string
    publicKey: string
    privateKey: string
  }

  /** Policy decision TTL in minutes. Default: 5 */
  decisionTTLMinutes?: number

  /** Callback fired on every policy decision. For logging, monitoring. */
  onPolicyDecision?: (decision: PolicyDecision, intent: ActionIntent) => void

  /** Callback fired on audit findings (audit-mode principle failures). */
  onAuditFinding?: (findings: PolicyDecision) => void

  /** Callback fired on warnings (warn-mode principle failures). */
  onWarning?: (decision: PolicyDecision) => void

  /** Callback fired when an action is denied. */
  onDenied?: (decision: PolicyDecision, intent: ActionIntent) => void
}

// ── Execution Request ──

export interface ExecuteRequest {
  /** Action type: "api:fetch", "code:execute", "commerce:purchase", etc. */
  type: string
  /** What the action operates on */
  target: string
  /** Which delegation scope is needed */
  scope: string
  /** Optional spend */
  spend?: { amount: number; currency: string }
  /** Why the agent wants to do this */
  context?: string
  /** Which delegation to use. If omitted, context finds the best match. */
  delegationId?: string
}

// ── Execution Result ──

export interface ExecuteResult {
  /** Whether the action was permitted */
  permitted: boolean
  /** The policy verdict */
  verdict: 'permit' | 'deny' | 'narrow'
  /** The signed intent (signature 1) */
  intent: ActionIntent
  /** The signed policy decision (signature 2) */
  decision: PolicyDecision
  /** Constraints applied if verdict is 'narrow' */
  constraints?: string[]
  /** Audit findings (logged but didn't block) */
  auditFindings?: number
  /** Warnings (surfaced but didn't block) */
  warnings?: number
  /** Human-readable reason */
  reason: string
}

// ── Completed Action (after execution) ──

export interface CompletedAction {
  /** The execution result from the policy check */
  execution: ExecuteResult
  /** The signed action receipt (signature 3) */
  receipt: ActionReceipt
  /** The policy receipt linking all 3 signatures */
  policyReceipt: PolicyReceipt
}

// ── Context State ──

export interface AgentContextState {
  /** Agent identity */
  agentId: string
  publicKey: string
  /** Active delegations available to this agent */
  delegations: Map<string, Delegation>
  /** Floor this agent attested to */
  floor: ValuesFloor
  attestation: FloorAttestation
  /** All receipts produced through this context */
  receipts: ActionReceipt[]
  /** All policy decisions made through this context */
  decisions: PolicyDecision[]
  /** All policy receipts linking the 3-signature chains */
  policyReceipts: PolicyReceipt[]
  /** Audit log: every action attempted, permitted or denied */
  auditLog: AuditEntry[]
}

export interface AuditEntry {
  timestamp: string
  action: ExecuteRequest
  verdict: 'permit' | 'deny' | 'narrow'
  intentId: string
  decisionId: string
  receiptId?: string    // only if action was completed
  reason: string
  enforcement: {
    inlinePassed: boolean
    auditIssueCount: number
    warningCount: number
  }
}
