// ══════════════════════════════════════════════════════════════════
// Values Floor Policy — Three-Signature Chain
// ══════════════════════════════════════════════════════════════════
// Architecture from Agent Agora deliberation (px2-006):
//   1. ActionIntent — agent declares what it wants to do (signed)
//   2. PolicyDecision — evaluator checks against floor (signed)
//   3. ActionReceipt — executor proves what was done (signed)
//
// Three signatures. Full audit trail. Every step cryptographically
// provable. The floor becomes not just "did you read it" but
// "here's proof of what was checked."
// ══════════════════════════════════════════════════════════════════

import type { EnforcementMode } from './passport.js'
import type { ContentHash, EvaluationMethod } from './decision-semantics.js'

// ── Action Intent ──
// Before executing, the agent declares intent. This is the request.

export interface ActionIntent {
  intentId: string
  agentId: string
  agentPublicKey: string
  delegationId: string
  action: {
    type: string            // "code_execution", "web_search", etc.
    target: string          // what the action operates on
    scopeRequired: string   // which delegation scope is needed
    spend?: {
      amount: number
      currency: string
    }
  }
  context?: string          // optional: why the agent wants to do this
  contentHash?: ContentHash // Module 37: content-addressable hash of unsigned intent
  createdAt: string
  signature: string         // signed by the requesting agent
}

// ── Policy Decision ──
// The evaluator checks the intent against the floor and delegation.
// This is the permit/deny gate.

export type PolicyVerdict = 'permit' | 'deny' | 'narrow'

export interface PrincipleEvaluation {
  principleId: string       // "F-001", "F-003", etc.
  principleName: string
  status: 'pass' | 'fail' | 'not_applicable'
  detail: string
  enforcementMode?: EnforcementMode  // what happens when this fails
}

export interface PolicyDecision {
  decisionId: string
  intentId: string          // which intent this decides on
  evaluatorId: string       // who evaluated (agent or system)
  evaluatorPublicKey: string
  verdict: PolicyVerdict
  evaluationMethod?: EvaluationMethod  // Module 37: deterministic | model_dependent | hybrid
  principlesEvaluated: PrincipleEvaluation[]
  constraints?: string[]    // if verdict is 'narrow', what constraints apply
  reason: string            // human-readable explanation
  floorVersion: string      // which floor version was used
  evaluatedAt: string
  expiresAt: string         // decision is time-limited
  signature: string         // signed by the evaluator
  // Graduated enforcement (optional — populated by FloorValidatorV1)
  auditFindings?: PrincipleEvaluation[]  // V5-MED-1: removes as-any cast in context.ts
  warnings?: PrincipleEvaluation[]       // V5-MED-1: removes as-any cast in context.ts
  enforcement?: Record<string, unknown>  // enforcement summary from graduated evaluation
}

// ── Policy Receipt ──
// After execution, links intent → decision → receipt.
// The full chain is: "I wanted to do X" → "Floor said yes" → "Here's what happened."

export interface PolicyReceipt {
  policyReceiptId: string
  intentId: string
  decisionId: string
  receiptId: string         // the ActionReceipt from delegation.ts
  chain: {
    intentSignature: string
    decisionSignature: string
    receiptSignature: string
  }
  verifiedAt: string
  signature: string         // signed by the verifier
}

// ── Validator Interface ──
// v1: scope/expiry/registration checks
// v2+: pluggable — OPA, Cedar, LLM-based reasoning evaluators

export interface PolicyValidator {
  readonly version: string
  readonly name: string
  evaluate(
    intent: Omit<ActionIntent, 'signature'>,
    context: ValidationContext
  ): PolicyEvaluationResult
}

export interface ValidationContext {
  floorVersion: string
  floorPrinciples: Array<{
    id: string
    name: string
    enforcement: {
      mode?: EnforcementMode    // graduated enforcement
      technical?: boolean       // deprecated compat
      mechanism: string
    }
    weight: string
  }>
  delegation: {
    scope: string[]
    spendLimit?: number
    spentAmount?: number
    expiresAt: string
    revoked: boolean
    currentDepth: number
    maxDepth: number
  }
  agentRegistered: boolean
  agentAttestationValid: boolean
}

export interface PolicyEvaluationResult {
  verdict: PolicyVerdict
  evaluationMethod?: EvaluationMethod  // Module 37: how the verdict was computed
  principlesEvaluated: PrincipleEvaluation[]
  constraints?: string[]
  reason: string
  // Graduated enforcement output
  auditFindings?: PrincipleEvaluation[]   // audit-mode failures (logged, don't block)
  warnings?: PrincipleEvaluation[]         // warn-mode failures (surfaced, don't block)
  enforcement?: {
    inlinePassed: boolean       // all inline principles passed?
    auditIssueCount: number     // how many audit findings?
    warningCount: number        // how many warnings?
  }
}
