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
  /** Content-addressed request identity (A2A#1672 xsa520/desiorac).
   *  SHA-256(canonical(agentId + action.type + action.scopeRequired + second-precision timestamp)).
   *  Two receipts with the same actionRef describe the same REQUEST.
   *  Compare with PolicyReceipt.compoundDigest (same evaluated DECISION). */
  actionRef?: string
  /** Routing context at intent time — for divergence detection (desiorac OATR#2) */
  routingContext?: {
    intentDid?: string                // DID at intent declaration time
    intentDidDocumentHash?: string    // SHA-256 of resolved DID doc at intent time
    intentEndpointHash?: string       // SHA-256 of resolved endpoint at intent time
  }
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
  layer?: 'structural' | 'trust'     // structural = deterministic, trust = engine-specific
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

// ── Epistemic Claim Status (v2.3, Component 4) ──
// Each claim in a receipt is labelled with its epistemic status so downstream
// verifiers can reject `unresolved` or `self-asserted` claims per policy.
// See docs/ENFORCEMENT-TRUST-ANCHOR.md Component 4 ("typed epistemic receipts").
export type EpistemicStatus =
  | 'closed'               // cryptographically verifiable without honesty assumption
  | 'witnessed'            // verified by an external party under a stated threat model
  | 'unresolved'           // asserted but not externally attested
  | 'witnessed-by-subject' // co-signed by the acting subject (effect-class only)
  | 'self-asserted'        // the gateway's own assertion (effect-class only, weakest)

/** Epistemic labelling for the four claim classes carried by a v2.3 receipt.
 *  v2.3 emitters populate this; v2.3 verifiers prefer it when present.
 *  Absence is legal (v2.2.x backward compatibility). */
export interface EpistemicClaims {
  /** Was the policy actually evaluated against the stated floor? */
  policy_evaluated: EpistemicStatus
  /** Was authority consumed (vs invented by the gateway)?
   *  v2.3 has no consumable-token substrate yet; expect `witnessed` until v3. */
  authority_consumed: EpistemicStatus
  /** Did the action stay within the delegation's scope? */
  scope_within_bounds: EpistemicStatus
  /** Did the effect observably occur at the sink?
   *  Accepts the full `EpistemicStatus` set; `witnessed-by-subject` is the
   *  subject-cosign path and `self-asserted` marks gateway-only assertions. */
  effect_occurred: EpistemicStatus
}

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
  /** Content-addressed request identity, copied from the ActionIntent at receipt creation.
   *  Request identity (actionRef) is orthogonal to decision identity (compoundDigest). */
  actionRef?: string
  /** Compound digest binding intent + receipt + frame (desiorac A2A#1672) */
  compoundDigest?: string   // SHA-256(hash(ActionIntent) + hash(PolicyReceipt) + executionFrameId + timestamp)
  /** Routing context at execution time — compared against intent routingContext for divergence */
  executionRoutingContext?: {
    actualDid?: string
    actualDidDocumentHash?: string
    actualEndpointHash?: string
    resolutionDeltaMs?: number   // ms between intent and execution endpoint resolution
  }
  /** v2.3 — SHA-256 (hex) of the JCS canonicalization of the full delegation chain
   *  that authorized the action. Lets a verifier cross-reference the receipt to the
   *  authority path without replaying the chain itself. Optional for v2.2 back-compat. */
  delegation_chain_root?: string
  /** v2.3 — Number of hops from the root principal to the acting agent.
   *  Redundant with the chain but carried inline for cheap monotonic narrowing checks.
   *  Optional for v2.2 back-compat. */
  delegation_depth?: number
  /** v2.3 — Typed epistemic labels for the four claim classes this receipt carries.
   *  See {@link EpistemicClaims} and docs/ENFORCEMENT-TRUST-ANCHOR.md Component 4.
   *  v2.3 emitters populate this; v2.3 verifiers prefer it when present; v2.2.x
   *  consumers ignore it silently. Optional for back-compat. */
  epistemic_claims?: EpistemicClaims
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
