// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
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

import type { EnforcementMode, AttestationFreshness } from './passport.js'
import type { ContentHash, EvaluationMethod } from './decision-semantics.js'

// ══════════════════════════════════════════════════════════════════
// M4. Verifier production-hardening (additive, optional)
// ══════════════════════════════════════════════════════════════════
// These types are consumed by the reference verifier-hardening module at
// src/v2/verifier-hardening/. They are all optional on the wire. A v2.2.x
// receipt without `revocation_freshness` canonicalizes and verifies
// unchanged. The action_ref preimage and existing receipt signing are
// untouched: `revocation_freshness` is recorded ALONGSIDE the receipt as a
// new optional field, never folded into any existing signed digest.
//
// Claims language: this metadata is "specified / tested / validated", it is
// not "proved". See the proof box in src/v2/verifier-hardening/index.ts.

/** Result of a revocation-freshness check at verification time.
 *  - 'fresh': the revocation source was checked and is within max staleness.
 *  - 'stale': the source was checked but is older than the allowed window.
 *  - 'unavailable': the source could not be reached at verification time.
 *  - 'skipped': the verifier chose not to check (documented integrator policy). */
export type RevocationFreshnessResult = 'fresh' | 'stale' | 'unavailable' | 'skipped'

/** Recorded outcome of the revocation-freshness check, attached to a policy
 *  receipt as an optional field. Reuses {@link AttestationFreshness} for the
 *  staleness shape rather than inventing a parallel one. */
export interface RevocationFreshnessRecord {
  /** ISO 8601 timestamp of when the verifier consulted the revocation source. */
  checkedAt: string
  /** Identifier for the revocation source consulted (e.g. a CRL URL, a
   *  registry id, 'in-memory'). Not a service; the integrator supplies it. */
  source: string
  /** Reused staleness metadata. `validAt` is when the source data was
   *  produced; `maxAge` / `ttl` express the max staleness the verifier
   *  tolerated. Present whenever the source reported its own age. */
  freshness?: AttestationFreshness
  /** Maximum staleness the verifier was willing to accept, in milliseconds.
   *  Documented so a reader knows the threshold that produced `result`. */
  maxStalenessMs: number
  /** The outcome of the check. */
  result: RevocationFreshnessResult
  /** True when the verifier proceeded even though `result` was 'stale' or
   *  'unavailable'. Records an explicit, auditable risk acceptance. */
  allowedDespiteStale: boolean
}

/** Uniform clock-skew option for the core verify path. Consolidates the
 *  per-verifier skews that already exist (ap2 `clock_skew_seconds`,
 *  instruction-provenance `clockSkewMs`). Those remain as-is; this is the
 *  one millisecond-based option a caller can thread uniformly. */
export interface CoreVerifyClockOptions {
  /** Allowed clock skew in milliseconds for timestamp comparisons.
   *  When omitted, callers fall back to their existing per-verifier default. */
  allowedClockSkewMs?: number
  /** Verifier clock; defaults to the current time when omitted. */
  now?: Date
}

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
  /** M4. Recorded outcome of the revocation-freshness check performed at
   *  verification time. Optional; absence means the verifier did not record a
   *  freshness check. Carried alongside the receipt; does NOT alter the
   *  action_ref preimage or any existing signed digest. */
  revocation_freshness?: RevocationFreshnessRecord
  /** Optional pointer to an external soundness proof for this receipt's decision.
   *  Names the proof artifact by content hash. This field is deliberately format
   *  agnostic: it commits to no cross-system proof object schema, which is tracked
   *  separately (A2A#1463). Presence asserts only that the receipt points at the
   *  named artifact. It does NOT assert that the referenced proof is valid, sound,
   *  or even retrievable. A verifier that trusts a proof_ref must fetch and check
   *  the artifact out of band. Optional and absent by default for back-compat.
   *  See {@link ProofRef} in ../v2/feasibility/proof-ref.js. */
  proof_ref?: ProofRef
  signature: string         // signed by the verifier
}

/** Algorithm used to content-address an external proof artifact. */
export type ProofRefHashAlgorithm = 'sha256'

/** Names an external soundness proof by content hash, without committing to the
 *  proof's internal format. See the proof box in ../v2/feasibility/proof-ref.ts.
 *
 *  Proves: a receipt points at the artifact whose bytes hash to {@link ProofRef.hash}.
 *  Does not prove: that the artifact is a valid or sound proof, or that it is
 *  retrievable. Validation of the referenced proof is out of band and out of scope
 *  for this round. */
export interface ProofRef {
  /** Hash algorithm. Only 'sha256' is specified this round. */
  algorithm: ProofRefHashAlgorithm
  /** Lowercase hex content hash of the external proof artifact's bytes. */
  hash: string
  /** Free-form identifier for the proof system or convention that produced the
   *  artifact (e.g. 'smtlib2', 'lean4', 'coq'). Advisory only. No schema is
   *  committed here; cross-system proof format is tracked at A2A#1463. */
  proofSystem?: string
  /** Optional advisory URI hint for where the artifact may be fetched. The
   *  reference is the hash, not the locator. A verifier MUST re-hash fetched
   *  bytes and compare against {@link ProofRef.hash}. */
  locator?: string
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
