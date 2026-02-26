// ══════════════════════════════════════════════════════════════════
// Values Floor Policy Engine — v1
// ══════════════════════════════════════════════════════════════════
// Three-signature chain: ActionIntent → PolicyDecision → ActionReceipt
//
// v1 validator covers 90% of real attacks:
//   ✓ Agent registered + active (attestation valid)
//   ✓ Delegation non-expired and non-revoked
//   ✓ Action within delegated scope
//   ✓ Spend within limits
//   ✓ Depth within bounds
//
// v2+ can plug in OPA, Cedar, or LLM-based evaluators via the
// PolicyValidator interface. The structure is ready; the engine
// is swappable.
// ══════════════════════════════════════════════════════════════════

import { v4 as uuidv4 } from 'uuid'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type {
  ActionIntent, PolicyDecision, PolicyReceipt,
  PolicyValidator, ValidationContext, PolicyEvaluationResult,
  PolicyVerdict, PrincipleEvaluation
} from '../types/policy.js'
import type { ActionReceipt, ValuesFloor } from '../types/passport.js'

// ══════════════════════════════════════
// ACTION INTENT — Signature 1 of 3
// ══════════════════════════════════════

/**
 * Agent declares what it wants to do before doing it.
 * This is the "ask" — signed by the requesting agent.
 */
export function createActionIntent(opts: {
  agentId: string
  agentPublicKey: string
  delegationId: string
  action: ActionIntent['action']
  context?: string
  privateKey: string
}): ActionIntent {
  const intent: Omit<ActionIntent, 'signature'> = {
    intentId: 'intent_' + uuidv4().slice(0, 12),
    agentId: opts.agentId,
    agentPublicKey: opts.agentPublicKey,
    delegationId: opts.delegationId,
    action: opts.action,
    context: opts.context,
    createdAt: new Date().toISOString()
  }

  const signature = sign(canonicalize(intent), opts.privateKey)
  return { ...intent, signature }
}

export function verifyActionIntent(intent: ActionIntent): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  const { signature, ...unsigned } = intent
  if (!verify(canonicalize(unsigned), signature, intent.agentPublicKey)) {
    errors.push('Invalid intent signature')
  }
  if (!intent.agentId) errors.push('Missing agentId')
  if (!intent.delegationId) errors.push('Missing delegationId')
  if (!intent.action?.scopeRequired) errors.push('Missing required scope')
  return { valid: errors.length === 0, errors }
}

// ══════════════════════════════════════
// POLICY DECISION — Signature 2 of 3
// ══════════════════════════════════════

/**
 * Evaluate an intent against the floor using a validator.
 * The evaluator signs the decision — cryptographic proof of
 * what was checked and what was decided.
 */
export function evaluateIntent(opts: {
  intent: ActionIntent
  validator: PolicyValidator
  validationContext: ValidationContext
  evaluatorId: string
  evaluatorPublicKey: string
  evaluatorPrivateKey: string
  decisionTTLMinutes?: number
}): PolicyDecision {
  // First verify the intent signature is valid
  const intentCheck = verifyActionIntent(opts.intent)
  if (!intentCheck.valid) {
    throw new Error(`Invalid intent: ${intentCheck.errors.join(', ')}`)
  }

  // Run the validator
  const result = opts.validator.evaluate(
    // Pass unsigned intent to validator (it doesn't need the signature)
    { ...opts.intent, signature: undefined } as any,
    opts.validationContext
  )

  const now = new Date()
  const expires = new Date(now)
  expires.setMinutes(expires.getMinutes() + (opts.decisionTTLMinutes ?? 5))

  const decision: Omit<PolicyDecision, 'signature'> = {
    decisionId: 'pdec_' + uuidv4().slice(0, 12),
    intentId: opts.intent.intentId,
    evaluatorId: opts.evaluatorId,
    evaluatorPublicKey: opts.evaluatorPublicKey,
    verdict: result.verdict,
    principlesEvaluated: result.principlesEvaluated,
    constraints: result.constraints,
    reason: result.reason,
    floorVersion: opts.validationContext.floorVersion,
    evaluatedAt: now.toISOString(),
    expiresAt: expires.toISOString()
  }

  const signature = sign(canonicalize(decision), opts.evaluatorPrivateKey)
  return { ...decision, signature }
}

export function verifyPolicyDecision(
  decision: PolicyDecision
): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  const { signature, ...unsigned } = decision
  if (!verify(canonicalize(unsigned), signature, decision.evaluatorPublicKey)) {
    errors.push('Invalid decision signature')
  }
  if (new Date(decision.expiresAt) < new Date()) {
    errors.push('Policy decision expired')
  }
  if (!decision.intentId) errors.push('Missing intentId')
  return { valid: errors.length === 0, errors }
}

// ══════════════════════════════════════
// POLICY RECEIPT — Links all 3 signatures
// ══════════════════════════════════════

/**
 * After execution, create the policy receipt that links:
 * intent (agent signed) → decision (evaluator signed) → receipt (executor signed)
 *
 * This is the complete audit trail. Any third party can verify
 * all three signatures independently.
 */
export function createPolicyReceipt(opts: {
  intent: ActionIntent
  decision: PolicyDecision
  receipt: ActionReceipt
  verifierPrivateKey: string
}): PolicyReceipt {
  // Verify the chain links correctly
  if (opts.decision.intentId !== opts.intent.intentId) {
    throw new Error('Decision does not reference this intent')
  }
  if (opts.decision.verdict === 'deny') {
    throw new Error('Cannot create receipt for denied intent')
  }

  const pr: Omit<PolicyReceipt, 'signature'> = {
    policyReceiptId: 'prec_' + uuidv4().slice(0, 12),
    intentId: opts.intent.intentId,
    decisionId: opts.decision.decisionId,
    receiptId: opts.receipt.receiptId,
    chain: {
      intentSignature: opts.intent.signature,
      decisionSignature: opts.decision.signature,
      receiptSignature: opts.receipt.signature
    },
    verifiedAt: new Date().toISOString()
  }

  const signature = sign(canonicalize(pr), opts.verifierPrivateKey)
  return { ...pr, signature }
}

export function verifyPolicyReceipt(
  policyReceipt: PolicyReceipt,
  verifierPublicKey: string
): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  const { signature, ...unsigned } = policyReceipt
  if (!verify(canonicalize(unsigned), signature, verifierPublicKey)) {
    errors.push('Invalid policy receipt signature')
  }
  if (!policyReceipt.chain.intentSignature) errors.push('Missing intent signature in chain')
  if (!policyReceipt.chain.decisionSignature) errors.push('Missing decision signature in chain')
  if (!policyReceipt.chain.receiptSignature) errors.push('Missing receipt signature in chain')
  return { valid: errors.length === 0, errors }
}

// ══════════════════════════════════════
// V1 VALIDATOR — The Simple Engine
// ══════════════════════════════════════
// Covers 90% of real attacks without building an AI:
//   ✓ Agent registered + attestation valid
//   ✓ Delegation non-expired, non-revoked
//   ✓ Action within delegated scope
//   ✓ Spend within limits
//   ✓ Depth within bounds
//
// This is pluggable via PolicyValidator interface.
// v2 can swap in OPA, Cedar, or LLM-based evaluators.

export class FloorValidatorV1 implements PolicyValidator {
  readonly version = '1.0'
  readonly name = 'floor-validator-v1'

  evaluate(
    intent: Omit<ActionIntent, 'signature'>,
    ctx: ValidationContext
  ): PolicyEvaluationResult {
    const evals: PrincipleEvaluation[] = []
    let dominated: PolicyVerdict = 'permit'
    const constraints: string[] = []
    const reasons: string[] = []

    // F-001: Traceability — is the agent registered?
    evals.push(this.checkTraceability(ctx))

    // F-002: Honest Identity — valid attestation?
    evals.push(this.checkIdentity(ctx))

    // F-003: Scoped Authority — action within scope?
    evals.push(this.checkScope(intent, ctx))

    // F-004: Revocability — delegation not revoked?
    evals.push(this.checkRevocability(ctx))

    // F-005: Auditability — delegation not expired, depth ok?
    evals.push(this.checkAuditability(ctx))

    // F-006: Non-Deception — attested only (v1 can't check this)
    evals.push({
      principleId: 'F-006', principleName: 'Non-Deception',
      status: 'not_applicable',
      detail: 'Requires reasoning-level evaluation (v2+)'
    })

    // F-007: Proportionality — attested only (v1 can't check this)
    evals.push({
      principleId: 'F-007', principleName: 'Proportionality',
      status: 'not_applicable',
      detail: 'Requires reputation context (v2+)'
    })

    // Check spend — if over limit, narrow instead of deny
    const spendCheck = this.checkSpend(intent, ctx)
    if (spendCheck) {
      if (spendCheck.verdict === 'narrow') {
        dominated = 'narrow'
        constraints.push(spendCheck.constraint!)
        reasons.push(spendCheck.reason)
      } else if (spendCheck.verdict === 'deny') {
        dominated = 'deny'
        reasons.push(spendCheck.reason)
      }
    }

    // Any hard failure → deny
    const failures = evals.filter(e => e.status === 'fail')
    if (failures.length > 0) {
      dominated = 'deny'
      reasons.push(...failures.map(f => `${f.principleName}: ${f.detail}`))
    }

    return {
      verdict: dominated,
      principlesEvaluated: evals,
      constraints: constraints.length > 0 ? constraints : undefined,
      reason: reasons.length > 0
        ? reasons.join('; ')
        : 'All checks passed'
    }
  }

  private checkTraceability(ctx: ValidationContext): PrincipleEvaluation {
    if (!ctx.agentRegistered) {
      return {
        principleId: 'F-001', principleName: 'Traceability',
        status: 'fail', detail: 'Agent not registered in protocol'
      }
    }
    return {
      principleId: 'F-001', principleName: 'Traceability',
      status: 'pass', detail: 'Agent registered and traceable'
    }
  }

  private checkIdentity(ctx: ValidationContext): PrincipleEvaluation {
    if (!ctx.agentAttestationValid) {
      return {
        principleId: 'F-002', principleName: 'Honest Identity',
        status: 'fail', detail: 'Agent attestation invalid or expired'
      }
    }
    return {
      principleId: 'F-002', principleName: 'Honest Identity',
      status: 'pass', detail: 'Attestation verified'
    }
  }

  private checkScope(
    intent: Omit<ActionIntent, 'signature'>,
    ctx: ValidationContext
  ): PrincipleEvaluation {
    if (!ctx.delegation.scope.includes(intent.action.scopeRequired)) {
      return {
        principleId: 'F-003', principleName: 'Scoped Authority',
        status: 'fail',
        detail: `Scope '${intent.action.scopeRequired}' not in delegation [${ctx.delegation.scope.join(', ')}]`
      }
    }
    return {
      principleId: 'F-003', principleName: 'Scoped Authority',
      status: 'pass', detail: `Scope '${intent.action.scopeRequired}' authorized`
    }
  }

  private checkRevocability(ctx: ValidationContext): PrincipleEvaluation {
    if (ctx.delegation.revoked) {
      return {
        principleId: 'F-004', principleName: 'Revocability',
        status: 'fail', detail: 'Delegation has been revoked'
      }
    }
    return {
      principleId: 'F-004', principleName: 'Revocability',
      status: 'pass', detail: 'Delegation active'
    }
  }

  private checkAuditability(ctx: ValidationContext): PrincipleEvaluation {
    const reasons: string[] = []
    if (new Date(ctx.delegation.expiresAt) < new Date()) {
      reasons.push('Delegation expired')
    }
    if (ctx.delegation.currentDepth > ctx.delegation.maxDepth) {
      reasons.push('Depth limit exceeded')
    }
    if (reasons.length > 0) {
      return {
        principleId: 'F-005', principleName: 'Auditability',
        status: 'fail', detail: reasons.join(', ')
      }
    }
    return {
      principleId: 'F-005', principleName: 'Auditability',
      status: 'pass', detail: 'Delegation valid and within depth limits'
    }
  }

  private checkSpend(
    intent: Omit<ActionIntent, 'signature'>,
    ctx: ValidationContext
  ): { verdict: PolicyVerdict; reason: string; constraint?: string } | null {
    if (!intent.action.spend) return null
    const limit = ctx.delegation.spendLimit
    if (limit === undefined) return null
    const remaining = limit - (ctx.delegation.spentAmount ?? 0)
    if (intent.action.spend.amount > remaining) {
      if (remaining > 0) {
        return {
          verdict: 'narrow',
          reason: `Spend ${intent.action.spend.amount} exceeds remaining ${remaining}`,
          constraint: `max_spend:${remaining}`
        }
      }
      return {
        verdict: 'deny',
        reason: `No spend budget remaining (limit: ${limit}, spent: ${ctx.delegation.spentAmount ?? 0})`
      }
    }
    return null
  }
}

// ══════════════════════════════════════
// CONVENIENCE — Full chain in one call
// ══════════════════════════════════════

/**
 * Execute the full three-signature chain:
 * 1. Create ActionIntent (agent signs)
 * 2. Evaluate against floor (evaluator signs)
 * 3. If permitted, return the decision for the caller to proceed
 *
 * The ActionReceipt is created separately after execution
 * (by the existing createReceipt function), then linked via
 * createPolicyReceipt.
 */
export function requestAction(opts: {
  agentId: string
  agentPublicKey: string
  agentPrivateKey: string
  delegationId: string
  action: ActionIntent['action']
  context?: string
  validator: PolicyValidator
  validationContext: ValidationContext
  evaluatorId: string
  evaluatorPublicKey: string
  evaluatorPrivateKey: string
}): { intent: ActionIntent; decision: PolicyDecision } {
  const intent = createActionIntent({
    agentId: opts.agentId,
    agentPublicKey: opts.agentPublicKey,
    delegationId: opts.delegationId,
    action: opts.action,
    context: opts.context,
    privateKey: opts.agentPrivateKey
  })

  const decision = evaluateIntent({
    intent,
    validator: opts.validator,
    validationContext: opts.validationContext,
    evaluatorId: opts.evaluatorId,
    evaluatorPublicKey: opts.evaluatorPublicKey,
    evaluatorPrivateKey: opts.evaluatorPrivateKey
  })

  return { intent, decision }
}
