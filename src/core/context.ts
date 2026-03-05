// ══════════════════════════════════════════════════════════════════
// Agent Context — Automatic Protocol Compliance
// ══════════════════════════════════════════════════════════════════
//
// The missing piece between "agent has access to trust infrastructure"
// and "agent is trustworthy."
//
// Without context: agent CAN call evaluateIntent() but nothing
// forces it. The protocol is opt-in at the action level.
//
// With context: every action goes through the 3-signature chain
// automatically. The agent physically cannot skip enforcement.
//
// Usage:
//   const ctx = createAgentContext(agent, floor, { enforcement: 'auto' })
//   ctx.addDelegation(delegation)
//   const result = ctx.execute({ type: 'api:fetch', scope: 'data:read', target: '...' })
//   const completed = ctx.complete(result, { status: 'success', summary: '...' })
//
// ══════════════════════════════════════════════════════════════════

import { v4 as uuidv4 } from 'uuid'
import { sign } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import { createActionIntent, evaluateIntent, createPolicyReceipt, FloorValidatorV1 } from './policy.js'
import { createReceipt, scopeAuthorizes } from './delegation.js'
import { verifyAttestation } from './values.js'
import type { SocialContractAgent } from '../contract.js'
import type { ValuesFloor, FloorAttestation, Delegation, ActionReceipt } from '../types/passport.js'
import type { ActionIntent, PolicyDecision, PolicyReceipt, PolicyValidator, ValidationContext } from '../types/policy.js'
import type {
  AgentContextConfig, AgentContextState,
  ExecuteRequest, ExecuteResult, CompletedAction,
  AuditEntry, EnforcementLevel
} from '../types/context.js'

// ══════════════════════════════════════
// AGENT CONTEXT CLASS
// ══════════════════════════════════════

export class AgentContext {
  private agent: SocialContractAgent
  private floor: ValuesFloor
  private config: Required<Pick<AgentContextConfig, 'enforcement' | 'decisionTTLMinutes'>> & AgentContextConfig
  private validator: PolicyValidator
  private state: AgentContextState

  constructor(
    agent: SocialContractAgent,
    floor: ValuesFloor,
    config: Partial<AgentContextConfig> = {}
  ) {
    this.agent = agent
    this.floor = floor
    this.validator = config.validator || new FloorValidatorV1()
    this.config = {
      enforcement: config.enforcement || 'auto',
      decisionTTLMinutes: config.decisionTTLMinutes || 5,
      ...config
    }

    this.state = {
      agentId: agent.agentId,
      publicKey: agent.publicKey,
      delegations: new Map(),
      floor,
      attestation: agent.attestation!,
      receipts: [],
      decisions: [],
      policyReceipts: [],
      auditLog: []
    }
  }

  // ── Delegation Management ──

  /** Register a delegation this agent can use. */
  addDelegation(delegation: Delegation): void {
    this.state.delegations.set(delegation.delegationId, delegation)
  }

  /** Remove a delegation (e.g., after revocation). */
  removeDelegation(delegationId: string): boolean {
    return this.state.delegations.delete(delegationId)
  }

  /** Find the best matching delegation for a required scope. */
  findDelegation(scopeRequired: string): Delegation | null {
    for (const [, d] of this.state.delegations) {
      if (scopeAuthorizes(d.scope, scopeRequired) && new Date(d.expiresAt) > new Date()) {
        return d
      }
    }
    return null
  }

  // ── Core: Execute with Enforcement ──

  /**
   * Execute an action through the policy engine.
   *
   * In 'auto' and 'strict' mode, this runs the full 3-signature chain:
   *   1. Creates ActionIntent (signed by this agent)
   *   2. Evaluates against floor via validator (signed by evaluator)
   *   3. Returns the decision — caller decides whether to proceed
   *
   * In 'manual' mode, skips enforcement and returns a permit.
   */
  execute(request: ExecuteRequest): ExecuteResult {
    // Find delegation
    const delegation = request.delegationId
      ? this.state.delegations.get(request.delegationId) || null
      : this.findDelegation(request.scope)

    if (!delegation) {
      const intent = this.createIntent(request, 'no-delegation')
      const denied = this.createDeniedResult(intent, 'No valid delegation for scope: ' + request.scope)
      this.logAudit(request, denied)
      this.config.onDenied?.(denied.decision, denied.intent)
      return denied
    }

    // Manual mode: skip enforcement, return permit
    if (this.config.enforcement === 'manual') {
      const intent = this.createIntent(request, delegation.delegationId)
      return this.createPermitResult(intent, 'Manual mode — enforcement skipped')
    }

    // Auto/Strict mode: full 3-signature chain
    return this.enforceAction(request, delegation)
  }

  /**
   * Complete an action after execution.
   *
   * Takes the ExecuteResult from execute() plus the actual outcome,
   * creates the ActionReceipt (signature 3) and PolicyReceipt
   * (linking all 3 signatures).
   */
  complete(
    execution: ExecuteResult,
    outcome: { status: 'success' | 'failure' | 'partial'; summary: string }
  ): CompletedAction {
    if (!execution.permitted) {
      throw new Error('Cannot complete a denied action')
    }

    const delegation = this.state.delegations.get(execution.intent.delegationId)
    if (!delegation) {
      throw new Error('Delegation not found: ' + execution.intent.delegationId)
    }

    // Create ActionReceipt (signature 3)
    const receipt = createReceipt({
      agentId: this.agent.agentId,
      delegationId: delegation.delegationId,
      delegation,
      action: {
        type: execution.intent.action.type,
        target: execution.intent.action.target,
        scopeUsed: execution.intent.action.scopeRequired,
        spend: execution.intent.action.spend
      },
      result: outcome,
      delegationChain: [delegation.delegatedBy, this.agent.publicKey],
      privateKey: this.agent.keyPair.privateKey
    })

    // Create PolicyReceipt (links all 3 signatures)
    const evaluatorKey = this.config.evaluator?.privateKey || this.agent.keyPair.privateKey
    const policyReceipt = createPolicyReceipt({
      intent: execution.intent,
      decision: execution.decision,
      receipt,
      verifierPrivateKey: evaluatorKey
    })

    // Store everything
    this.state.receipts.push(receipt)
    this.state.policyReceipts.push(policyReceipt)

    // Update audit log with receipt
    const lastAudit = this.state.auditLog[this.state.auditLog.length - 1]
    if (lastAudit && lastAudit.intentId === execution.intent.intentId) {
      lastAudit.receiptId = receipt.receiptId
    }

    return { execution, receipt, policyReceipt }
  }

  // ── Internal: Enforcement Logic ──

  private enforceAction(request: ExecuteRequest, delegation: Delegation): ExecuteResult {
    // 1. Create ActionIntent (signature 1)
    const intent = createActionIntent({
      agentId: this.agent.agentId,
      agentPublicKey: this.agent.publicKey,
      delegationId: delegation.delegationId,
      action: {
        type: request.type,
        target: request.target,
        scopeRequired: request.scope,
        spend: request.spend
      },
      context: request.context,
      privateKey: this.agent.keyPair.privateKey
    })

    // 2. Build validation context
    const validationContext = this.buildValidationContext(delegation)

    // 3. Evaluate against floor (signature 2)
    const evaluatorId = this.config.evaluator?.id || this.agent.agentId
    const evaluatorPub = this.config.evaluator?.publicKey || this.agent.publicKey
    const evaluatorPriv = this.config.evaluator?.privateKey || this.agent.keyPair.privateKey

    const decision = evaluateIntent({
      intent,
      validator: this.validator,
      validationContext,
      evaluatorId,
      evaluatorPublicKey: evaluatorPub,
      evaluatorPrivateKey: evaluatorPriv,
      decisionTTLMinutes: this.config.decisionTTLMinutes
    })

    // Store decision
    this.state.decisions.push(decision)

    // Build result
    const result: ExecuteResult = {
      permitted: decision.verdict !== 'deny',
      verdict: decision.verdict,
      intent,
      decision,
      constraints: decision.constraints,
      auditFindings: (decision as any).auditFindings?.length,
      warnings: (decision as any).warnings?.length,
      reason: decision.reason
    }

    // Fire callbacks
    this.config.onPolicyDecision?.(decision, intent)
    if (decision.verdict === 'deny') {
      this.config.onDenied?.(decision, intent)
    }
    if ((decision as any).auditFindings?.length > 0) {
      this.config.onAuditFinding?.(decision)
    }
    if ((decision as any).warnings?.length > 0) {
      this.config.onWarning?.(decision)
    }

    this.logAudit(request, result)
    return result
  }

  private buildValidationContext(delegation: Delegation): ValidationContext {
    const attValid = this.agent.attestation
      ? verifyAttestation(this.agent.attestation).valid
      : false

    return {
      floorVersion: this.floor.version,
      floorPrinciples: this.floor.floor.map(p => ({
        id: p.id,
        name: p.name!,
        enforcement: p.enforcement,
        weight: p.weight!
      })),
      delegation: {
        scope: delegation.scope,
        spendLimit: delegation.spendLimit,
        spentAmount: delegation.spentAmount || 0,
        expiresAt: delegation.expiresAt,
        revoked: false,
        currentDepth: delegation.currentDepth,
        maxDepth: delegation.maxDepth
      },
      agentRegistered: true,
      agentAttestationValid: attValid
    }
  }

  // ── Internal: Result Builders ──

  private createIntent(request: ExecuteRequest, delegationId: string): ActionIntent {
    return createActionIntent({
      agentId: this.agent.agentId,
      agentPublicKey: this.agent.publicKey,
      delegationId,
      action: {
        type: request.type,
        target: request.target,
        scopeRequired: request.scope,
        spend: request.spend
      },
      context: request.context,
      privateKey: this.agent.keyPair.privateKey
    })
  }

  private createDeniedResult(intent: ActionIntent, reason: string): ExecuteResult {
    // Create a synthetic denial decision (not from the validator)
    const evaluatorPriv = this.config.evaluator?.privateKey || this.agent.keyPair.privateKey
    const evaluatorPub = this.config.evaluator?.publicKey || this.agent.publicKey
    const evaluatorId = this.config.evaluator?.id || this.agent.agentId

    // Use evaluateIntent would fail without delegation context, so build synthetic

    const now = new Date()
    const expires = new Date(now)
    expires.setMinutes(expires.getMinutes() + (this.config.decisionTTLMinutes || 5))

    const decision: Omit<PolicyDecision, 'signature'> = {
      decisionId: 'pdec_' + uuidv4().slice(0, 12),
      intentId: intent.intentId,
      evaluatorId,
      evaluatorPublicKey: evaluatorPub,
      verdict: 'deny',
      principlesEvaluated: [],
      reason,
      floorVersion: this.floor.version,
      evaluatedAt: now.toISOString(),
      expiresAt: expires.toISOString()
    }

    const signature = sign(canonicalize(decision), evaluatorPriv)
    const signedDecision: PolicyDecision = { ...decision, signature }

    this.state.decisions.push(signedDecision)

    return {
      permitted: false,
      verdict: 'deny',
      intent,
      decision: signedDecision,
      reason
    }
  }

  private createPermitResult(intent: ActionIntent, reason: string): ExecuteResult {
    const now = new Date()
    const manualDecision: PolicyDecision = {
      decisionId: `manual-${intent.intentId}`,
      intentId: intent.intentId,
      evaluatorId: 'manual-mode',
      evaluatorPublicKey: '',
      verdict: 'permit',
      principlesEvaluated: [],
      reason,
      floorVersion: this.floor.version,
      evaluatedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 3600_000).toISOString(),
      signature: '',  // Explicitly unsigned — manual mode bypass
    }
    return {
      permitted: true,
      verdict: 'permit',
      intent,
      decision: manualDecision,
      reason
    }
  }

  private logAudit(request: ExecuteRequest, result: ExecuteResult): void {
    this.state.auditLog.push({
      timestamp: new Date().toISOString(),
      action: request,
      verdict: result.verdict,
      intentId: result.intent.intentId,
      decisionId: result.decision.decisionId || 'manual',
      receiptId: undefined,
      reason: result.reason,
      enforcement: {
        inlinePassed: result.verdict !== 'deny',
        auditIssueCount: result.auditFindings || 0,
        warningCount: result.warnings || 0
      }
    })
  }

  // ── Query State ──

  /** Get the current enforcement level. */
  get enforcement(): EnforcementLevel { return this.config.enforcement }

  /** Get all receipts produced through this context. */
  get allReceipts(): ActionReceipt[] { return [...this.state.receipts] }

  /** Get all policy decisions made through this context. */
  get allDecisions(): PolicyDecision[] { return [...this.state.decisions] }

  /** Get the full audit log. */
  get auditLog(): AuditEntry[] { return [...this.state.auditLog] }

  /** Get context state snapshot (for serialization / inspection). */
  getState(): AgentContextState { return { ...this.state } }

  /** How many actions have been permitted vs denied. */
  get stats(): { permitted: number; denied: number; narrowed: number; total: number } {
    const log = this.state.auditLog
    return {
      permitted: log.filter(e => e.verdict === 'permit').length,
      denied: log.filter(e => e.verdict === 'deny').length,
      narrowed: log.filter(e => e.verdict === 'narrow').length,
      total: log.length
    }
  }
}

// ══════════════════════════════════════
// FACTORY FUNCTION
// ══════════════════════════════════════

/**
 * Create an Agent Context — the enforcement boundary.
 *
 * Every action that goes through this context is automatically
 * checked against the Values Floor via the 3-signature chain.
 *
 * @param agent - From joinSocialContract()
 * @param floor - The Values Floor to enforce
 * @param config - Enforcement level and callbacks
 */
export function createAgentContext(
  agent: SocialContractAgent,
  floor: ValuesFloor,
  config?: Partial<AgentContextConfig>
): AgentContext {
  if (!agent.attestation) {
    throw new Error('Agent must have a floor attestation to create a context. Did you pass a floor to joinSocialContract()?')
  }
  return new AgentContext(agent, floor, config)
}
