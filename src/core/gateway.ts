// ══════════════════════════════════════════════════════════════════
// Proxy Gateway — Enforcement Boundary
// ══════════════════════════════════════════════════════════════════
//
// The gateway solves the core unsolved problem in the protocol:
// the enforcement boundary.
//
// Without gateway: SDK is an optional library. Agent can bypass it.
// With gateway: agent sends requests, gateway executes and proves.
// The agent never touches the receipt. Receipt generation moves
// from the agent to the enforcement layer.
//
// Architecture:
//   Agent → [signed request] → Gateway → [policy check]
//     → [execute tool] → [generate receipt] → [return result + proof]
//
// Six properties (from GPT/Gemini hostile review):
//   1. Gateway is the executor (not just the approver)
//   2. Exact parameter binding (tool + params + target + spend)
//   3. Revocation recheck at execution time
//   4. Gateway generates the receipt (not the agent)
//   5. Replay protection (same request can't be used twice)
//   6. Timeout on approvals (approval expires after N seconds)
//
// ══════════════════════════════════════════════════════════════════

import { v4 as uuidv4 } from 'uuid'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import { createActionIntent, evaluateIntent, createPolicyReceipt, FloorValidatorV1 } from './policy.js'
import { verifyDelegation, createReceipt, scopeAuthorizes, getRevocation } from './delegation.js'
import { verifyPassport } from '../verification/verify.js'
import { verifyAttestation } from './values.js'
import { createTaintLabel, createSAO, createExecutionFrame, recordAccess, checkDataFlow, mergeTaints } from './cross-chain.js'
import { checkFulfillment, resolveObligation } from './obligations.js'
import type { Delegation, ActionReceipt, ValuesFloor, FloorAttestation } from '../types/passport.js'
import type { ActionIntent, PolicyDecision, PolicyReceipt, PolicyValidator, ValidationContext } from '../types/policy.js'
import type { TaintLabel, TaintSet, CrossChainPermit, ExecutionFrame, SignedAuthorityObject } from '../types/cross-chain.js'
import type { Obligation, ObligationResolution } from '../types/obligations.js'
import type {
  ToolCallRequest, ToolCallResult, GatewayProof,
  GatewayApproval, ToolExecutor, GatewayConfig,
  RegisteredAgent, GatewayStats
} from '../types/gateway.js'


// ══════════════════════════════════════
// PROXY GATEWAY CLASS
// ══════════════════════════════════════

export class ProxyGateway {
  private config: Required<Pick<GatewayConfig, 'approvalTTLSeconds' | 'maxPendingPerAgent' | 'recheckRevocationOnExecute'>> & GatewayConfig & { requestIdTTLMs: number }
  private validator: PolicyValidator
  private agents: Map<string, RegisteredAgent> = new Map()
  private approvals: Map<string, GatewayApproval> = new Map()
  private usedRequestIds: Map<string, number> = new Map() // requestId → timestamp (NW-001: TTL-based pruning)
  private executor: ToolExecutor
  private stats: GatewayStats = {
    totalRequests: 0,
    totalPermitted: 0,
    totalDenied: 0,
    totalExecuted: 0,
    totalToolErrors: 0,
    replayAttemptsBlocked: 0,
    expiredApprovalsCleared: 0,
    revocationRechecksTriggered: 0,
    activeAgents: 0,
    pendingApprovals: 0,
    crossChainChecks: 0,
    crossChainBlocked: 0,
    crossChainPermitted: 0,
    obligationsRegistered: 0,
    obligationsFulfilled: 0,
    obligationsTerminated: 0
  }

  constructor(config: GatewayConfig, executor: ToolExecutor) {
    this.config = {
      approvalTTLSeconds: config.approvalTTLSeconds ?? 30,
      maxPendingPerAgent: config.maxPendingPerAgent ?? 10,
      recheckRevocationOnExecute: config.recheckRevocationOnExecute ?? true,
      requestIdTTLMs: (config as any).requestIdTTLMs ?? 3_600_000, // 1 hour default (NW-001)
      ...config
    }
    this.validator = config.validator || new FloorValidatorV1()
    this.executor = executor
  }

  // ── Agent Registration ──

  registerAgent(
    passport: RegisteredAgent['passport'],
    attestation: FloorAttestation,
    delegations: Delegation[]
  ): { registered: boolean; error?: string } {
    // Verify passport (SignedPassport wraps AgentPassport)
    const passportCheck = verifyPassport(passport)
    if (!passportCheck.valid) {
      return { registered: false, error: `Invalid passport: ${passportCheck.errors.join(', ')}` }
    }

    // Verify floor attestation
    const attestationCheck = verifyAttestation(attestation)
    if (!attestationCheck.valid) {
      return { registered: false, error: `Invalid floor attestation: ${attestationCheck.errors.join(', ')}` }
    }

    // Verify each delegation
    const delegationMap = new Map<string, Delegation>()
    for (const d of delegations) {
      const status = verifyDelegation(d)
      if (status.valid && !status.expired && !status.revoked) {
        delegationMap.set(d.delegationId, d)
      }
    }

    const agentId = passport.passport.agentId
    this.agents.set(agentId, {
      passport, attestation, delegations: delegationMap,
      executionFrame: this.config.enableCrossChainEnforcement ? createExecutionFrame(agentId) : undefined,
      permits: this.config.enableCrossChainEnforcement ? [] : undefined,
      obligations: this.config.enableObligationMonitoring ? [] : undefined
    })
    this.stats.activeAgents = this.agents.size
    return { registered: true }
  }

  unregisterAgent(agentId: string): boolean {
    for (const [id, approval] of this.approvals) {
      if (approval.agentId === agentId) {
        this.approvals.delete(id)
      }
    }
    const deleted = this.agents.delete(agentId)
    this.stats.activeAgents = this.agents.size
    this.stats.pendingApprovals = Array.from(this.approvals.values()).filter(a => !a.consumed).length
    return deleted
  }

  addDelegation(agentId: string, delegation: Delegation): { added: boolean; error?: string } {
    const agent = this.agents.get(agentId)
    if (!agent) return { added: false, error: 'Agent not registered' }
    const status = verifyDelegation(delegation)
    if (!status.valid) return { added: false, error: `Invalid delegation: ${status.errors?.join(', ')}` }
    if (status.expired) return { added: false, error: 'Delegation expired' }
    if (status.revoked) return { added: false, error: 'Delegation revoked' }
    agent.delegations.set(delegation.delegationId, delegation)
    return { added: true }
  }

  revokeDelegation(agentId: string, delegationId: string): boolean {
    const agent = this.agents.get(agentId)
    if (!agent) return false
    const deleted = agent.delegations.delete(delegationId)
    // Terminate obligations associated with this delegation (Module 20)
    if (deleted && this.config.enableObligationMonitoring && agent.obligations) {
      for (const obligation of agent.obligations) {
        if (obligation.delegationId === delegationId && obligation.status === 'pending') {
          if (!obligation.survivesTermination) {
            obligation.status = 'terminated_by_revocation'
            this.stats.obligationsTerminated = (this.stats.obligationsTerminated || 0) + 1
            const resolution = resolveObligation({
              obligation,
              receipts: [],
              delegationRevoked: true,
              gatewayId: this.config.gatewayId,
              gatewayPrivateKey: this.config.gatewayPrivateKey
            })
            this.config.onObligationResolved?.(resolution)
          }
        }
      }
    }
    this.stats.pendingApprovals = Array.from(this.approvals.values()).filter(a => !a.consumed).length
    return deleted
  }

  // ── Core: Process Tool Call ──

  async processToolCall(request: ToolCallRequest): Promise<ToolCallResult> {
    this.stats.totalRequests++

    // Step 0: Replay protection
    if (this.usedRequestIds.has(request.requestId)) {
      this.stats.replayAttemptsBlocked++
      this.config.onSuspicious?.(request.agentId, `Replay attempt: requestId ${request.requestId}`)
      return {
        executed: false,
        requestId: request.requestId,
        denialReason: 'Replay detected: this requestId has already been processed'
      }
    }

    // Step 1: Verify agent identity
    const agent = this.agents.get(request.agentId)
    if (!agent) {
      this.stats.totalDenied++
      return { executed: false, requestId: request.requestId, denialReason: 'Agent not registered with gateway' }
    }

    // Verify request signature
    const requestPayload = canonicalize({
      requestId: request.requestId,
      agentId: request.agentId,
      tool: request.tool,
      params: request.params,
      scopeRequired: request.scopeRequired,
      spend: request.spend
    })
    const sigValid = verify(requestPayload, request.signature, request.agentPublicKey)
    if (!sigValid) {
      this.stats.totalDenied++
      this.config.onSuspicious?.(request.agentId, 'Invalid request signature')
      return { executed: false, requestId: request.requestId, denialReason: 'Invalid request signature' }
    }

    // Step 2: Find and verify delegation
    const delegation = this.findDelegation(agent, request)
    if (!delegation) {
      this.stats.totalDenied++
      return {
        executed: false, requestId: request.requestId,
        denialReason: `No valid delegation covers scope "${request.scopeRequired}" for tool "${request.tool}"`
      }
    }

    const delegationStatus = verifyDelegation(delegation)
    if (!delegationStatus.valid || delegationStatus.expired || delegationStatus.revoked) {
      this.stats.totalDenied++
      return { executed: false, requestId: request.requestId, denialReason: `Delegation ${delegation.delegationId} is no longer valid` }
    }

    // Step 3: Create intent
    const intent = createActionIntent({
      agentId: this.config.gatewayId,
      agentPublicKey: this.config.gatewayPublicKey,
      privateKey: this.config.gatewayPrivateKey,
      delegationId: delegation.delegationId,
      action: {
        type: request.tool,
        target: JSON.stringify(request.params),
        scopeRequired: request.scopeRequired,
        spend: request.spend
      },
      context: `[Gateway ${this.config.gatewayId}] Proxy for ${request.agentId}: ${request.context || 'Tool call via proxy gateway'}`
    })

    // Step 4: Evaluate intent against policy
    const validationCtx = this.buildValidationContext(agent, delegation)
    const decision = evaluateIntent({
      intent,
      evaluatorId: this.config.gatewayId,
      evaluatorPublicKey: this.config.gatewayPublicKey,
      evaluatorPrivateKey: this.config.gatewayPrivateKey,
      validator: this.validator,
      validationContext: validationCtx
    })

    if (decision.verdict === 'deny') {
      this.stats.totalDenied++
      this.usedRequestIds.set(request.requestId, Date.now())
      const result: ToolCallResult = { executed: false, requestId: request.requestId, denialReason: decision.reason, decision }
      this.config.onToolCall?.(request, result)
      return result
    }

    // Step 5: Revocation recheck (paranoid mode)
    if (this.config.recheckRevocationOnExecute) {
      this.stats.revocationRechecksTriggered++
      const revocation = getRevocation(delegation.delegationId)
      if (revocation) {
        this.stats.totalDenied++
        this.usedRequestIds.set(request.requestId, Date.now())
        return { executed: false, requestId: request.requestId, denialReason: 'Delegation was revoked between approval and execution', decision }
      }
    }

    // Step 5.5: Cross-chain data flow check (Module 18)
    // If the agent's frame is tainted by a different principal than this
    // delegation's principal, block unless a valid permit exists.
    let flowCheckResult: import('../types/cross-chain.js').FlowCheckResult | undefined
    if (this.config.enableCrossChainEnforcement && agent.executionFrame) {
      const actionPrincipalId = delegation.delegatedBy
      const frameTaint = agent.executionFrame.frameTaint
      // Only run check if frame has accumulated taint
      if (frameTaint.labels.length > 0) {
        this.stats.crossChainChecks = (this.stats.crossChainChecks || 0) + 1
        flowCheckResult = checkDataFlow({
          inputTaint: frameTaint,
          actionPrincipalId,
          actionScope: request.scopeRequired,
          permits: agent.permits || [],
          frame: agent.executionFrame
        })
        if (flowCheckResult.verdict === 'blocked') {
          this.stats.crossChainBlocked = (this.stats.crossChainBlocked || 0) + 1
          this.stats.totalDenied++
          this.usedRequestIds.set(request.requestId, Date.now())
          this.config.onCrossChainBlocked?.(request.agentId, flowCheckResult)
          const result: ToolCallResult = {
            executed: false, requestId: request.requestId,
            denialReason: `Cross-chain blocked: ${flowCheckResult.reason}`,
            decision, flowCheck: flowCheckResult
          }
          this.config.onToolCall?.(request, result)
          return result
        }
        if (flowCheckResult.verdict === 'permitted') {
          this.stats.crossChainPermitted = (this.stats.crossChainPermitted || 0) + 1
        }
      }
    }

    // Step 6: Execute the tool (GATEWAY executes, not agent)
    this.stats.totalPermitted++
    let toolResult: { success: boolean; result?: unknown; error?: string }
    try {
      toolResult = await this.executor(request.tool, request.params)
    } catch (err: unknown) {
      this.stats.totalToolErrors++
      this.usedRequestIds.set(request.requestId, Date.now())
      const result: ToolCallResult = { executed: true, requestId: request.requestId, toolError: err instanceof Error ? err.message : String(err), decision }
      this.config.onToolCall?.(request, result)
      return result
    }

    if (!toolResult.success) { this.stats.totalToolErrors++ } else { this.stats.totalExecuted++ }

    // Step 6.5: Taint tracking + SAO wrapping (Module 18)
    // After execution, taint the frame with the delegation's principal
    // and wrap the result in an SAO for downstream taint propagation
    let sao: SignedAuthorityObject | undefined
    if (this.config.enableCrossChainEnforcement && agent.executionFrame && toolResult.success) {
      const taintLabel = createTaintLabel(
        delegation.delegatedBy,         // principal who authorized this
        delegation.delegationId,         // chain ID
        delegation.delegationId,         // delegation ID
        'same-context-only'
      )
      // Record this access on the agent's frame (accumulates taint)
      agent.executionFrame = recordAccess(agent.executionFrame, taintLabel)
      // Wrap result in SAO so downstream consumers see the taint
      sao = createSAO(
        toolResult.result,
        taintLabel,
        this.config.gatewayPrivateKey,
        this.config.gatewayPublicKey
      )
    }

    // Step 7: Generate receipt (GATEWAY signs, not agent)
    const receipt = createReceipt({
      agentId: this.config.gatewayId,
      delegationId: delegation.delegationId,
      delegation: delegation,
      action: {
        type: `gateway:${request.tool}`,
        target: JSON.stringify(request.params),
        scopeUsed: request.scopeRequired,
        spend: request.spend
      },
      result: {
        status: toolResult.success ? 'success' as const : 'failure' as const,
        summary: toolResult.success
          ? `Executed ${request.tool} successfully`
          : `Executed ${request.tool} with error: ${toolResult.error}`
      },
      delegationChain: [this.config.gatewayPublicKey],
      privateKey: this.config.gatewayPrivateKey
    })

    // Step 8: Create policy receipt (links all 3 signatures)
    const policyReceipt = createPolicyReceipt({
      intent,
      decision,
      receipt,
      verifierPrivateKey: this.config.gatewayPrivateKey
    })

    // Step 8.5: Obligation fulfillment check (Module 20)
    // Check if this receipt satisfies any pending obligations for this agent
    const obligationResolutions: ObligationResolution[] = []
    if (this.config.enableObligationMonitoring && agent.obligations && toolResult.success) {
      const receiptForCheck = {
        receiptId: receipt.receiptId,
        action: { type: receipt.action.type, scopeUsed: receipt.action.scopeUsed },
        params: request.params,
        timestamp: receipt.timestamp,
        toolError: undefined
      }
      for (const obligation of agent.obligations) {
        if (obligation.status !== 'pending') continue
        const fulfillment = checkFulfillment(obligation.evidence, [receiptForCheck])
        if (fulfillment.fulfilled) {
          const resolution = resolveObligation({
            obligation,
            receipts: [receiptForCheck],
            gatewayId: this.config.gatewayId,
            gatewayPrivateKey: this.config.gatewayPrivateKey
          })
          obligationResolutions.push(resolution)
          obligation.status = 'fulfilled'
          this.stats.obligationsFulfilled = (this.stats.obligationsFulfilled || 0) + 1
          this.config.onObligationResolved?.(resolution)
        }
      }
    }

    this.usedRequestIds.set(request.requestId, Date.now())

    const proof: GatewayProof = {
      requestSignature: request.signature, decisionSignature: decision.signature,
      receiptSignature: receipt.signature, policyReceipt
    }

    const result: ToolCallResult = {
      executed: true, requestId: request.requestId,
      result: toolResult.result, toolError: toolResult.success ? undefined : toolResult.error,
      proof, receipt, decision,
      sao, flowCheck: flowCheckResult,
      obligationResolutions: obligationResolutions.length > 0 ? obligationResolutions : undefined
    }

    this.config.onToolCall?.(request, result)
    return result
  }

  // ── Two-Phase: Approve then Execute ──

  approve(request: ToolCallRequest): { approved: boolean; approval?: GatewayApproval; denial?: { reason: string; decision?: PolicyDecision } } {
    this.stats.totalRequests++

    if (this.usedRequestIds.has(request.requestId)) {
      this.stats.replayAttemptsBlocked++
      return { approved: false, denial: { reason: 'Replay detected' } }
    }

    const agent = this.agents.get(request.agentId)
    if (!agent) { this.stats.totalDenied++; return { approved: false, denial: { reason: 'Agent not registered' } } }

    const requestPayload = canonicalize({
      requestId: request.requestId, agentId: request.agentId, tool: request.tool,
      params: request.params, scopeRequired: request.scopeRequired, spend: request.spend
    })
    if (!verify(requestPayload, request.signature, request.agentPublicKey)) {
      this.stats.totalDenied++
      return { approved: false, denial: { reason: 'Invalid signature' } }
    }

    const delegation = this.findDelegation(agent, request)
    if (!delegation) { this.stats.totalDenied++; return { approved: false, denial: { reason: `No delegation covers scope "${request.scopeRequired}"` } } }

    const pendingCount = Array.from(this.approvals.values()).filter(a => a.agentId === request.agentId && !a.consumed).length
    if (pendingCount >= this.config.maxPendingPerAgent) {
      this.stats.totalDenied++
      return { approved: false, denial: { reason: 'Too many pending approvals' } }
    }

    const intent = createActionIntent({
      agentId: this.config.gatewayId, agentPublicKey: this.config.gatewayPublicKey, privateKey: this.config.gatewayPrivateKey,
      delegationId: delegation.delegationId,
      action: { type: request.tool, target: JSON.stringify(request.params), scopeRequired: request.scopeRequired, spend: request.spend },
      context: `[Gateway ${this.config.gatewayId}] Proxy for ${request.agentId}: ${request.context || ''}`
    })

    const validationCtx = this.buildValidationContext(agent, delegation)
    const decision = evaluateIntent({
      intent, evaluatorId: this.config.gatewayId, evaluatorPublicKey: this.config.gatewayPublicKey,
      evaluatorPrivateKey: this.config.gatewayPrivateKey, validator: this.validator,
      validationContext: validationCtx
    })

    if (decision.verdict === 'deny') { this.stats.totalDenied++; return { approved: false, denial: { reason: decision.reason, decision } } }

    this.stats.totalPermitted++
    const nonce = uuidv4()
    const ttlMs = this.config.approvalTTLSeconds * 1000
    const approval: GatewayApproval = {
      approvalId: uuidv4(), requestId: request.requestId, agentId: request.agentId,
      tool: request.tool, params: request.params, scopeRequired: request.scopeRequired,
      delegationId: delegation.delegationId, intent, decision,
      expiresAt: new Date(Date.now() + ttlMs).toISOString(), nonce, consumed: false
    }

    this.approvals.set(approval.approvalId, approval)
    this.stats.pendingApprovals = Array.from(this.approvals.values()).filter(a => !a.consumed).length
    return { approved: true, approval }
  }

  async executeApproval(approvalId: string): Promise<ToolCallResult> {
    const approval = this.approvals.get(approvalId)
    if (!approval) return { executed: false, requestId: '', denialReason: 'Approval not found' }
    if (approval.consumed) { this.stats.replayAttemptsBlocked++; return { executed: false, requestId: approval.requestId, denialReason: 'Approval already consumed (replay)' } }
    if (new Date(approval.expiresAt) < new Date()) { this.stats.expiredApprovalsCleared++; this.approvals.delete(approvalId); return { executed: false, requestId: approval.requestId, denialReason: 'Approval expired' } }

    // NW-003: Always check agent exists, regardless of recheckRevocationOnExecute
    const agent = this.agents.get(approval.agentId)
    if (!agent) return { executed: false, requestId: approval.requestId, denialReason: 'Agent unregistered since approval' }
    const delegation = agent.delegations.get(approval.delegationId)
    if (!delegation) return { executed: false, requestId: approval.requestId, denialReason: 'Delegation removed since approval' }

    if (this.config.recheckRevocationOnExecute) {
      this.stats.revocationRechecksTriggered++
      const delegationStatus = verifyDelegation(delegation)
      if (!delegationStatus.valid || delegationStatus.expired || delegationStatus.revoked) return { executed: false, requestId: approval.requestId, denialReason: 'Delegation invalidated since approval' }
    }

    approval.consumed = true
    this.usedRequestIds.set(approval.requestId, Date.now())

    let toolResult: { success: boolean; result?: unknown; error?: string }
    try { toolResult = await this.executor(approval.tool, approval.params) }
    catch (err: unknown) { this.stats.totalToolErrors++; return { executed: true, requestId: approval.requestId, toolError: err instanceof Error ? err.message : String(err), decision: approval.decision } }

    if (toolResult.success) { this.stats.totalExecuted++ } else { this.stats.totalToolErrors++ }

    const receipt = createReceipt({
      agentId: this.config.gatewayId,
      delegationId: approval.delegationId,
      delegation: delegation,
      action: {
        type: `gateway:${approval.tool}`,
        target: JSON.stringify(approval.params),
        scopeUsed: approval.scopeRequired,
      },
      result: {
        status: toolResult.success ? 'success' as const : 'failure' as const,
        summary: toolResult.success
          ? `Executed ${approval.tool} successfully`
          : `Executed ${approval.tool} with error: ${toolResult.error}`
      },
      delegationChain: [this.config.gatewayPublicKey],
      privateKey: this.config.gatewayPrivateKey
    })

    const policyReceipt = createPolicyReceipt({
      intent: approval.intent,
      decision: approval.decision,
      receipt,
      verifierPrivateKey: this.config.gatewayPrivateKey
    })

    const proof: GatewayProof = { requestSignature: approval.intent.signature, decisionSignature: approval.decision.signature, receiptSignature: receipt.signature, policyReceipt }

    this.stats.pendingApprovals = Array.from(this.approvals.values()).filter(a => !a.consumed).length

    return { executed: true, requestId: approval.requestId, result: toolResult.result, toolError: toolResult.success ? undefined : toolResult.error, proof, receipt, decision: approval.decision }
  }

  clearExpired(): number {
    const now = new Date()
    let cleared = 0
    for (const [id, approval] of this.approvals) { if (new Date(approval.expiresAt) < now) { this.approvals.delete(id); cleared++ } }
    this.stats.expiredApprovalsCleared += cleared
    this.stats.pendingApprovals = this.approvals.size

    // NW-001: Prune stale requestIds to prevent unbounded memory growth
    const ttl = this.config.requestIdTTLMs
    const cutoff = Date.now() - ttl
    let pruned = 0
    for (const [id, ts] of this.usedRequestIds) {
      if (ts < cutoff) { this.usedRequestIds.delete(id); pruned++ }
    }

    return cleared + pruned
  }

  getStats(): GatewayStats { return { ...this.stats } }

  getAgentApprovals(agentId: string): GatewayApproval[] {
    return Array.from(this.approvals.values()).filter(a => a.agentId === agentId)
  }

  // ── Cross-Chain + Obligation Management ──

  registerPermit(agentId: string, permit: CrossChainPermit): boolean {
    const agent = this.agents.get(agentId)
    if (!agent || !agent.permits) return false
    agent.permits.push(permit)
    return true
  }

  registerObligation(agentId: string, obligation: Obligation): boolean {
    const agent = this.agents.get(agentId)
    if (!agent || !agent.obligations) return false
    agent.obligations.push(obligation)
    this.stats.obligationsRegistered = (this.stats.obligationsRegistered || 0) + 1
    return true
  }

  getAgentFrame(agentId: string): ExecutionFrame | undefined {
    return this.agents.get(agentId)?.executionFrame
  }

  getAgentObligations(agentId: string): Obligation[] | undefined {
    return this.agents.get(agentId)?.obligations
  }

  private findDelegation(agent: RegisteredAgent, request: ToolCallRequest): Delegation | null {
    if (request.delegationId) {
      const d = agent.delegations.get(request.delegationId)
      if (d && scopeAuthorizes(d.scope, request.scopeRequired)) return d
      return null
    }
    for (const [, d] of agent.delegations) {
      if (scopeAuthorizes(d.scope, request.scopeRequired)) {
        if (request.spend && d.spendLimit !== undefined && request.spend.amount > d.spendLimit) continue
        return d
      }
    }
    return null
  }

  private buildValidationContext(agent: RegisteredAgent, delegation: Delegation): ValidationContext {
    return {
      floorVersion: agent.attestation.floorVersion,
      floorPrinciples: this.config.floor.floor.map((p: any) => ({
        id: p.id, name: p.name,
        enforcement: { mode: p.enforcement?.mode, technical: p.enforcement?.technical, mechanism: p.enforcement?.mechanism || 'unknown' },
        weight: p.weight || 'mandatory'
      })),
      delegation: {
        scope: delegation.scope, spendLimit: delegation.spendLimit, spentAmount: 0,
        expiresAt: delegation.expiresAt, revoked: !!getRevocation(delegation.delegationId),
        currentDepth: delegation.currentDepth, maxDepth: delegation.maxDepth
      },
      agentRegistered: true, agentAttestationValid: true
    }
  }
}

export function createProxyGateway(config: GatewayConfig, executor: ToolExecutor): ProxyGateway {
  return new ProxyGateway(config, executor)
}
