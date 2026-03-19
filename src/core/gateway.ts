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
import { verify, sign as signData } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import { createActionIntent, evaluateIntent, createPolicyReceipt, FloorValidatorV1 } from './policy.js'
import { verifyDelegation, createReceipt, scopeAuthorizes, getRevocation } from './delegation.js'
import { verifyPassport } from '../verification/verify.js'
import { verifyAttestation } from './values.js'
import { createTaintLabel, createSAO, createExecutionFrame, recordAccess, checkDataFlow, mergeTaints, verifyCrossChainPermit, isFrameExpired, rotateFrame } from './cross-chain.js'
import { checkFulfillment, resolveObligation } from './obligations.js'
import { createExecutionEnvelope } from './execution-envelope.js'
import {
  verifyGovernanceArtifact, classifyGovernanceChange,
  loadGovernanceArtifact as loadGovArtifact
} from './governance.js'
import {
  checkEscalatedAction, isEscalationActive, revokeEscalation,
  type ActiveEscalation, type EscalationGrant, type ActionClass
} from './escalation.js'
import { DEFAULT_LOAD_POLICY } from '../types/governance.js'
import type { GovernanceArtifact, GovernanceEnvelope, GovernanceLoadPolicy, GovernanceDiff } from '../types/governance.js'
import {
  computeEffectiveScore, createScopedReputation, resolveAuthorityTier,
  checkTierForIntent, updateReputationFromResult, shouldDemote,
  triggerDemotion, DEFAULT_TIERS
} from './reputation-authority.js'
import type { Delegation, ActionReceipt, ValuesFloor, FloorAttestation } from '../types/passport.js'
import type { ActionIntent, PolicyDecision, PolicyReceipt, PolicyValidator, ValidationContext } from '../types/policy.js'
import type { TaintLabel, TaintSet, CrossChainPermit, ExecutionFrame, SignedAuthorityObject } from '../types/cross-chain.js'
import type { Obligation, ObligationResolution } from '../types/obligations.js'
import type { ExecutionEnvelope } from '../types/execution-envelope.js'
import type { ScopedReputation, AuthorityTier, TierEscalation, EvidenceClass, TierCheckContext } from '../types/reputation-authority.js'
import type { AutonomyLevel } from '../types/intent.js'
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
  private requestsSinceCleanup = 0 // V5-MED-4: auto-cleanup counter
  private agentLocks: Map<string, Promise<void>> = new Map() // Per-agent sequential execution (concurrency fix)
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
    obligationsTerminated: 0,
    tierDenials: 0,
    reputationUpdates: 0,
    demotions: 0,
    governanceUpdates: 0,
    governanceWeakeningBlocked: 0,
    governanceStaleBlocks: 0,
    escalationsActivated: 0,
    escalationsUsed: 0,
    escalationsExpired: 0,
    escalationsDenied: 0,
    reversibilityDenied: 0
  }

  constructor(config: GatewayConfig, executor: ToolExecutor) {
    this.config = {
      approvalTTLSeconds: config.approvalTTLSeconds ?? 30,
      maxPendingPerAgent: config.maxPendingPerAgent ?? 10,
      recheckRevocationOnExecute: config.recheckRevocationOnExecute ?? true,
      requestIdTTLMs: config.requestIdTTLMs ?? 3_600_000, // 1 hour default (NW-001)
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

    // Initialize reputation + tier if reputation gating is enabled
    let reputation: ScopedReputation | undefined
    let authorityTier: AuthorityTier | undefined
    if (this.config.enableReputationGating) {
      reputation = createScopedReputation(passport.passport.publicKey, agentId, '*')
      const score = computeEffectiveScore(reputation.mu, reputation.sigma)
      const tierDef = resolveAuthorityTier(score, 0)
      authorityTier = {
        tier: tierDef.tier,
        name: tierDef.name,
        origin: 'earned' as const,
        autonomyLevel: tierDef.autonomyLevel,
        maxDelegationDepth: tierDef.maxDelegationDepth,
        maxSpendPerAction: tierDef.maxSpendPerAction,
        demotionCount: 0,
      }
    }

    this.agents.set(agentId, {
      passport, attestation, delegations: delegationMap,
      executionFrame: this.config.enableCrossChainEnforcement ? createExecutionFrame(agentId, { ttlMinutes: this.config.frameTTLMinutes ?? 0 }) : undefined,
      permits: this.config.enableCrossChainEnforcement ? [] : undefined,
      obligations: this.config.enableObligationMonitoring ? [] : undefined,
      reputation,
      authorityTier,
      governanceVersion: this.config.enableGovernanceEnforcement && this.config.governanceEnvelope
        ? this.config.governanceEnvelope.artifact.version : undefined,
      escalationGrants: this.config.enableEscalation ? [] : undefined,
      activeEscalations: this.config.enableEscalation ? [] : undefined,
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
    // Per-agent sequential execution: prevents concurrent frame clobbering
    // (Claude Opus review finding: async chain-fork attack)
    const agentId = request.agentId
    const previousLock = this.agentLocks.get(agentId) || Promise.resolve()
    let releaseLock: () => void
    const currentLock = new Promise<void>(resolve => { releaseLock = resolve })
    this.agentLocks.set(agentId, currentLock)

    try {
      await previousLock
      return await this._processToolCallInner(request)
    } finally {
      releaseLock!()
    }
  }

  private async _processToolCallInner(request: ToolCallRequest): Promise<ToolCallResult> {
    this.stats.totalRequests++

    // V5-MED-4: Periodic auto-cleanup to prevent unbounded memory growth
    if (++this.requestsSinceCleanup >= 100) {
      this.clearExpired()
      this.requestsSinceCleanup = 0
    }

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
    let delegation = this.findDelegation(agent, request)
    let viaEscalation = false
    let usedEscalationId: string | undefined
    let escalationDelegation: Delegation | undefined

    if (!delegation) {
      // Step 2.1: Escalation fallback (Module 27 / INV-4)
      // If no delegation covers this action, check for active escalation grants
      if (this.config.enableEscalation && agent.activeEscalations) {
        // Expire stale escalations first
        this._expireAgentEscalations(agent)

        const esc = agent.activeEscalations.find(e => {
          if (!isEscalationActive(e)) return false
          const grant = agent.escalationGrants?.find(g => g.grantId === e.grantId)
          if (!grant) return false
          const check = checkEscalatedAction({
            escalation: e, grant,
            action: request.scopeRequired,
            actionClass: 'tentative', // default — gateway can only do tentative via escalation
            spend: request.spend?.amount,
          })
          return check.permitted
        })

        if (esc) {
          viaEscalation = true
          usedEscalationId = esc.escalationId
          // Track spend
          if (request.spend) {
            esc.spentDuringEscalation += request.spend.amount
          }
          this.stats.escalationsUsed = (this.stats.escalationsUsed ?? 0) + 1
          this.config.onEscalationUsed?.(request.agentId, esc.escalationId, request.tool)
          // Use the first delegation from agent's set as the base for intent creation
          // (escalation extends beyond delegation scope, but we need a delegation for the 3-sig chain)
          escalationDelegation = agent.delegations.values().next().value
        }
      }

      if (!viaEscalation) {
        this.stats.totalDenied++
        return {
          executed: false, requestId: request.requestId,
          denialReason: `No valid delegation covers scope "${request.scopeRequired}" for tool "${request.tool}"`
        }
      }
      // Use escalation delegation as base
      delegation = escalationDelegation!
    }

    const delegationStatus = verifyDelegation(delegation)
    if (!delegationStatus.valid || delegationStatus.expired || delegationStatus.revoked) {
      this.stats.totalDenied++
      return { executed: false, requestId: request.requestId, denialReason: `Delegation ${delegation.delegationId} is no longer valid` }
    }

    // Step 2.5: Governance staleness check (Module 21 / INV-2)
    // If governance enforcement is enabled and the agent's attested version doesn't
    // match the current governance version, block the action until re-attestation.
    if (this.config.enableGovernanceEnforcement && this.config.governanceEnvelope) {
      const currentVersion = this.config.governanceEnvelope.artifact.version
      const agentVersion = agent.governanceVersion
      if (agentVersion !== currentVersion) {
        this.stats.totalDenied++
        this.stats.governanceStaleBlocks = (this.stats.governanceStaleBlocks ?? 0) + 1
        this.config.onGovernanceStaleBlock?.(request.agentId, agentVersion ?? 'none', currentVersion)
        return {
          executed: false, requestId: request.requestId,
          denialReason: `Governance stale: agent attested to v${agentVersion ?? 'none'}, current is v${currentVersion}. Re-attestation required.`
        }
      }
    }

    // Step 2.6: Reversibility check (Gap 3 taxonomy)
    if (this.config.maxReversibility && request.reversibility) {
      const RANK: Record<string, number> = { tentative: 0, compensable: 1, irreversible: 2 }
      const maxRank = RANK[this.config.maxReversibility] ?? 2
      const actionRank = RANK[request.reversibility] ?? 2
      if (actionRank > maxRank) {
        this.stats.totalDenied++
        this.stats.reversibilityDenied = (this.stats.reversibilityDenied ?? 0) + 1
        return {
          executed: false, requestId: request.requestId,
          denialReason: `Action reversibility "${request.reversibility}" exceeds gateway max "${this.config.maxReversibility}"`
        }
      }
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
    // INV-4: Override scope for escalated actions — use escalation's effective scope
    if (viaEscalation && usedEscalationId) {
      const esc = agent.activeEscalations?.find(e => e.escalationId === usedEscalationId)
      if (esc) {
        validationCtx.delegation.scope = esc.effectiveScope
        if (esc.effectiveSpendLimit !== undefined) {
          validationCtx.delegation.spendLimit = esc.effectiveSpendLimit
        }
      }
    }
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

    // Step 4.5: Reputation-gated authority check (Module 10)
    // Core invariant: effectiveAuthority = min(delegation, tier)
    // Even if delegation allows $10,000 spend, a recruit (tier 0) gets $0.
    let tierCheck: TierEscalation | null = null
    if (this.config.enableReputationGating && agent.authorityTier && agent.reputation) {
      const tierCtx: TierCheckContext = {
        agentTier: agent.authorityTier,
        effectiveScore: computeEffectiveScore(agent.reputation.mu, agent.reputation.sigma),
      }
      tierCheck = checkTierForIntent({
        tierContext: tierCtx,
        requestedSpend: request.spend?.amount,
      })
      if (tierCheck) {
        // Tier insufficient — deny even though policy permitted
        this.stats.totalDenied++;
        (this.stats.tierDenials as number)++
        this.usedRequestIds.set(request.requestId, Date.now())
        const reason = `Tier ${tierCheck.currentTier} (${agent.authorityTier.name}) insufficient: ` +
          (tierCheck.requestedSpend !== undefined
            ? `spend $${tierCheck.requestedSpend} exceeds tier max $${agent.authorityTier.maxSpendPerAction}`
            : `requires tier ${tierCheck.requiredTier}`)
        const result: ToolCallResult = { executed: false, requestId: request.requestId, denialReason: reason, decision, tierCheck }
        this.config.onTierDenied?.(request.agentId, tierCheck)
        this.config.onToolCall?.(request, result)
        return result
      }
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
    // First: auto-rotate frame if TTL expired (F-2 fix from 3-model review)
    if (this.config.enableCrossChainEnforcement && agent.executionFrame) {
      if (isFrameExpired(agent.executionFrame)) {
        const { sealed, fresh } = rotateFrame(agent.executionFrame, { ttlMinutes: this.config.frameTTLMinutes ?? 0 })
        this.config.onFrameRotated?.(request.agentId, sealed.frameId, fresh.frameId)
        agent.executionFrame = fresh
      }
    }
    // Now check cross-chain taint on the (possibly fresh) frame
    // If the agent's frame is tainted by a different principal than this
    // delegation's principal, block unless a valid permit exists.
    let flowCheckResult: import('../types/cross-chain.js').FlowCheckResult | undefined
    if (this.config.enableCrossChainEnforcement && agent.executionFrame) {
      const actionPrincipalId = delegation.delegatedBy
      const frameTaint = agent.executionFrame.frameTaint
      const residue = agent.executionFrame.residuePrincipals || []
      // Run check if frame has taint OR residue from previous epochs (V2-MED-1 fix)
      if (frameTaint.labels.length > 0 || residue.length > 0) {
        // Build effective taint: current labels + synthetic labels from residue
        let effectiveLabels = [...frameTaint.labels]
        for (const rp of residue) {
          if (!frameTaint.principals.includes(rp)) {
            effectiveLabels.push(createTaintLabel(rp, 'residue', 'residue', 'same-context-only'))
          }
        }
        const effectiveTaint = mergeTaints(...effectiveLabels)
        this.stats.crossChainChecks = (this.stats.crossChainChecks || 0) + 1
        flowCheckResult = checkDataFlow({
          inputTaint: effectiveTaint,
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

    // Step 5.75: Permit recheck before execution (TOCTOU fix — all 3 review models flagged this)
    // If step 5.5 authorized via a permit, recheck that the permit is still valid
    // right before we execute. Closes the window between check and execute.
    if (flowCheckResult?.verdict === 'permitted' && flowCheckResult.permitId) {
      const permit = (agent.permits || []).find(p => p.permitId === flowCheckResult!.permitId)
      if (!permit || permit.revoked || new Date(permit.expiresAt) < new Date()) {
        this.stats.totalDenied++
        this.usedRequestIds.set(request.requestId, Date.now())
        return {
          executed: false, requestId: request.requestId,
          denialReason: `Cross-chain permit ${flowCheckResult.permitId} was revoked or expired between approval and execution`,
          decision
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
    // For escalated actions, build receipt directly (base delegation's scope doesn't cover
    // the escalated action — that's the whole point of escalation). The gateway IS the
    // enforcement boundary and is authorized to sign receipts for escalated actions.
    let receipt: ActionReceipt
    if (viaEscalation && usedEscalationId) {
      const receiptData: Omit<ActionReceipt, 'signature'> = {
        receiptId: 'rcpt_' + uuidv4().slice(0, 12),
        version: '1.1',
        timestamp: new Date().toISOString(),
        agentId: this.config.gatewayId,
        delegationId: delegation.delegationId,
        action: {
          type: `gateway:${request.tool}`,
          target: JSON.stringify(request.params),
          scopeUsed: request.scopeRequired,
          spend: request.spend
        },
        result: {
          status: toolResult.success ? 'success' as const : 'failure' as const,
          summary: toolResult.success
            ? `Executed ${request.tool} via escalation ${usedEscalationId}`
            : `Executed ${request.tool} via escalation with error: ${toolResult.error}`
        },
        delegationChain: [this.config.gatewayPublicKey],
      }
      const canonical = canonicalize(receiptData)
      receipt = { ...receiptData, signature: signData(canonical, this.config.gatewayPrivateKey) }
    } else {
      receipt = createReceipt({
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
    }

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

    // Step 8.7: Reputation update (Module 10)
    // Update agent reputation based on execution outcome, then recompute tier.
    if (this.config.enableReputationGating && agent.reputation && agent.authorityTier) {
      const evidenceClass: EvidenceClass = request.evidenceClass ?? this.config.defaultEvidenceClass ?? 'standard'
      const success = toolResult.success
      agent.reputation = updateReputationFromResult(agent.reputation, success, evidenceClass);
      (this.stats.reputationUpdates as number)++

      // Recompute tier
      const newScore = computeEffectiveScore(agent.reputation.mu, agent.reputation.sigma)
      const newTierDef = resolveAuthorityTier(newScore, agent.authorityTier.demotionCount)

      // Check for demotion
      if (shouldDemote(newScore, agent.authorityTier.tier) && agent.authorityTier.tier > 0) {
        const oldTier = agent.authorityTier.tier
        const demotion = triggerDemotion({
          agentId: request.agentId,
          principalId: agent.passport.passport.publicKey,
          scope: request.scopeRequired,
          currentTier: agent.authorityTier.tier,
          cause: 'behavioral',
          reason: `Score ${newScore.toFixed(1)} below demotion threshold`,
        })
        agent.authorityTier = {
          ...agent.authorityTier,
          tier: demotion.toTier,
          name: DEFAULT_TIERS[demotion.toTier]?.name ?? 'recruit',
          autonomyLevel: DEFAULT_TIERS[demotion.toTier]?.autonomyLevel ?? (1 as AutonomyLevel),
          maxDelegationDepth: DEFAULT_TIERS[demotion.toTier]?.maxDelegationDepth ?? 0,
          maxSpendPerAction: DEFAULT_TIERS[demotion.toTier]?.maxSpendPerAction ?? 0,
          demotionCount: agent.authorityTier.demotionCount + 1,
        };
        (this.stats.demotions as number)++
        this.config.onDemotion?.(request.agentId, oldTier, demotion.toTier, demotion.reason)
      } else if (newTierDef.tier > agent.authorityTier.tier) {
        // Promotion (automatic — formal promotion reviews are separate)
        agent.authorityTier = {
          ...agent.authorityTier,
          tier: newTierDef.tier,
          name: newTierDef.name,
          autonomyLevel: newTierDef.autonomyLevel,
          maxDelegationDepth: newTierDef.maxDelegationDepth,
          maxSpendPerAction: newTierDef.maxSpendPerAction,
          promotedAt: new Date().toISOString(),
        }
      }

      this.config.onReputationUpdated?.(request.agentId, agent.reputation, agent.authorityTier)
    }

    this.usedRequestIds.set(request.requestId, Date.now())

    // Step 9: Produce execution envelope for cross-engine interop (optional)
    let envelope: ExecutionEnvelope | undefined
    if (this.config.produceEnvelope && toolResult.success) {
      envelope = createExecutionEnvelope({
        intent,
        decision,
        receipt: policyReceipt,
        delegation,
        runId: request.requestId,
        agentDid: `did:aps:${request.agentPublicKey}`,
        evaluatorDid: `did:aps:${this.config.gatewayPublicKey}`,
        revocationStatus: 'active',
        chainDepth: delegation.currentDepth,
        evaluationMethod: 'deterministic',
        signerPrivateKey: this.config.gatewayPrivateKey,
        signerPublicKey: this.config.gatewayPublicKey
      })
    }

    const proof: GatewayProof = {
      requestSignature: request.signature, decisionSignature: decision.signature,
      receiptSignature: receipt.signature, policyReceipt
    }

    const result: ToolCallResult = {
      executed: true, requestId: request.requestId,
      result: toolResult.result, toolError: toolResult.success ? undefined : toolResult.error,
      proof, receipt, decision,
      sao, flowCheck: flowCheckResult,
      obligationResolutions: obligationResolutions.length > 0 ? obligationResolutions : undefined,
      envelope,
      tierCheck,
      viaEscalation: viaEscalation || undefined,
      escalationId: usedEscalationId,
      reversibility: request.reversibility,
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
      expiresAt: new Date(Date.now() + ttlMs).toISOString(), nonce, consumed: false,
      spend: request.spend, evidenceClass: request.evidenceClass, // V5-MED-1: carry through from request
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

    // ═══ V2-CRIT-1 FIX: All enforcement steps from processToolCall now applied here ═══
    // Per-agent sequential execution (concurrency protection)
    const agentId = approval.agentId
    const previousLock = this.agentLocks.get(agentId) || Promise.resolve()
    let releaseLock: () => void
    const currentLock = new Promise<void>(resolve => { releaseLock = resolve })
    this.agentLocks.set(agentId, currentLock)

    try {
      await previousLock
      return await this._executeApprovalInner(approval, agent, delegation)
    } finally {
      releaseLock!()
    }
  }

  private async _executeApprovalInner(
    approval: GatewayApproval,
    agent: RegisteredAgent,
    delegation: Delegation
  ): Promise<ToolCallResult> {
    // Frame TTL auto-rotation (F-2 fix)
    if (this.config.enableCrossChainEnforcement && agent.executionFrame) {
      if (isFrameExpired(agent.executionFrame)) {
        const { sealed, fresh } = rotateFrame(agent.executionFrame, { ttlMinutes: this.config.frameTTLMinutes ?? 0 })
        this.config.onFrameRotated?.(approval.agentId, sealed.frameId, fresh.frameId)
        agent.executionFrame = fresh
      }
    }

    // Governance staleness recheck at execution time (Module 21 / INV-2)
    // Even if the approval was granted under the old governance, execution
    // must verify the agent's attestation is still current.
    if (this.config.enableGovernanceEnforcement && this.config.governanceEnvelope) {
      const currentVersion = this.config.governanceEnvelope.artifact.version
      const agentVersion = agent.governanceVersion
      if (agentVersion !== currentVersion) {
        this.stats.totalDenied++
        this.stats.governanceStaleBlocks = (this.stats.governanceStaleBlocks ?? 0) + 1
        this.config.onGovernanceStaleBlock?.(approval.agentId, agentVersion ?? 'none', currentVersion)
        return {
          executed: false, requestId: approval.requestId,
          denialReason: `Governance stale at execution: agent attested to v${agentVersion ?? 'none'}, current is v${currentVersion}`,
          decision: approval.decision
        }
      }
    }

    // Cross-chain data flow check (Module 18)
    let flowCheckResult: import('../types/cross-chain.js').FlowCheckResult | undefined
    if (this.config.enableCrossChainEnforcement && agent.executionFrame) {
      const actionPrincipalId = delegation.delegatedBy
      const frameTaint = agent.executionFrame.frameTaint
      const residue = agent.executionFrame.residuePrincipals || []
      if (frameTaint.labels.length > 0 || residue.length > 0) {
        let effectiveLabels = [...frameTaint.labels]
        for (const rp of residue) {
          if (!frameTaint.principals.includes(rp)) {
            effectiveLabels.push(createTaintLabel(rp, 'residue', 'residue', 'same-context-only'))
          }
        }
        const effectiveTaint = mergeTaints(...effectiveLabels)
        this.stats.crossChainChecks = (this.stats.crossChainChecks || 0) + 1
        flowCheckResult = checkDataFlow({
          inputTaint: effectiveTaint,
          actionPrincipalId,
          actionScope: approval.scopeRequired,
          permits: agent.permits || [],
          frame: agent.executionFrame
        })
        if (flowCheckResult.verdict === 'blocked') {
          this.stats.crossChainBlocked = (this.stats.crossChainBlocked || 0) + 1
          this.stats.totalDenied++
          this.config.onCrossChainBlocked?.(approval.agentId, flowCheckResult)
          return {
            executed: false, requestId: approval.requestId,
            denialReason: `Cross-chain blocked: ${flowCheckResult.reason}`,
            decision: approval.decision, flowCheck: flowCheckResult
          }
        }
        if (flowCheckResult.verdict === 'permitted') {
          this.stats.crossChainPermitted = (this.stats.crossChainPermitted || 0) + 1
        }
      }
    }

    // Permit TOCTOU recheck (step 5.75)
    if (flowCheckResult?.verdict === 'permitted' && flowCheckResult.permitId) {
      const permit = (agent.permits || []).find(p => p.permitId === flowCheckResult!.permitId)
      if (!permit || permit.revoked || new Date(permit.expiresAt) < new Date()) {
        this.stats.totalDenied++
        return {
          executed: false, requestId: approval.requestId,
          denialReason: `Cross-chain permit ${flowCheckResult.permitId} revoked/expired between approval and execution`,
          decision: approval.decision
        }
      }
    }

    // Reputation-gated authority check (step 4.5 parity)
    let tierCheck: TierEscalation | null = null
    if (this.config.enableReputationGating && agent.authorityTier && agent.reputation) {
      const tierCtx: TierCheckContext = {
        agentTier: agent.authorityTier,
        effectiveScore: computeEffectiveScore(agent.reputation.mu, agent.reputation.sigma),
      }
      tierCheck = checkTierForIntent({
        tierContext: tierCtx,
        requestedSpend: approval.spend?.amount,
      })
      if (tierCheck) {
        this.stats.totalDenied++;
        (this.stats.tierDenials as number)++
        const reason = `Tier ${tierCheck.currentTier} (${agent.authorityTier.name}) insufficient`
        this.config.onTierDenied?.(approval.agentId, tierCheck)
        return { executed: false, requestId: approval.requestId, denialReason: reason, decision: approval.decision, tierCheck }
      }
    }

    // Execute
    approval.consumed = true
    this.usedRequestIds.set(approval.requestId, Date.now())

    let toolResult: { success: boolean; result?: unknown; error?: string }
    try { toolResult = await this.executor(approval.tool, approval.params) }
    catch (err: unknown) { this.stats.totalToolErrors++; return { executed: true, requestId: approval.requestId, toolError: err instanceof Error ? err.message : String(err), decision: approval.decision } }

    if (toolResult.success) { this.stats.totalExecuted++ } else { this.stats.totalToolErrors++ }

    // Taint recording + SAO wrapping (step 6.5)
    let sao: SignedAuthorityObject | undefined
    if (this.config.enableCrossChainEnforcement && agent.executionFrame && toolResult.success) {
      const taintLabel = createTaintLabel(delegation.delegatedBy, delegation.delegationId, delegation.delegationId, 'same-context-only')
      agent.executionFrame = recordAccess(agent.executionFrame, taintLabel)
      sao = createSAO(toolResult.result, taintLabel, this.config.gatewayPrivateKey, this.config.gatewayPublicKey)
    }

    // Receipt generation
    const receipt = createReceipt({
      agentId: this.config.gatewayId, delegationId: approval.delegationId, delegation,
      action: { type: `gateway:${approval.tool}`, target: JSON.stringify(approval.params), scopeUsed: approval.scopeRequired },
      result: { status: toolResult.success ? 'success' as const : 'failure' as const, summary: toolResult.success ? `Executed ${approval.tool} successfully` : `Executed ${approval.tool} with error: ${toolResult.error}` },
      delegationChain: [this.config.gatewayPublicKey], privateKey: this.config.gatewayPrivateKey
    })

    const policyReceipt = createPolicyReceipt({ intent: approval.intent, decision: approval.decision, receipt, verifierPrivateKey: this.config.gatewayPrivateKey })

    // Obligation fulfillment check (Module 20)
    const obligationResolutions: ObligationResolution[] = []
    if (this.config.enableObligationMonitoring && agent.obligations && toolResult.success) {
      const receiptForCheck = { receiptId: receipt.receiptId, action: { type: receipt.action.type, scopeUsed: receipt.action.scopeUsed }, params: approval.params, timestamp: receipt.timestamp, toolError: undefined }
      for (const obligation of agent.obligations) {
        if (obligation.status !== 'pending') continue
        const fulfillment = checkFulfillment(obligation.evidence, [receiptForCheck])
        if (fulfillment.fulfilled) {
          const resolution = resolveObligation({ obligation, receipts: [receiptForCheck], gatewayId: this.config.gatewayId, gatewayPrivateKey: this.config.gatewayPrivateKey })
          obligationResolutions.push(resolution)
          obligation.status = 'fulfilled'
          this.stats.obligationsFulfilled = (this.stats.obligationsFulfilled || 0) + 1
          this.config.onObligationResolved?.(resolution)
        }
      }
    }

    // Reputation update (step 8.7 parity)
    if (this.config.enableReputationGating && agent.reputation && agent.authorityTier) {
      const evidenceClass: EvidenceClass = approval.evidenceClass ?? this.config.defaultEvidenceClass ?? 'standard'
      agent.reputation = updateReputationFromResult(agent.reputation, toolResult.success, evidenceClass);
      (this.stats.reputationUpdates as number)++
      const newScore = computeEffectiveScore(agent.reputation.mu, agent.reputation.sigma)
      const newTierDef = resolveAuthorityTier(newScore, agent.authorityTier.demotionCount)
      if (shouldDemote(newScore, agent.authorityTier.tier) && agent.authorityTier.tier > 0) {
        const oldTier = agent.authorityTier.tier
        const demotion = triggerDemotion({ agentId: approval.agentId, principalId: agent.passport.passport.publicKey, scope: approval.scopeRequired, currentTier: agent.authorityTier.tier, cause: 'behavioral', reason: `Score ${newScore.toFixed(1)} below demotion threshold` })
        agent.authorityTier = { ...agent.authorityTier, tier: demotion.toTier, name: DEFAULT_TIERS[demotion.toTier]?.name ?? 'recruit', autonomyLevel: DEFAULT_TIERS[demotion.toTier]?.autonomyLevel ?? (1 as AutonomyLevel), maxDelegationDepth: DEFAULT_TIERS[demotion.toTier]?.maxDelegationDepth ?? 0, maxSpendPerAction: DEFAULT_TIERS[demotion.toTier]?.maxSpendPerAction ?? 0, demotionCount: agent.authorityTier.demotionCount + 1 };
        (this.stats.demotions as number)++
        this.config.onDemotion?.(approval.agentId, oldTier, demotion.toTier, demotion.reason)
      } else if (newTierDef.tier > agent.authorityTier.tier) {
        agent.authorityTier = { ...agent.authorityTier, tier: newTierDef.tier, name: newTierDef.name, autonomyLevel: newTierDef.autonomyLevel, maxDelegationDepth: newTierDef.maxDelegationDepth, maxSpendPerAction: newTierDef.maxSpendPerAction, promotedAt: new Date().toISOString() }
      }
      this.config.onReputationUpdated?.(approval.agentId, agent.reputation, agent.authorityTier)
    }

    // Execution envelope (step 9)
    let envelope: ExecutionEnvelope | undefined
    if (this.config.produceEnvelope && toolResult.success) {
      envelope = createExecutionEnvelope({
        intent: approval.intent, decision: approval.decision, receipt: policyReceipt, delegation,
        runId: approval.requestId, agentDid: `did:aps:${approval.agentId}`,
        evaluatorDid: `did:aps:${this.config.gatewayPublicKey}`, revocationStatus: 'active',
        chainDepth: delegation.currentDepth, evaluationMethod: 'deterministic',
        signerPrivateKey: this.config.gatewayPrivateKey, signerPublicKey: this.config.gatewayPublicKey
      })
    }

    const proof: GatewayProof = { requestSignature: approval.intent.signature, decisionSignature: approval.decision.signature, receiptSignature: receipt.signature, policyReceipt }
    this.stats.pendingApprovals = Array.from(this.approvals.values()).filter(a => !a.consumed).length

    return {
      executed: true, requestId: approval.requestId,
      result: toolResult.result, toolError: toolResult.success ? undefined : toolResult.error,
      proof, receipt, decision: approval.decision,
      sao, flowCheck: flowCheckResult,
      obligationResolutions: obligationResolutions.length > 0 ? obligationResolutions : undefined,
      envelope,
      tierCheck
    }
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
    // Verify both signatures before storing (GPT review finding)
    if (!verifyCrossChainPermit(permit)) return false
    agent.permits.push(permit)
    return true
  }

  revokePermit(agentId: string, permitId: string): boolean {
    const agent = this.agents.get(agentId)
    if (!agent || !agent.permits) return false
    const permit = agent.permits.find(p => p.permitId === permitId)
    if (!permit) return false
    permit.revoked = true
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

  /** Get agent's current Bayesian reputation state */
  getAgentReputation(agentId: string): ScopedReputation | undefined {
    return this.agents.get(agentId)?.reputation
  }

  /** Get agent's current authority tier */
  getAgentTier(agentId: string): AuthorityTier | undefined {
    return this.agents.get(agentId)?.authorityTier
  }

  /** Externally set agent reputation (for injection from external reputation systems) */
  setAgentReputation(agentId: string, reputation: ScopedReputation): boolean {
    const agent = this.agents.get(agentId)
    if (!agent) return false
    agent.reputation = reputation
    // Recompute tier
    const score = computeEffectiveScore(reputation.mu, reputation.sigma)
    const tierDef = resolveAuthorityTier(score, agent.authorityTier?.demotionCount ?? 0)
    agent.authorityTier = {
      tier: tierDef.tier, name: tierDef.name, origin: 'earned' as const,
      autonomyLevel: tierDef.autonomyLevel, maxDelegationDepth: tierDef.maxDelegationDepth,
      maxSpendPerAction: tierDef.maxSpendPerAction,
      demotionCount: agent.authorityTier?.demotionCount ?? 0,
    }
    return true
  }

  // ── Governance Enforcement (Module 21 / INV-2) ──

  /** Update the gateway's governance artifact. Enforces INV-2: governance can only
   *  strengthen; weakening requires higher-order authorization (more approvals). */
  updateGovernance(envelope: GovernanceEnvelope, previousArtifact?: GovernanceArtifact | null): {
    accepted: boolean; error?: string; diff?: GovernanceDiff
  } {
    if (!this.config.enableGovernanceEnforcement) {
      return { accepted: false, error: 'Governance enforcement not enabled' }
    }

    const policy = this.config.governanceLoadPolicy ?? DEFAULT_LOAD_POLICY
    const verification = loadGovArtifact(envelope, policy, previousArtifact ?? this.config.governanceEnvelope?.artifact ?? null)

    if (!verification.valid) {
      // Check specifically for weakening block
      if (!verification.weakeningApproved) {
        this.stats.governanceWeakeningBlocked = (this.stats.governanceWeakeningBlocked ?? 0) + 1
        this.config.onGovernanceWeakeningBlocked?.(envelope.artifact, verification.errors.join('; '))
      }
      return { accepted: false, error: verification.errors.join('; ') }
    }

    // Compute diff if we have a previous artifact
    let diff: GovernanceDiff | undefined
    if (this.config.governanceEnvelope) {
      const prev = this.config.governanceEnvelope.artifact
      // Extract principle IDs or item identifiers from content for diff
      // Use additions/removals from the artifact metadata
      diff = {
        changeType: envelope.artifact.changeType,
        additions: envelope.artifact.additions,
        modifications: envelope.artifact.modifications,
        removals: envelope.artifact.removals,
        isWeakening: envelope.artifact.removals.length > 0,
        isStrengthening: envelope.artifact.additions.length > 0 && envelope.artifact.removals.length === 0,
      }
    }

    // Accept the update
    this.config.governanceEnvelope = envelope
    this.stats.governanceUpdates = (this.stats.governanceUpdates ?? 0) + 1
    this.config.onGovernanceChange?.(diff ?? {
      changeType: 'initial', additions: [], modifications: [], removals: [],
      isWeakening: false, isStrengthening: false,
    }, envelope.artifact)

    return { accepted: true, diff }
  }

  /** Re-attest an agent to the current governance version after an update. */
  reattestGovernance(agentId: string): { success: boolean; error?: string } {
    const agent = this.agents.get(agentId)
    if (!agent) return { success: false, error: 'Agent not registered' }
    if (!this.config.enableGovernanceEnforcement) return { success: false, error: 'Governance enforcement not enabled' }
    if (!this.config.governanceEnvelope) return { success: false, error: 'No governance artifact loaded' }
    agent.governanceVersion = this.config.governanceEnvelope.artifact.version
    return { success: true }
  }

  /** Get current governance artifact version */
  getGovernanceVersion(): string | undefined {
    return this.config.governanceEnvelope?.artifact.version
  }

  /** Get agent's attested governance version */
  getAgentGovernanceVersion(agentId: string): string | undefined {
    return this.agents.get(agentId)?.governanceVersion
  }

  // ── Escalation Enforcement (Module 27 / INV-4) ──

  /** Add an escalation grant for an agent */
  addEscalationGrant(agentId: string, grant: EscalationGrant): { added: boolean; error?: string } {
    const agent = this.agents.get(agentId)
    if (!agent) return { added: false, error: 'Agent not registered' }
    if (!this.config.enableEscalation) return { added: false, error: 'Escalation not enabled' }
    if (!agent.escalationGrants) agent.escalationGrants = []
    agent.escalationGrants.push(grant)
    return { added: true }
  }

  /** Activate an escalation for an agent (gateway validates and activates) */
  activateAgentEscalation(agentId: string, escalation: ActiveEscalation): { activated: boolean; error?: string } {
    const agent = this.agents.get(agentId)
    if (!agent) return { activated: false, error: 'Agent not registered' }
    if (!this.config.enableEscalation) return { activated: false, error: 'Escalation not enabled' }
    if (!agent.activeEscalations) agent.activeEscalations = []

    // Expire stale ones first
    this._expireAgentEscalations(agent)

    // Check max concurrent
    const maxConcurrent = this.config.maxConcurrentEscalations ?? 1
    const activeCount = agent.activeEscalations.filter(e => isEscalationActive(e)).length
    if (activeCount >= maxConcurrent) {
      this.stats.escalationsDenied = (this.stats.escalationsDenied ?? 0) + 1
      return { activated: false, error: `Max concurrent escalations reached (${maxConcurrent})` }
    }

    agent.activeEscalations.push(escalation)
    this.stats.escalationsActivated = (this.stats.escalationsActivated ?? 0) + 1
    return { activated: true }
  }

  /** Get active escalations for an agent */
  getAgentEscalations(agentId: string): ActiveEscalation[] {
    const agent = this.agents.get(agentId)
    if (!agent || !agent.activeEscalations) return []
    this._expireAgentEscalations(agent)
    return agent.activeEscalations.filter(e => isEscalationActive(e))
  }

  /** Expire stale escalations for an agent */
  private _expireAgentEscalations(agent: RegisteredAgent): void {
    if (!agent.activeEscalations) return
    for (const esc of agent.activeEscalations) {
      if (esc.status === 'active' && !isEscalationActive(esc)) {
        esc.status = 'expired'
        this.stats.escalationsExpired = (this.stats.escalationsExpired ?? 0) + 1
        this.config.onEscalationExpired?.(agent.passport.passport.agentId, esc.escalationId)
      }
    }
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
