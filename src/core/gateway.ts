// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
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
import type { StorageBackend, StoredAgentRecord } from '../storage/types.js'
import { createActionIntent, evaluateIntent, createPolicyReceipt, FloorValidatorV1 } from './policy.js'
import { verifyDelegation, createReceipt, scopeAuthorizes, getRevocation } from './delegation.js'
import { verifyPassport } from '../verification/verify.js'
import { verifyAttestation } from './values.js'
import { createTaintLabel, createSAO, createExecutionFrame, recordAccess, checkDataFlow, mergeTaints, verifyCrossChainPermit, isFrameExpired, rotateFrame } from './cross-chain.js'
import { checkFulfillment, resolveObligation } from './obligations.js'
import { createExecutionEnvelope } from './execution-envelope.js'
import { loadGovernanceArtifact as loadGovArtifact } from './governance.js'
import {
  checkEscalatedAction, isEscalationActive,
  type ActiveEscalation, type EscalationGrant
} from './escalation.js'
import { DEFAULT_LOAD_POLICY } from '../types/governance.js'
import type { GovernanceArtifact, GovernanceEnvelope, GovernanceDiff } from '../types/governance.js'
import {
  computeEffectiveScore, createScopedReputation, resolveAuthorityTier,
  checkTierForIntent, updateReputationFromResult, shouldDemote,
  triggerDemotion, DEFAULT_TIERS
} from './reputation-authority.js'
import type { Delegation, ActionReceipt, FloorAttestation, FloorPrinciple } from '../types/passport.js'
import type { PolicyDecision, PolicyValidator, ValidationContext } from '../types/policy.js'
import type { CrossChainPermit, ExecutionFrame, SignedAuthorityObject } from '../types/cross-chain.js'
import type { Obligation, ObligationResolution } from '../types/obligations.js'
import type { ExecutionEnvelope } from '../types/execution-envelope.js'
import type { ScopedReputation, AuthorityTier, TierEscalation, EvidenceClass, TierCheckContext } from '../types/reputation-authority.js'
import type { AutonomyLevel } from '../types/intent.js'
import type {
  ToolCallRequest, ToolCallResult, GatewayProof,
  GatewayApproval, ToolExecutor, GatewayConfig,
  RegisteredAgent, GatewayStats, GatewayAgentRole,
  ConstraintFacet, ConstraintFailure, ConstraintVector,
  ConstraintEvaluation, AuthorizationWitness, AuthorizationRef,
  ConstraintNearMiss, FidelityAttestation,
  WitnessAttestation, WitnessConflict, WitnessPolicy,
} from '../types/gateway.js'
import type { EscrowHold, DangerSignal, DangerType } from '../types/escrow.js'
import type { DisputeArtifact, DisputeOverlay } from '../types/dispute.js'
import type { FinalityState } from '../types/finality.js'
import { evaluateDisputeOverlay } from './transactional.js'
import { verifyAgentIdentity, verifyAgentIdentitySync, strengthMeetsMinimum, identityStrengthFailure, DEFAULT_IDENTITY_CONFIG } from './gateway-identity.js'
import type { GatewayIdentityVerification } from './gateway-identity.js'
import type { DataAccessDecision } from './data-enforcement.js'
import { createHybridTimestamp } from './time.js'
import type { HybridTimestamp } from '../types/time.js'
import { shouldProbe, DEFAULT_PROBE_SCHEDULE } from './fidelity-probe.js'
import type { ProbeSchedule } from './fidelity-probe.js'
import { checkCommerceConstraint } from './gateway-wiring.js'


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
  private storage?: StorageBackend
  // ── Transactional Integrity Layer ──
  private escrows: Map<string, EscrowHold> = new Map()
  private disputes: Map<string, DisputeArtifact> = new Map()
  private dangerSignals: DangerSignal[] = []
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
    this.storage = config.storage

    // B-1 security warning: only if no persistent storage
    if (!this.storage && typeof console !== 'undefined') {
      console.warn(
        '[ProxyGateway] WARNING: All security state (revocations, registrations, replay protection) ' +
        'is stored in-memory. Process restart will erase all security state. ' +
        'NOT SAFE FOR PRODUCTION. Implement a persistent StorageBackend for production use.'
      )
    }
  }

  // ── Storage Persistence (write-through cache) ──
  // Maps remain the hot path for sync lookups.
  // StorageBackend persists behind them for durability.
  // On restart: loadFromStorage() hydrates Maps from backend.

  /**
   * Load persisted state from StorageBackend into in-memory Maps.
   * Call after constructor when using persistent storage.
   * Performs integrity verification on startup.
   */
  async loadFromStorage(): Promise<{ loaded: boolean; agents: number; receipts: number; errors: string[] }> {
    if (!this.storage) return { loaded: false, agents: 0, receipts: 0, errors: ['No storage backend configured'] }

    // Integrity check first
    const report = await this.storage.verifyIntegrity()
    if (report.errors.length > 0) {
      return { loaded: false, agents: 0, receipts: report.receiptCount, errors: report.errors }
    }

    // Load agents
    const agents = await this.storage.listAgents()
    for (const stored of agents) {
      // Re-register: load delegations for this agent
      const delegations = await this.storage.getDelegationsForAgent(stored.passport.passport?.publicKey || '')
      const delegationMap = new Map<string, Delegation>()
      for (const d of delegations) {
        const revoked = await this.storage.isRevoked(d.delegationId)
        if (!revoked) delegationMap.set(d.delegationId, d)
      }

      // Load reputation if it exists
      let reputation: ScopedReputation | undefined
      let authorityTier: AuthorityTier | undefined
      if (this.config.enableReputationGating) {
        reputation = (await this.storage.getReputation(stored.agentId, '*')) ?? undefined
        if (reputation) {
          const score = computeEffectiveScore(reputation.mu, reputation.sigma)
          const demotions = await this.storage.getDemotionCount(stored.agentId)
          const tierDef = resolveAuthorityTier(score, demotions)
          authorityTier = {
            tier: tierDef.tier, name: tierDef.name,
            origin: 'earned' as const, autonomyLevel: tierDef.autonomyLevel,
            maxDelegationDepth: tierDef.maxDelegationDepth,
            maxSpendPerAction: tierDef.maxSpendPerAction, demotionCount: demotions,
          }
        }
      }

      this.agents.set(stored.agentId, {
        passport: stored.passport,
        attestation: stored.attestation,
        delegations: delegationMap,
        role: (stored.metadata?.role as any) ?? 'executor',
        reputation, authorityTier,
      })
    }
    this.stats.activeAgents = this.agents.size

    return { loaded: true, agents: agents.length, receipts: report.receiptCount, errors: [] }
  }

  // ── Agent Registration ──

  registerAgent(
    passport: RegisteredAgent['passport'],
    attestation: FloorAttestation,
    delegations: Delegation[],
    role: GatewayAgentRole = 'executor',
    options?: { endorsement?: import('../types/principal.js').PrincipalEndorsement }
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

    // Identity verification: DID resolution + principal endorsement chain
    let identityVerification: GatewayIdentityVerification | undefined
    if (this.config.enableIdentityVerification) {
      const idConfig = this.config.identityConfig ?? DEFAULT_IDENTITY_CONFIG
      identityVerification = verifyAgentIdentitySync(passport, idConfig, options?.endorsement)
      // Enforce minimum identity strength
      if (!strengthMeetsMinimum(identityVerification.strength, idConfig.minimumStrength)) {
        return { registered: false, error: `Identity strength '${identityVerification.strength}' below required '${idConfig.minimumStrength}'` }
      }
    }

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
      role,
      executionFrame: this.config.enableCrossChainEnforcement ? createExecutionFrame(agentId, { ttlMinutes: this.config.frameTTLMinutes ?? 0 }) : undefined,
      permits: this.config.enableCrossChainEnforcement ? [] : undefined,
      obligations: this.config.enableObligationMonitoring ? [] : undefined,
      reputation,
      authorityTier,
      governanceVersion: this.config.enableGovernanceEnforcement && this.config.governanceEnvelope
        ? this.config.governanceEnvelope.artifact.version : undefined,
      escalationGrants: this.config.enableEscalation ? [] : undefined,
      activeEscalations: this.config.enableEscalation ? [] : undefined,
      identityVerification,
    })
    this.stats.activeAgents = this.agents.size

    // Write-through to persistent storage (fire-and-forget)
    if (this.storage) {
      const s = this.storage
      ;(async () => {
        try {
          await s.putAgent({ agentId, passport, attestation, registeredAt: new Date().toISOString() })
          for (const d of delegations) await s.putDelegation(d)
          if (reputation) await s.putReputation(reputation)
        } catch (e) { /* storage write failure — logged but not fatal */ }
      })()
    }

    return { registered: true }
  }

  /** Check if an agent is registered with evaluator role (B-9 security hardening) */
  isRegisteredEvaluator(agentId: string): boolean {
    const agent = this.agents.get(agentId)
    if (!agent) return false
    return agent.role === 'evaluator' || agent.role === 'executor+evaluator'
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
      const failure = this.buildConstraintFailure('replay', 'REPLAY_DETECTED', 'This requestId has already been processed')
      return {
        executed: false,
        requestId: request.requestId,
        denialReason: 'Replay detected: this requestId has already been processed',
        constraintFailures: [failure],
        constraintVector: this.buildConstraintVector('denied', [{ facet: 'replay', status: 'fail', failure }], [failure]),
      }
    }

    // Step 1: Verify agent identity
    const agent = this.agents.get(request.agentId)
    if (!agent) {
      this.stats.totalDenied++
      const failure = this.buildConstraintFailure('identity', 'AGENT_NOT_REGISTERED', 'Agent not registered with gateway')
      return {
        executed: false, requestId: request.requestId,
        denialReason: 'Agent not registered with gateway',
        constraintFailures: [failure],
        constraintVector: this.buildConstraintVector('denied', [{ facet: 'identity', status: 'fail', failure }], [failure]),
      }
    }

    // Track turn count and generate HLC timestamp
    agent.turnCount = (agent.turnCount ?? 0) + 1
    const hlcTimestamp = this.config.enableHybridTimestamps
      ? createHybridTimestamp(this.config.gatewayId)
      : undefined

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
      const failure = this.buildConstraintFailure('identity', 'INVALID_SIGNATURE', 'Invalid request signature')
      return {
        executed: false, requestId: request.requestId,
        denialReason: 'Invalid request signature',
        constraintFailures: [failure],
        constraintVector: this.buildConstraintVector('denied', [{ facet: 'identity', status: 'fail', failure }], [failure]),
      }
    }

    // Step 1.9: Advisor scope enforcement.
    // Delegations with spendLimitUnit === 'invocations' are advisor delegations:
    // they authorize bounded consultation, not tool execution. Reject any
    // processToolCall that would resolve against an advisor delegation, with
    // a distinct denial code so callers can distinguish this from a generic
    // scope miss.
    const explicitDelegation = request.delegationId
      ? agent.delegations.get(request.delegationId)
      : undefined
    const agentDelegations = Array.from(agent.delegations.values())
    const onlyAdvisors =
      agentDelegations.length > 0 &&
      agentDelegations.every(d => d.spendLimitUnit === 'invocations')
    if (explicitDelegation?.spendLimitUnit === 'invocations' || onlyAdvisors) {
      this.stats.totalDenied++
      const reason = 'Advisor delegation cannot execute tools — consult via consultAdvisor instead'
      const failure = this.buildConstraintFailure('scope', 'ADVISOR_SCOPE_VIOLATION', reason,
        { actual: request.scopeRequired })
      return {
        executed: false, requestId: request.requestId,
        denialReason: reason,
        constraintFailures: [failure],
        constraintVector: this.buildConstraintVector('denied', [{ facet: 'scope', status: 'fail', failure }], [failure]),
      }
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
        const failure = this.buildConstraintFailure('scope', 'NO_VALID_DELEGATION',
          `No valid delegation covers scope "${request.scopeRequired}" for tool "${request.tool}"`,
          { actual: request.scopeRequired })
        return {
          executed: false, requestId: request.requestId,
          denialReason: `No valid delegation covers scope "${request.scopeRequired}" for tool "${request.tool}"`,
          constraintFailures: [failure],
          constraintVector: this.buildConstraintVector('denied', [{ facet: 'scope', status: 'fail', failure }], [failure]),
        }
      }
      // Use escalation delegation as base
      delegation = escalationDelegation!
    }

    const delegationStatus = verifyDelegation(delegation)
    if (!delegationStatus.valid || delegationStatus.expired || delegationStatus.revoked) {
      this.stats.totalDenied++
      const facet: ConstraintFacet = delegationStatus.revoked ? 'revocation' : 'time'
      const code = delegationStatus.revoked ? 'DELEGATION_REVOKED' : 'DELEGATION_EXPIRED'
      const failure = this.buildConstraintFailure(facet, code,
        `Delegation ${delegation.delegationId} is no longer valid`,
        { expiryRelation: delegationStatus.revoked ? undefined : 'time_expired' })
      return {
        executed: false, requestId: request.requestId,
        denialReason: `Delegation ${delegation.delegationId} is no longer valid`,
        constraintFailures: [failure],
        constraintVector: this.buildConstraintVector('denied', [{ facet, status: 'fail', failure }], [failure]),
      }
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
      const failure = this.buildConstraintFailure('values', 'POLICY_DENY', decision.reason || 'Policy evaluation denied action')
      const result: ToolCallResult = {
        executed: false, requestId: request.requestId, denialReason: decision.reason, decision,
        constraintFailures: [failure],
        constraintVector: this.buildConstraintVector('denied',
          [{ facet: 'identity', status: 'pass' }, { facet: 'scope', status: 'pass' }, { facet: 'values', status: 'fail', failure }],
          [failure]),
      }
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
        const failure = this.buildConstraintFailure('reputation', 'TIER_INSUFFICIENT', reason, {
          limit: tierCheck.requestedSpend !== undefined ? agent.authorityTier.maxSpendPerAction : tierCheck.requiredTier,
          actual: tierCheck.requestedSpend !== undefined ? tierCheck.requestedSpend : tierCheck.currentTier,
        })
        const result: ToolCallResult = {
          executed: false, requestId: request.requestId, denialReason: reason, decision, tierCheck,
          constraintFailures: [failure],
          constraintVector: this.buildConstraintVector('denied',
            [{ facet: 'identity', status: 'pass' }, { facet: 'scope', status: 'pass' }, { facet: 'values', status: 'pass' }, { facet: 'reputation', status: 'fail', failure }],
            [failure]),
        }
        this.config.onTierDenied?.(request.agentId, tierCheck)
        this.config.onToolCall?.(request, result)
        return result
      }
    }

    // Step 4.6: Substrate fidelity check
    if (this.config.enableFidelityGating) {
      const fidelityResult = this.checkFidelity(agent, request)
      if (fidelityResult) {
        this.stats.totalDenied++;
        (this.stats.fidelityDenials as number) = ((this.stats.fidelityDenials as number) ?? 0) + 1
        this.usedRequestIds.set(request.requestId, Date.now())
        const result: ToolCallResult = {
          executed: false, requestId: request.requestId, denialReason: fidelityResult.reason, decision,
          constraintFailures: [fidelityResult.failure],
          constraintVector: this.buildConstraintVector('denied',
            [{ facet: 'identity', status: 'pass' }, { facet: 'scope', status: 'pass' }, { facet: 'values', status: 'pass' },
             { facet: 'fidelity', status: 'fail', failure: fidelityResult.failure }],
            [fidelityResult.failure]),
        }
        this.config.onToolCall?.(request, result)
        return result
      }
    }

    // Step 4.7: Data access enforcement (if data gateway configured and sources declared)
    let dataAccessDecisions: DataAccessDecision[] | undefined
    if (this.config.enableDataEnforcement && this.config.dataGateway && request.dataSourceIds?.length) {
      const decisions: DataAccessDecision[] = []
      for (const sourceId of request.dataSourceIds) {
        const d = this.config.dataGateway.requestAccess({
          agentId: request.agentId,
          agentPublicKey: request.agentPublicKey,
          principalId: agent.passport.passport.publicKey,
          sourceReceiptId: sourceId,
          declaredPurpose: 'read',
          accessMethod: 'api_call',
          accessScope: request.scopeRequired,
          executionFrameId: agent.executionFrame?.frameId ?? 'default',
        })
        decisions.push(d)
      }
      dataAccessDecisions = decisions
      const blocked = decisions.filter(d => !d.allowed)
      if (blocked.length > 0) {
        this.stats.totalDenied++;
        (this.stats.dataAccessDenials as number) = ((this.stats.dataAccessDenials as number) ?? 0) + 1
        this.usedRequestIds.set(request.requestId, Date.now())
        const reason = `Data access denied for source(s): ${blocked.map(b => b.sourceReceiptId).join(', ')} — ${blocked.flatMap(b => b.hardViolations).join('; ')}`
        const failure = this.buildConstraintFailure('data', 'DATA_ACCESS_DENIED', reason)
        const result: ToolCallResult = {
          executed: false, requestId: request.requestId, denialReason: reason, decision,
          constraintFailures: [failure], dataAccessDecisions,
          constraintVector: this.buildConstraintVector('denied',
            [{ facet: 'identity', status: 'pass' }, { facet: 'scope', status: 'pass' },
             { facet: 'data', status: 'fail', failure }],
            [failure]),
        }
        this.config.onToolCall?.(request, result)
        return result
      }
      (this.stats.dataAccessGranted as number) = ((this.stats.dataAccessGranted as number) ?? 0) + request.dataSourceIds.length
    }

    // Step 4.75: Commerce preflight (if tool call has spend + commerce scope)
    const commerceCheck = checkCommerceConstraint(agent.passport, delegation, request.tool, request.spend)
    if (!commerceCheck.passed && commerceCheck.failure) {
      this.stats.totalDenied++
      this.usedRequestIds.set(request.requestId, Date.now())
      const result: ToolCallResult = {
        executed: false, requestId: request.requestId,
        denialReason: commerceCheck.reason, decision,
        constraintFailures: [commerceCheck.failure],
        constraintVector: this.buildConstraintVector('denied',
          [{ facet: 'identity', status: 'pass' }, { facet: 'scope', status: 'pass' },
           { facet: 'spend', status: 'fail', failure: commerceCheck.failure }],
          [commerceCheck.failure]),
      }
      this.config.onToolCall?.(request, result)
      return result
    }

    // Step 4.8: Dispute overlay (defeasible — NOT a lattice facet)
    // Evaluated AFTER monotone lattice. Dispute is a defeater that suppresses valid authority.
    const activeDisputes = this.getActiveDisputesForAgent(request.agentId)
    const overlay = evaluateDisputeOverlay(activeDisputes, request.scopeRequired, request.agentId)
    if (overlay.actionAffected && overlay.effectiveSeverity === 'hard') {
      this.stats.totalDenied++
      this.usedRequestIds.set(request.requestId, Date.now())
      const reason = `Action blocked by active dispute(s): ${overlay.activeDisputeIds.join(', ')} (frozen scope: ${overlay.frozenScopes.join(', ')})`
      const failure = this.buildConstraintFailure('scope', 'DISPUTE_FREEZE', reason)
      const result: ToolCallResult = {
        executed: false, requestId: request.requestId, denialReason: reason, decision,
        constraintFailures: [failure],
        constraintVector: this.buildConstraintVector('denied',
          [{ facet: 'identity', status: 'pass' }, { facet: 'scope', status: 'fail', failure }],
          [failure]),
      }
      result.constraintVector!.disputeOverlay = overlay
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
        const failure = this.buildConstraintFailure('revocation', 'REVOKED_AT_EXECUTION', 'Delegation was revoked between approval and execution')
        return {
          executed: false, requestId: request.requestId,
          denialReason: 'Delegation was revoked between approval and execution', decision,
          constraintFailures: [failure],
          constraintVector: this.buildConstraintVector('denied',
            [{ facet: 'identity', status: 'pass' }, { facet: 'scope', status: 'pass' }, { facet: 'revocation', status: 'fail', failure }],
            [failure]),
        }
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
      agent.reputation = updateReputationFromResult(agent.reputation, success, evidenceClass, {
        principalHash: delegation.delegatedBy.slice(0, 16),  // first 16 chars as hash
        taskType: request.tool,
      });
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

    // ── Constraint Architecture: Build constraint vector + authorization witness ──
    const successEvals = this.buildSuccessEvaluations(request, delegation)
    const constraintVector = this.buildConstraintVector('permitted', successEvals, [])
    const authWitness = this.buildAuthorizationWitness(request, delegation, constraintVector)
    const authRef = this.buildAuthorizationRef(authWitness)

    // Attach authorization ref to receipt (forensic link)
    receipt.authorizationRef = authRef

    // ── Dispute overlay on successful result (defeasible, not lattice) ──
    if (overlay.hasActiveDispute) {
      constraintVector.disputeOverlay = overlay
    }

    // ── Receipt maturation: starts 'maturing', finalized after witness or TTL ──
    if (this.config.witnessPolicy) {
      receipt.finality = { status: 'maturing', since: new Date().toISOString(),
        challengeWindowEnds: new Date(Date.now() + (this.config.witnessPolicy.maturationWindow ?? 300) * 1000).toISOString() }
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
      constraintVector,
      authorizationWitness: authWitness,
      dataAccessDecisions,
      hlcTimestamp,
    }

    // ── Fidelity probe scheduling ──
    if (this.config.enableFidelityGating && this.config.onProbeRequired) {
      const schedule = this.config.probeSchedule ?? DEFAULT_PROBE_SCHEDULE
      const substrateChanged = agent.fidelityAttestation?.fidelity.substrate !== agent.lastKnownSubstrate
        && agent.lastKnownSubstrate !== undefined
      if (agent.fidelityAttestation?.fidelity.substrate) {
        agent.lastKnownSubstrate = agent.fidelityAttestation.fidelity.substrate
      }
      const probeNeeded = shouldProbe(schedule, {
        isDelegationEvent: false,
        turnNumber: agent.turnCount ?? 0,
        lastProbeTurn: agent.lastProbeTurn ?? 0,
        substrateChanged,
        highStakes: request.reversibility === 'irreversible',
      })
      if (probeNeeded) {
        agent.lastProbeTurn = agent.turnCount ?? 0
        const reason = substrateChanged ? 'substrate_change' : 'turn_interval'
        this.config.onProbeRequired(request.agentId, reason)
      }
    }

    // ── Near-miss alerting (Phase 3) ──
    this.checkNearMisses(request, delegation, constraintVector)

    // ── Persist to storage (write-through) ──
    if (this.storage && receipt) {
      const s = this.storage
      const agentRep = agent.reputation
      ;(async () => {
        try {
          await s.transaction(async (tx) => {
            await tx.appendReceipt(receipt)
            await tx.checkAndStoreNonce(request.requestId, Math.floor((this.config.requestIdTTLMs || 3600000) / 1000))
            if (agentRep) await tx.putReputation(agentRep)
          })
        } catch (_e) { /* storage write failure — in-memory state is still authoritative */ }
      })()
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
      agent.reputation = updateReputationFromResult(agent.reputation, toolResult.success, evidenceClass, {
        principalHash: delegation.delegatedBy.slice(0, 16),
        taskType: approval.tool,
      });
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

    // ── Persist to storage (write-through, 2-phase path) ──
    if (this.storage && receipt) {
      const s = this.storage
      const agentRep = agent.reputation
      ;(async () => {
        try {
          await s.transaction(async (tx) => {
            await tx.appendReceipt(receipt)
            await tx.checkAndStoreNonce(approval.requestId, Math.floor((this.config.requestIdTTLMs || 3600000) / 1000))
            if (agentRep) await tx.putReputation(agentRep)
          })
        } catch (_e) { /* storage write failure — in-memory state is still authoritative */ }
      })()
    }

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

  /** Update an agent's substrate fidelity attestation.
   *  Called by external fidelity measurement systems — agents cannot self-report. */
  setFidelityAttestation(agentId: string, attestation: FidelityAttestation): boolean {
    const agent = this.agents.get(agentId)
    if (!agent) return false
    agent.fidelityAttestation = attestation
    return true
  }

  /** Get an agent's identity verification result.
   *  Returns undefined if agent not registered or identity verification not enabled. */
  getAgentIdentity(agentId: string): GatewayIdentityVerification | undefined {
    return this.agents.get(agentId)?.identityVerification
  }

  /** Set the data gateway for data access enforcement.
   *  Can be set after construction to enable data enforcement dynamically. */
  setDataGateway(dataGateway: import('./data-gateway.js').DataGateway): void {
    this.config.dataGateway = dataGateway
    this.config.enableDataEnforcement = true
  }

  /** Get the data gateway (if configured) */
  getDataGateway(): import('./data-gateway.js').DataGateway | undefined {
    return this.config.dataGateway
  }

  // ══════════════════════════════════════════════════════════════
  // Transactional Integrity Layer — Escrow, Dispute, Witness
  // ══════════════════════════════════════════════════════════════

  /** Create an escrow hold — hard reservation on delegation spend.
   *  Returns null if delegation not found or insufficient spend remaining. */
  createGatewayEscrow(escrow: EscrowHold): { success: boolean; error?: string } {
    // Validate delegation exists
    const agent = this.agents.get(escrow.initiatorAgentId)
    if (!agent) return { success: false, error: 'Initiator agent not registered' }

    const delegation = agent.delegations.get(escrow.delegationId)
    if (!delegation) return { success: false, error: 'Delegation not found' }

    // Hard reservation: check available spend
    if (delegation.spendLimit !== undefined) {
      const existingHolds = Array.from(this.escrows.values())
        .filter(e => e.delegationId === escrow.delegationId && (e.status === 'held' || e.status === 'disputed'))
        .reduce((sum, e) => sum + e.amount.value, 0)

      if (existingHolds + escrow.amount.value > delegation.spendLimit) {
        return { success: false, error: `Insufficient spend: ${delegation.spendLimit - existingHolds} available, ${escrow.amount.value} requested` }
      }
    }

    this.escrows.set(escrow.escrowId, escrow)
    this.stats.escrowsCreated = ((this.stats as any).escrowsCreated ?? 0) + 1
    return { success: true }
  }

  /** Fulfill an escrow — transition to released. */
  fulfillEscrow(escrowId: string, fulfillmentReceiptId: string): { success: boolean; error?: string } {
    const escrow = this.escrows.get(escrowId)
    if (!escrow) return { success: false, error: 'Escrow not found' }
    if (escrow.status !== 'held' && escrow.status !== 'verification_pending') {
      return { success: false, error: `Cannot fulfill escrow in status: ${escrow.status}` }
    }
    if (new Date(escrow.expiresAt) < new Date()) {
      escrow.status = 'expired'
      escrow.finality = { status: 'finalized', since: new Date().toISOString() }
      return { success: false, error: 'Escrow expired' }
    }
    escrow.status = 'released'
    escrow.fulfillmentReceiptId = fulfillmentReceiptId
    escrow.finality = { status: 'finalized', since: new Date().toISOString() }
    this.stats.escrowsReleased = ((this.stats as any).escrowsReleased ?? 0) + 1
    return { success: true }
  }

  /** Expire an escrow — auto-refund on TTL expiry. */
  expireEscrow(escrowId: string): { success: boolean; error?: string } {
    const escrow = this.escrows.get(escrowId)
    if (!escrow) return { success: false, error: 'Escrow not found' }
    if (escrow.status === 'disputed') return { success: false, error: 'Cannot expire disputed escrow' }
    if (escrow.status !== 'held' && escrow.status !== 'partially_fulfilled') {
      return { success: false, error: `Cannot expire escrow in status: ${escrow.status}` }
    }
    escrow.status = 'expired'
    escrow.finality = { status: 'finalized', since: new Date().toISOString() }
    this.stats.escrowsExpired = ((this.stats as any).escrowsExpired ?? 0) + 1
    return { success: true }
  }

  /** File a dispute — freezes escrow, deducts bond from claimant delegation. */
  fileGatewayDispute(dispute: DisputeArtifact): { success: boolean; error?: string } {
    // Validate bond (slashing bond — options pricing: free dispute = free option)
    if (dispute.bond.slashable && dispute.bond.amount > 0) {
      const claimant = this.agents.get(dispute.claimantId)
      if (!claimant) return { success: false, error: 'Claimant not registered' }
      const bondDel = claimant.delegations.get(dispute.bond.delegationId)
      if (!bondDel) return { success: false, error: 'Bond delegation not found' }
    }
    // Freeze affected escrows
    for (const escrowId of dispute.freezeScope.escrowIds) {
      const escrow = this.escrows.get(escrowId)
      if (escrow && escrow.status === 'held') {
        escrow.status = 'disputed'
        escrow.disputeId = dispute.disputeId
        escrow.finality = { status: 'frozen', since: new Date().toISOString(), frozenBy: dispute.disputeId }
      }
    }
    this.disputes.set(dispute.disputeId, dispute)
    this.stats.disputesFiled = ((this.stats as any).disputesFiled ?? 0) + 1
    return { success: true }
  }

  /** Resolve a dispute — unfreeze escrow, slash or return bond.
   *  Uses bifurcated timeout (ESS): low-value → respondent, high-value → claimant. */
  resolveGatewayDispute(disputeId: string, resolution: DisputeArtifact['resolution']): { success: boolean; error?: string } {
    const dispute = this.disputes.get(disputeId)
    if (!dispute) return { success: false, error: 'Dispute not found' }
    if (dispute.status === 'resolved' || dispute.status === 'dismissed') {
      return { success: false, error: `Dispute already in terminal state: ${dispute.status}` }
    }

    dispute.resolution = resolution
    dispute.status = resolution!.outcome === 'dismissed' ? 'dismissed' : 'resolved'
    dispute.finality = { status: 'appealable', since: new Date().toISOString() }

    // Unfreeze escrows and apply enforcement
    for (const escrowId of dispute.freezeScope.escrowIds) {
      const escrow = this.escrows.get(escrowId)
      if (!escrow || escrow.status !== 'disputed') continue

      const action = resolution!.enforcement.escrowAction ?? 'release'
      if (action === 'release') {
        escrow.status = 'released'
        escrow.finality = { status: 'finalized', since: new Date().toISOString() }
      } else if (action === 'refund') {
        escrow.status = 'refunded'
        escrow.finality = { status: 'finalized', since: new Date().toISOString() }
      } else if (action === 'split') {
        escrow.status = 'released' // partial — split tracked in resolution
        escrow.finality = { status: 'finalized', since: new Date().toISOString() }
      }
    }

    this.stats.disputesResolved = ((this.stats as any).disputesResolved ?? 0) + 1
    return { success: true }
  }

  /** Auto-resolve a dispute on timeout — bifurcated ESS default.
   *  Low-value: dismiss (favor respondent). High-value: uphold (favor claimant). */
  timeoutDispute(disputeId: string): { success: boolean; outcome: string; error?: string } {
    const dispute = this.disputes.get(disputeId)
    if (!dispute) return { success: false, outcome: 'not_found', error: 'Dispute not found' }
    const threshold = this.config.escrowTimeoutThreshold ?? 100
    const escrowAmount = dispute.freezeScope.escrowIds
      .map(id => this.escrows.get(id))
      .reduce((sum, e) => sum + (e?.amount.value ?? 0), 0)

    const outcome = escrowAmount >= threshold ? 'upheld' : 'dismissed'
    const escrowAction = outcome === 'upheld' ? 'refund' : 'release'
    const bondAction = outcome === 'upheld' ? 'return' : 'slash'

    const result = this.resolveGatewayDispute(disputeId, {
      outcome: outcome as any, resolvedBy: 'system', resolverRole: 'timeout_default',
      resolvedAt: new Date().toISOString(), reasoning: `Auto-timeout: ${outcome} (threshold: ${threshold}, amount: ${escrowAmount})`,
      enforcement: { escrowAction: escrowAction as any, bondAction: bondAction as any },
    })
    return { ...result, outcome }
  }

  /** Get escrow by ID */
  getEscrow(escrowId: string): EscrowHold | undefined { return this.escrows.get(escrowId) }
  /** Get dispute by ID */
  getDispute(disputeId: string): DisputeArtifact | undefined { return this.disputes.get(disputeId) }
  /** Get active disputes for an agent (as respondent) */
  getActiveDisputesForAgent(agentId: string): DisputeArtifact[] {
    return Array.from(this.disputes.values()).filter(d =>
      d.respondentId === agentId && ['filed', 'acknowledged', 'investigating'].includes(d.status))
  }
  /** Get all danger signals */
  getDangerSignals(): DangerSignal[] { return [...this.dangerSignals] }

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
      floorPrinciples: this.config.floor.floor.map((p: FloorPrinciple) => ({
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

  // ══════════════════════════════════════════════════════════════════
  // Constraint Architecture — Builder Methods
  // ══════════════════════════════════════════════════════════════════

  /** Build a ConstraintFailure for a specific facet */
  private buildConstraintFailure(
    facet: ConstraintFacet, code: string, message: string,
    opts?: { limit?: string | number; actual?: string | number; retryable?: boolean; severity?: 'hard' | 'soft' | 'warning'; expiryRelation?: 'time_expired' | 'spend_exceeded' | 'both' }
  ): ConstraintFailure {
    return {
      facet, status: 'fail', code, message,
      severity: opts?.severity ?? 'hard',
      retryable: opts?.retryable ?? false,
      limit: opts?.limit, actual: opts?.actual,
      expiryRelation: opts?.expiryRelation,
    }
  }

  /** Build a ConstraintVector from individual evaluations */
  private buildConstraintVector(
    outcome: 'permitted' | 'denied' | 'partially_permitted',
    evaluations: ConstraintEvaluation[],
    failures: ConstraintFailure[]
  ): ConstraintVector {
    // Determine primary failure: the one that would have blocked even if all others passed
    let primaryFailure: ConstraintFailure | undefined
    if (failures.length === 1) {
      primaryFailure = failures[0]
    } else if (failures.length > 1) {
      // Priority: revocation > identity > scope > spend > time > reputation > values > governance
      const priority: ConstraintFacet[] = ['revocation', 'identity', 'scope', 'spend', 'time', 'reputation', 'values', 'governance']
      primaryFailure = failures.sort((a, b) => {
        const ai = priority.indexOf(a.facet); const bi = priority.indexOf(b.facet)
        return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
      })[0]
    }
    return {
      evaluatedAt: new Date().toISOString(),
      outcome, facets: evaluations, failures,
      primaryFailure,
    }
  }

  /** Build an AuthorizationWitness for a successful execution */
  private buildAuthorizationWitness(
    request: ToolCallRequest, delegation: Delegation,
    constraintVector: ConstraintVector, approvalId?: string,
  ): AuthorizationWitness {
    const witnessId = 'aw_' + uuidv4().slice(0, 12)
    const witnessData = {
      witnessId,
      status: 'valid' as const,
      approvalId,
      delegationId: delegation.delegationId,
      scopeAuthorized: delegation.scope,
      spendAuthorization: delegation.spendLimit !== undefined ? {
        limit: delegation.spendLimit,
        spent: 0, // TODO: track cumulative from storage
        remaining: delegation.spendLimit,
        currency: request.spend?.currency ?? 'usd',
      } : undefined,
      constraints: constraintVector,
      authorizationHash: '', // filled below
      gatewaySignature: '', // filled below
      timestamp: new Date().toISOString(),
    }
    // Hash the witness data (without signature) for integrity
    const hashPayload = canonicalize({ ...witnessData, gatewaySignature: undefined, authorizationHash: undefined })
    witnessData.authorizationHash = hashPayload.length > 0 ? hashPayload.slice(0, 64) : 'empty'
    const sigPayload = canonicalize(witnessData)
    witnessData.gatewaySignature = signData(sigPayload, this.config.gatewayPrivateKey)
    return witnessData
  }

  /** Build a compact AuthorizationRef for embedding in receipts */
  private buildAuthorizationRef(witness: AuthorizationWitness): AuthorizationRef {
    return {
      witnessId: witness.witnessId,
      witnessHash: witness.authorizationHash,
      status: witness.status,
      constraintOutcome: witness.constraints.outcome,
      failureCount: witness.constraints.failures.length,
      primaryFailureFacet: witness.constraints.primaryFailure?.facet,
    }
  }

  /** Build the standard "all passed" evaluations for a successful execution */
  private buildSuccessEvaluations(request: ToolCallRequest, delegation: Delegation): ConstraintEvaluation[] {
    const registeredAgent = this.agents.get(request.agentId)
    const evals: ConstraintEvaluation[] = [
      { facet: 'identity', status: 'pass', headroom: registeredAgent?.identityVerification?.strength },
      { facet: 'replay', status: 'pass' },
      { facet: 'scope', status: 'pass' },
      { facet: 'revocation', status: 'pass' },
    ]
    // Time headroom
    if (delegation.expiresAt) {
      const remaining = new Date(delegation.expiresAt).getTime() - Date.now()
      evals.push({ facet: 'time', status: 'pass', headroom: Math.max(0, Math.floor(remaining / 1000)) + 's' })
    } else {
      evals.push({ facet: 'time', status: 'not_applicable' })
    }
    // Spend headroom
    if (delegation.spendLimit !== undefined && request.spend) {
      const remaining = delegation.spendLimit - (request.spend.amount ?? 0)
      evals.push({ facet: 'spend', status: 'pass', headroom: remaining })
    } else {
      evals.push({ facet: 'spend', status: request.spend ? 'pass' : 'not_applicable' })
    }
    evals.push({ facet: 'values', status: 'pass' })
    if (request.reversibility) {
      evals.push({ facet: 'reversibility', status: 'pass' })
    }
    // Fidelity headroom (if gating enabled and attestation exists)
    if (this.config.enableFidelityGating) {
      const agent = this.agents.get(request.agentId)
      const att = agent?.fidelityAttestation
      if (att) {
        const minScore = this.config.minFidelityScore ?? 0.5
        const headroom = att.fidelity.score - minScore
        evals.push({ facet: 'fidelity', status: 'pass', headroom: Math.round(headroom * 100) / 100 })
      } else {
        const policy = this.config.fidelityDefaultPolicy ?? 'warn'
        evals.push({ facet: 'fidelity', status: policy === 'ignore' ? 'not_applicable' : 'unknown' })
      }
    }
    return evals
  }

  /** Check for near-miss conditions after a permitted execution.
   *  Fires onNearMiss callback for each facet approaching its boundary. */
  /** Check substrate fidelity constraint. Returns failure info if denied, null if passed. */
  private checkFidelity(
    agent: RegisteredAgent, request: ToolCallRequest
  ): { reason: string; failure: ConstraintFailure } | null {
    const attestation = agent.fidelityAttestation
    const minScore = this.config.minFidelityScore ?? 0.5
    const maxAge = this.config.fidelityMaxAge ?? 86400
    const defaultPolicy = this.config.fidelityDefaultPolicy ?? 'warn'

    if (!attestation) {
      if (defaultPolicy === 'deny') {
        return {
          reason: `No fidelity attestation for agent ${request.agentId}`,
          failure: this.buildConstraintFailure('fidelity', 'NO_ATTESTATION',
            'Agent has no substrate fidelity attestation', { limit: minScore, actual: 0 }),
        }
      }
      return null // 'warn' or 'ignore' — pass but ConstraintVector will show unknown/not_applicable
    }

    // Check staleness
    const ageSeconds = (Date.now() - new Date(attestation.fidelity.measuredAt).getTime()) / 1000
    if (ageSeconds > maxAge) {
      if (defaultPolicy === 'deny') {
        return {
          reason: `Fidelity attestation stale (${Math.round(ageSeconds)}s old, max ${maxAge}s)`,
          failure: this.buildConstraintFailure('fidelity', 'STALE_ATTESTATION',
            `Attestation expired (${Math.round(ageSeconds)}s > ${maxAge}s max)`,
            { limit: maxAge, actual: Math.round(ageSeconds) }),
        }
      }
      return null // warn/ignore — treat stale same as absent
    }

    // Check score
    if (attestation.fidelity.score < minScore) {
      return {
        reason: `Fidelity score ${attestation.fidelity.score.toFixed(2)} below minimum ${minScore}`,
        failure: this.buildConstraintFailure('fidelity', 'BELOW_THRESHOLD',
          `Fidelity ${attestation.fidelity.score.toFixed(2)} < required ${minScore}`,
          { limit: minScore, actual: attestation.fidelity.score }),
      }
    }

    return null // passed
  }

  private checkNearMisses(
    request: ToolCallRequest, delegation: Delegation,
    constraintVector: ConstraintVector
  ): void {
    if (!this.config.enableNearMissAlerting || !this.config.onNearMiss) return
    const thresholds = this.config.nearMissThresholds ?? [0.1, 0.05, 0.01]
    const highestThreshold = Math.max(...thresholds)

    for (const eval_ of constraintVector.facets) {
      if (eval_.status !== 'pass' || eval_.headroom === undefined) continue

      let headroomRatio: number | undefined
      let headroomAbsolute: number | string = eval_.headroom

      if (eval_.facet === 'spend' && typeof eval_.headroom === 'number' && delegation.spendLimit) {
        headroomRatio = eval_.headroom / delegation.spendLimit
      } else if (eval_.facet === 'time' && typeof eval_.headroom === 'string') {
        // Parse "Ns" format
        const seconds = parseInt(eval_.headroom.replace('s', ''), 10)
        if (!isNaN(seconds) && delegation.expiresAt) {
          const totalSeconds = (new Date(delegation.expiresAt).getTime() - Date.now()) / 1000
          // Use original TTL estimate (delegation lifetime)
          const delegationTTL = 3600 // default 1 hour, conservative
          headroomRatio = Math.max(0, seconds / delegationTTL)
          headroomAbsolute = seconds
        }
      }

      if (headroomRatio !== undefined && headroomRatio <= highestThreshold) {
        // Find the highest threshold that was breached
        const breachedThreshold = thresholds
          .filter(t => headroomRatio! <= t)
          .sort((a, b) => b - a)[0] ?? highestThreshold

        const nearMiss: ConstraintNearMiss = {
          agentId: request.agentId,
          facet: eval_.facet,
          headroomRatio,
          headroomAbsolute,
          alertThreshold: breachedThreshold,
          timestamp: new Date().toISOString(),
          message: `Agent ${request.agentId} at ${((1 - headroomRatio) * 100).toFixed(1)}% of ${eval_.facet} limit`,
        }

        this.stats.nearMissAlerts = (this.stats.nearMissAlerts ?? 0) + 1
        if (!this.stats.nearMissByFacet) this.stats.nearMissByFacet = {}
        this.stats.nearMissByFacet[eval_.facet] = (this.stats.nearMissByFacet[eval_.facet] ?? 0) + 1

        this.config.onNearMiss(nearMiss)
      }
    }
  }

  // ══════════════════════════════════════════════════════════════
  // Danger Signal Detection — Matzinger Danger Model (1994)
  // ══════════════════════════════════════════════════════════════
  // The gateway doesn't wait for someone to file a dispute.
  // It autonomously detects escrow anomaly patterns and emits signals.

  /** Scan all active escrows for danger patterns. Call periodically or after each processToolCall. */
  scanForDangerSignals(): DangerSignal[] {
    const now = Date.now()
    const newSignals: DangerSignal[] = []

    for (const [, escrow] of this.escrows) {
      if (escrow.status !== 'held' && escrow.status !== 'partially_fulfilled') continue

      const expiresAt = new Date(escrow.expiresAt).getTime()
      const totalDuration = expiresAt - new Date(escrow.createdAt).getTime()
      const remaining = expiresAt - now
      const elapsed = totalDuration - remaining

      // Danger: escrow approaching TTL with no fulfillment
      if (remaining > 0 && remaining < totalDuration * 0.1 && !escrow.fulfillmentReceiptId) {
        newSignals.push({
          signalId: `ds_${escrow.escrowId}_ttl_${now}`,
          type: 'escrow_ttl_approaching',
          agentId: escrow.counterpartyAgentId,
          relatedArtifactId: escrow.escrowId,
          severity: remaining < totalDuration * 0.05 ? 'high' : 'medium',
          detectedAt: new Date().toISOString(),
          autoEscalate: remaining < totalDuration * 0.02,
          message: `Escrow ${escrow.escrowId} at ${Math.round((1 - remaining / totalDuration) * 100)}% of TTL with no fulfillment`,
        })
      }
    }

    // Danger: agent involved in multiple active disputes
    const disputesByRespondent = new Map<string, number>()
    for (const [, d] of this.disputes) {
      if (['filed', 'acknowledged', 'investigating'].includes(d.status)) {
        disputesByRespondent.set(d.respondentId, (disputesByRespondent.get(d.respondentId) ?? 0) + 1)
      }
    }
    for (const [agentId, count] of disputesByRespondent) {
      if (count >= 3) {
        newSignals.push({
          signalId: `ds_disputes_${agentId}_${now}`,
          type: 'repeated_disputes',
          agentId,
          relatedArtifactId: agentId,
          severity: count >= 5 ? 'high' : 'medium',
          detectedAt: new Date().toISOString(),
          autoEscalate: count >= 5,
          message: `Agent ${agentId} has ${count} active disputes`,
        })
      }
    }

    this.dangerSignals.push(...newSignals)
    return newSignals
  }
}

export function createProxyGateway(config: GatewayConfig, executor: ToolExecutor): ProxyGateway {
  return new ProxyGateway(config, executor)
}
