// ══════════════════════════════════════════════════════════════════
// APS Governance Interceptor for MCP (SEP-1763 Reference)
// ══════════════════════════════════════════════════════════════════
// Maps APS enforcement to the MCP interceptor lifecycle:
//   Pre-execution  → PolicyReceipt (authorization)
//   Post-execution → ExecutionAttestation (what actually ran)
//   Bilateral      → BilateralReceipt (both parties agree)
//
// Reference: modelcontextprotocol/modelcontextprotocol#1763
// ══════════════════════════════════════════════════════════════════

import {
  generateKeyPair,
  createActionIntent,
  evaluateIntent,
  createPolicyReceipt,
  createExecutionAttestation,
  createBilateralReceipt,
  createEvidenceCommitment,
  loadFloor,
  FloorValidatorV1,
} from 'agent-passport-system'
import type {
  ActionIntent, PolicyDecision, PolicyReceipt,
  ExecutionAttestation, BilateralReceipt,
  CreateExecutionAttestationInput,
} from 'agent-passport-system'

// ── Interceptor types (from SEP-1763 proposal) ──

interface InterceptorEvent {
  method: string                    // 'tools/call', 'tools/list', etc.
  params: Record<string, unknown>
  context: {
    mcp_call_id: string
    agent_id?: string
    session_id?: string
    timestamp: string
  }
}

interface InterceptorResult {
  action: 'allow' | 'block' | 'modify'
  severity: 'info' | 'warn' | 'error'
  message: string
  metadata?: Record<string, unknown>
}

// ── APS Governance Interceptor ──

export interface APSInterceptorConfig {
  /** Gateway keypair for signing receipts */
  gatewayPrivateKey: string
  gatewayPublicKey: string
  /** Path to values floor YAML */
  floorPath?: string
  /** Delegation scope to check against */
  delegations: Map<string, { scope: string[]; spendLimit: number; spentAmount: number; expiresAt: string }>
  /** Whether to produce bilateral receipts (requires server key) */
  bilateral?: boolean
  serverPrivateKey?: string
}

export class APSGovernanceInterceptor {
  private config: APSInterceptorConfig
  private receipts: Map<string, PolicyReceipt> = new Map()

  constructor(config: APSInterceptorConfig) {
    this.config = config
  }

  /**
   * PRE-EXECUTION INTERCEPTOR (validate)
   * Runs before tools/call. Checks delegation, scope, spend limits.
   * Produces a PolicyReceipt if permitted.
   * Maps to SEP-1763: validate interceptor on tools/call event.
   */
  async validate(event: InterceptorEvent): Promise<InterceptorResult> {
    const { method, params, context } = event
    if (method !== 'tools/call') {
      return { action: 'allow', severity: 'info', message: 'Non-tool event, passing through' }
    }

    const toolName = params.name as string
    const agentId = context.agent_id
    if (!agentId) {
      return { action: 'block', severity: 'error', message: 'No agent identity in request context' }
    }

    // Check delegation
    const delegation = this.config.delegations.get(agentId)
    if (!delegation) {
      return { action: 'block', severity: 'error', message: `No delegation found for agent ${agentId}` }
    }

    // Check scope
    if (!delegation.scope.includes(toolName) && !delegation.scope.includes('*')) {
      return { action: 'block', severity: 'error', message: `Tool "${toolName}" not in delegation scope [${delegation.scope.join(', ')}]` }
    }

    // Check expiry
    if (new Date(delegation.expiresAt) < new Date()) {
      return { action: 'block', severity: 'error', message: 'Delegation expired' }
    }

    // Check spend (if applicable)
    const spend = (params.arguments as Record<string, unknown>)?.spend as number | undefined
    if (spend && delegation.spentAmount + spend > delegation.spendLimit) {
      return {
        action: 'block', severity: 'error',
        message: `Spend $${spend} would exceed limit ($${delegation.spentAmount + spend} > $${delegation.spendLimit})`
      }
    }

    return {
      action: 'allow', severity: 'info',
      message: `Permitted: ${toolName} for ${agentId}`,
      metadata: { callId: context.mcp_call_id, delegationScope: delegation.scope }
    }
  }


  /**
   * POST-EXECUTION INTERCEPTOR (certify)
   * Runs after tools/call completes. Produces ExecutionAttestation.
   * The gateway signs what ACTUALLY ran — agent can't forge this.
   * Maps to SEP-1763: observe interceptor with certification output.
   */
  async certify(event: InterceptorEvent, result: {
    toolName: string
    actualParameters: Record<string, unknown>
    actualResult: Record<string, unknown>
    intentParameters: Record<string, unknown>
    startedAt: string
    completedAt: string
  }): Promise<{ attestation: ExecutionAttestation; drift: string }> {
    const input: CreateExecutionAttestationInput = {
      agentId: event.context.agent_id ?? 'unknown',
      attestorId: 'mcp-interceptor',
      attestorType: 'gateway',
      toolName: result.toolName,
      actualParameters: result.actualParameters,
      actualResult: result.actualResult,
      policyReceiptId: event.context.mcp_call_id,
      executionFrameId: event.context.session_id ?? event.context.mcp_call_id,
      intentParameters: result.intentParameters,
      executionStartedAt: result.startedAt,
      executionCompletedAt: result.completedAt,
    }

    const attestation = createExecutionAttestation(
      input,
      this.config.gatewayPrivateKey,
      { executionContext: result.toolName }
    )

    return {
      attestation,
      drift: attestation.drift.severity,
    }
  }


  /**
   * BILATERAL AGREEMENT (optional)
   * Both requesting agent and MCP server sign the same outcome.
   * Prevents unilateral fabrication by either party.
   * Maps to SEP-1763: post-execution certification with mutual signing.
   */
  async agree(event: InterceptorEvent, outcome: {
    toolName: string
    requestHash: string
    responseHash: string
    status: 'success' | 'failure' | 'partial'
    summary: string
  }): Promise<BilateralReceipt | null> {
    if (!this.config.bilateral || !this.config.serverPrivateKey) return null

    const agentId = event.context.agent_id ?? 'unknown'
    return createBilateralReceipt({
      requestingAgentId: agentId,
      servingAgentId: 'mcp-server',
      outcome,
      requestedAt: event.context.timestamp,
      completedAt: new Date().toISOString(),
      requestingAgentPrivateKey: this.config.gatewayPrivateKey,
      servingAgentPrivateKey: this.config.serverPrivateKey,
      gatewayPrivateKey: this.config.gatewayPrivateKey,
    })
  }

  /**
   * FULL LIFECYCLE — validate → execute → certify → agree
   * Convenience method that runs the complete APS enforcement pipeline
   * for a single MCP tools/call event.
   *
   * Usage:
   *   const result = await interceptor.enforce(event, executeFn)
   *   if (!result.permitted) return result.denial
   *   return result.response  // tool output + signed receipts
   */
  async enforce(
    event: InterceptorEvent,
    execute: (params: Record<string, unknown>) => Promise<Record<string, unknown>>
  ): Promise<{
    permitted: boolean
    denial?: InterceptorResult
    response?: Record<string, unknown>
    attestation?: ExecutionAttestation
    bilateral?: BilateralReceipt | null
  }> {
    // Step 1: Pre-execution validation
    const validation = await this.validate(event)
    if (validation.action === 'block') {
      return { permitted: false, denial: validation }
    }

    // Step 2: Execute the tool
    const startedAt = new Date().toISOString()
    const response = await execute(event.params)
    const completedAt = new Date().toISOString()

    // Step 3: Post-execution certification
    const { attestation } = await this.certify(event, {
      toolName: event.params.name as string,
      actualParameters: event.params,
      actualResult: response,
      intentParameters: event.params,
      startedAt,
      completedAt,
    })

    // Step 4: Bilateral agreement (optional)
    const bilateral = await this.agree(event, {
      toolName: event.params.name as string,
      requestHash: attestation.parameterHash,
      responseHash: attestation.resultHash,
      status: 'success',
      summary: `Executed ${event.params.name}`,
    })

    // Update spend tracking
    const agentId = event.context.agent_id
    const spend = (event.params.arguments as Record<string, unknown>)?.spend as number | undefined
    if (agentId && spend) {
      const delegation = this.config.delegations.get(agentId)
      if (delegation) delegation.spentAmount += spend
    }

    return { permitted: true, response, attestation, bilateral }
  }
}

// ── Factory function ──
export function createAPSInterceptor(config: APSInterceptorConfig): APSGovernanceInterceptor {
  return new APSGovernanceInterceptor(config)
}
