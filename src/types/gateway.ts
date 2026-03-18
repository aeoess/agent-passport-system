// ══════════════════════════════════════════════════════════════════
// Proxy Gateway — Type Definitions
// ══════════════════════════════════════════════════════════════════
// The enforcement boundary that GPT and Gemini identified as the
// core unsolved problem. AgentContext trusts the agent to self-enforce.
// The gateway IS the enforcement. Agent cannot bypass, forge, or skip.
//
// Key difference: gateway generates receipts, not the agent.
// The agent requested. The gateway executed. The gateway proves it.
// ══════════════════════════════════════════════════════════════════

import type { SignedPassport, Delegation, ActionReceipt, ValuesFloor, FloorAttestation } from './passport.js'
import type { ActionIntent, PolicyDecision, PolicyReceipt, PolicyValidator } from './policy.js'
import type { SignedAuthorityObject, FlowCheckResult, ExecutionFrame, CrossChainPermit } from './cross-chain.js'
import type { Obligation, ObligationResolution } from './obligations.js'
import type { ExecutionEnvelope } from './execution-envelope.js'

// ── Tool Executor ──
// The gateway wraps any tool. This is the abstraction.
// Could be an MCP tool, an HTTP API, a function call, anything.

export interface ToolCallRequest {
  /** Unique request ID (client-generated, used for replay protection) */
  requestId: string
  /** Agent making the request */
  agentId: string
  /** Agent's public key for identity verification */
  agentPublicKey: string
  /** Signature over canonicalized { requestId, agentId, tool, params } */
  signature: string
  /** Tool name / action type (maps to delegation scope) */
  tool: string
  /** Tool parameters */
  params: Record<string, unknown>
  /** Scope claim: which delegation scope this tool call requires */
  scopeRequired: string
  /** Optional: specific delegation to use */
  delegationId?: string
  /** Optional: spend associated with this call */
  spend?: { amount: number; currency: string }
  /** Optional: human-readable context for audit */
  context?: string
}

export interface ToolCallResult {
  /** Whether the call was permitted and executed */
  executed: boolean
  /** Request ID echo (for correlation) */
  requestId: string
  /** The tool's return value (only if executed) */
  result?: unknown
  /** Error from the tool itself (only if executed but tool failed) */
  toolError?: string
  /** Why it was denied (only if not executed) */
  denialReason?: string
  /** The full 3-signature chain proof */
  proof?: GatewayProof
  /** Gateway-generated receipt (only if executed successfully) */
  receipt?: ActionReceipt
  /** Policy decision (always present, even on denial) */
  decision?: PolicyDecision
  /** Signed Authority Object wrapping the result (cross-chain enforcement) */
  sao?: SignedAuthorityObject
  /** Cross-chain flow check result (if cross-chain enforcement enabled) */
  flowCheck?: FlowCheckResult
  /** Obligation resolutions triggered by this call (if obligation monitoring enabled) */
  obligationResolutions?: ObligationResolution[]
  /** Execution envelope for cross-engine interop (if produceEnvelope enabled) */
  envelope?: ExecutionEnvelope
}

/** The complete cryptographic proof chain */
export interface GatewayProof {
  /** Signature 1: the agent's original request signature */
  requestSignature: string
  /** Signature 2: the gateway's policy decision signature */
  decisionSignature: string
  /** Signature 3: the gateway's execution receipt signature */
  receiptSignature: string
  /** Full policy receipt linking all three */
  policyReceipt: PolicyReceipt
}

// ── Gateway Approval (intermediate state) ──
// After policy check, before execution. Has TTL and nonce.

export interface GatewayApproval {
  approvalId: string
  requestId: string
  agentId: string
  tool: string
  params: Record<string, unknown>
  scopeRequired: string
  delegationId: string
  intent: ActionIntent
  decision: PolicyDecision
  /** When this approval expires (ISO 8601) */
  expiresAt: string
  /** Nonce for replay protection. Each approval can be used exactly once. */
  nonce: string
  /** Whether this approval has been consumed (executed) */
  consumed: boolean
}

// ── Tool Executor Interface ──
// The downstream tool. Gateway calls this after policy approval.

export type ToolExecutor = (
  tool: string,
  params: Record<string, unknown>
) => Promise<{ success: boolean; result?: unknown; error?: string }>

// ── Gateway Configuration ──

export interface GatewayConfig {
  /** Gateway's own identity (it's an agent too) */
  gatewayId: string
  gatewayPublicKey: string
  gatewayPrivateKey: string
  /** The floor to enforce */
  floor: ValuesFloor
  /** Policy validator. Default: FloorValidatorV1 */
  validator?: PolicyValidator
  /** Approval TTL in seconds. Default: 30 */
  approvalTTLSeconds?: number
  /** Maximum pending approvals per agent. Default: 10 */
  maxPendingPerAgent?: number
  /** Whether to recheck revocation at execution time (after approval).
   *  Default: true. This is the paranoid mode GPT recommended. */
  recheckRevocationOnExecute?: boolean
  /** Callback: fires on every tool call (permitted or denied) */
  onToolCall?: (request: ToolCallRequest, result: ToolCallResult) => void
  /** Callback: fires when a suspicious pattern is detected */
  onSuspicious?: (agentId: string, reason: string) => void
  /** Enable cross-chain data flow enforcement (Module 18). Default: false */
  enableCrossChainEnforcement?: boolean
  /** Enable obligation monitoring (Module 20). Default: false */
  enableObligationMonitoring?: boolean
  /** Produce ExecutionEnvelope on successful tool calls for cross-engine interop. Default: false */
  produceEnvelope?: boolean
  /** Callback: fires when an obligation is resolved */
  onObligationResolved?: (resolution: ObligationResolution) => void
  /** Callback: fires when cross-chain flow is blocked */
  onCrossChainBlocked?: (agentId: string, result: FlowCheckResult) => void
}

// ── Registered Agent ──
// The gateway maintains a registry of agents it serves.

export interface RegisteredAgent {
  passport: SignedPassport
  attestation: FloorAttestation
  delegations: Map<string, Delegation>
  /** Per-agent execution frame for taint tracking (cross-chain) */
  executionFrame?: ExecutionFrame
  /** Active cross-chain permits for this agent */
  permits?: CrossChainPermit[]
  /** Pending obligations for this agent */
  obligations?: Obligation[]
}

// ── Gateway Stats ──

export interface GatewayStats {
  totalRequests: number
  totalPermitted: number
  totalDenied: number
  totalExecuted: number
  totalToolErrors: number
  replayAttemptsBlocked: number
  expiredApprovalsCleared: number
  revocationRechecksTriggered: number
  activeAgents: number
  pendingApprovals: number
  /** Cross-chain enforcement stats */
  crossChainChecks?: number
  crossChainBlocked?: number
  crossChainPermitted?: number
  /** Obligation monitoring stats */
  obligationsRegistered?: number
  obligationsFulfilled?: number
  obligationsTerminated?: number
}
