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
import type { ScopedReputation, AuthorityTier, TierEscalation, EvidenceClass } from './reputation-authority.js'
import type { GovernanceArtifact, GovernanceEnvelope, GovernanceLoadPolicy, GovernanceDiff } from './governance.js'
import type { ActiveEscalation, EscalationGrant } from '../core/escalation.js'

// ── Action Reversibility (Gap 3 taxonomy) ──
// Actions are classified by how recoverable they are after execution.
// Delegations can restrict agents to only tentative/compensable actions.

export type ActionReversibility = 'tentative' | 'compensable' | 'irreversible'

// ══════════════════════════════════════════════════════════════════
// Constraint Architecture — Authorization Witness & Constraint Vector
// ══════════════════════════════════════════════════════════════════
// Consilium decision (March 26, 2026): receipts must capture WHY an
// action was allowed/denied, not just WHAT happened. Authorization
// proof and execution proof are separate but hash-linked.
//
// Design: referential receipts + optional embedded witness snapshot.
// Types here are protocol primitives (SDK). Evaluation is gateway.
// ══════════════════════════════════════════════════════════════════

// ── Constraint Facets ──
// The dimensions of authority. Each narrows independently through
// delegation (faceted Monotonic Narrowing). Product lattice:
// Time × Spend × Scope × Reputation × Values × Revocation × Reversibility

export type ConstraintFacet =
  | 'time'           // approval TTL, delegation expiry
  | 'spend'          // per-action limit, cumulative limit, delegation budget
  | 'scope'          // tool name, parameter patterns, target restrictions
  | 'reputation'     // tier threshold, minimum evidence count
  | 'values'         // F-001 through F-008, graduated enforcement
  | 'revocation'     // delegation revoked, cascade revocation
  | 'reversibility'  // tentative/compensable/irreversible classification
  | 'governance'     // governance artifact version, stale attestation
  | 'identity'       // passport verification, signature validity
  | 'replay'         // request ID reuse detection
  | 'cross_chain'    // taint tracking, confused deputy prevention
  | 'escalation'     // bounded escalation grant validity

// ── Constraint Status ──
// Four-valued evaluation inspired by Belnap logic:
// pass/fail are standard; not_applicable when constraint doesn't apply;
// unknown when evidence is insufficient to evaluate.

export type ConstraintStatus = 'pass' | 'fail' | 'not_applicable' | 'unknown'

// ── Constraint Severity ──
// How serious is this failure? Affects retry strategy and alerting.

export type ConstraintSeverity = 'hard' | 'soft' | 'warning'

// ── Constraint Failure ──
// Machine-readable denial reason. Replaces free-text denialReason.
// Every denial carries structured data about WHICH constraint failed
// and by how much. This is the vocabulary that becomes the standard.

export interface ConstraintFailure {
  /** Which dimension failed */
  facet: ConstraintFacet
  /** Evaluation result */
  status: ConstraintStatus
  /** Specific reason code within the facet */
  code: string
  /** The constraint's limit/threshold */
  limit?: string | number
  /** The actual value at evaluation time */
  actual?: string | number
  /** How serious: hard (blocked), soft (logged), warning (near-miss) */
  severity: ConstraintSeverity
  /** Can the agent retry with modified parameters? */
  retryable: boolean
  /** For time/spend dual-expiry: which expiry relation triggered */
  expiryRelation?: 'time_expired' | 'spend_exceeded' | 'both'
  /** Human-readable explanation (for logs, not for parsing) */
  message: string
}

// ── Constraint Vector ──
// Complete constraint evaluation for a single action.
// Every processToolCall produces one, regardless of outcome.

export interface ConstraintVector {
  /** Timestamp of evaluation */
  evaluatedAt: string
  /** Overall outcome */
  outcome: 'permitted' | 'denied' | 'partially_permitted'
  /** Per-facet evaluation results */
  facets: ConstraintEvaluation[]
  /** Failures only (convenience accessor, subset of facets where status = 'fail') */
  failures: ConstraintFailure[]
  /** Primary failure: the one that would have blocked even if all others passed */
  primaryFailure?: ConstraintFailure
}

export interface ConstraintEvaluation {
  facet: ConstraintFacet
  status: ConstraintStatus
  /** Headroom: how far from the constraint boundary (for near-miss alerting) */
  headroom?: number | string
  /** Details (only for failures) */
  failure?: ConstraintFailure
}

// ── Authorization Witness ──
// Compact signed authorization state projection at execution time.
// Separate from the receipt. Hash-linked for forensic integrity.
// The witness proves what the gateway BELIEVED at execution time.

export interface AuthorizationWitness {
  /** Unique witness ID */
  witnessId: string
  /** What was the authorization status at execution time? */
  status: 'valid' | 'expired' | 'revoked' | 'none' | 'superseded'
  /** Approval ID (if an approval existed) */
  approvalId?: string
  /** When the authorization was issued */
  issuedAt?: string
  /** When it expires/expired */
  expiresAt?: string
  /** Who approved (principal DID or public key fingerprint) */
  approvedBy?: string
  /** Delegation ID in the chain */
  delegationId: string
  /** Scope that was authorized */
  scopeAuthorized: string[]
  /** Spend authorization (if applicable) */
  spendAuthorization?: {
    limit: number
    spent: number
    remaining: number
    currency: string
  }
  /** Constraint vector at evaluation time */
  constraints: ConstraintVector
  /** SHA-256 hash of the full authorization object (for deep inspection) */
  authorizationHash: string
  /** Gateway signature over this witness */
  gatewaySignature: string
  /** Timestamp */
  timestamp: string
}

// ── Authorization Reference ──
// Embedded in ActionReceipt. Points to the full AuthorizationWitness.
// Receipt stays compact; witness is available for deep forensics.

export interface AuthorizationRef {
  /** ID of the AuthorizationWitness */
  witnessId: string
  /** SHA-256 hash of the witness (integrity check without the full witness) */
  witnessHash: string
  /** Authorization status at execution time */
  status: 'valid' | 'expired' | 'revoked' | 'none' | 'superseded'
  /** Summary of constraint evaluation (compact) */
  constraintOutcome: 'permitted' | 'denied' | 'partially_permitted'
  /** Number of constraints that failed (0 for permitted actions) */
  failureCount: number
  /** Primary failure facet (if denied) */
  primaryFailureFacet?: ConstraintFacet
}

// ── Near-Miss Event ──
// Emitted when an agent approaches a constraint boundary.
// Pure product intelligence — gateway alerting, not protocol.

export interface ConstraintNearMiss {
  agentId: string
  facet: ConstraintFacet
  /** How close to the boundary (0.0 = at boundary, 1.0 = fully within) */
  headroomRatio: number
  /** Absolute headroom value */
  headroomAbsolute: number | string
  /** Threshold that triggered the near-miss alert */
  alertThreshold: number
  timestamp: string
  message: string
}

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
  /** Optional: evidence class for reputation update. Default: from GatewayConfig.defaultEvidenceClass */
  evidenceClass?: EvidenceClass
  /** Optional: declared reversibility class of this action (Gap 3 taxonomy) */
  reversibility?: ActionReversibility
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
  /** Tier escalation info (if reputation gating enabled and action was above tier) */
  tierCheck?: TierEscalation | null
  /** Whether this action was permitted via bounded escalation (Module 27 / INV-4) */
  viaEscalation?: boolean
  /** Escalation ID used (if viaEscalation is true) */
  escalationId?: string
  /** Reversibility class of the executed action */
  reversibility?: ActionReversibility
  /** Constraint vector: complete per-facet evaluation of all constraints.
   *  Present on EVERY result (permitted or denied). Machine-readable denial taxonomy. */
  constraintVector?: ConstraintVector
  /** Authorization witness: signed snapshot of authorization state at execution time.
   *  Present when gateway produces forensic evidence. Hash-linked from receipt. */
  authorizationWitness?: AuthorizationWitness
  /** Structured denial reasons (replaces free-text denialReason for machine consumers).
   *  denialReason is kept for backward compatibility; constraintFailures is the canonical source. */
  constraintFailures?: ConstraintFailure[]
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
  /** Spend from original request (V5-MED-1: removes as-any cast) */
  spend?: { amount: number; currency: string }
  /** Evidence class from original request (V5-MED-1: removes as-any cast) */
  evidenceClass?: EvidenceClass
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
  /** TTL for used request IDs in milliseconds. Default: 3,600,000 (1 hour).
   *  After this period, old request IDs are pruned to prevent unbounded memory growth. (NW-001) */
  requestIdTTLMs?: number
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
  /** Frame TTL in minutes. When > 0, execution frames auto-rotate after this duration.
   *  Prevents taint accumulation paralysis (F-2). Default: 0 (no TTL). */
  frameTTLMinutes?: number
  /** Callback: fires when a frame is auto-rotated due to TTL expiry */
  onFrameRotated?: (agentId: string, sealedFrameId: string, newFrameId: string) => void
  /** Enable reputation-gated authority (Module 10). When true, agent tier limits
   *  spend-per-action and autonomy level even if delegation scope allows it.
   *  Core invariant: effectiveAuthority = min(delegation, tier). Default: false */
  enableReputationGating?: boolean
  /** Evidence class to assign to gateway-executed actions for reputation updates.
   *  Default: 'standard'. Override per-request via ToolCallRequest.evidenceClass. */
  defaultEvidenceClass?: EvidenceClass
  /** Callback: fires when an action is denied due to insufficient tier */
  onTierDenied?: (agentId: string, escalation: TierEscalation) => void
  /** Callback: fires when an agent's reputation is updated after execution */
  onReputationUpdated?: (agentId: string, reputation: ScopedReputation, tier: AuthorityTier) => void
  /** Callback: fires when an agent is automatically demoted */
  onDemotion?: (agentId: string, fromTier: number, toTier: number, reason: string) => void
  /** Enable governance artifact enforcement (Module 21). When true, gateway verifies
   *  governance artifact signatures and blocks agents with stale attestations after
   *  governance updates. Weakening changes require higher-order authorization.
   *  Core invariant: governance can only strengthen; weakening requires escalation. Default: false */
  enableGovernanceEnforcement?: boolean
  /** Current governance envelope (signed artifact + approvals). Set via updateGovernance(). */
  governanceEnvelope?: GovernanceEnvelope
  /** Load policy for governance artifacts. Default: DEFAULT_LOAD_POLICY */
  governanceLoadPolicy?: GovernanceLoadPolicy
  /** Callback: fires when governance is updated */
  onGovernanceChange?: (diff: GovernanceDiff, artifact: GovernanceArtifact) => void
  /** Callback: fires when a governance weakening is blocked */
  onGovernanceWeakeningBlocked?: (artifact: GovernanceArtifact, reason: string) => void
  /** Callback: fires when an agent is blocked due to stale governance attestation */
  onGovernanceStaleBlock?: (agentId: string, agentVersion: string, currentVersion: string) => void
  /** Enable bounded escalation enforcement (Module 27). When true, if delegation check
   *  fails, gateway checks for active escalation grants before denying. Actions via
   *  escalation carry a viaEscalation flag in the result. Default: false */
  enableEscalation?: boolean
  /** Maximum concurrent active escalations per agent. Default: 1 */
  maxConcurrentEscalations?: number
  /** Maximum reversibility class allowed by this gateway (Gap 3 taxonomy).
   *  'tentative' = only tentative actions allowed
   *  'compensable' = tentative + compensable allowed
   *  'irreversible' = all actions allowed (default)
   *  Actions exceeding this class are denied. */
  maxReversibility?: ActionReversibility
  /** Callback: fires when an action is permitted via escalation */
  onEscalationUsed?: (agentId: string, escalationId: string, tool: string) => void
  /** Callback: fires when an escalation expires */
  onEscalationExpired?: (agentId: string, escalationId: string) => void
  /** Optional: persistent storage backend. When provided, gateway persists
   *  agents, delegations, receipts, revocations, nonces, and reputation.
   *  State survives restarts. Use loadFromStorage() after construction to hydrate. */
  storage?: import('../storage/types.js').StorageBackend
}

// ── Registered Agent ──
// The gateway maintains a registry of agents it serves.

/** Gateway agent role determines what actions an agent can perform.
 *  - 'executor': Can submit tool calls for execution (default)
 *  - 'evaluator': Can serve as policy evaluator for other agents' intents
 *  - 'executor+evaluator': Both roles */
export type GatewayAgentRole = 'executor' | 'evaluator' | 'executor+evaluator'

export interface RegisteredAgent {
  passport: SignedPassport
  attestation: FloorAttestation
  delegations: Map<string, Delegation>
  /** Agent's role in the gateway (default: 'executor') */
  role: GatewayAgentRole
  /** Per-agent execution frame for taint tracking (cross-chain) */
  executionFrame?: ExecutionFrame
  /** Active cross-chain permits for this agent */
  permits?: CrossChainPermit[]
  /** Pending obligations for this agent */
  obligations?: Obligation[]
  /** Agent's current Bayesian reputation state (reputation-gated authority) */
  reputation?: ScopedReputation
  /** Agent's current authority tier computed from reputation */
  authorityTier?: AuthorityTier
  /** Governance artifact version this agent last attested to */
  governanceVersion?: string
  /** Active escalation grants for this agent */
  escalationGrants?: EscalationGrant[]
  /** Currently active escalations */
  activeEscalations?: ActiveEscalation[]
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
  /** Reputation-gated authority stats */
  tierDenials?: number
  reputationUpdates?: number
  demotions?: number
  /** Governance enforcement stats */
  governanceUpdates?: number
  governanceWeakeningBlocked?: number
  governanceStaleBlocks?: number
  /** Escalation enforcement stats */
  escalationsActivated?: number
  escalationsUsed?: number
  escalationsExpired?: number
  escalationsDenied?: number
  /** Reversibility enforcement stats */
  reversibilityDenied?: number
}
