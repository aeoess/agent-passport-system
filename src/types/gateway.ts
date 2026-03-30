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
  | 'fidelity'       // substrate behavioral fidelity — is agent still operating as itself?
  | 'data'           // data source access terms, contribution tracking

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
  /** Defeasible dispute overlay — NOT a lattice facet. Applied after monotone evaluation.
   *  Dispute is an epistemological defeater (Defeasible Logic, Nute 1994) that suppresses
   *  otherwise valid authority. When dismissed, the defeater is removed, not authority restored. */
  disputeOverlay?: import('./dispute.js').DisputeOverlay
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

// ── Substrate Fidelity ──
// Measures whether an agent is still behaving consistently with its identity.
// When an agent migrates to a different LLM substrate (cheaper model, fine-tuned variant),
// the cryptographic identity and reputation don't change — but behavior may drift.
// Fidelity is a constraint: the gateway can require a minimum fidelity score before
// permitting high-authority actions, similar to how it requires minimum reputation.

export interface SubstrateFidelity {
  /** Fidelity score (0.0 = complete drift, 1.0 = perfect behavioral consistency) */
  score: number
  /** LLM substrate identifier (e.g., "gpt-4-turbo", "claude-3-opus", "llama-3-70b") */
  substrate: string
  /** When this measurement was taken */
  measuredAt: string
  /** How the measurement was performed (method identifier from the measuring system) */
  method: string
  /** Optional breakdown by measurement category */
  dimensions?: {
    /** Voice/style consistency (0-1) */
    voice?: number
    /** Reasoning pattern consistency (0-1) */
    reasoning?: number
    /** Refusal/boundary consistency (0-1) — critical for governance */
    boundaries?: number
    /** Task completion quality consistency (0-1) */
    quality?: number
  }
}

export interface FidelityAttestation {
  /** Unique attestation ID */
  attestationId: string
  /** DID or public key of the agent being measured */
  agentId: string
  /** The fidelity measurement */
  fidelity: SubstrateFidelity
  /** DID or public key of the measuring system (not the agent itself) */
  measuredBy: string
  /** Ed25519 signature by the measuring system over canonical(attestation minus signature) */
  signature: string
}

// ── Witness Attestation (enhanced per consilium) ──
// Witnesses reduce gateway power concentration. Post-execution, non-blocking for v1.
// Witness attests to WHAT it observed and HOW it observed it (observation basis).
// Gateway-witness disagreement creates real state (WitnessConflict), not silence.

export type WitnessObservationBasis =
  | 'direct_observation'         // witness directly observed execution
  | 'replay_verification'       // witness replayed and verified
  | 'receipt_only'              // witness only checked the receipt
  | 'log_derived'               // witness derived from execution logs
  | 'independent_recomputation' // witness independently recomputed result

export interface WitnessAttestation {
  witnessId: string
  witnessRole: 'notary' | 'co_signer' | 'auditor' | 'external_anchor'
  receiptId: string
  receiptHash: string              // SHA-256 of canonical(receipt minus witnessSignature)
  attestedAt: string
  attestation: {
    executionObserved: boolean
    receiptConsistent: boolean
    constraintsVerified: boolean
  }
  /** HOW the witness observed — not all attestations are equally strong */
  observationBasis: WitnessObservationBasis
  /** Prediction error (Friston Free Energy) — focus on what's surprising */
  predictionError?: {
    expectedOutcome: string
    observedOutcome: string
    divergence: number             // 0 = matched, 1 = completely unexpected
  }
  signature: string
}

/** Gateway-witness disagreement creates real state, not just absent signature.
 *  A conflict is a first-class event: possible fraud, or minimum a contestable inconsistency. */
export interface WitnessConflict {
  conflictId: string
  receiptId: string
  gatewayAssertion: 'success' | 'failure'
  witnessAssertion: 'consistent' | 'inconsistent' | 'refused'
  divergenceDetails?: string
  /** Should this auto-file a dispute? */
  autoDisputeCandidate: boolean
  createdAt: string
}

export interface WitnessPolicy {
  requireWitness: 'always' | 'above_spend_threshold' | 'irreversible_only' | 'never'
  spendThreshold?: number
  /** Seconds before unwitnessed receipt auto-finalizes (receipt maturation) */
  maturationWindow?: number
  witnesses: Array<{
    agentId: string
    publicKey: string
    role: WitnessAttestation['witnessRole']
  }>
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
  /** Optional: data source IDs this tool call will access.
   *  When present and data gateway is configured, the gateway checks data terms
   *  and produces data access receipts alongside the standard ActionReceipt. */
  dataSourceIds?: string[]
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
  /** Data access decisions (if data gateway configured and dataSourceIds present).
   *  Contains terms compliance check + access receipts for each data source. */
  dataAccessDecisions?: import('../core/data-enforcement.js').DataAccessDecision[]
  /** Hybrid logical clock timestamp (if enableHybridTimestamps is true).
   *  Enables causal ordering across gateway operations. */
  hlcTimestamp?: import('../types/time.js').HybridTimestamp
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
  /** Enable near-miss alerting. When true, gateway checks constraint headroom
   *  after every permitted action and fires onNearMiss when thresholds are breached.
   *  Pure operational intelligence — proactive governance vs. reactive enforcement. */
  enableNearMissAlerting?: boolean
  /** Near-miss threshold ratios (0-1). Alert when headroom drops below these.
   *  Default: [0.1, 0.05, 0.01] → alerts at 90%, 95%, 99% utilization. */
  nearMissThresholds?: number[]
  /** Callback: fires when an agent approaches a constraint boundary */
  onNearMiss?: (nearMiss: ConstraintNearMiss) => void
  /** Enable substrate fidelity gating. When true, the gateway checks the agent's
   *  fidelity attestation before permitting actions. Agents without a fidelity
   *  attestation are treated based on fidelityDefaultPolicy. */
  enableFidelityGating?: boolean
  /** Enable identity verification during agent registration. When true, the gateway
   *  resolves the agent's DID, verifies principal endorsement chain, and optionally
   *  performs entity verification. Results stored on RegisteredAgent. */
  enableIdentityVerification?: boolean
  /** Identity verification configuration. Controls which verification steps run
   *  and the minimum identity strength required for registration. */
  identityConfig?: import('../core/gateway-identity.js').IdentityVerificationConfig
  /** Enable data access enforcement. When true and dataGateway is provided,
   *  tool calls with dataSourceIds trigger data terms checking and receipt generation. */
  enableDataEnforcement?: boolean
  /** Data gateway instance for data access enforcement. Set via constructor or setDataGateway(). */
  dataGateway?: import('../core/data-gateway.js').DataGateway
  /** Enable hybrid logical clock timestamps on receipts and witnesses.
   *  When true, all gateway timestamps use HLC with NTP uncertainty bounds
   *  instead of plain ISO 8601 strings. Enables causal ordering. Default: false */
  enableHybridTimestamps?: boolean
  /** Fidelity probe schedule. Controls when probes fire during agent interactions.
   *  Only relevant when enableFidelityGating is true. Default: DEFAULT_PROBE_SCHEDULE */
  probeSchedule?: import('../core/fidelity-probe.js').ProbeSchedule
  /** Callback: fires when the probe schedule determines a fidelity probe should run.
   *  The external measurement system should fire the probe and call setFidelityAttestation. */
  onProbeRequired?: (agentId: string, reason: 'delegation' | 'turn_interval' | 'substrate_change') => void
  /** Minimum fidelity score (0-1) required for action permission.
   *  Default: 0.5. Actions by agents below this threshold are denied. */
  minFidelityScore?: number
  /** Maximum age (in seconds) of a fidelity attestation before it's considered stale.
   *  Default: 86400 (24 hours). Stale attestations are treated as absent. */
  fidelityMaxAge?: number
  /** How to handle agents without a fidelity attestation when fidelity gating is enabled.
   *  'deny': deny all actions (strict). 'warn': permit but mark as warning. 'ignore': skip check.
   *  Default: 'warn'. */
  fidelityDefaultPolicy?: 'deny' | 'warn' | 'ignore'
  /** Witness policy — when witnesses are required and who they are */
  witnessPolicy?: WitnessPolicy
  /** Escrow dispute timeout direction (Evolutionary Stable Strategy).
   *  Low-value escrow timeout favors respondent (release). High-value favors claimant (refund).
   *  This threshold determines the crossover point. Default: 100. */
  escrowTimeoutThreshold?: number
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
  /** Latest substrate fidelity attestation — proof the agent is still behaving
   *  consistently with its identity on the current LLM substrate.
   *  Updated by external fidelity measurement systems, not self-reported. */
  fidelityAttestation?: FidelityAttestation
  /** Identity verification result — DID resolution, principal chain, entity verification.
   *  Set during registration when enableIdentityVerification is true. */
  identityVerification?: import('../core/gateway-identity.js').GatewayIdentityVerification
  /** Turn counter — increments on every processToolCall for this agent */
  turnCount?: number
  /** Turn number when fidelity probe was last fired */
  lastProbeTurn?: number
  /** Last known substrate (for substrate change detection) */
  lastKnownSubstrate?: string
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
  /** Near-miss alerting stats */
  nearMissAlerts?: number
  nearMissByFacet?: Record<string, number>
  /** Fidelity gating stats */
  fidelityDenials?: number
  /** Data access enforcement stats */
  dataAccessDenials?: number
  dataAccessGranted?: number
  /** Transactional integrity stats */
  escrowsCreated?: number
  escrowsReleased?: number
  escrowsExpired?: number
  disputesFiled?: number
  disputesResolved?: number
}


// ══════════════════════════════════════════════════════════════════
// Gateway Identity — Institutional Identity for Gateways
// ══════════════════════════════════════════════════════════════════
// GPT correction #12: gateways must publish what regime they operate under.
// A gateway is not just enforcement — it's an institution with its own
// identity, trust basis, fee policy, and sovereignty level.
// Phase 2 — Rome Completeness: cross-domain governance requires
// gateways to identify themselves to each other.
// ══════════════════════════════════════════════════════════════════

/** Gateway jurisdiction — where this gateway operates legally. */
export interface GatewayJurisdiction {
  /** Primary jurisdiction (e.g. "US", "EU", "SG") */
  primary: string
  /** Additional jurisdictions this gateway complies with */
  additional?: string[]
  /** Data residency requirements */
  dataResidency?: string
}

/** Infrastructure fee policy — how the gateway charges for services.
 *  Deferred to Phase 2+ for full typed design (Gemini S2 open item). */
export interface InfrastructureFeePolicy {
  /** Fee model: flat per-action, percentage of spend, or subscription */
  model: 'per_action' | 'percentage' | 'subscription' | 'free'
  /** Fee amount (interpretation depends on model) */
  amount?: number
  /** Currency for the fee */
  currency?: string
  /** SHA-256 hash of the full fee schedule document */
  feeScheduleHash: string
}

/** Import rules — what this gateway accepts from foreign gateways.
 *  GPT #13: separate channels per artifact type. */
export interface GatewayImportPolicy {
  /** Receipt import rules */
  receipts: { acceptFrom: string[]; requireWitness: boolean }
  /** Reputation import rules — downgradeRatio: 0.5 means foreign rep counts half */
  reputation: { acceptFrom: string[]; downgradeRatio: number }
  /** Witness attestation import rules */
  witnessAttestations: { acceptFrom: string[]; minObservationBasis: WitnessObservationBasis }
  /** Reserve attestation import rules */
  reserveAttestations: { acceptFrom: string[]; requireLiabilityClass: boolean }
  /** Charter fact import rules */
  charterFacts: { acceptFrom: string[] }
  /** Default tier assigned to foreign agents */
  foreignAgentDefaultTier: number
}

/** Sovereignty level — graduated gateway authority.
 *  border_outpost: minimal, forwards most decisions upstream
 *  province: local authority with oversight
 *  sovereign: full independent authority */
export type GatewaySovereigntyLevel = 'border_outpost' | 'province' | 'sovereign'

/** Gateway trust basis — WHY anyone should trust this gateway's receipts.
 *  Published as part of GatewayIdentity so agents can evaluate
 *  whether to interact through this gateway. */
export interface GatewayTrustBasis {
  /** Charter that operates this gateway (institutional anchor) */
  charterAnchor?: string
  /** SHA-256 hash of the witness policy document */
  witnessPolicyHash: string
  /** How receipts are archived */
  archivePolicy: 'local' | 'external_anchor' | 'federated'
  /** When receipts become final */
  finalityPolicy: 'immediate' | 'witness_required' | 'maturation_window'
  /** SHA-256 hash of the fee schedule */
  feePolicyHash: string
  /** SHA-256 hash of the dispute policy */
  disputePolicyHash: string
}

/** Full institutional identity of a gateway. Published so other
 *  gateways and agents can evaluate trust, fees, and jurisdiction
 *  before routing transactions through this gateway. */
export interface GatewayIdentity {
  /** Unique gateway identifier */
  gatewayId: string
  /** Ed25519 public key (hex) of the gateway */
  publicKey: string
  /** Human-readable name */
  displayName: string
  /** Who operates this gateway (charterId or principalId) */
  operator: string
  /** Why anyone should trust this gateway */
  trustBasis: GatewayTrustBasis
  /** Fee schedule */
  feePolicy: InfrastructureFeePolicy
  /** Witness requirements */
  witnessPolicy: WitnessPolicy
  /** Trust domain this gateway belongs to */
  trustDomainId: string
  /** Legal jurisdiction */
  jurisdiction?: GatewayJurisdiction
  /** What this gateway accepts from foreign gateways (GPT #13) */
  importPolicy: GatewayImportPolicy
  /** Graduated sovereignty level */
  sovereigntyLevel: GatewaySovereigntyLevel
  /** ISO datetime — when this gateway was registered */
  registeredAt: string
  /** ISO datetime — last heartbeat (liveness check) */
  lastHeartbeat?: string
  /** Ed25519 signature over canonical identity content */
  signature: string
}
