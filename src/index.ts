// Agent Passport System — Public API v2.0
// The Agent Social Contract: Identity · Values · Attribution
//
// HIGH-LEVEL API (start here):
//   joinSocialContract()    — create an agent in the contract
//   verifySocialContract()  — verify another agent
//   delegate()              — grant authority
//   recordWork()            — sign a receipt for work done
//   proveContributions()    — generate Merkle proofs of contributions
//   auditCompliance()       — check agent against the Floor
//
// Everything else below is the implementation these build on.

// ── The Social Contract (high-level) ──
export {
  joinSocialContract, verifySocialContract,
  delegate, recordWork,
  proveContributions, auditCompliance
} from './contract.js'

export type {
  JoinOptions, SocialContractAgent, TrustVerification,
  DelegateOptions, WorkOptions, ContributionProof
} from './contract.js'

// ── Layer 1: Identity & Accountability ──
export { createPassport, signPassport, updatePassport, isExpired } from './core/passport.js'
export { canonicalize } from './core/canonical.js'
export { generateKeyPair, sign, verify, publicKeyFromPrivate } from './crypto/keys.js'
export { verifyPassport, createChallenge, verifyChallenge } from './verification/verify.js'
export { applyReputationEvent, calculateOverallScore } from './verification/reputation.js'

// v1.1 — Delegation, Receipts, Revocation
// v1.4 — Cascade Revocation, Chain Validation, Batch Revocation
export {
  createDelegation, subDelegate, verifyDelegation,
  revokeDelegation, verifyRevocation,
  cascadeRevoke, revokeByAgent, validateChain,
  getDescendants, getChainEntry, onRevocation,
  createReceipt, verifyReceipt,
  getReceipts, getRevocation, clearStores,
  scopeCovers, scopeAuthorizes
} from './core/delegation.js'

// ── Layer 2: Human Values Floor ──
export {
  loadFloor, loadFloorFromFile,
  attestFloor, verifyAttestation,
  evaluateCompliance,
  negotiateCommonGround,
  resolveEnforcementMode, effectiveEnforcementMode
} from './core/values.js'

export { ENFORCEMENT_ESCALATION_ORDER } from './types/passport.js'

// ── Layer 3: Beneficiary Attribution ──
export {
  hashReceipt,
  traceBeneficiary,
  computeAttribution, verifyAttributionReport,
  buildMerkleRoot, generateMerkleProof, verifyMerkleProof,
  computeCollaborationAttribution,
  DEFAULT_SCOPE_WEIGHTS
} from './core/attribution.js'

// ── Layer 4: Agent Agora (Communication) ──
export {
  createAgoraMessage, verifyAgoraMessage,
  createFeed, appendToFeed, getThread, getByTopic, getByAuthor, getTopics,
  createRegistry, registerAgent, verifyFeed
} from './core/agora.js'

// ── Types ──
export type {
  // Layer 1
  AgentPassport, SignedPassport, KeyPair, VerificationResult,
  Challenge, ChallengeResponse, ReputationScore, ReputationEvent,
  Delegation, RuntimeInfo, CreatePassportOptions,
  ActionReceipt, RevocationRecord, DelegationStatus,
  // v1.4 — Cascade Revocation
  CascadeRevocationResult, DelegationChainValidation,
  DelegationChainLink, RevocationEvent,
  // Layer 2
  ValuesFloor, FloorPrinciple, FloorAttestation,
  ComplianceCheck, ComplianceReport, SharedGround, FloorReference,
  // Layer 2 — Enforcement
  EnforcementMode,
  // Layer 3
  BeneficiaryInfo, BeneficiaryTrace, DelegationHop,
  AttributionEntry, AttributionReport,
  MerkleProof, MerkleProofNode
} from './types/passport.js'

export type {
  // Layer 4
  AgoraMessage, AgoraMessageContent, AgoraVerification,
  AgoraFeed, AgoraAgent, AgoraRegistry
} from './types/agora.js'

// Re-export collaboration attribution type
export type { CollaborationAttribution } from './core/attribution.js'

// ── Layer 5: Intent Architecture ──
export {
  assignRole,
  createTradeoffRule, evaluateTradeoff,
  createIntentDocument,
  createDeliberation, submitConsensusRound, evaluateConsensus, resolveDeliberation,
  getPrecedentsByTopic, citePrecedent,
  createIntentPassportExtension,
} from './core/intent.js'

export type { TradeoffEvaluation, ConsensusEvaluation } from './core/intent.js'

export type {
  // Layer 5 — Intent Architecture
  AgentRole, AutonomyLevel, RoleAssignment,
  IntentDocument, IntentGoal, TradeoffRule,
  ConsensusRound, Deliberation, DeliberationOutcome,
  DomainAssessment, Precedent,
  MemoryTier, ContextGovernance,
  IntentPassportExtension,
} from './types/intent.js'

// ── Layer 6: Coordination Primitives ──
export {
  createTaskBrief, verifyTaskBrief,
  assignTask, acceptTask,
  submitEvidence, verifyEvidence,
  reviewEvidence, verifyReview,
  handoffEvidence, verifyHandoff,
  submitDeliverable, verifyDeliverable,
  completeTask, verifyCompletion,
  createTaskUnit, getTaskStatus, validateTaskUnit,
} from './core/coordination.js'

export type {
  CoordinationRole, TaskStatus, ReviewVerdict,
  TaskBrief, TaskRoleSpec, DeliverableSpec,
  TaskAssignment, EvidencePacket, EvidenceClaim,
  ReviewDecision, ReviewIssue,
  EvidenceHandoff, Deliverable,
  TaskCompletion, TaskMetrics, TaskUnit,
} from './types/coordination.js'

// ── Values Floor Policy Engine ──
export {
  createActionIntent, verifyActionIntent,
  evaluateIntent, verifyPolicyDecision,
  createPolicyReceipt, verifyPolicyReceipt,
  FloorValidatorV1,
  requestAction,
} from './core/policy.js'

export type {
  ActionIntent, PolicyDecision, PolicyReceipt,
  PolicyVerdict, PrincipleEvaluation,
  PolicyValidator, ValidationContext, PolicyEvaluationResult,
} from './types/policy.js'

// ── Layer 7: Agentic Commerce (ACP) ──
export {
  commercePreflight,
  createCheckout, updateCheckout, completeCheckout, cancelCheckout,
  requestHumanApproval,
  createCommerceDelegation,
  getSpendSummary,
  verifyCommerceReceipt,
} from './core/commerce.js'

export type {
  ACPCheckoutSession, ACPLineItem, ACPMoney, ACPTotals,
  ACPFulfillment, ACPFulfillmentOption, ACPPaymentMethod,
  ACPCustomer, ACPAddress, ACPOrderEvent,
  CommerceConfig, CommerceDelegation,
  CommercePreflightResult, CommercePreflightCheck,
  CommerceActionReceipt, HumanApprovalRequest,
} from './types/commerce.js'

// ── Layer Integration — Wiring ──
export {
  commerceWithIntent,
  commerceReceiptToActionReceipt,
  validateCommerceDelegation,
  coordinationToAgora,
  postTaskCreated,
  postReviewCompleted,
  postTaskCompleted,
} from './core/integration.js'

export type {
  CommerceIntentResult,
  DelegationValidationResult,
  CoordinationEventType,
} from './core/integration.js'

// ── Agent Context — Automatic Compliance Enforcement ──
export { AgentContext, createAgentContext } from './core/context.js'

export type {
  EnforcementLevel,
  AgentContextConfig,
  ExecuteRequest, ExecuteResult,
  CompletedAction,
  AgentContextState, AuditEntry,
} from './types/context.js'

// ── Task Routing Protocol ──
export {
  createTaskRequest, verifyTaskRequest,
  advertiseCapabilities, verifyAdvertisement,
  claimTask, verifyClaim,
  declineTask, verifyDecline,
  routeTask, verifyRoutingDecision,
  scoreCandidate,
  capabilityMatches, capabilityCoverage,
  checkDelegationScope, isAdvertisementFresh,
  DEFAULT_ROUTER_CONFIG, DEFAULT_MATCH_WEIGHTS, DEFAULT_PRIORITY_BOOSTS,
} from './core/routing.js'

export type {
  TaskRequest, TaskRequestStatus, TaskRequestPriority,
  CapabilityAdvertisement, AgentEnvironment,
  ClaimResponse, TaskDecline, RoutingDecision,
  RouterConfig, MatchWeights, CandidateScore, RoutingResult,
  CapabilityString,
} from './types/routing.js'

// ── Proxy Gateway (Enforcement Boundary) ──
export { ProxyGateway, createProxyGateway } from './core/gateway.js'

export type {
  ToolCallRequest, ToolCallResult, GatewayProof,
  GatewayApproval, ToolExecutor, GatewayConfig,
  RegisteredAgent, GatewayStats
} from './types/gateway.js'

// ── Layer 9: W3C DID & Verifiable Credentials Bridge ──
export {
  createDID, publicKeyFromDID, isValidDID,
  passportToDIDDocument, resolveDID,
  signWithDID, verifyWithDID,
  hexToMultibase, multibaseToHex
} from './core/did.js'

export {
  passportToVC, delegationToVC,
  floorAttestationToVC, receiptToVC,
  createPresentation,
  verifyVC, verifyPresentation
} from './core/vc.js'

export type {
  DIDDocument, VerificationMethod, ServiceEndpoint,
  DIDResolutionResult,
  VerifiableCredential, VerifiablePresentation, LinkedDataProof,
  PassportCredentialSubject, DelegationCredentialSubject,
  FloorAttestationCredentialSubject, PolicyReceiptCredentialSubject
} from './types/did.js'


// ── Layer 10: A2A Protocol Bridge ──
export {
  passportToAgentCard, verifyAgentCard,
  agentCardToCapabilities, hasPassportIdentity,
  getDIDFromAgentCard
} from './core/a2a.js'

export type {
  A2AAgentCard, A2AAgentSkill, A2AAgentProvider,
  A2ACapabilities, A2ASecurityScheme
} from './types/a2a.js'


// ── EU AI Act Compliance ──
export {
  classifyRisk, mapArticles, generateTransparencyDisclosure,
  generateComplianceProfile, identifyGaps, generateComplianceReport
} from './core/euaiact.js'

export type {
  RiskCategory, EUAIActArticle, ComplianceProfile,
  TransparencyDisclosure, EUComplianceReport, EUComplianceGap
} from './types/euaiact.js'


// ── Principal Identity ──
export {
  createPrincipalIdentity, endorseAgent, verifyEndorsement,
  revokeEndorsement, createDisclosure, verifyDisclosure,
  createFleet, addToFleet, getFleetStatus, revokeFromFleet,
  endorsePassport, verifyPassportEndorsement, hasPrincipalEndorsement
} from './core/principal.js'

export type {
  PrincipalIdentity, PrincipalEndorsement, PrincipalDisclosure,
  FleetRecord, FleetAgent, EndorsementVerification, DisclosureLevel
} from './types/principal.js'


// ── Reputation-Gated Authority ──
export {
  DEFAULT_K, MAX_SIGMA, INITIAL_MU, INITIAL_SIGMA, SCARRING_PENALTY,
  DEFAULT_TIERS, DEFAULT_PROMOTION_REQUIREMENTS,
  computeEffectiveScore, createScopedReputation,
  classifyEvidence, resolveAuthorityTier, shouldDemote,
  effectiveAutonomy, effectiveSpendLimit, effectiveDelegationDepth,
  classifyRuntimeChange, sigmaAfterRuntimeChange,
  meetsPromotionRequirements,
  createPromotionReview, validatePromotionReview,
  triggerDemotion, checkTierForIntent, advisoryTierPrecheck,
  updateReputationFromResult
} from './core/reputation-authority.js'

export type {
  ScopedReputation, AuthorityTier, TierDefinition, TierOrigin,
  EvidenceClass, TaskClassification, EvidencePortfolio,
  PromotionRequirements, PromotionReview,
  RuntimeProfile, RuntimeChangeClass,
  DemotionCause, DemotionEvent,
  TierEscalation, TierCheckContext
} from './types/reputation-authority.js'

// ── Intent Network (Module 17) ──

export {
  createIntentNetwork,
  createIntentCard, verifyIntentCard, isCardExpired,
  publishCard, removeCard,
  computeRelevance, searchMatches,
  requestIntro, respondToIntro,
  getDigest, getVisibleItems
} from './core/intent-network.js'

export type {
  IntentCard, IntentItem, IntentNetwork, NeedOfferMatch,
  RelevanceMatch, IntroRequest, IntroResponse, Digest, SearchOptions
} from './types/intent-network.js'


// ── Cross-Chain Data Flow Authorization (Module 18) ──

export {
  createTaintLabel, mergeTaints,
  createSAO, verifySAO, isSAOExpired,
  createExecutionFrame, recordAccess, closeFrame,
  computeStepHash, verifyFrameChain,
  isFrameExpired, rotateFrame,
  verifyEpochChain,
  createCrossChainPermit, countersignPermit,
  verifyCrossChainPermit, revokePermit,
  checkDataFlow,
  deriveSAO,
  createExecutionReceipt, verifyExecutionReceipt,
  createCrossChainViolation
} from './core/cross-chain.js'

export type {
  TaintLabel, TaintUsage, TaintSet,
  SignedAuthorityObject, CrossChainPermit,
  ExecutionFrame, ExecutionStep, FlowCheckResult, FlowVerdict,
  TaintTransformation, TransformationType,
  ExecutionReceipt, CrossChainViolation
} from './types/cross-chain.js'


// ── E2E Encrypted Messaging (Module 19) ──

export {
  generateEncryptionKeypair,
  createKeyAnnouncement, verifyKeyAnnouncement,
  padToBlock, unpad,
  encryptPayload, decryptPayload,
  createEncryptedAgoraMessage, decryptAgoraMessage,
  verifyOuterSignature
} from './core/encrypted-messaging.js'

export type {
  EncryptionKeyAnnouncement, EncryptionKeypair,
  EncryptedAgoraMessage, DecryptedPayload,
  MessageValidation
} from './types/encrypted-messaging.js'


// ── Cross-Engine Signed Execution Envelope (RFC implementation) ──

export {
  createExecutionEnvelope,
  verifyExecutionEnvelope,
  createMinimalEnvelope
} from './core/execution-envelope.js'

export type {
  ExecutionEnvelope, EnvelopeVerification,
  EvaluationMethod, EnvelopeVerdict, RevocationStatus
} from './types/execution-envelope.js'

// ── Feasibility Linting (Module 24, Gap 7) ──

export {
  lintDelegation, lintTaskFeasibility,
} from './core/feasibility.js'

export type {
  FeasibilitySeverity, FeasibilityIssue, FeasibilityResult,
} from './types/feasibility.js'


// ── Governance Artifact Provenance (Module 21) ──

export {
  hashContent,
  createGovernanceArtifact, verifyGovernanceArtifact,
  approveArtifact, verifyApproval,
  createGovernanceEnvelope, loadGovernanceArtifact,
  upgradeGovernanceArtifact, classifyGovernanceChange,
  DEFAULT_LOAD_POLICY,
} from './core/governance.js'

export type {
  GovernanceArtifact, GovernanceApproval, GovernanceVerification,
  GovernanceEnvelope, GovernanceLoadPolicy,
  GovernanceChangeType, GovernanceDiff,
} from './types/governance.js'


// ── Obligations Model (Module 20) ──

export {
  createObligation, createObligationBundle, acceptObligationBundle,
  checkFulfillment, resolveObligation, createFulfillmentReceipt,
  scheduleNextRecurrence, validateObligationConstraints, validatePenaltySeverity
} from './core/obligations.js'

export type {
  Obligation, ObligationAction, EvidenceRequirement,
  PenaltySpec, RecurrenceSpec, ObligationBundle,
  FulfillmentReceipt, ObligationResolution, ObligationOutcome,
  ObligationStatus, ParamConstraint
} from './types/obligations.js'


// ── Identity & Key Rotation (Module 22) ──

export {
  createIdentityDocument, rotateKey, emergencyRotate,
  verifyRotation, verifyRotationLog,
  resolveCurrentKey, wasKeyActive,
} from './core/identity.js'

export type {
  IdentityDocument, KeyRotationEntry, RotationVerification,
} from './types/identity.js'

// ── Receipt Ledger — Merkle-Committed Audit (Module 23) ──

export {
  createReceiptLedger, addReceipt, commitBatch,
  proveInclusion, verifyInclusion,
  verifyBatch, verifyBatchChain,
} from './core/receipt-ledger.js'

export type {
  ReceiptBatch, ReceiptInclusionProof, ReceiptLedger,
  BatchVerification, BatchChainVerification,
} from './core/receipt-ledger.js'


// ── Precedent Control (Module 25) ──

export {
  createPrecedentLibrary, markAsNormative, verifyNormativePrecedent,
  addToLibrary, checkAlignment, supersedePrecedent, analyzeDrift,
} from './core/precedent.js'

export type {
  NormativePrecedent, PrecedentAlignment, PrecedentLibrary, DriftAnalysis,
} from './core/precedent.js'


// ── Delegation Re-anchoring (Module 26) ──

export {
  createDelegationRef, resolvePublicKey, reanchorDelegation,
  verifyReanchoredDelegation, verifyWithRef, didCoversKey,
} from './core/reanchor.js'

export type {
  DelegationRef, ReanchoredDelegation,
} from './core/reanchor.js'
