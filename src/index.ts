// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
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
export { InMemoryKeyStorage, EncryptedFileKeyStorage } from './crypto/key-storage.js'
export type { KeyStorageBackend } from './crypto/key-storage.js'
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
  RegisteredAgent, GatewayStats, ActionReversibility, GatewayAgentRole,
  ConstraintFacet, ConstraintStatus, ConstraintSeverity,
  ConstraintFailure, ConstraintVector, ConstraintEvaluation,
  AuthorizationWitness, AuthorizationRef, ConstraintNearMiss,
} from './types/gateway.js'

// ── Layer 9: W3C DID & Verifiable Credentials Bridge ──
export {
  createDID, createDIDHex, publicKeyFromDID, isValidDID,
  passportToDIDDocument, resolveDID,
  signWithDID, verifyWithDID,
  hexToMultibase, multibaseToHex
} from './core/did.js'

export {
  verifyEntityChain,
  cacheDIDResolution, getCachedDIDResolution, clearDIDCache,
  computeSenderId,
} from './core/entity-verification.js'

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
  FloorAttestationCredentialSubject, PolicyReceiptCredentialSubject,
  DIDResolutionStatus, DIDResolutionCacheEntry,
  PublicProofSurface, EntityVerificationResult,
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
  FleetRecord, FleetAgent, EndorsementVerification, DisclosureLevel,
  EntityBinding,
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
  generateEncryptionKeypair, deriveEncryptionKeypair,
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


// ── Bounded Escalation (Module 27 — Fourth Attenuation Invariant) ──

export {
  createEscalationGrant, verifyEscalationGrant,
  requestEscalation, activateEscalation,
  checkEscalatedAction, revokeEscalation, isEscalationActive,
} from './core/escalation.js'

export type {
  EscalationGrant, EscalationRequest, ActiveEscalation,
  EscalationVerification, EscalationTriggerType, ActionClass,
} from './core/escalation.js'


// ── Oracle Witness Diversity (Module 28 — Gap 4) ──

export {
  createWitnessPool, createAttestation, verifyWitnessAttestation,
  addAttestation, computeDiversityScore, evaluateWitnessConsensus,
  wouldIncreaseDiversity,
} from './core/oracle-witness.js'

export type {
  WitnessAttestation, WitnessPool, WitnessPoolConfig,
  DiversityScore, WitnessConsensusResult,
} from './types/oracle-witness.js'


// ── Encrypted Messaging Audit Bridge (Module 29) ──

export {
  createMessageAuditLog, createAuditRecord, verifyAuditRecord,
  appendToAuditLog, queryBySender, queryCrossChainMessages,
  totalBytesBySender,
} from './core/messaging-audit.js'

export type {
  MessageAuditRecord, AuditVerification, MessageAuditLog,
} from './core/messaging-audit.js'


// ── Policy Conflict Detection (Module 30) ──

export {
  detectCycles, detectShadowedRules, detectContradictions,
  detectUnreachableActions, analyzePolicyRules,
} from './core/policy-conflict.js'

export type {
  PolicyRule, PolicyConflictReport, ShadowedRule,
  PolicyContradiction,
} from './core/policy-conflict.js'


// ── Data Source Registration & Access Receipts (Module 36A) ──

export {
  registerSelfAttestedSource, registerCustodianAttestedSource,
  registerGatewayObservedSource, verifySourceReceipt, revokeSourceReceipt,
  recordDataAccess, verifyDataAccessReceipt,
  checkTermsCompliance, composeTerms,
  buildDataAccessMerkleRoot, proveDataAccessInclusion,
  verifyDataAccessInclusionProof, addDataAccessToLedger,
} from './core/data-source.js'

export type {
  SourceReceipt, SourceMode, DataContentType,
  DataTerms, DataPurpose, CompensationModel, DerivativePolicy, AuditVisibility,
  DataAccessReceipt, AccessMethod, TermsComplianceResult,
  SourceReceiptVerification, AccessReceiptVerification,
} from './types/data-source.js'


// ══════════════════════════════════════
// MODULE 37 — Decision Semantics & Cross-Engine Interop
// ══════════════════════════════════════

export {
  computeContentHash, verifyContentHash,
  createContentAddressableIntent,
  classifyEvaluationMethod, decomposeDecision,
  createDecisionArtifact, verifyDecisionArtifact,
  getEffectiveScopeInterpretation,
  validateIdentityBoundary, MINIMUM_IDENTITY_FIELDS,
} from './core/decision-semantics.js'

export type {
  ScopeInterpretation,
  ContentHash, ContentHashAlgorithm,
  DecisionSemantics, DecisionArtifact, DecisionArtifactVerification,
} from './types/decision-semantics.js'



// ══════════════════════════════════════
// v2: Constitutional Governance Extensions
// ══════════════════════════════════════

export * from './v2/index.js'

// ══════════════════════════════════════
// Interop: qntm E2E Encrypted Relay Bridge
// ══════════════════════════════════════

export * from './interop/qntm-bridge.js'

// ══════════════════════════════════════
// Interop: agent.json Commerce Bridge
// ══════════════════════════════════════

export * from './interop/agent-json-bridge.js'

// ══════════════════════════════════════
// Module 38: Data Contribution Ledger
// Module 39: Data Settlement Protocol
// ══════════════════════════════════════

export * from './types/data-contribution.js'
export * from './core/data-contribution.js'
export * from './core/data-settlement.js'

// ══════════════════════════════════════
// Data Enforcement Gate + Training Attribution
// ══════════════════════════════════════

export * from './core/data-enforcement.js'
export * from './core/training-attribution.js'

// ══════════════════════════════════════
// Data Gateway (Composable: Gateway + Data Enforcement + Terms Acceptance)
// ══════════════════════════════════════

export * from './core/data-gateway.js'

// ══════════════════════════════════════
// Decision Equivalence (Canonical Boundary Profiles + Comparison)
// ══════════════════════════════════════

export * from './types/decision-equivalence.js'
export * from './core/decision-equivalence.js'

// ══════════════════════════════════════
// Data Lifecycle Governance
// ══════════════════════════════════════

export * from './types/data-lifecycle.js'
export * from './core/data-lifecycle.js'


// ══════════════════════════════════════
// Framework Adapters
// ══════════════════════════════════════

export { GovernanceHook } from './adapters/governance-hook.js'
export type {
  GovernanceHookConfig, ActionDescriptor, GovernanceVerdict,
  GovernanceResult, GovernanceReceipt,
} from './adapters/governance-hook.js'

export { createCrewAIGovernance } from './adapters/crewai.js'
export type { CrewAIGovernance, CrewAITaskOutput } from './adapters/crewai.js'

export { createADKGovernancePlugin } from './adapters/adk.js'
export type { ADKGovernancePlugin, ADKActionContext } from './adapters/adk.js'

export { createLangChainGovernanceHandler } from './adapters/langchain.js'
export type { LangChainGovernanceHandler } from './adapters/langchain.js'

export { createA2AGovernance } from './adapters/a2a.js'
export type { A2AGovernance } from './adapters/a2a.js'


// ══════════════════════════════════════
// Conformance Test Suite
// ══════════════════════════════════════

export { runConformanceSuite } from './conformance/suite.js'
export type { ConformanceTest, ConformanceSuiteResult } from './conformance/suite.js'


// ══════════════════════════════════════
// Governance Block (HTML-embedded governance)
// ══════════════════════════════════════

export {
  generateGovernanceBlock, verifyGovernanceBlock,
  renderGovernanceHTML, renderGovernanceMeta,
  parseGovernanceBlockFromHTML, embedGovernance, isUsagePermitted,
  DEFAULT_REVOCATION_POLICY,
} from './core/governance-block.js'
export type {
  GovernanceBlock, GovernanceTerms, RevocationPolicy,
  UsagePermission, GovernanceBlockVerification,
  GenerateGovernanceBlockInput,
} from './core/governance-block.js'


// ══════════════════════════════════════
// aps.txt + HTTP Headers + Chained Blocks
// ══════════════════════════════════════

export {
  generateApsTxt, verifyApsTxt, serializeApsTxt, parseApsTxt,
  resolveTermsForPath, governanceHeaders, parseGovernanceHeaders,
  createChainedGovernanceBlock, verifyChainedBlock,
} from './core/aps-txt.js'
export type {
  ApsTxt, PathOverride, GenerateApsTxtInput,
  ChainedGovernanceBlock,
} from './core/aps-txt.js'


// ══════════════════════════════════════
// Governance Consumer (agent-side 360 loop)
// ══════════════════════════════════════

export {
  checkHTMLGovernance, checkHeaderGovernance,
  createAccessReceipt, verifyAccessReceipt,
  governanceLoop360,
} from './core/governance-consumer.js'
export type {
  AccessReceipt, GovernanceCheckResult, Full360Result,
} from './core/governance-consumer.js'

// ── Storage Layer ──
export { VolatileBackend } from './storage/volatile-backend.js'
export {
  createReceiptBundle, verifyReceiptBundle, importReceiptBundle
} from './storage/receipt-bundle.js'
export type {
  StorageBackend, StorageOperations, StoredAgentRecord,
  CursorPage, ReceiptFilter, SpendReservation, SpendReservationResult,
  GatewayCheckpoint, IntegrityReport, CheckpointCallback
} from './storage/types.js'
export type { ReceiptBundle, BundleVerificationResult } from './storage/receipt-bundle.js'
