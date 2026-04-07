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
export { createPassport, signPassport, updatePassport, isExpired, isPassportValid, countersignPassport, verifyIssuerSignature, isIssuerVerified, isIssuerSigned } from './core/passport.js'
export { canonicalize, canonicalJson, canonicalHash, normalizeTimestamp } from './core/canonical.js'

// ── action_ref (A2A#1672) — Content-Addressed Request Identity ──
export { computeActionRef, actionRefsMatch } from './core/action-ref.js'

// ── Attestation Freshness (A2A#1712) ──
export { computeEvidenceAge, isEvidenceFresh, createSnapshotFreshness, createRotatingFreshness } from './core/freshness.js'
export type { AttestationFreshness } from './types/passport.js'

// ── Agent Attestation Architecture (Phase 1 — Consilium Build) ──
export {
  createIssuanceChallenge, verifyRuntimeAttestation,
  computePassportGrade, computeAttestationFlags, computeAttestationBundleHash,
  createIssuanceContext, bindAttestation,
  createWorkspaceManifest, createEmptyEvidenceRecord,
  isChallengeFresh, isGradeAtLeast,
  importProviderAttestation, addIdentityBoundary,
  classifyEvidenceQuality, evidenceQualityToGrade,
} from './core/attestation.js'

export type {
  PassportGrade, EvidenceQuality, AttestationProvenance, SignalStability, VerificationStatus,
  AttestedSignal, ObservedContext,
  RuntimeAttestation, ProviderAttestation,
  IssuanceEvidenceRecord, IssuanceAssessment, IssuanceContext,
  PassportAttestationSummary, AttestationFlag,
  IssuanceChallenge, IssuanceChallengeResponse, AttestationClass,
  DerivedSignal, SignalVerificationResult, GradeChange,
  WorkspaceManifest, WorkspaceManifestEntry, WorkspaceCheckpoint,
  RecoveryRequest, RecoveryResult,
} from './types/attestation.js'

export { PASSPORT_GRADE_LABELS } from './types/attestation.js'

// ── JCS Canonicalization (RFC 8785) ──
export { canonicalizeJCS, detectCanonicalVariant, getTestVectors } from './core/canonical-jcs.js'
export type { CanonicalizationTestVector } from './core/canonical-jcs.js'
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
export type { RevocationCheckPolicy } from './core/delegation.js'

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
  AgentPassport, SignedPassport, IssuerSignature, KeyPair, VerificationResult,
  Challenge, ChallengeResponse, ReputationScore, ReputationEvent,
  Delegation, RuntimeInfo, CreatePassportOptions,
  ActionReceipt, RevocationRecord, DelegationStatus,
  // v1.4 — Cascade Revocation
  CascadeRevocationResult, DelegationChainValidation,
  DelegationChainLink, RevocationEvent,
  // Key Rotation
  RotationMode, RotationState, DIDRotationEntry,
  RotatableDIDDocument, RotatableVerificationMethod,
  AgentPostureStatus,
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
  computeCompoundDigest, captureRoutingContext, detectRoutingDivergence,
  createPolicyChain, appendPolicyChainEntry, verifyPolicyChain, detectConstraintDrift,
  type DivergencePattern, type PolicyChain, type PolicyChainEntry, type PolicyConstraintSnapshot,
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

// ── Fidelity Probe: Substrate Behavioral Drift Measurement ──
export {
  scoreFidelityResponse, aggregateFidelityScores,
  createFidelityAttestation, verifyFidelityAttestation,
  shouldProbe, fidelityDelta, measureCompactionDrift,
  DEFAULT_PROBE_SCHEDULE,
} from './core/fidelity-probe.js'

export type {
  FidelityChallenge, FidelityResponse, FidelityOutcome, FidelityScore,
  ProbeSchedule, PressureType, SpecificationClarity,
  CompactionProbePoint, CompactionDriftResult,
} from './core/fidelity-probe.js'

// ── DID Interop: did:key + did:web ──
export {
  toDIDKey, fromDIDKey,
  didWebToUrl, resolveDIDWeb,
  passportToDIDDocument as passportToDIDKeyDocument,
} from './core/did-interop.js'

// ── Identity Bridge: SPIFFE + OAuth → APS ──
export {
  parseSPIFFEID, importSPIFFESVID,
  mapOAuthScopes, importOAuthToken,
} from './core/identity-bridge.js'

export type {
  SPIFFESVIDInput, ParsedSPIFFEID,
  OAuthTokenInput, OAuthImportResult,
} from './core/identity-bridge.js'

// ── VC Wrapper: Interop Bridge (did:key + SPIFFE evidence) ──
export {
  passportToVerifiableCredential,
  verifyVerifiableCredential,
  createVerifiablePresentation,
  verifyVerifiablePresentation,
} from './core/vc-wrapper.js'

export type {
  PassportVCInput, VCVerifyResult, VPVerifyResult,
} from './core/vc-wrapper.js'

// ── Credential Request: Selective Disclosure Protocol ──
export {
  createCredentialRequest,
  fulfillCredentialRequest,
  verifyCredentialResponse,
} from './core/credential-request.js'

export type {
  CredentialRequest, CredentialResponseResult, SelectivePassport,
} from './core/credential-request.js'

// ── Gateway Identity: DID + Principal + Entity Verification ──
export {
  verifyAgentIdentity, verifyAgentIdentitySync,
  strengthMeetsMinimum, identityStrengthFailure,
  DEFAULT_IDENTITY_CONFIG,
} from './core/gateway-identity.js'

export type {
  GatewayIdentityVerification, IdentityVerificationConfig,
} from './core/gateway-identity.js'

// ── Gateway Wiring: module integration hooks ──
export {
  checkCommerceConstraint, extractCharterPolicy,
} from './core/gateway-wiring.js'

export type {
  CommerceCheckResult, CharterPolicyExtract,
} from './core/gateway-wiring.js'

// ── Denial Domains: operator-facing constraint grouping ──
export {
  getDomain, getDomainLabel, summarizeDenial, groupByDomain,
  EVALUATION_ORDER,
} from './core/denial-domains.js'

export type { DenialDomain, DenialSummary } from './core/denial-domains.js'

// ── Data Narrowing: monotonic narrowing for data influence ──
export {
  assertDataNarrowsOnly, applyDataConstraints,
  isValidNarrowing, NARROWING_ORDER,
} from './core/data-narrowing.js'

export type { FacetSnapshot, NarrowingCheckResult } from './core/data-narrowing.js'

// ── Governance Posture: behavioral → structural propagation ──
export {
  createInitialPosture, recordBehavioralFailure, recordBehavioralSuccess,
  upgradePosture, getPostureConstraints, isScopeBlocked, comparePostureTiers,
  DEFAULT_POSTURE_CONSTRAINTS, DEFAULT_DOWNGRADE_POLICY,
} from './core/governance-posture.js'

export type {
  PostureTier, PostureConstraints, GovernancePosture,
  PostureChange, PostureDowngradePolicy,
} from './core/governance-posture.js'

// ── Anchor States: external verifiability tracking ──
export {
  createAnchorMetadata, markBatched, markAnchored,
  shouldAutoBatch, meetsAnchorRequirement, isValidAnchorTransition,
  DEFAULT_AUTO_BATCH_CONFIG, ANCHOR_STATE_ORDER,
} from './core/anchor-state.js'

export type {
  AnchorState, AnchorMetadata, AutoBatchConfig,
} from './core/anchor-state.js'

export type {
  ToolCallRequest, ToolCallResult, GatewayProof,
  GatewayApproval, ToolExecutor, GatewayConfig,
  RegisteredAgent, GatewayStats, ActionReversibility, GatewayAgentRole,
  ConstraintFacet, ConstraintStatus, ConstraintSeverity,
  ConstraintFailure, ConstraintVector, ConstraintEvaluation,
  AuthorizationWitness, AuthorizationRef, ConstraintNearMiss,
  SubstrateFidelity, FidelityAttestation,
  WitnessAttestation, WitnessConflict, WitnessPolicy, WitnessObservationBasis,
  InfrastructureFeePolicy, GatewayImportPolicy,
  GatewaySovereigntyLevel, GatewayTrustBasis, GatewayIdentity, GatewayJurisdiction,
} from './types/gateway.js'

// ── Transactional Integrity Layer: Finality, Evidence, Escrow, Dispute ──
export type {
  FinalityStatus, FinalityState,
} from './types/finality.js'

export type {
  EvidenceType, TypedEvidence,
} from './types/evidence.js'

export type {
  EscrowStatus, EscrowHold, EscrowMilestone, EscrowFulfillmentCondition,
  DangerType, DangerSignal,
} from './types/escrow.js'

export type {
  DisputeStatus, DisputeResolution, DisputeSubject, ResolverRole,
  DisputeBond, DisputeArtifact, DisputeOverlay,
} from './types/dispute.js'

export {
  createEscrowHold, verifyEscrowHold,
  createDisputeArtifact, verifyDisputeArtifact,
  createWitnessAttestation, verifyWitnessAttestation,
  evaluateDisputeOverlay,
} from './core/transactional.js'

// ── Layer 9: W3C DID & Verifiable Credentials Bridge ──
export {
  createDID, createDIDHex, publicKeyFromDID, isValidDID,
  passportToDIDDocument, resolveDID,
  signWithDID, verifyWithDID,
  hexToMultibase, multibaseToHex
} from './core/did.js'

// ── Key Rotation — DID Document + Identity Continuity ──
export {
  createDIDDocument, announceKeyRotation, activateKeyRotation,
  verifyRotationChain, isKeyActive, rotateAndInvalidate,
} from './core/key-rotation.js'
export type { RotationResult } from './core/key-rotation.js'

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

// ── Trust Bootstrap Adapters ──
export {
  bootstrapFromAPIKey, bootstrapFromGitHub, bootstrapFromCIKey,
  upgradeBootstrappedPassport,
} from './core/trust-adapters.js'
export type { ImportEvidence, BootstrapResult } from './core/trust-adapters.js'


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
  computeEffectiveScore, createScopedReputation, computeConfidence, createEvidenceDiversity,
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
  EvidenceClass, TaskClassification, EvidencePortfolio, EvidenceDiversity,
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


// ── Execution Attestation (Checkpoint 3 — what ACTUALLY ran) ──

export {
  createExecutionAttestation,
  verifyExecutionAttestation,
  detectExecutionDrift,
} from './core/execution-attestation.js'

export type {
  ExecutionAttestation,
  ExecutionAttestationVerification,
  ExecutionDrift, ExecutionDriftSeverity,
  AttestorType, CreateExecutionAttestationInput,
  DriftClassificationRule,
} from './types/execution-attestation.js'

export { DEFAULT_DRIFT_RULES } from './types/execution-attestation.js'


// ── Bilateral Receipt + Evidence Commitments + Compromise Window ──

export {
  createBilateralReceipt,
  verifyBilateralReceipt,
  createEvidenceCommitment,
  verifyEvidenceCommitment,
  checkCompromiseWindow,
} from './core/bilateral-receipt.js'

export type {
  BilateralReceipt, BilateralReceiptVerification,
  InteractionOutcome, EvidenceCommitment,
  CompromiseWindowCheck, RevocationReason,
} from './types/bilateral-receipt.js'


// ── Feasibility Linting (Module 24, Gap 7) ──

export {
  lintDelegation, lintTaskFeasibility, lintDelegationForGateway,
} from './core/feasibility.js'
export type { GatewayLintResult, GatewayLintReport } from './core/feasibility.js'

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
  createWitnessPool, createAttestation,
  verifyWitnessAttestation as verifyOracleWitnessAttestation,
  addAttestation, computeDiversityScore, evaluateWitnessConsensus,
  wouldIncreaseDiversity,
} from './core/oracle-witness.js'

export type {
  WitnessAttestation as OracleWitnessAttestation, WitnessPool, WitnessPoolConfig,
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
// Charter — Institutional Root Object
// ══════════════════════════════════════

export type {
  CharterStatus, OfficeHolderMode, OfficeStatus,
  OfficeHolder, OfficeDelegationPolicy, Office,
  CharterSignature, DelegationSurvival, DissolutionPolicy, DisputeVenue,
  CharterCore,
  SuccessionTrigger, SuccessionRule, QuorumFailurePolicy,
  OfficeRegistry, CharterAmendment,
  CharterVerification, AmendmentVerification,
  OfficeTransfer,
} from './types/charter.js'


// ══════════════════════════════════════
// Approval — Multi-Class Threshold Policies
// ══════════════════════════════════════

export type {
  KeyClassRequirement, MultiClassThresholdPolicy,
  ApprovalType, ApprovalPolicy,
  ApprovalSignature, ApprovalSubjectType, ApprovalRequest,
  ApprovalEvaluation, KeyClassStatus,
} from './types/approval.js'


// ══════════════════════════════════════
// Charter & Approval — Pure Functions
// ══════════════════════════════════════

export {
  createCharter, signCharter, verifyCharter,
  createAmendment, signAmendment, verifyAmendment,
  evaluateThreshold,
  createOfficeRegistry,
  createOfficeTransfer,
  createApprovalRequest, addApprovalSignature, evaluateApprovalRequest,
  findOffice, findOfficesByHolder, resolveSuccessor,
  checkIncompatibility, checkQuorum,
} from './core/charter.js'

export type { CreateCharterOptions, CreateAmendmentOptions, CreateOfficeTransferOptions } from './core/charter.js'


// ══════════════════════════════════════
// Time — Hybrid Logical Clocks + Temporal Rights
// ══════════════════════════════════════

export type {
  HybridTimestamp, TemporalBound, TemporalRights,
  TemporalOrdering, TemporalValidation,
} from './types/time.js'

export {
  DEFAULT_NTP_DRIFT_MS,
  createHybridTimestamp, createTemporalBound,
  compareTimestamps, isTemporalBoundExpired,
  validateTemporalRights, resetLogicalCounter,
} from './core/time.js'


// ══════════════════════════════════════
// Foreign Counterparty — Non-APS Entity Handling
// ══════════════════════════════════════

export type {
  ForeignProvenanceClass, ForeignTrustClass,
  ForeignSandboxPolicy, ForeignReclassificationRules,
  ForeignCounterpartyEnvelope,
} from './types/foreign.js'


// ══════════════════════════════════════
// Escrow-Aware Revocation
// ══════════════════════════════════════

export type {
  EscrowRevocationStatus, EscrowAwareRevocation,
} from './types/escrow.js'


// ══════════════════════════════════════
// Reserve Attestation
// ══════════════════════════════════════

export type {
  ReserveAssuranceClass, AttestationBasis, FalseAttestationPenalty,
  ReserveAttestationLiability, ReserveAttestation,
} from './types/reserve.js'

export {
  createReserveAttestation, verifyReserveAttestation,
  compareAssuranceClass, meetsAssuranceRequirement,
} from './core/reserve.js'

export type { CreateReserveAttestationOptions, ReserveAttestationVerification } from './core/reserve.js'


// ══════════════════════════════════════
// Federation — Cross-Gateway Portability (WS-2, WS-3)
// ══════════════════════════════════════

export type {
  ForeignReceiptEnvelope, VouchedReputation,
} from './types/federation.js'

export {
  importReceipt, verifyReceiptEnvelope,
  vouchReputation, verifyVouchedReputation,
  applyReputationDowngrade,
} from './core/federation.js'

export type { ImportReceiptOptions, VouchReputationOptions } from './core/federation.js'


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
export * from './core/data-source-attribution.js'

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
export { verifyCrewMember, governCrewTask, crewTaskToScopes } from './adapters/crewai.js'
export type { CrewTask, CrewGovernanceConfig, GovernedTaskResult } from './adapters/crewai.js'

export { createADKGovernancePlugin } from './adapters/adk.js'
export type { ADKGovernancePlugin, ADKActionContext } from './adapters/adk.js'

export { createLangChainGovernanceHandler } from './adapters/langchain.js'
export type { LangChainGovernanceHandler } from './adapters/langchain.js'
export { governLangChainTool, createLangGraphGovernance, langchainToolToScope } from './adapters/langchain.js'
export type { LangChainToolCall, GovernedToolResult, DeniedToolResult, LangChainGovernanceConfig } from './adapters/langchain.js'

export { createA2AGovernance } from './adapters/a2a.js'
export type { A2AGovernance } from './adapters/a2a.js'
export { passportToA2ACard, a2aCardToPassportMeta, verifyA2AIdentity, a2aSkillsToScope, embedA2ATrustSignal } from './adapters/a2a.js'
export type { A2AAgentCardV2 } from './adapters/a2a.js'

export { governMCPToolCall, createMCPGovernanceInterceptor, mcpToolToScope } from './adapters/mcp.js'
export type { MCPToolCall, MCPGovernanceConfig } from './adapters/mcp.js'

export {
  verifyGonkaHost, governGonkaInference, createDevshardReceipt,
  delegationToAllowlistEntry, epochToDelegationExpiry, verifyPoCParticipation,
} from './adapters/gonka.js'
export type {
  GonkaInferenceRequest, GonkaHostConfig, GonkaInferenceReceipt, GonkaHostVerification,
} from './adapters/gonka.js'

export { delegationToPolicy, policyToYaml, extractEffectiveScopes } from './adapters/openshell.js'
export type { OpenShellPolicy, NetworkPolicyEntry, ScopeMapping } from './adapters/openshell.js'

export {
  ibacIntentToScope, ibacTuplesToDelegation,
  evaluateIBACTuples, governIBACIntent,
} from './adapters/ibac.js'
export type {
  IBACIntent, IBACAction, IBACTuple, IBACEvaluationResult,
} from './adapters/ibac.js'

export { cedarPolicyToTuples, delegationToCedarPolicy } from './adapters/ibac-cedar.js'

export { reportReceipt, reportEvaluation } from './adapters/gateway-reporter.js'
export type { GatewayReporterConfig } from './adapters/gateway-reporter.js'


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
  isGovernanceBlockExpired,
  createVerifiedGovernanceCredential, verifyGovernanceCredential,
  bindGovernanceToImplementation,
} from './core/governance-block.js'
export type {
  GovernanceBlock, GovernanceTerms, RevocationPolicy,
  UsagePermission, GovernanceBlockVerification,
  GenerateGovernanceBlockInput,
  VerifiedGovernanceCredential, GovernanceBinding,
} from './core/governance-block.js'


// ══════════════════════════════════════
// aps.txt + HTTP Headers + Chained Blocks
// ══════════════════════════════════════

export {
  generateApsTxt, verifyApsTxt, serializeApsTxt, parseApsTxt,
  resolveTermsForPath, governanceHeaders, parseGovernanceHeaders,
  createChainedGovernanceBlock, verifyChainedBlock,
  enforceApsTxt, evaluateApsTxtRisk,
} from './core/aps-txt.js'
export type {
  ApsTxt, PathOverride, GenerateApsTxtInput,
  ChainedGovernanceBlock,
  VerifyApsTxtOptions, VerifyApsTxtResult,
  ApsTxtEnforcementMode, ApsTxtEnforcementResult,
  ApsTxtRiskLevel, ApsTxtRiskResult,
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

export * from './core/proof-namespace.js'

export {
  createToolRegistryEntry, verifyToolIntegrity,
} from './core/tool-integrity.js'
export type {
  ToolRegistryEntry, ToolRequirements, ToolIntegrityResult,
} from './core/tool-integrity.js'

// ── Recovery Policy (Standard Failure Patterns) ──
export {
  evaluateRecovery, createRecoveryEvent, createDefaultRecoveryPolicy,
} from './core/recovery.js'
export type {
  RecoveryPolicy, RecoveryRule, RecoveryEvent,
  RecoveryStrategy, RecoveryTrigger,
} from './types/recovery.js'


// ══════════════════════════════════════
// Behavioral Evaluation Context (Issue #9)
// ══════════════════════════════════════

export {
  createEvaluationContext, createBehavioralAttestationResult,
  validateAttestationResult,
} from './core/evaluation-context.js'

export type {
  EvaluationContext, BehavioralAttestationResult,
} from './types/attestation.js'


// ══════════════════════════════════════
// Agent Health Status (Enterprise Monitoring)
// ══════════════════════════════════════

export type { AgentHealthStatus } from './types/health.js'
export { deriveHealthStatus } from './types/health.js'
