// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
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

// ── Scope Version Hash (MCP#1763) — bilateral receipt pre-commitment ──
export { computeScopeVersionHash, verifyScopeVersionMatch } from './core/scope-version.js'

// ── action_ref (A2A#1672) — Content-Addressed Request Identity ──
export { computeActionRef, actionRefsMatch } from './core/action-ref.js'
// External cross-ecosystem correlation key (action-ref-v1-jcs-sha256).
// Distinct primitive from the APS-native action_ref above.
export { computeExternalActionRefV1 } from './core/external-action-ref.js'
export type { ExternalActionRefV1Input } from './core/external-action-ref.js'
export { computeIdempotencyKey } from './core/idempotency.js'

// ── Attestation Freshness (A2A#1712) ──
export { computeEvidenceAge, isEvidenceFresh, createSnapshotFreshness, createRotatingFreshness } from './core/freshness.js'
export type { AttestationFreshness } from './types/passport.js'

// ── Agent Attestation Architecture (Phase 1 — Review Build) ──
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

// ── Bilateral Completion Receipts ──
export { createCompletionReceipt, verifyCompletionReceipt, linkPermitAndCompletion } from './core/completion.js'
export type { CompletionReceiptOptions, CompletionReceipt } from './core/completion.js'

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
// Primitives only. Weight-based report generators
// (computeAttribution, computeCollaborationAttribution,
// DEFAULT_SCOPE_WEIGHTS) moved to @aeoess/gateway.
// See MIGRATION.md#attribution-reports.
export {
  hashReceipt,
  traceBeneficiary,
  verifyAttributionReport,
  buildMerkleRoot, generateMerkleProof, verifyMerkleProof,
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
  createPolicyReceiptWithDecisionReceipt,
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
  EpistemicClaims, EpistemicStatus,
} from './types/policy.js'

// ── v2.3 — in-toto Decision Receipt v0.1 primitive ──
// Reference implementation of ENFORCEMENT-TRUST-ANCHOR.md Component A
// (bilateral receipts for dumb Web2 sinks). Pure primitive; gateway
// integration lives at the caller (e.g. @aeoess/gateway's ProxyGateway.emit).
export {
  emitDecisionReceipt,
  parseDecisionReceiptStatement,
  computeDelegationChainRoot,
  DECISION_RECEIPT_PREDICATE_TYPE,
  INTOTO_STATEMENT_V1,
  INTOTO_PAYLOAD_TYPE,
} from './decisionReceipt.js'
export type {
  DecisionReceiptEnvelope,
  DecisionReceiptPredicate,
  IntotoStatement,
  IntotoResourceDescriptor,
  DSSESignature,
  EmitDecisionReceiptInput,
} from './decisionReceipt.js'

// ── Layer 7: Agentic Commerce (ACP) ──
// Gate predicates + signing primitives stay in SDK. The 6-gate orchestrator
// (commercePreflight) and the four ACP REST wrappers moved to @aeoess/gateway
// as product workflow. Deprecated re-exports throw with a migration message.
export {
  commercePreflight,
  createCheckout, updateCheckout, completeCheckout, cancelCheckout,
  checkPassportGate, checkScopeGate, checkSpendGate,
  checkHumanApprovalThreshold, checkMerchantGate, checkWalletGate,
  hasCommerceScope,
  signCommerceReceipt, extractDelegationChain,
  requestHumanApproval,
  createCommerceDelegation,
  recordSpend,
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
  IdempotencyCheck, IdempotencyStore,
} from './types/commerce.js'

// ── Layer Integration — Wiring ──
// Bridge functions (commerceWithIntent, commerceReceiptToActionReceipt,
// validateCommerceDelegation, coordinationToAgora, postTaskCreated,
// postReviewCompleted, postTaskCompleted) moved to @aeoess/gateway.
// See MIGRATION.md#data-lifecycle.

// ── Agent Context — Automatic Compliance Enforcement ──
// AgentContext and createAgentContext moved to @aeoess/gateway. Types remain.

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

// ── Proxy Gateway: runtime implementation moved to @aeoess/gateway (2026-04-17).
// SDK ships only the gateway interface types in src/types/gateway.ts.
// See MIGRATION.md#gateway.

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

// ── Key Resolution (M3): KeyResolver interface + did:cycles/JWKS ──
export {
  CyclesKeyResolver,
  parseDIDCycles, isDIDCycles, cyclesJwksUrl, asJWKS, selectKey,
  decodeBase64Url, bytesToHex as keyResolutionBytesToHex,
  DEFAULT_TIMEOUT_MS as KEY_RESOLUTION_DEFAULT_TIMEOUT_MS,
  DEFAULT_CACHE_POLICY as KEY_RESOLUTION_DEFAULT_CACHE_POLICY,
} from './v2/key-resolution/index.js'
export type {
  KeyResolver, KeyResolution, KeyResolutionStatus, KeyLocator,
  FailurePolicy, CachePolicy, KeyResolverConfig,
  Ed25519JWK, JWKS, ParsedDIDCycles, JWKSelection,
} from './v2/key-resolution/index.js'

// ── Identity Bridge: SPIFFE + OAuth → APS ──
export {
  parseSPIFFEID, importSPIFFESVID,
  mapOAuthScopes, importOAuthToken,
} from './core/identity-bridge.js'

export type {
  SPIFFESVIDInput, ParsedSPIFFEID,
  OAuthTokenInput, OAuthImportResult,
} from './core/identity-bridge.js'

// ── OAuth 2.1 / RFC 8693 Token Exchange delegation-token bridge ──
export {
  TOKEN_TYPE_URN, TOKEN_EXCHANGE_GRANT_TYPE, JWT_SVID_APPROVED_ALGS,
  bridgeScopeOfClaim, isNarrowing, assertChainNarrows, effectiveScope,
  chainToTokenExchangeClaims, tokenExchangeClaimsToChain, parseScope,
  assertRoundTripNarrows, actorSatisfiesMayAct, currentActor,
  validateSpiffeId, spiffeIdToDidInput, jwtSvidToDidInput,
} from './adapters/oauth-rfc8693/index.js'

export type {
  ActClaim, MayActClaim, TokenExchangeClaims,
  OAuthDelegationHop, DelegationChainView, RecoveredChain,
  JwtSvidView, SpiffeIdentityInput,
} from './adapters/oauth-rfc8693/index.js'

// ── OAuth ID-JAG binding (draft-ietf-oauth-identity-assertion-authz-grant-04) ──
// Imports a caller-verified ID-JAG grant as external authority and adds the
// actor-delegation layer the draft leaves to profiles in section 9.7. Binding
// only: no signature check, no JWKS, no revocation, no decision. Stable APS
// semantics; draft-pinned external protocol semantics. See adapters/oauth-id-jag.
export {
  bindIdJagGrant, verifiedIdJagGrant, IDJAG_DRAFT, SOURCE_GRANT_REF_TAG, IdJagBindingError,
} from './adapters/oauth-id-jag/index.js'
export { verifyIdJagDescriptor } from './adapters/oauth-id-jag/verify.js'
export type {
  IdJagClaims, IdJagVerification, VerifiedIdJagGrant, IdJagAuthorizationDetail,
  IdJagDescriptor, IdJagCarriedAudience, IdJagActReconciliation, IdJagCallerVerification,
  IdJagDiagnostic, IdJagOpaqueContext, IdJagBindOptions, SourceGrantRefPreimage,
  IdJagExternalRoot, IdJagVerifyResult,
} from './adapters/oauth-id-jag/index.js'

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

// ── Governance Posture: tier definitions + constraint primitives ──
// State machine (createInitialPosture, recordBehavioralFailure,
// recordBehavioralSuccess, upgradePosture, DEFAULT_DOWNGRADE_POLICY)
// moved to @aeoess/gateway src/sdk-migrated/core/posture-state.ts.
// Stubs preserve the function symbols so existing imports resolve;
// calling them throws.
export {
  createInitialPosture, recordBehavioralFailure, recordBehavioralSuccess,
  upgradePosture, getPostureConstraints, isScopeBlocked, comparePostureTiers,
  DEFAULT_POSTURE_CONSTRAINTS,
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

// ── A2A composition-contract §5 / §6.3 — IdentityCompositionError ──
export {
  IdentityCompositionError,
  assertKeyPurpose,
} from './errors/identity-composition-error.js'

export type {
  IdentityCompositionErrorReason,
  IdentityCompositionErrorContext,
} from './errors/identity-composition-error.js'

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
// Compliance automation (classifyRisk, mapArticles, generateComplianceProfile,
// identifyGaps, generateComplianceReport, generateTransparencyDisclosure)
// moved to @aeoess/gateway. Types remain.

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
  DEFAULT_K, MAX_SIGMA, MIN_SIGMA, INITIAL_MU, INITIAL_SIGMA, SCARRING_PENALTY,
  DEFAULT_TIERS, DEFAULT_PROMOTION_REQUIREMENTS,
  DEFAULT_DECAY_DAYS, DEFAULT_DRIFT_RATE_PER_DAY,
  RECENT_OBSERVATIONS_CAP,
  computeEffectiveScore, createScopedReputation, computeConfidence, createEvidenceDiversity,
  classifyEvidence, resolveAuthorityTier, shouldDemote,
  effectiveAutonomy, effectiveSpendLimit, effectiveDelegationDepth,
  classifyRuntimeChange, sigmaAfterRuntimeChange,
  meetsPromotionRequirements,
  validatePromotionReview,
  checkTierForIntent, advisoryTierPrecheck,
  updateReputationFromResult,
  applyTemporalDecay, confidenceBreakdown,
} from './core/reputation-authority.js'

export type {
  ScopedReputation, AuthorityTier, TierDefinition, TierOrigin,
  EvidenceClass, TaskClassification, EvidencePortfolio, EvidenceDiversity,
  PromotionRequirements, PromotionReview,
  RuntimeProfile, RuntimeChangeClass,
  DemotionCause, DemotionEvent,
  TierEscalation, TierCheckContext,
  ReputationObservation
} from './types/reputation-authority.js'

export type { ConfidenceBreakdown } from './core/reputation-authority.js'

// Deprecation stubs: reputation analytics moved to @aeoess/gateway on 2026-04-17.
// See MIGRATION.md#reputation-analytics.
const REPUTATION_ANALYTICS_MOVED =
  'Moved to @aeoess/gateway (src/sdk-migrated/core/reputation-analytics.ts). ' +
  'See MIGRATION.md#reputation-analytics'
export function createPromotionReview(..._args: unknown[]): never { throw new Error('createPromotionReview: ' + REPUTATION_ANALYTICS_MOVED) }
export function triggerDemotion(..._args: unknown[]): never { throw new Error('triggerDemotion: ' + REPUTATION_ANALYTICS_MOVED) }
export function computeReputationDrift(..._args: unknown[]): never { throw new Error('computeReputationDrift: ' + REPUTATION_ANALYTICS_MOVED) }
export function computeConsistencyScore(..._args: unknown[]): never { throw new Error('computeConsistencyScore: ' + REPUTATION_ANALYTICS_MOVED) }
export const DEFAULT_DRIFT_WARNING_THRESHOLD = 0.15
export const DEFAULT_DRIFT_CRITICAL_THRESHOLD = 0.30

// ── Behavioral Fingerprint ──
// Three-axis joint measurement envelope: HBB fidelity (axis 1) +
// PDR cross-session reliability (axis 2) + Saebo within-session
// constraint compliance (axis 3). Composes all three into one signed
// artifact. Reference: Nanook PDR v2.19 §2.2 / §8.10, gap audit §5 rank 2.
export {
  createBehavioralFingerprint,
  verifyBehavioralFingerprint,
  composeFingerprintAxes,
} from './core/behavioral-fingerprint.js'

export type {
  BehavioralFingerprint,
  PDRScoreRef,
  SaeboScoreRef,
  FingerprintVerificationResult,
} from './core/behavioral-fingerprint.js'

// ── Probe Identity ──
// Content-addressable hashing for evaluation probes. Lets a downstream
// scoring system prove that the probe it scored is byte-identical to
// the probe the issuer published, by hashing canonical JSON of the
// probe and binding the hash to scoring observations.
// Reference: Nanook PDR v2.19 §5.9, gap audit §5 rank 7.
export {
  computeProbeIdentity,
  verifyProbeIdentity,
} from './core/probe-identity.js'

export type {
  ProbeIdentity,
  ProbeIdentityVerification,
} from './core/probe-identity.js'

// ── Intent Network (Module 17) ──
// Matching engine moved to @aeoess/gateway. Types remain.

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


// ── Hash-and-Pointer Payloads + Field-Disclosure Profile (W2-B6) ──

export {
  REDACTED_SENTINEL,
  buildFieldDisclosureProfile,
  verifyFieldDisclosureProfile,
  canonicalProfileBytes,
  bbsProofToFieldDisclosureRef,
  fieldDisclosureRefToBbsProof,
} from './v2/hash-pointer/index.js'
export type {
  FieldDisclosurePolicy,
  HashPointerAlgorithm,
  HashPointerPayload,
  DisclosedField,
  FieldDisclosureProofRef,
  FieldDisclosureProfile,
  BuildFieldDisclosureProfileInput,
  FieldDisclosureVerification,
  BbsDisclosureProofShape,
} from './v2/hash-pointer/index.js'


// ── Governance Artifact Provenance (Module 21) ──

export {
  hashContent,
  createGovernanceArtifact, verifyGovernanceArtifact,
  approveArtifact, verifyApproval,
  createGovernanceEnvelope, loadGovernanceArtifact,
  upgradeGovernanceArtifact, classifyGovernanceChange,
  validateCredentialLifecycle,
  DEFAULT_LOAD_POLICY,
} from './core/governance.js'

export type {
  GovernanceArtifact, GovernanceApproval, GovernanceVerification,
  GovernanceEnvelope, GovernanceLoadPolicy,
  GovernanceChangeType, GovernanceDiff,
  CredentialLifecyclePolicy,
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
  approvalSignContent,
  findOffice, findOfficesByHolder, resolveSuccessor,
  checkIncompatibility, checkQuorum,
} from './core/charter.js'

export type { CreateCharterOptions, CreateAmendmentOptions, CreateOfficeTransferOptions } from './core/charter.js'


// ══════════════════════════════════════
// Time — Hybrid Logical Clocks + Temporal Rights
// ══════════════════════════════════════

export type {
  HybridTimestamp, TemporalBound, TemporalRights,
  TemporalOrdering, TemporalValidation, SessionBoundary,
} from './types/time.js'

export {
  DEFAULT_NTP_DRIFT_MS, DEFAULT_SESSION_GAP_MS,
  createHybridTimestamp, createHybridTimestampAt,
  createTemporalBound,
  compareTimestamps, isTemporalBoundExpired,
  validateTemporalRights, resetLogicalCounter,
  extractSessions,
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

// ── v2 primitives (explicit re-exports for public API discoverability) ──
// These are protocol primitives — verification and gating logic that
// downstream integrators (including the gateway) compose on top of.

// APS Regulated Action Profile v0 (Reconciled Action Attestation). Exposed as a single namespace
// to avoid generic-name collisions across this barrel (ActionReceipt, AuthorityRef, Disposition,
// VerificationContext). Use RegulatedActionV0.verifyRegulatedAction etc. (AP-3 explicit block.)
export { RegulatedActionV0 } from './v2/index.js'

// APS Composition Check Receipt v0. The PUBLIC carrier for an external attestor's
// composition-hazard check: a signed receipt plus a stateless ANCHOR verifier. Detection of
// composition hazards is private gateway intelligence and is NOT in this SDK; the verifier
// checks signature, binding, freshness, and attestor trust, surfaces independence, and never
// emits a "safe" verdict. Namespaced to avoid name collisions (VerificationContext); use
// CompositionCheckV0.verifyCompositionCheck etc.
export { CompositionCheckV0 } from './v2/index.js'

export {
  verifyOnAccept, evaluateCredentialCheck, resolveCheckMode,
} from './v2/credential-check-policy/index.js'
export type {
  AcceptanceStamp, CredentialCheckMode, CredentialCheckPolicy,
  CredentialCheckResult, CredentialCheckDenialCode,
} from './v2/credential-check-policy/index.js'

export {
  createAttributionReceipt, signAttributionConsent,
  verifyAttributionConsent, checkArtifactCitations, receiptCore,
} from './v2/attribution-consent/index.js'
export type {
  AttributionReceipt, AttributionConsentResult, ArtifactCitation,
  CitingArtifact, CreateAttributionReceiptParams,
} from './v2/attribution-consent/index.js'

// ══════════════════════════════════════
// Accountability MVP (Wave 1)
// ══════════════════════════════════════
export {
  createActionReceipt, verifyActionReceipt,
  createAuthorityBoundaryReceipt, verifyAuthorityBoundaryReceipt,
  createCustodyReceipt, verifyCustodyReceipt,
  createContestabilityReceipt, attachControllerResponse, verifyContestabilityReceipt,
  createAPSBundle, verifyAPSBundle, computeMerkleRoot,
} from './v2/accountability/index.js'

// ══════════════════════════════════════
// Claim → Evidence Types (skeleton)
// ══════════════════════════════════════
export {
  ClaimType, RecordType, EvidenceProfiles, requiredEvidenceFor,
} from './v2/claim-evidence-types.js'
export type { EvidenceProfile } from './v2/claim-evidence-types.js'

// ══════════════════════════════════════
// Claim Verifier (Module 2 + Module 4 hook)
// ══════════════════════════════════════
// Named 'verifyEvidenceClaim' to disambiguate from the task-routing
// 'verifyClaim' re-exported from './core/routing.js' above.
export { verifyEvidenceClaim } from './v2/claim-verifier.js'
export type {
  ClaimVerificationInput, ClaimVerificationResult,
  OpenContestationResolver, OpenContestationLookup,
} from './v2/claim-verifier.js'

// ══════════════════════════════════════
// Downstream Taint (Module 4) — public cascade primitive
// ══════════════════════════════════════
export {
  isContestationTainting, computeDownstreamTaint,
} from './v2/downstream-taint.js'
export type {
  TaintedRecord, TaintedSet, TaintCandidate,
} from './v2/downstream-taint.js'

// ══════════════════════════════════════
// Offline verifier (W2-C2) - zero-network verify path + descriptor
// ══════════════════════════════════════
// A standalone APS verify path with no network dependency. It composes the
// existing crypto-layer receipt verifier with the promoted context-layer
// verifier and emits the W2-A1 Evidence Descriptor (a verifier OUTPUT, not
// an issuer field). Ships alongside a framework-agnostic relying-party gate
// (Express/Fastify adapters in examples/aps-relying-party-middleware) and a
// conformance runner over the canonicalization vectors.
export {
  verifyOffline,
  verifyReceiptContext, CRYPTO_LAYER_REASONS,
  buildDescriptor,
  evaluateRequest, runGate,
  runCanonicalizationConformance, checkCanonicalizationVector, summarize,
} from './v2/offline-verifier/index.js'
export type {
  OfflineVerifyOptions, OfflineVerifyResult, OfflineVerifyVerdict, OfflineDescriptorInputs,
  RejectReason, ReceiptContext, ContextVerifyResult,
  BuildDescriptorInput, EvidenceDescriptor, SignerClaim, WitnessObservationFact,
  CheckedSignature, IndependenceRelation, SignerNode, SignerGraph, DescriptorBuilder,
  GateDecision, GateDenyReason, GateOptions, GateRequestLike, GateResponseLike,
  ConformanceCheck, ConformanceRunnerResult,
} from './v2/offline-verifier/index.js'

// NOTE: 'ActionReceipt' name collides with the legacy commerce-flavored
// ActionReceipt re-exported at line 129 (from './types/passport.js'). Alias
// the new accountability one as 'AccountabilityActionReceipt' to preserve
// the public surface. The unaliased name remains available from
// './v2/accountability/index.js'.
export type {
  AccountabilityReceiptBase, CaptureMode, Completeness, ScopeOfClaim,
  ActionReceipt as AccountabilityActionReceipt, SideEffectClass,
  AuthorityBoundaryReceipt, BoundaryResult,
  CustodyReceipt, CustodyEventType, CustodyPurpose,
  ContestabilityReceipt, StandingBasis, RequestedRemedy, ContestStatus, GroundsClass,
  APSBundle, BundledReceiptRef,
} from './v2/accountability/index.js'

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
// Module 40: Data Source Attribution (the "pixel" primitive)
// ══════════════════════════════════════
// ContributionLedger + SettlementGenerator moved to @aeoess/gateway.
// Primitive types and data-source-attribution (Module 40 Merkle primitive)
// remain in the SDK.

export * from './types/data-contribution.js'
export * from './core/data-source-attribution.js'

// ══════════════════════════════════════
// Data Enforcement Gate + Training Attribution
// Data Gateway (Composable: Gateway + Data Enforcement + Terms Acceptance)
// ══════════════════════════════════════
// Implementations moved to @aeoess/gateway. Interface shapes remain here
// so downstream integrators (including the gateway's own ProxyGateway)
// can type-check config surfaces. See MIGRATION.md#data-lifecycle.

export type {
  DataAccessRequest, DataAccessDecision, DataEnforcementConfig,
} from './core/data-enforcement.js'
export type {
  DataGatewayConfig, TermsAcceptance,
} from './core/data-gateway.js'
export { DataGateway } from './core/data-gateway.js'
export { DataEnforcementGate } from './core/data-enforcement.js'

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

// GovernanceHook, createCrewAIGovernance, createADKGovernancePlugin,
// createLangChainGovernanceHandler, createA2AGovernance, reportReceipt,
// reportEvaluation — moved to @aeoess/gateway (see MIGRATION.md).

export { verifyCrewMember, governCrewTask, crewTaskToScopes } from './adapters/crewai.js'
export type { CrewTask, CrewGovernanceConfig, GovernedTaskResult } from './adapters/crewai.js'

export { adkContextToAction, adkToolToScope, adkAuthorizes } from './adapters/adk.js'
export type { ADKActionContext, ADKActionDescriptor } from './adapters/adk.js'

export { governLangChainTool, createLangGraphGovernance, langchainToolToScope } from './adapters/langchain.js'
export type { LangChainToolCall, GovernedToolResult, DeniedToolResult, LangChainGovernanceConfig } from './adapters/langchain.js'

export { deriveA2AScopes, passportToA2ACard, a2aCardToPassportMeta, verifyA2AIdentity, a2aSkillsToScope, embedA2ATrustSignal } from './adapters/a2a.js'
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
// deriveHealthStatus removed in v1.47.0 — the thresholds were product
// policy, not protocol primitive. Reference implementation now lives
// in the private gateway. See specs/AAIF-BOUNDARY-AUDIT.md.


// ══════════════════════════════════════
// Observation Governance — Behavioral Memory
// ══════════════════════════════════════

export type { DerivationRights, ObservationPolicy } from './types/passport.js'
export type { BehavioralMemoryObject, BMOReceipt, BMOExportBundle } from './types/behavioral-memory.js'

export {
  createBehavioralMemoryObject, verifyBehavioralMemoryObject,
  isBMOExpired, exportBehavioralMemory, importBehavioralMemory,
} from './core/behavioral-memory.js'

export { createBMOReceipt, verifyBMOReceipt } from './core/behavioral-memory-receipt.js'


// ══════════════════════════════════════
// Mutual Authentication v1 (v2.2.0)
// ══════════════════════════════════════
// Closes the asymmetry where agents authenticate to systems but
// systems do not authenticate to agents. Ships as a small signed
// envelope + local trust-anchor verification + downgrade-proof
// handshake. No federation, no gossip, no distributed CA.

export type {
  MutualAuthRole,
  MutualAuthCertificate,
  MutualAuthHello,
  MutualAuthAttest,
  MutualAuthSession,
  MutualAuthResult,
  MutualAuthPolicy,
  MutualAuthFailureReason,
  TrustAnchor,
  TrustAnchorBundle,
  AgentCertBinding,
  BuildCertificateInput,
  VerifyCertificateOutcome,
  AnchorCheckOutcome,
  BuildBundleInput,
  BundleVerifyOutcome,
  BundleVerifyReason,
  BuildAttestInput,
  VerifyAttestInput,
  VerifyAttestOutcome,
} from './v2/mutual-auth/index.js'

export {
  buildCertificate,
  signCertificate,
  certificateId,
  verifyCertificateSignature,
  isCertificateTemporallyValid,
  checkAnchor,
  buildBundle,
  signBundle,
  verifyBundle,
  newNonce,
  buildHello,
  chooseVersion,
  buildAttest,
  verifyAttest,
  deriveSession,
  isSessionActive,
} from './v2/mutual-auth/index.js'

// Adapters for mutual-auth
export {
  a2aBeginHandshake,
  a2aRespondHandshake,
  a2aCounterAttest,
  a2aFinalizeSession,
  attachMutualAuthToA2ACard,
  extractMutualAuthFromA2ACard,
} from './adapters/mutual-auth-a2a.js'

export type {
  A2AMutualAuthEnvelope,
} from './adapters/mutual-auth-a2a.js'

export {
  mcpServerBinding,
  mcpBeginHandshake,
  mcpRespondHandshake,
  mcpCounterAttest,
  mcpFinalizeSession,
  mcpIsToolCallPermitted,
} from './adapters/mutual-auth-mcp.js'

export type {
  MCPToolCallAuthCheck,
} from './adapters/mutual-auth-mcp.js'

// ── W2-B1: Trust Root Policy + trust_policy_ref ──
// A signed, anti-rollback trust-root-policy artifact, a verifier that
// derives a relying-party verdict for a receipt's signer, and the
// did:web .well-known/aps-agents.json discovery convention + generator.
// Extends mutual-auth trust anchors and the M3 key resolver; ships the
// artifact + verifier + convention, not a hosted resolution service.
export {
  TRUST_ROOT_POLICY_SPEC_VERSION,
  buildTrustRootPolicy,
  signTrustRootPolicy,
  verifyTrustRootPolicy,
  evaluateReceiptAgainstPolicy,
  WELL_KNOWN_APS_AGENTS_PATH,
  APS_AGENTS_DOC_SPEC_VERSION,
  generateApsAgentsDoc,
  apsAgentsUrl,
} from './v2/trust-policy/index.js'

export type {
  PinnedKey,
  TrustedIssuer,
  ResolverRule,
  RotationRule,
  StaleBehavior,
  OfflineBehavior,
  TrustRootPolicyBody,
  TrustRootPolicy,
  PolicyVerifyReason,
  PolicyVerifyOutcome,
  TrustPolicyVerdictReason,
  TrustPolicyStatus,
  TrustPolicyVerdict,
  BuildTrustRootPolicyInput,
  VerifyTrustRootPolicyOptions,
  ReceiptSignerFacts,
  EvaluateOptions,
  ApsAgentEntry,
  ApsAgentsDoc,
  GenerateApsAgentsInput,
} from './v2/trust-policy/index.js'

// ── v2.4-alpha — InstructionProvenanceReceipt (Paper 8 candidate) ──
// Spec: ~/aeoess_web/specs/INSTRUCTION-PROVENANCE-RECEIPT-DRAFT-v0.2.md
// Tier scope this version: 'self-asserted' only.
export {
  createInstructionProvenanceReceipt,
  verifyInstructionProvenanceReceipt,
  verifyActionTimeContextRoot,
  canonicalizePath,
  canonicalizeEnvelope,
  computeContextRoot,
} from './v2/instruction-provenance/index.js'

export type {
  AttestationTier,
  FilesystemMode,
  InstructionRole,
  InstructionFile,
  InstructionProvenanceReceipt,
} from './v2/instruction-provenance/index.js'

// ── v2.6.x payment-rails — public PaymentRail interface, signed
//      PaymentReceipt + PaymentDenial primitives, composable
//      governance hooks (preAuthorize, emitReceipt, emitDenial),
//      Nano reference adapter. Custodial wallet + credential
//      storage stay gateway-private.
export {
  // hooks
  createDefaultGovernanceHooks,
  emitDenial,
  emitReceipt,
  preAuthorize,
  verifyPaymentDenial,
  verifyPaymentReceipt,
  // canonicalize
  canonicalizeDenialForId,
  canonicalizeDenialForSig,
  canonicalizeInvoice,
  canonicalizeReceiptForId,
  canonicalizeReceiptForSig,
  invoiceDigest,
  paymentRailsSha256Hex,
  // nano reference adapter
  createNanoRail,
  NanoPaymentRail,
  rawToXno,
  xnoToRaw,
  // conformance harness
  HARNESS_FIXED_NOW,
  HARNESS_ISSUER_PRIV,
  resolveSpendLimitCents,
  runConformance,
  STANDARD_SCENARIOS,
} from './v2/payment-rails/index.js'

export type {
  ConformanceContext,
  ConformanceReport,
  ConformanceScenario,
  CreateInvoiceOpts,
  DelegationView,
  DenialReason,
  DenialVerifyReason,
  DenialVerifyResult,
  EmitDenialInput,
  EmitReceiptInput,
  FetchBlockInfo,
  FetchHistory,
  GovernanceHooks,
  InvoiceStatus,
  NanoBlockInfo,
  NanoHistoryEntry,
  NanoRailConfig,
  PaymentDenial,
  PaymentInvoice,
  PaymentRail,
  PaymentReceipt,
  PreAuthorizeInput,
  PreAuthorizeResult,
  ReceiptVerifyReason,
  ReceiptVerifyResult,
  RunConformanceOpts,
  ScenarioOutcome,
  ScenarioReport,
  SendPaymentOpts,
  VerifyTransactionResult,
} from './v2/payment-rails/index.js'

// ── AP2 v0.2 interop (Google Agent Payments Protocol) ────────────
// Pinned to AP2 v0.2 (April 2026). Crosswalk between APS V2Delegation
// and AP2 mandate dicts. See docs/governance/ap2-interop.md.
export {
  AP2_VERSION,
  ap2MandateToApsDelegation,
  apsToAp2CartMandate,
  apsToAp2IntentMandate,
  apsToAp2OpenPaymentMandate,
  apsToAp2PaymentMandate,
  signAp2Mandate,
  verifyAp2Mandate,
} from './v2/payment-rails/index.js'

export type {
  AP2Amount,
  AP2CheckoutConstraint,
  AP2CheckoutMandate,
  AP2Cnf,
  AP2Item,
  AP2Mandate,
  AP2Merchant,
  AP2OpenCheckoutMandate,
  AP2OpenPaymentMandate,
  AP2PaymentConstraint,
  AP2PaymentInstrument,
  AP2PaymentMandate,
  AP2VctCheckout,
  AP2VctOpenCheckout,
  AP2VctOpenPayment,
  AP2VctPayment,
  Ap2VerifyReason,
  Ap2VerifyResult,
  Ap2ToApsOptions,
  ApsToAp2CartOptions,
  ApsToAp2IntentOptions,
  ApsToAp2OpenPaymentOptions,
  ApsToAp2PaymentOptions,
  CartDetails,
  CartMandate,
  IntentMandate,
  SignedAP2Mandate,
  VerifyAp2MandateOptions,
} from './v2/payment-rails/index.js'

// ── v2.6.x payment-rails / x402 reference adapter (Base + USDC) ──
// Settles via the x402 v1 protocol against a caller-supplied
// facilitator (Coinbase CDP public endpoint by default). Mocked
// facilitator in tests; on-chain settlement happens via
// EIP-3009 transferWithAuthorization at the facilitator.
export {
  createX402Rail,
  USDC_BASE_MAINNET,
  USDC_BASE_SEPOLIA,
  X402_DEFAULT_FACILITATOR_URL,
  X402_VERSION,
  X402PaymentRail,
} from './v2/payment-rails/index.js'

export type {
  EIP3009Authorization,
  X402ExactSchemePayload,
  X402FacilitatorSettle,
  X402FacilitatorVerify,
  X402Network,
  X402PaymentPayload,
  X402PaymentRequirements,
  X402PaymentRequirementsResponse,
  X402RailConfig,
  X402Scheme,
  X402SettleRequest,
  X402SettleResponse,
  X402SubmitOutcome,
  X402VerifyRequest,
  X402VerifyResponse,
} from './v2/payment-rails/index.js'

// ── v2.6.x payment-rails / Stripe Issuing protocol primitives ────
// Phase 4.1 boundary split moved the orchestration class
// `StripeIssuingRail` and `createStripeIssuingRail` factory to the
// private gateway repo (live HTTP client + credential handling +
// in-memory card↔delegation registry). The SDK ships protocol
// primitives only: V2Delegation→SpendingControls mapper,
// V2Delegation→DelegationView projection, Stripe webhook signature
// verifier (HMAC-SHA256 over `${t}.${rawBody}` per Stripe scheme=v1),
// the form-urlencoded body encoder pinning the on-the-wire shape,
// and the rail constants. Gateway consumes via this package.
export {
  defaultMapDelegationToSpendingControls,
  stripeIssuingDelegationToView,
  stripeIssuingEncodeForm,
  verifyStripeSignature,
  STRIPE_ISSUING_DEFAULT_API_BASE,
  STRIPE_ISSUING_DEFAULT_REQUIRED_SCOPE,
  STRIPE_ISSUING_DEFAULT_TOLERANCE_SEC,
  STRIPE_ISSUING_RAIL_NAME,
} from './v2/payment-rails/index.js'

export type {
  StripeAuthorization,
  StripeAuthorizationDecision,
  StripeAuthorizationEvent,
  StripeCardholderRef,
  StripeDelegationLookup,
  StripeFetchLike,
  StripeIssuingConfig,
  StripeMerchantData,
  StripeSpendingControls,
  StripeSpendingControlsMapper,
  StripeSpendingLimit,
  StripeSpendingLimitInterval,
  StripeVirtualCard,
} from './v2/payment-rails/index.js'

// ── v2.6.x payment-rails / ACP reference adapter (OpenAI + Stripe) ─
// Agentic Commerce Protocol v2025-09-29 binding. Crosswalks APS
// V2Delegation to ACP checkout-session permissions, maps APS denial
// reasons to ACP error type/code envelopes, and mints signed
// AcpReceipt / AcpDenial primitives over RFC 8785 JCS canonical bytes.
// Reference adapter does not transport — gateway product.
export {
  ACP_API_VERSION,
  acpSessionToDelegationHints,
  apsToAcpError,
  checkAcpSessionUnderBudget,
  delegationToAcpAllowed,
  mapAcpDenialToFoundation,
  preAuthorizeAcpCheckout,
  signAcpDenial,
  signAcpReceipt,
  verifyAcpDenial,
  verifyAcpReceipt,
} from './v2/payment-rails/index.js'

export type {
  AcpAllowedFromDelegation,
  AcpBuyer,
  AcpCheckoutSession,
  AcpCheckoutSessionStatus,
  AcpCompleteCheckoutSessionRequest,
  AcpCreateCheckoutSessionRequest,
  AcpDenial,
  AcpDenialReason,
  AcpErrorCode,
  AcpErrorResponse,
  AcpErrorType,
  AcpFulfillmentAddress,
  AcpFulfillmentOption,
  AcpHookConfig,
  AcpItem,
  AcpLineItem,
  AcpMessage,
  AcpMessageContentType,
  AcpMessageType,
  AcpOp,
  AcpPaymentData,
  AcpPaymentMethod,
  AcpPaymentProvider,
  AcpPaymentProviderName,
  AcpPreAuthorizeResult,
  AcpReceipt,
  AcpTotal,
  AcpTotalType,
  AcpUpdateCheckoutSessionRequest,
  AcpVerifyReason,
  AcpVerifyResult,
  SignAcpDenialInput,
  SignAcpReceiptInput,
  VerifyAcpReceiptOptions,} from './v2/payment-rails/index.js'

// ── v2.6.x payment-rails / MPP reference adapter (Stripe + Tempo + Visa) ──
// Machine Payments Protocol draft-httpauth-payment-00 binding (March
// 30 2026). Crosswalks APS V2Delegation to MPP method/currency/cap
// permissions, maps APS denial reasons to MPP HTTP error envelopes
// (402/403/410/503 + WWW-Authenticate error= token), and mints
// signed MppApsReceipt / MppDenial primitives over RFC 8785 JCS
// canonical bytes. Reference adapter does not transport — gateway
// product handles live HTTP intercept and on-chain verification.
export {
  apsToMppHttpError,
  delegationToMppAllowed,
  mapMppDenialToFoundation,
  MPP_VERSION,
  preAuthorizeMppPayment,
  signMppDenial,
  signMppReceipt,
  verifyMppDenial,
  verifyMppReceipt,
} from './v2/payment-rails/index.js'

export type {
  MppAllowedFromDelegation,
  MppApsReceipt,
  MppAuthorization,
  MppDenial,
  MppDenialReason,
  MppMethod,
  MppMethodCard,
  MppMethodLightning,
  MppMethodTempo,
  MppMethodType,
  MppPaymentChallenge,
  MppPaymentReceipt,
  MppPreAuthorizeResult,
  MppVerifyReason,
  MppVerifyResult,
  PreAuthorizeMppOptions,
  SignMppDenialInput,
  SignMppReceiptInput,
  VerifyMppOptions,
} from './v2/payment-rails/index.js'

// M5 policy-bundle (added at merge time; module omitted its own root export)
export * from './v2/policy-bundle/index.js'

// W2-B2 Remote Signer adapters - pluggable async Signer over the unchanged
// Ed25519 default. Cloud adapters (AWS KMS, Azure Key Vault, Vault Transit,
// PKCS#11) live in the isolated optional package packages/aps-remote-signer and
// are not exported here (core ships no cloud SDK).
export {
  type Signer,
  type SignerHandle,
  RemoteSignerError,
  defaultKeyId,
  assertRawEd25519SignatureHex,
  LocalEd25519Signer,
  createLocalSigner,
  type LocalSignerOptions,
  HandleSigner,
  createHandleSigner,
  type HandleSignerOptions,
  type RemoteSignFn,
  type RemotePublicKeyFn,
  verifyWithSigner,
  buildRemoteSignerScopeOfClaim,
} from './adapters/remote-signer/index.js'

// ── W2-A1 Evidence Descriptor: canonical builder + advisory layer ──
// The descriptor types and the buildDescriptor alias already reach the
// public surface via the offline verifier (both sourced from
// src/v2/assurance). Here we expose A1's canonical builder name and the
// verifier-derived advisory layer that sits on top of the Belnap
// descriptor. Assurance is verifier-derived OUTPUT only; nothing exported
// here reads an issuer-set grade.
export {
  buildEvidenceDescriptor,
  computeAdvisoryScalar,
  generalizeBilateralVerification,
  DEFAULT_OBSERVATION_WEIGHTS,
  type AdvisoryScalar,
  type BilateralVerificationLike,
} from './v2/assurance/descriptor.js'

// ── Verification source: how a verifying key was obtained, carried in
// signed evidence (EvidenceCommitment.verificationSource) and in the
// descriptor's signer facts. Record and validation only; judging the
// acquisition posture is relying-party policy and is not exported here.
export {
  buildVerificationSource,
  validateVerificationSource,
  type VerificationSource,
  type VerificationSourceValidation,
} from './v2/verification-source/index.js'

// ── Producer attestation: an external attestation (EAT, TEE quote, vendor
// report) bound into receipt evidence and into a CPA by hash reference.
// APS does not parse or evaluate attestations; the claim is custody of
// the reference, not validity of the attestation.
export {
  createProducerAttestationCommitment,
  verifyProducerAttestationCommitment,
  validateProducerAttestationCommitment,
  buildCpaProducerAttestationRef,
  validateCpaProducerAttestationRef,
  type ProducerAttestationCommitment,
  type CpaProducerAttestationRef,
  type ProducerAttestationValidation,
} from './v2/producer-attestation/index.js'

// ── Jurisdiction selection provenance (VWE T5) ──
// Records which policy packs matched a set of jurisdiction facts; constraint
// conflicts are surfaced, never auto-resolved.
export { selectJurisdictionPacks, RESOLVER_VERSION } from './core/jurisdiction-selection.js'
export type { JurisdictionFacts, PolicyPackRef, PackConflict, SelectionOptions, SelectionRecord } from './types/jurisdiction-selection.js'

// ── Bilateral pair reconciliation (VWE T6, FREEZE-VWE F2) ──
// Compares the two parties' copies of a bilateral receipt; five frozen
// mismatch classes; audience failures via the canonical builder below.
export { reconcileBilateralPair } from './v2/bilateral-pair/reconcile.js'
export type { BilateralMismatchReason, BilateralPairPolicy, BilateralPairVerdict } from './v2/bilateral-pair/types.js'

// ── Audience binding verification surface (VWE T6) ──
// Public so route-side verifiers can consume the SDK check instead of
// mirroring it (the gateway mirror swap is queued on this export).
export { checkAudience, bindAudience, matchAudience } from './v2/audience-binding/verify.js'
export { audienceFailure } from './v2/audience-binding/reconcile.js'
export type { AudienceBinding, AudiencePolicy, AudienceCheckResult } from './v2/audience-binding/types.js'

// ── Revocation observation (VWE T7, FREEZE-VWE F4) ──
// Signed verifier-side record of an observed revocation signal and the
// decision taken under a stated freshness contract; labels derived, never stored.
export {
  buildRevocationObservation,
  verifyRevocationObservation,
  classifyObservation,
  observationParamsFromSET,
} from './v2/revocation-enforcement/observation.js'
export type { BuildObservationParams } from './v2/revocation-enforcement/observation.js'
export type {
  RevocationObservation,
  SignedRevocationObservation,
  RevocationStatusSource,
  RevocationObservationDecision,
  RevocationOutcomeLabel,
  ObservationVerifyResult,
} from './v2/revocation-enforcement/types.js'

// ── Evidence bundle + claim boundary report (VWE T8, FREEZE-VWE F5/F6) ──
// Signed Merkle-committed evidence sets with per-member inclusion proofs and
// the per-axis ClaimState report consumed by the verify-bundle CLI.
export {
  createEvidenceBundle,
  verifyEvidenceBundle,
  computeMemberDigest,
  proveMemberInclusion,
  verifyMemberInclusion,
  computeClaimBoundaryReport,
} from './core/evidence-bundle.js'
export type { CreateEvidenceBundleOptions, ClaimBoundaryReportOptions } from './core/evidence-bundle.js'
export type {
  EvidenceBundle,
  EvidenceBundleManifest,
  EvidenceBundleManifestMember,
  EvidenceBundleMember,
  EvidenceBundleMemberType,
  EvidenceBundleVerification,
  EvidenceBundleMemberVerification,
  ClaimState,
  ClaimAxis,
  ClaimAxisReport,
  ClaimBoundaryReport,
} from './types/evidence-bundle.js'

// ── Protocol binding profiles (v1): MCP aps-mcp-1 + A2A identity extension ──
// Pre-dispatch authorization middleware for MCP tools/call and the native
// Agent Card identity extension for A2A. Both resolve signing keys through a
// caller-supplied HistoricalKeyResolver.
export * from './profiles/mcp/index.js'
export * from './profiles/a2a/index.js'
export type {
  HistoricalKeyResolver,
  HistoricalKeyResolutionRequest,
  HistoricalKeyResolutionResult,
} from './v2/identity-binding/types.js'

// ── Receipt core (v2): signed decision receipts ──
// Verification establishes the integrity and semantics represented by a
// receipt. It does not authorize dispatch, consume receipt_id, enforce
// single-use, recheck revocation or time at dispatch, or reserve spend.
// Those obligations belong to the enforcement boundary.
// For serialized artifacts the safe public route is verifyReceiptV1Serialized,
// which rejects duplicate members before structured parsing destroys the
// evidence; the object-taking entrypoints cannot detect duplicates that
// existed in serialized JSON.
export {
  RECEIPT_ID_TAG,
  RECEIPT_SIG_TAG,
  isExactUtcMilliseconds,
  receiptIdPayloadV1,
  computeReceiptIdV1,
  receiptSignaturePayloadV1,
  validateReceiptV1,
  createReceiptV1,
  verifyReceiptV1,
  verifyReceiptV1Serialized,
} from './v2/receipt-core/receipt.js'
export type {
  ReceiptV1,
  ReceiptSignatureV1,
  ReceiptSignerV1,
} from './v2/receipt-core/types.js'
export type { ReceiptVerificationV1 } from './v2/receipt-core/receipt.js'
export { verifyReceiptWithDecisionV1 } from './v2/receipt-core/composite.js'
export type {
  DecisionEvidenceV1,
  ReceiptWithDecisionVerificationV1,
} from './v2/receipt-core/composite.js'

// ── Authority delegation (v2): signed delegation records ──
export {
  AUTHORITY_DELEGATION_ID_DOMAIN,
  AUTHORITY_DELEGATION_SIGNATURE_DOMAIN,
  authorityDelegationIdInput,
  computeAuthorityDelegationId,
  authorityDelegationSignatureInput,
  signAuthorityDelegation,
  verifyAuthorityDelegationSignature,
} from './v2/authority-delegation/canonical.js'
export { parseAuthorityDelegationJson } from './v2/authority-delegation/parse.js'
// Full root-to-leaf chain validation (structural, cryptographic, temporal, revocation,
// attenuation via compareAuthority). Verification only: a valid result is admissibility of
// the chain at `options.now`, never authorization to dispatch.
export { verifyAuthorityDelegationChain } from './v2/authority-delegation/verify.js'
export { compareAuthority } from './v2/authority-delegation/compare.js'
export type {
  AuthorityDelegationV1,
  AuthorityDelegationBodyV1,
  AuthorityFailureCode,
  AuthorityFailure,
  AuthorityValidationResult,
  AuthorityValidationState,
  AuthorityChainVerificationOptions,
  RevocationResolution,
} from './v2/authority-delegation/types.js'
