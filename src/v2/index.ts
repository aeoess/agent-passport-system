// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS v2 Module Index — Constitutional Governance Extensions
 * Full v2 implementation: Bridge + Delegation + Outcome + Anomaly + Emergency + Migration + Attestation
 */

// v2 Types
export type {
  PolicyContext, V2Delegation, V2ScopeDefinition, V2DelegationStatus,
  AssuranceClass, SemanticUncertainty, OutcomeClass, EarningContext,
  RiskClass, ReputationInheritance, ReviewMode, AnomalyType,
  ActivationStatus, OutcomePerspective, OutcomeRecord,
  ArtifactProvenance, BehavioralEvidenceMetadata,
  Condition, ConditionSet,
  ActionRecord, AnomalyFlag, ConcentrationMetrics,
  MigrationRequest, MigrationRecord,
  AlternativeRejected, ContextualAttestation,
  TrustTier, DecayConfig, AttestationQuality,
  ApprovalRecord, ApprovalDecision, FatigueMetrics, FatigueAnomalyType,
  EffectDeclaration, EffectVerification, EffectPattern,
  EscalationRequirement, ConfirmationRequest, OwnerConfirmation, ConfirmationScope,
  AgentActionSummary, SystemMetrics, EmergencePatternType, EmergenceFlag,
  GovernancePhase, AuthorityTransitionPlan,
  SemanticIntentRecord, SemanticDriftResult,
  PipelineAction, CompositeCapability,
} from './types.js'

// v2 Bridge (crypto adapter, type converters, core functions)
export {
  sha256, hashObject, signObject, verifyObject,
  createPolicyContext, isPolicyContextActive, isPolicyContextInGrace,
  v1DelegationToV2, v2DelegationToV1,
  createArtifactProvenance, verifyArtifactIntegrity,
  computeDecayedWeight,
  getUncertaintyRequirements, resolveUncertaintyLevel,
  evaluateConditions,
} from './bridge.js'

// v2 Delegation Versioning
export {
  createV2Delegation, supersedeV2Delegation, renewV2Delegation,
  revokeV2Delegation, validateV2Delegation,
  getV2Delegation, getV2DelegationsFor, getActiveV2Delegation,
  traceV2DelegationHistory, getExpiringV2Delegations,
  processV2Expirations, clearV2DelegationStore,
  isScopeExpansion, isScopeNarrowing,
} from './delegation-v2.js'
export type { CreateV2DelegationParams, SupersedeV2DelegationParams } from './delegation-v2.js'

// v2 Outcome Registration
export {
  createV2OutcomeRecord, addV2PrincipalReport, addV2AdjudicatedReport,
  getV2OutcomeRecord, getV2OutcomesForAgent,
  getV2EffectiveDivergence, getV2AgentDivergenceAverage,
  getV2DisputedOutcomes, isV2AgentFlaggedForReview,
  clearV2OutcomeStore,
} from './outcome-v2.js'

// v2 Anomaly Detection
export {
  recordV2Action, getV2ActionHistory,
  checkV2FirstMaxAuthority,
  validateV2UncertaintyCompliance,
  computeV2ConcentrationMetrics,
  getV2AnomalyFlags, getV2UnreviewedFlags,
  reviewV2AnomalyFlag, clearV2AnomalyStores,
} from './anomaly-v2.js'

// v2 Emergency Pathways
export {
  defineV2EmergencyPathway, activateV2Emergency,
  logV2EmergencyAction, reviewV2Emergency,
  getV2Pathway, getV2PathwaysForDelegation,
  getV2Activation, getV2ActiveEmergencies,
  getV2OverdueReviews, clearV2EmergencyStores,
} from './emergency-v2.js'
export type { V2EmergencyPathway, V2EmergencyActivation } from './emergency-v2.js'

// v2 Fork-and-Sunset Migration
export {
  requestV2Migration, approveV2Migration, executeV2Migration,
  isV2InProbation, computeV2MigrationDiscount,
  traceV2MigrationLineage, rollbackV2Migration,
  processV2CompletedProbations,
  getV2MigrationRequest, getV2MigrationRecord,
  getV2MigrationsForAgent, getV2ActiveProbations,
  clearV2MigrationStores,
} from './migration-v2.js'

// v2 Contextual Attestation
export {
  createV2Attestation, assessV2AttestationQuality,
  getV2AgentAttestationQualityAvg,
  getV2Attestation, getV2AttestationForAction,
  getV2AttestationsForAgent, clearV2AttestationStore,
} from './attestation-v2.js'


// v2 Semantic Drift Detection (Intent Subversion)
export {
  extractKeywords, recordSemanticIntent, analyzeSemanticDrift,
  getDriftResults, getAgentDriftAverage, isAgentSemanticRisk,
  getSemanticRecord, clearSemanticDriftStores,
} from './semantic-drift.js'

// v2 Epistemic Isolation (Consensus Trap Defense)
export {
  createBarrier, submitToBarrier, isBarrierComplete,
  getBarrierStatus, revealResults, getBarrier,
  clearEpistemicIsolationStores,
} from './epistemic-isolation.js'
export type { SubmissionBarrier, BarrierSlot, BarrierResult } from './epistemic-isolation.js'

// v2 End-to-End Intent Binding (Distributed Responsibility Defense)
export {
  createIntentChain, extendChain, validateChainIntegrity,
  getIntentChain, clearIntentBindingStores,
} from './intent-binding.js'
export type { ChainedIntent } from './intent-binding.js'

// v2 Semantic Scoping (Section 4 — runtime enforcement)
export {
  defineSemanticScope, checkSemanticCompliance, getScopeViolations,
  clearSemanticScopingStores,
} from './semantic-scoping.js'
export type { SemanticConstraint, SemanticScope, ScopeViolation } from './semantic-scoping.js'

// v2 Policy Profiles (Section 9.14)
export {
  createProfile, attachProfile, getProfilesForTarget,
  checkProfileCompliance, detachProfile,
  listActiveProfiles, getProfile, clearPolicyProfileStores,
} from './policy-profiles.js'
export type { ProfileConstraint, PolicyProfile, ProfileAttachment } from './policy-profiles.js'

// v2 Sub-Delegate Advisor (bounded-escalation delegation primitive)
export {
  subDelegateAdvisor, consultAdvisor,
  getAdvisorUses, clearAdvisorUseTracker,
} from './sub-delegate-advisor.js'
export type {
  SubDelegateAdvisorOptions, ConsultAdvisorOptions, ConsultAdvisorResult,
  ValidityWindow,
} from './sub-delegate-advisor.js'


// v2 HumanEscalationFlag (per-action-class owner confirmation)
export {
  checkEscalationRequired, requestOwnerConfirmation, recordOwnerConfirmation,
  verifyOwnerConfirmation, isConfirmationValid, verifyV2DelegationForAction,
  hashActionDetails, DEFAULT_FLAGGED_ACTION_CLASSES,
} from './human-escalation.js'
export type {
  EscalationAction, EscalationCheck, RecordConfirmationParams,
  ConfirmationVerdict, VerifyForActionResult,
} from './human-escalation.js'


// Wallet Binding (agent-native structural attestation)
export {
  bindWallet, unbindWallet, verifyBoundWallet, verifyUnbindEvent,
} from "./wallet-binding/index.js"
export type {
  BoundWallet, WalletChain, WalletVerificationChallenge, UnbindEvent,
} from "./wallet-binding/index.js"

// Credential Check Policy (verification timing for governance metadata)
// Proposed by @piiiico on a2aproject/A2A governance metadata thread.
export {
  verifyOnAccept, evaluateCredentialCheck, resolveCheckMode,
} from "./credential-check-policy/index.js"
export type {
  CredentialCheckMode, CredentialCheckPolicy, CredentialCheckResult,
  CredentialCheckDenialCode, AcceptanceStamp,
} from "./credential-check-policy/index.js"

// Attribution Consent (citation requires cited-principal sign-off)
// Triggered by the Apr 14 A2A#1734 pattern.
export {
  createAttributionReceipt, signAttributionConsent,
  verifyAttributionConsent, checkArtifactCitations, receiptCore,
} from './attribution-consent/index.js'
export type {
  AttributionReceipt, AttributionConsentResult, ArtifactCitation,
  CitingArtifact, CreateAttributionReceiptParams,
} from './attribution-consent/index.js'

// Provisional Statement — default for agent-to-agent negotiation statements.
// Binding status requires explicit PromotionEvent satisfying a PromotionPolicy.
export {
  createProvisional, isBinding, verifyAuthorSignature,
  withdrawProvisional, withdrawalPayload, statementSigningPayload,
  promoteStatement, processDeadMan, promotionSigningPayload,
  verifyPromotion,
} from './provisional-statement/index.js'
export type {
  ProvisionalStatement, PromotionEvent, PromotionPolicy,
  PromotionKind, ProvisionalStatus, PromotionVerifyResult,
  CreateProvisionalParams,
} from './provisional-statement/index.js'

// Attribution Weights — Build B fractional weight formulas for D and C
// axes. Spec: BUILD-B-FRACTIONAL-WEIGHTS.md. Runs upstream of Build A
// construction: callers compute weights from AccessReceipt/billing data
// here and feed the resulting axis entries into constructAttributionPrimitive.
export {
  ATTRIBUTION_ROLES,
  DEFAULT_WEIGHT_PROFILE,
  computeComputeAxisWeights,
  computeDataAxisWeights,
  contentLengthWeight,
  hashWeightProfile,
  recencyDecay,
  roleWeight,
  validateWeightProfile,
} from './attribution-weights/index.js'
export type {
  AccessReceiptWithRole,
  AttributionRole,
  ComputeComputeAxisOptions,
  ComputeDataAxisOptions,
  InferenceBillingRecord,
  ValidationResult,
  WeightProfile,
} from './attribution-weights/index.js'

// Attribution Settlement — Build C. Aggregates a stream of Attribution
// Primitives over a settlement period into one signed, queryable
// record. Spec: BUILD-C-SETTLEMENT-PIPELINE.md. Pure evidence; economic
// conversion (weight → currency) stays gateway-private.
export {
  aggregateAttributionPrimitives,
  buildContributorMerklePath,
  buildContributorQueryResponse,
  buildMerkleRoot as settlementBuildMerkleRoot,
  contributorLeafHashHex,
  emptyAxisMerkleRoot,
  formatSettlementWeight,
  residualLeafHashHex,
  settlementLeafHash,
  settlementRecordHash,
  settlementSigningPayload,
  signSettlementRecord,
  verifyContributorQueryResponse,
  verifyMerklePath as verifySettlementMerklePath,
  verifySettlementRecord,
  verifySettlementSignature,
} from './attribution-settlement/index.js'
// Renamed under an AttributionSettlement* prefix to avoid collision with
// Module 39's (data-only) SettlementPeriod / SettlementRecord types which
// predate Build C. Module 39 stays exported at its original path per
// spec §"Build C is a port and extension of Module 39".
export type {
  AggregateOptions as AttributionSettlementAggregateOptions,
  ContributorQueryAxisBody as AttributionContributorQueryAxisBody,
  ContributorQueryResponse as AttributionContributorQueryResponse,
  SettlementAxisIndex as AttributionSettlementAxisIndex,
  SettlementContributor as AttributionSettlementContributor,
  SettlementPeriod as AttributionSettlementPeriod,
  SettlementRecord as AttributionSettlementRecord,
  SettlementResidualBucket as AttributionSettlementResidualBucket,
  SettlementVerifyReason as AttributionSettlementVerifyReason,
  SettlementVerifyResult as AttributionSettlementVerifyResult,
  VerifySettlementOptions as AttributionVerifySettlementOptions,
} from './attribution-settlement/index.js'

// Attribution Primitive — unified four-axis (D, P, G, C) signed Merkle
// receipt. Spec: ATTRIBUTION-PRIMITIVE-v1.1.md. Disjoint from
// attribution-consent (that module's AttributionReceipt is a citation-
// consent primitive; this one is the per-action cross-axis primitive).
export {
  ATTRIBUTION_AXIS_TAGS, DEFAULT_MIN_WEIGHT,
  aggregateComputeAxis, aggregateDataAxis, aggregateProtocolAxis,
  assertCanonicalTimestamp, buildMerkleFrame,
  canonicalTimestamp as attributionCanonicalTimestamp,
  canonicalHashHex as attributionCanonicalHashHex,
  checkProjectionConsistency, computeAttributionActionRef,
  constructAttributionPrimitive, envelopeBytes,
  hashAxisLeaf, hashNode,
  normalizeAxes, orderGovernanceAxis,
  projectAllAxes, projectAttribution, projectionPath,
  projectionDataAsC, projectionDataAsD,
  projectionDataAsG, projectionDataAsP,
  reconstructRoot, resignAttributionPrimitive,
  sortComputeAxis, sortDataAxis, sortProtocolAxis,
  toWeightString,
  verifyAttributionPrimitive, verifyAttributionProjection,
} from './attribution-primitive/index.js'
export type {
  AggregateOptions, AggregationResult,
  AttributionAction, AttributionAxes, AttributionAxisTag,
  AttributionConsistencyResult, AttributionEnvelope,
  AttributionPrimitive, AttributionProjection, AttributionVerifyResult,
  ComputeAxisEntry, ComputeAxisItem,
  ConstructAttributionParams,
  DataAxisEntry, DataAxisItem,
  GovernanceAxisEntry,
  MerkleFrame,
  ProtocolAxisEntry, ProtocolAxisItem,
  ResidualBucket,
} from './attribution-primitive/index.js'
