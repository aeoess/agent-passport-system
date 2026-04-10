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


// v2 Approval Fatigue Detection (Bureaucratic DDoS)
export {
  recordApproval, getApprovalHistory,
  checkImpossibleLatency, checkRubberStamping,
  checkVelocitySpike, checkComplexityMasking,
  computeFatigueMetrics,
  getFatigueFlags, getUnreviewedFatigueFlags, reviewFatigueFlag,
  clearApprovalFatigueStores,
} from './approval-fatigue.js'
export type { FatigueFlag } from './approval-fatigue.js'

// v2 Effect Enforcement (Authorization-Effect Gap)
export {
  declareEffects, getDeclaration, getDeclarationsForAgent,
  verifyEffects, getVerification, getVerificationsForAgent,
  getAgentDivergenceAvg, isAgentBlockedByEffects,
  getEffectPatterns, clearEffectStores,
} from './effect-enforcement.js'

// v2 Emergence Detection (Aggregate Governance)
export {
  recordAgentActivity, getActivitySummaries,
  computeSystemMetrics, getMetricsHistory,
  detectEmergence,
  getEmergenceFlags, getUnreviewedEmergenceFlags,
  reviewEmergenceFlag, clearEmergenceStores,
} from './emergence.js'

// v2 Root Authority Transition
export {
  getCurrentPhase, getPhaseHistory,
  createTransitionPlan, approveTransition,
  executeTransition, abortTransition,
  getTransitionPlan, getAllTransitionPlans,
  getApprovalStatus, clearRootTransitionStores,
} from './root-transition.js'


// v2 Semantic Drift Detection (Intent Subversion)
export {
  extractKeywords, recordSemanticIntent, analyzeSemanticDrift,
  getDriftResults, getAgentDriftAverage, isAgentSemanticRisk,
  getSemanticRecord, clearSemanticDriftStores,
} from './semantic-drift.js'

// v2 Composite Workflow Audit (Authority Laundering)
export {
  recordPipelineAction, getPipelineActions,
  auditCompositeCapabilities,
  getCompositeFlags, isAgentInLaunderingPipeline,
  clearCompositeAuditStores,
} from './composite-audit.js'


// v2 Governance Drift Tracking (Regulatory Capture)
export {
  recordGovernanceChange, getGovernanceChanges,
  analyzeCumulativeDrift,
  getGovernanceDriftFlags, reviewGovernanceDriftFlag,
  clearGovernanceDriftStores,
} from './governance-drift.js'
export type {
  ChangeDirection, GovernanceChangeRecord,
  CumulativeDriftAnalysis, GovernanceDriftFlag,
} from './governance-drift.js'


// v2 Epistemic Isolation (Consensus Trap Defense)
export {
  createBarrier, submitToBarrier, isBarrierComplete,
  getBarrierStatus, revealResults, getBarrier,
  clearEpistemicIsolationStores,
} from './epistemic-isolation.js'
export type { SubmissionBarrier, BarrierSlot, BarrierResult } from './epistemic-isolation.js'

// v2 Values Override (Values Floor Paradox Defense)
export {
  invokeValuesOverride, reviewOverride, getOverrideHistory,
  getPendingOverrideReviews, getOverdueReviews, getAgentPenaltyCount,
  clearValuesOverrideStores,
} from './values-override.js'
export type { ValuesOverride } from './values-override.js'

// v2 Inaction Auditing (Proportionality Freeze Defense)
export {
  recordAvailableAction, recordInaction, recordConsequence,
  analyzeInactionPattern, getInactionRecords,
  clearInactionAuditStores,
} from './inaction-audit.js'
export type { AvailableAction, InactionRecord } from './inaction-audit.js'

// v2 End-to-End Intent Binding (Distributed Responsibility Defense)
export {
  createIntentChain, extendChain, validateChainIntegrity,
  getIntentChain, clearIntentBindingStores,
} from './intent-binding.js'
export type { ChainedIntent } from './intent-binding.js'

// v2 Effect Sampling (Random Deep Auditing)
export {
  createSamplingPolicy, shouldSample, recordSample,
  completeAudit, getSamplingStats, getPendingAudits,
  setSamplingRng, clearEffectSamplingStores,
} from './effect-sampling.js'
export type { SamplingPolicy, AuditSample } from './effect-sampling.js'

// v2 Output Proportionality (Truthful Deception Defense)
export {
  analyzeOutputProportionality, setSummaryRequirement,
  getOutputRecords, getFlaggedOutputs,
  clearOutputProportionalityStores,
} from './output-proportionality.js'
export type { OutputMetrics, SummaryRequirement } from './output-proportionality.js'

// v2 Collective Circuit Breakers (Emergence Defense)
export {
  defineBreaker, evaluateBreaker, tripBreaker, resetBreaker,
  isActionBlocked, getBreaker, getAllBreakers, getBlockedCategories,
  clearCircuitBreakerStores,
} from './circuit-breakers.js'
export type { CircuitBreaker, BreakerState } from './circuit-breakers.js'

// v2 Affected-Party Standing (Section 9.10)
export {
  registerAffectedParty, fileComplaint, resolveComplaint,
  fileAppeal, resolveAppeal,
  getComplaints, getAppeals, getAffectedParty,
  clearAffectedPartyStores,
} from './affected-party.js'
export type {
  AffectedParty, ComplaintEvent, AppealPathway,
  ComplaintStatus, ChallengeType,
} from './affected-party.js'


// v2 Semantic Scoping (Section 4 — runtime enforcement)
export {
  defineSemanticScope, checkSemanticCompliance, getScopeViolations,
  clearSemanticScopingStores,
} from './semantic-scoping.js'
export type { SemanticConstraint, SemanticScope, ScopeViolation } from './semantic-scoping.js'

// v2 Blind Evaluation (5.9 — Values Floor as Cover defense)
export {
  createBlindEvaluation, submitBlind, getBlindSubmission,
  evaluateBlind, revealIdentities, clearBlindEvaluationStores,
} from './blind-evaluation.js'
export type { BlindSubmission, BlindEvaluation } from './blind-evaluation.js'

// v2 Cascade Correlation (Section 7 — temporal convergence)
export {
  recordOutputDependency, detectFeedbackLoops,
  computeCorrelationMetrics, getDependenciesForAgent,
  getDetectedLoops, clearCascadeCorrelationStores,
} from './cascade-correlation.js'
export type { OutputDependency, FeedbackLoop, CorrelationMetrics } from './cascade-correlation.js'

// v2 Cross-Chain Audit (Section 7 — inter-chain monitoring)
export {
  recordCrossChainFlow, auditCrossChainFlows,
  detectUnauthorizedBridging, clearCrossChainAuditStores,
} from './cross-chain-audit.js'
export type { CrossChainFlow, FlowAuditResult } from './cross-chain-audit.js'

// v2 Externality Accounting (Section 7 — shared resource governance)
export {
  registerSharedResource, recordExternality,
  computeExternalityBudget, getResourceUtilization,
  isOverBudget, clearExternalityStores,
} from './externality.js'
export type { SharedResource, ExternalityRecord } from './externality.js'

// v2 Separation of Powers (Section 9.1)
export {
  assignBranch, getAgentBranches, checkSeparation,
  preventBranchConflict, getBranchMembers,
  clearSeparationOfPowersStores,
} from './separation-of-powers.js'
export type { BranchAssignment, PowerConflict } from './separation-of-powers.js'
export type { GovernanceBranch } from './separation-of-powers.js'

// v2 Constitutional Amendment (Section 9.11)
export {
  proposeAmendment, voteOnAmendment, checkSupermajority,
  ratifyAmendment, requiresHumanRatification,
  getAmendmentHistory, clearAmendmentStores,
} from './amendment.js'
export type { Amendment, AmendmentStatus } from './amendment.js'

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


// Wallet Binding (agent-native structural attestation)
export {
  bindWallet, unbindWallet, verifyBoundWallet, verifyUnbindEvent,
} from "./wallet-binding/index.js"
export type {
  BoundWallet, WalletChain, WalletVerificationChallenge, UnbindEvent,
} from "./wallet-binding/index.js"
