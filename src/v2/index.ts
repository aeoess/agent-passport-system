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
  ArtifactProvenance,
  Condition, ConditionSet,
  ActionRecord, AnomalyFlag, ConcentrationMetrics,
  MigrationRequest, MigrationRecord,
  AlternativeRejected, ContextualAttestation,
  TrustTier, DecayConfig, AttestationQuality,
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
