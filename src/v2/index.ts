/**
 * APS v2 Module Index — Constitutional Governance Extensions
 * Add to main src/index.ts: export * from './v2/index.js'
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
  AlternativeRejected, ContextualAttestation,
  TrustTier, DecayConfig,
} from './types.js'

// v2 Bridge functions
export {
  sha256, hashObject, signObject, verifyObject,
  createPolicyContext, isPolicyContextActive, isPolicyContextInGrace,
  v1DelegationToV2, v2DelegationToV1,
  createArtifactProvenance, verifyArtifactIntegrity,
  computeDecayedWeight,
  getUncertaintyRequirements, resolveUncertaintyLevel,
  evaluateConditions,
} from './bridge.js'
