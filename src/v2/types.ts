/**
 * APS v2 Types — Constitutional Governance Extensions
 * Integrated into the Agent Passport System SDK
 */

// ── Governance Assurance Classes ──
export type AssuranceClass = 'mechanically_enforceable' | 'evidentially_auditable' | 'socially_adjudicated'
export type SemanticUncertainty = 'low' | 'medium' | 'high' | 'critical'
export type OutcomeClass = 'success' | 'partial_success' | 'failure' | 'unintended_effect' | 'unknown'
export type EarningContext = 'bootstrap_sandbox' | 'bootstrap_field' | 'field_earned' | 'migration_carried'
export type V2DelegationStatus = 'active' | 'expired' | 'revoked' | 'superseded' | 'grace_period'
export type RiskClass = 'low' | 'medium' | 'high' | 'critical'
export type ReputationInheritance = 'full' | 'discounted' | 'scoped' | 'probationary'
export type ReviewMode = 'async' | 'sync' | 'none'
export type AnomalyType = 'first_max_authority' | 'semantic_uncertainty_violation' | 'delegation_concentration' | 'authority_spike'
export type ActivationStatus = 'active' | 'expired' | 'reviewed_justified' | 'reviewed_unjustified' | 'reviewed_ambiguous'

// ── PolicyContext — Universal Invariant ──
export interface PolicyContext {
  policy_version: string
  values_floor_version: string
  trust_epoch: number
  issuer_id: string
  created_at: string
  valid_from: string
  valid_until: string
}

// ── v2 Scope Definition ──
export interface V2ScopeDefinition {
  action_categories: string[]
  semantic_boundaries?: string[]
  resource_limits?: Record<string, number>
  domain?: string
  constraints?: Record<string, string>
}

// ── v2 Delegation ──
export interface V2Delegation {
  id: string
  version: number
  supersedes: string | null
  supersession_justification: string | null
  delegator: string
  delegatee: string
  scope: V2ScopeDefinition
  policy_context: PolicyContext
  signature: string
  status: V2DelegationStatus
  renewal_reason: string | null
  expansion_reviewer: string | null
  expansion_review_sig: string | null
  assurance_class: AssuranceClass
}

// ── Outcome Record ──
export interface OutcomePerspective {
  reporter: string
  observed_outcome: string
  outcome_class: OutcomeClass
  divergence_score: number
  signature: string
  reported_at: string
}

export interface OutcomeRecord {
  id: string
  action_id: string
  agent_id: string
  declared_intent: string
  semantic_uncertainty: SemanticUncertainty
  agent_report: OutcomePerspective
  principal_report: OutcomePerspective | null
  adjudicated_report: OutcomePerspective | null
  consensus: boolean
  policy_context: PolicyContext
  assurance_class: AssuranceClass
}

// ── Artifact Provenance ──
export interface ArtifactProvenance {
  artifact_id: string
  authoring_agent: string
  authority_scope: V2ScopeDefinition
  delegation_ref: string
  intended_use: string
  risk_class: RiskClass
  requires_human_execution: boolean
  content_hash: string
  content_size: number
  artifact_type: string
  policy_context: PolicyContext
  signature: string
  assurance_class: AssuranceClass
}

// ── Emergency Pathway ──
export interface Condition {
  field: string
  operator: 'eq' | 'neq' | 'gt' | 'lt' | 'gte' | 'lte' | 'contains' | 'matches'
  value: string | number | boolean
}
export interface ConditionSet {
  all_of?: Condition[]
  any_of?: Condition[]
}

// ── Anomaly Detection ──
export interface ActionRecord {
  action_id: string
  agent_id: string
  authority_level: number
  semantic_uncertainty: SemanticUncertainty
  risk_class: RiskClass
  delegation_ref: string
  was_delegated: boolean
  complexity: number
  timestamp: string
}

export interface AnomalyFlag {
  id: string
  agent_id: string
  anomaly_type: AnomalyType
  action_id: string
  description: string
  review_mode: ReviewMode
  reviewed: boolean
  review_outcome: string | null
  created_at: string
  assurance_class: AssuranceClass
}

export interface ConcentrationMetrics {
  agent_id: string
  tasks_retained_ratio: number
  scope_utilization_breadth: number
  delegation_refusal_count: number
  single_agent_workflow_pct: number
  concentration_risk: number
  flagged: boolean
  computed_at: string
}

// ── Contextual Attestation ──
export interface AlternativeRejected {
  alternative: string
  reason: string
}

export interface ContextualAttestation {
  id: string
  action_id: string
  agent_id: string
  delegation_ref: string
  context_understanding: string
  factors_considered: string[]
  alternatives_rejected: AlternativeRejected[]
  expected_outcome: string
  confidence: number
  semantic_uncertainty: SemanticUncertainty
  required: boolean
  policy_context: PolicyContext
  signature: string
  assurance_class: AssuranceClass
  created_at: string
}

// ── Reputation ──
export interface TrustTier {
  tier: number
  name: string
  min_effective_reputation: number
}

export interface DecayConfig {
  default_decay_factor: number
  domain_decay_overrides: Record<string, number>
  policy_version: string
}
