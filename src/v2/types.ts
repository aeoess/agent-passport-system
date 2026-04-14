// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
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
  /** HumanEscalationFlag: per-action-class owner-confirmation requirements. */
  escalation_requirements?: EscalationRequirement[]
}

// ── HumanEscalationFlag ──
export type ConfirmationScope = 'per_action' | 'per_session' | 'time_window'

export interface EscalationRequirement {
  action_class: string
  requires_owner_confirmation: boolean
  /** TTL of a recorded confirmation, in milliseconds. */
  confirmation_ttl_ms: number
  confirmation_scope: ConfirmationScope
}

export interface ConfirmationRequest {
  id: string
  delegation_id: string
  action_class: string
  action_details_hash: string
  confirmation_scope: ConfirmationScope
  session_id: string | null
  confirmation_ttl_ms: number
  created_at: string
}

export interface OwnerConfirmation {
  id: string
  request_id: string
  delegation_id: string
  action_class: string
  action_details_hash: string
  confirmation_scope: ConfirmationScope
  session_id: string | null
  confirmed_by: string
  confirmed_at: string
  expires_at: string
  signature: string
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

// ── Behavioral Evidence (Issue #9 wire-up) ──
export interface BehavioralEvidenceMetadata {
  evaluationContextHash: string
  aggregateScore: number
  classification: 'hold' | 'bend' | 'break'
  confidence: number
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
  behavioralEvidence?: BehavioralEvidenceMetadata
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


// ── Migration ──
export interface MigrationRequest {
  id: string
  source_agent: string
  source_delegation: string
  limitation: string
  requested_scope_change: string
  justification: string
  agent_signature: string
  policy_context: PolicyContext
  status: 'pending' | 'approved' | 'denied'
  approver_response: string | null
  approver_signature: string | null
  created_at: string
}

export interface MigrationRecord {
  id: string
  source_agent: string
  source_delegation: string
  target_agent: string
  target_delegation: string
  state_hash: string
  state_size: number
  reputation_inheritance: ReputationInheritance
  migration_factor: number
  probation_duration: string
  probation_ends_at: string
  probation_active: boolean
  justification: string
  request_ref: string
  approver: string
  approver_signature: string
  source_signature: string
  target_signature: string
  policy_context: PolicyContext
  assurance_class: AssuranceClass
  created_at: string
  status: 'active' | 'probation_complete' | 'rolled_back'
}

// ── Attestation Quality ──
export interface AttestationQuality {
  has_context: boolean
  has_factors: boolean
  has_alternatives: boolean
  confidence_calibrated: boolean
  quality_score: number
}


// ── Bureaucratic DDoS / Approval Fatigue ──
export type ApprovalDecision = 'approved' | 'denied' | 'deferred' | 'escalated'

export interface ApprovalRecord {
  id: string
  principal_id: string
  agent_id: string
  intent_id: string
  decision: ApprovalDecision
  decision_latency_ms: number
  intent_complexity: number // 0-1, how complex the intent is
  risk_class: RiskClass
  timestamp: string
}

export interface FatigueMetrics {
  principal_id: string
  window_size: number // number of recent decisions analyzed
  approval_rate: number // 0-1
  avg_decision_latency_ms: number
  min_decision_latency_ms: number
  decisions_per_hour: number
  trivial_before_critical_count: number // trivial approvals immediately before a critical one
  rubber_stamp_score: number // 0-1 composite
  flagged: boolean
  computed_at: string
}

export type FatigueAnomalyType =
  | 'rubber_stamping' // approval rate > threshold + fast decisions
  | 'velocity_spike' // sudden increase in approval volume
  | 'complexity_masking' // trivial intents clustered before critical ones
  | 'latency_impossible' // decisions faster than human reading speed


// ── Authorization-Effect Gap ──
export interface EffectDeclaration {
  id: string
  intent_id: string
  agent_id: string
  expected_effects: string[]
  acceptable_divergence: number // 0-1 threshold
  verification_method: 'self_report' | 'principal_report' | 'oracle' | 'automated'
  policy_context: PolicyContext
  signature: string
  created_at: string
}

export interface EffectVerification {
  id: string
  declaration_id: string
  intent_id: string
  agent_id: string
  actual_effects: string[]
  matched_effects: string[]
  unmatched_declared: string[] // declared but didn't happen
  undeclared_actual: string[] // happened but wasn't declared
  divergence_score: number // 0-1
  verdict: 'within_tolerance' | 'divergent' | 'blocked'
  verifier: string
  signature: string
  created_at: string
}

export interface EffectPattern {
  agent_id: string
  pattern_type: 'systematic_underdeclare' | 'systematic_side_effect' | 'selective_omission'
  frequency: number
  examples: string[]
  first_seen: string
  last_seen: string
}


// ── Emergence / Aggregate Governance ──
export interface AgentActionSummary {
  agent_id: string
  action_category: string
  count: number
  period: string
}

export interface SystemMetrics {
  id: string
  diversity_index: number // Shannon entropy of action distribution across agents
  resource_velocity: number // rate of resource consumption across all agents
  convergence_score: number // how similar agent behaviors are (0=diverse, 1=monoculture)
  top_action_concentration: number // % of all actions from top action category
  top_agent_concentration: number // % of all actions from top agent
  agent_count: number
  action_count: number
  computed_at: string
}

export type EmergencePatternType =
  | 'epistemic_monoculture' // agents converging on identical behaviors
  | 'resource_depletion' // aggregate resource consumption unsustainable
  | 'market_concentration' // few agents dominating action space
  | 'cascade_correlation' // failures in one agent predict failures in others
  | 'consent_gap' // aggregate outcome no principal individually authorized

export interface EmergenceFlag {
  id: string
  pattern_type: EmergencePatternType
  severity: RiskClass
  description: string
  affected_agents: string[]
  metrics_snapshot: SystemMetrics
  recommended_action: string
  reviewed: boolean
  review_outcome: string | null
  created_at: string
}

// ── Root Authority Transition ──
export type GovernancePhase = 'founding' | 'operational' | 'transitional' | 'democratic'

export interface AuthorityTransitionPlan {
  id: string
  current_phase: GovernancePhase
  target_phase: GovernancePhase
  conditions: ConditionSet
  required_signers: string[] // agents/principals who must approve
  minimum_agent_count: number // quorum for democratic phase
  transition_justification: string
  sunset_root_after_transition: boolean
  created_at: string
  status: 'proposed' | 'approved' | 'executing' | 'completed' | 'aborted'
}


// ── Semantic Compliance / Intent Subversion ──
export interface SemanticIntentRecord {
  id: string
  agent_id: string
  intent_id: string
  declared_purpose: string     // what the agent said it would do
  declared_keywords: string[]  // extracted semantic markers
  action_description: string   // what the agent actually did
  action_keywords: string[]    // extracted semantic markers from action
  scope_ref: string            // delegation scope that authorized it
  timestamp: string
}

export interface SemanticDriftResult {
  intent_id: string
  agent_id: string
  keyword_overlap: number      // 0-1 Jaccard similarity of keyword sets
  purpose_action_similarity: number // 0-1 word overlap between purpose and action
  drift_score: number          // 0-1 composite (higher = more drift)
  verdict: 'aligned' | 'drifted' | 'subverted'
  mismatched_keywords: string[] // action keywords absent from intent
}

// ── Authority Laundering / Composite Workflow Audit ──
export interface PipelineAction {
  id: string
  agent_id: string
  delegation_scope: string[]
  action_category: string
  input_from: string | null    // agent_id that provided input, null if original
  output_to: string | null     // agent_id receiving output, null if terminal
  timestamp: string
}

export interface CompositeCapability {
  pipeline_id: string
  agents: string[]
  individual_scopes: Record<string, string[]>  // agent → their scope
  composite_capabilities: string[]  // union of all scopes in pipeline
  unauthorized_composites: string[] // capabilities achieved by composition that no single agent holds
  flagged: boolean
  description: string
  created_at: string
}
