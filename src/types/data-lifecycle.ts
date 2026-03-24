// ══════════════════════════════════════════════════════════════════
// Data Lifecycle Governance — Types
// ══════════════════════════════════════════════════════════════════
// Consilium decision (6 model reviews, 2026-03-24):
//   Phase 1: Extended derivation, revocation obligations,
//            decision lineage, purpose taxonomy
//   "Evolve from access control into lifecycle governance"
// ══════════════════════════════════════════════════════════════════

// ── Transform Class Taxonomy ──
// What happened between source and derivative.
// Open enum — canonical values + extensible.

export type TransformClass =
  | 'copy'
  | 'subset'
  | 'summary'
  | 'embedding'
  | 'aggregation'
  | 'synthetic'
  | 'model_training'
  | 'fine_tune'
  | 'rag_index'
  | 'decision_artifact'
  | 'redacted'
  | string  // extensible

// ── Lineage Confidence ──
// How complete is the provenance chain?
// "An honest break marker is better than fake continuity"

export type LineageConfidence =
  | 'complete'           // full chain verified end-to-end
  | 'partial'            // some hops verified, gaps exist
  | 'asserted'           // chain declared by agent, not independently verified
  | 'inferred'           // reconstructed from indirect evidence
  | 'broken_external'    // chain crosses external system boundary
  | 'unverifiable'       // no provenance available

// ── Extended Derivation Receipt ──

export interface DerivationReceipt {
  receiptId: string
  timestamp: string
  // What was produced
  derivativeId: string
  derivativeType: string
  // What it came from (multiple parents allowed)
  parentArtifacts: ParentArtifact[]
  // How it was transformed
  transformClass: TransformClass
  // Lineage quality
  lineageConfidence: LineageConfidence
  externalBoundaryBreak: boolean
  breakReason?: string
  // Rights propagation
  upstreamObligationsRetained: boolean
  retainedObligationIds?: string[]
  // Synthetic provenance
  isSyntheticDerivative: boolean
  // Who created this derivation
  agentId: string
  delegationId?: string
  signature: string
}

export interface ParentArtifact {
  artifactId: string
  artifactType: 'access_receipt' | 'derivation_receipt' | 'training_receipt' | 'decision_artifact' | 'source_registration' | string
  sourceId?: string
  transformFromParent?: TransformClass
}

// ── Post-Revocation Obligation State ──
// Not deletion — obligation classification.
// Different artifact types have different erasure physics.

export type PostRevocationObligation =
  | 'none'
  | 'no_future_use'
  | 'delete_if_cached'
  | 'quarantine'
  | 'retraining_required'
  | 'compensation_only'
  | 'immutable_ledger_exempt'
  | 'contested'

export interface RevocationObligation {
  obligationId: string
  sourceId: string
  revokedAt: string
  // Which downstream artifacts are affected
  affectedArtifacts: AffectedArtifact[]
  // Summary
  totalAffected: number
  obligationsByType: Record<string, PostRevocationObligation>
  signature: string
}

export interface AffectedArtifact {
  artifactId: string
  artifactType: string
  obligation: PostRevocationObligation
  reason: string
  derivationDepth: number
}

// ── Decision Lineage Receipt ──
// Bridges Module 37 (decision artifacts) to data modules (38-42).
// "What data influenced this decision?"

export interface DecisionLineageReceipt {
  receiptId: string
  timestamp: string
  // The decision
  decisionArtifactId: string
  decisionType: string
  // Contributing data sources
  contributingSources: ContributingSource[]
  // Lineage quality
  lineageCompleteness: LineageConfidence
  externalHopsPresent: boolean
  // Transform chain summary
  transformChain: TransformClass[]
  // Governance context
  governingPurpose?: string
  jurisdictionContext?: string
  // Human-readable
  explanation?: string
  signature: string
}

export interface ContributingSource {
  sourceId: string
  accessReceiptId: string
  derivationDepth: number
  transformPath: TransformClass[]
  termsVersionAtAccess: string
  lineageConfidence: LineageConfidence
  compensationStatus: 'settled' | 'pending' | 'disputed' | 'revoked'
}

// ── Hierarchical Purpose Taxonomy ──
// Replaces freeform strings with structured, wildcard-matchable purposes.

export type StandardPurpose =
  | 'research:academic'
  | 'research:commercial'
  | 'training:model'
  | 'training:fine_tune'
  | 'training:embedding'
  | 'training:rag'
  | 'inference:routing'
  | 'inference:decision_support'
  | 'analytics:internal'
  | 'analytics:commercial'
  | 'moderation'
  | 'commerce'
  | string  // extensible

// ── Retention TTL ──
// How long accessed data can be held.
// Prevents indefinite caching after a single access receipt.

export interface RetentionPolicy {
  /** Max retention in milliseconds. null = no limit */
  maxRetentionMs: number | null
  /** What happens when retention expires */
  onExpiry: 'delete' | 'quarantine' | 'renegotiate'
  /** Access type distinctions */
  ephemeralAccessMs?: number   // context window only (e.g. 3600000 = 1 hour)
  persistentAccessMs?: number  // RAG/vector store (e.g. 2592000000 = 30 days)
}

// ── Terms Version Pin ──
// Freezes terms at moment of access for settlement consistency.

export interface TermsVersionPin {
  termsVersion: string
  pinnedAt: string
  compensationRate: number
  currency: string
  allowedPurposes: string[]
  retentionPolicy?: RetentionPolicy
}


// ══════════════════════════════════════════════════════════════════
// Phase 2: Aggregation, Jurisdiction, Governance Taint,
//          Dispute State, Combination Constraints
// ══════════════════════════════════════════════════════════════════

// ── Aggregation Controls ──
// Per-access gates are not enough. Bulk extraction is a real abuse pattern.

export interface AggregateConstraint {
  /** Max accesses per rolling window */
  maxAccessesPerWindow?: number
  /** Window duration in milliseconds */
  windowMs?: number
  /** Max distinct records per window */
  maxRecordsPerWindow?: number
  /** Burst limit (max in any 1-second interval) */
  burstLimit?: number
}

export interface AggregateAccessLog {
  sourceId: string
  agentId: string
  windowStartMs: number
  accessCount: number
  recordCount: number
  lastAccessMs: number
}

// ── Jurisdiction Envelope ──
// Legal context that travels with data. Not a law firm — a context carrier.

export interface JurisdictionEnvelope {
  /** Source data jurisdiction (ISO 3166-1 alpha-2) */
  sourceJurisdiction?: string
  /** Processing restrictions (e.g. 'EU_ONLY', 'NO_CROSS_BORDER') */
  processingRestrictions?: string[]
  /** Whether jurisdiction must propagate to derivatives */
  propagationRequired?: boolean
  /** Transfer constraints (e.g. 'GDPR_ADEQUATE_ONLY') */
  transferConstraints?: string[]
}

// ── Governance Taint / Contamination State ──
// Once a system touches restricted data, how does that propagate?
// Not about derivation (object-level) — about operational contamination.

export type GovernanceTaint =
  | 'clean'                    // no restricted data contact
  | 'source_bound'             // touched restricted data, obligations known
  | 'mixed'                    // touched multiple sources with different restrictions
  | 'restricted'               // under active restriction from revocation or terms
  | 'quarantined'              // flagged for review, access suspended
  | 'untraceable_contamination' // may have been contaminated but chain is broken

export interface TaintRecord {
  artifactId: string
  taintLevel: GovernanceTaint
  sources: string[]
  reason: string
  detectedAt: string
  /** Can this taint be cleared? */
  clearable: boolean
  clearCondition?: string
}

// ── Dispute / Contested State ──
// Reality produces conflicts. The protocol needs structured ambiguity.

export type DisputeStatus =
  | 'undisputed'
  | 'contested_by_source'      // source claims unauthorized use
  | 'contested_by_agent'       // agent claims terms were different
  | 'contested_by_principal'   // principal disputes delegation scope
  | 'under_review'             // dispute filed, awaiting resolution
  | 'resolved_in_favor_source'
  | 'resolved_in_favor_agent'
  | 'escalated_external'       // sent to external arbitration/legal

export interface DisputeRecord {
  disputeId: string
  artifactId: string
  disputeType: 'unauthorized_access' | 'terms_violation' | 'compensation_dispute' | 'revocation_dispute' | 'lineage_dispute'
  status: DisputeStatus
  filedBy: string
  filedAt: string
  evidence: string[]
  resolution?: string
  resolvedAt?: string
  signature: string
}

// ── Combination Constraints / Forbidden Joins ──
// Some data must NOT be combined with other data.
// Not competitive exclusion — prohibited inference prevention.
// e.g. health + geolocation, children + behavioral advertising

export interface CombinationConstraint {
  /** This source cannot be combined with sources of these classes */
  forbiddenSourceClasses?: string[]
  /** This source cannot be combined with specific source IDs */
  forbiddenSourceIds?: string[]
  /** Reason for the constraint */
  reason: string
  /** Regulatory basis (e.g. 'COPPA', 'HIPAA', 'GDPR_Art9') */
  regulatoryBasis?: string
}

// ── Access Snapshot (anti-rug-pull) ──
// Immutable record of exact terms + state at moment of access.
// Prevents retroactive term changes from holding downstream models hostage.

export interface AccessSnapshot {
  snapshotId: string
  accessReceiptId: string
  sourceId: string
  /** Exact terms hash at moment of access */
  termsHash: string
  /** Pinned terms (full copy) */
  pinnedTerms: TermsVersionPin
  /** Jurisdiction at access time */
  jurisdiction?: JurisdictionEnvelope
  /** Combination constraints active at access time */
  combinationConstraints?: CombinationConstraint[]
  timestamp: string
  signature: string
}


// ══════════════════════════════════════════════════════════════════
// Final Gaps: Rights Propagation, Purpose Drift, Re-identification
// ══════════════════════════════════════════════════════════════════

// ── Rights Propagation Semantics ──
// When an artifact is derived, what happens to upstream rights?
// Not just a boolean — a typed propagation rule.

export type RightsPropagation =
  | 'inherit_full'            // all upstream rights carry forward
  | 'inherit_partial'         // some rights carry, specified in retainedRights
  | 'inherit_by_class'        // rights depend on transform class
  | 'extinguished'            // upstream rights do not propagate
  | 'compensation_only'       // no usage rights, only compensation obligation
  | 'attribution_only'        // must credit source, no other obligation
  | 'explanation_only'        // must include in decision lineage, no other obligation

export interface RightsPropagationRule {
  /** How rights propagate by default */
  defaultPropagation: RightsPropagation
  /** Override by transform class (e.g. 'synthetic' → 'compensation_only') */
  byTransformClass?: Record<string, RightsPropagation>
  /** Specific rights retained when propagation is partial */
  retainedRights?: string[]
  /** Source-defined: what the source owner requires */
  sourceRequirement?: string
}

// ── Purpose Drift Detection ──
// Data accessed for one purpose drifts through workflows into another.
// No single hop looks wrong. The aggregate drifts.

export interface PurposeDriftCheck {
  originalPurpose: string
  currentPurpose: string
  driftDetected: boolean
  driftPath: string[]
  severity: 'none' | 'minor' | 'major' | 'violation'
  explanation: string
}

// ── Re-identification Risk Declaration ──
// Transformed/synthetic data may still leak recoverable source identity.
// "Synthetic" is not a clean safety state.

export type ReidentificationRisk =
  | 'none_declared'           // no known risk
  | 'low'                     // statistical methods unlikely to recover source
  | 'medium'                  // linkage attacks possible with auxiliary data
  | 'high'                    // direct identifiers may be recoverable
  | 'unknown'                 // risk not assessed
  | 'mitigated'               // risk assessed and mitigations applied

export interface ReidentificationDeclaration {
  risk: ReidentificationRisk
  assessmentMethod?: string
  mitigationsApplied?: string[]
  assessedAt: string
  assessedBy: string
}
