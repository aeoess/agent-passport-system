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
