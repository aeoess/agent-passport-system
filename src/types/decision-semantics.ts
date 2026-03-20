// ══════════════════════════════════════════════════════════════════
// Module 37: Decision Semantics & Cross-Engine Interop
// ══════════════════════════════════════════════════════════════════
// Types for content-addressable decisions, evaluation method
// classification, scope interpretation declaration, and
// cross-engine decision artifacts.
//
// Motivated by cross-engine verification work (kanoniv/agent-auth#2):
// four engines evaluating the same scenario produced identical
// structural verdicts but divergent trust verdicts. These types
// formalize the decomposition.
// ══════════════════════════════════════════════════════════════════

import type { ActionIntent, PolicyDecision, PolicyVerdict } from './policy.js'
import type { EvaluationMethod } from './execution-envelope.js'

// Re-export so consumers can get it from either place
export type { EvaluationMethod } from './execution-envelope.js'

// ── Scope Interpretation ──
// Declares how an engine resolves scope membership.
// Exact: literal string equality (data:read ≠ data:*)
// Glob: wildcard expansion (data:* covers data:read)
// Hierarchical: parent:child nesting (data covers data:read)

export type ScopeInterpretation = 'exact' | 'glob' | 'hierarchical'

// ── Evaluation Method ──
// Re-exported from execution-envelope.ts (unified type).
// Values: 'deterministic' | 'probabilistic' | 'model_dependent' | 'hybrid'

// ── Content Hash ──
// Algorithm used for content-addressable hashing of decision artifacts.
// SHA-256 of canonical JSON (unsigned fields only).

export type ContentHashAlgorithm = 'sha256'

export interface ContentHash {
  algorithm: ContentHashAlgorithm
  hash: string              // hex-encoded hash
  canonicalForm: string     // serialization method used (e.g. 'canonical_json_sorted_keys')
}

// ── Decision Semantics ──
// Decomposition of a verdict into structural and trust components.
// Captures the divergence patterns observed across engines.

export interface DecisionSemantics {
  structuralVerdict: PolicyVerdict     // scope/delegation/expiry checks
  trustVerdict: PolicyVerdict | null   // reputation/behavioral checks (null if no trust layer)
  override?: {
    active: boolean
    phase: string                      // mechanism name (e.g. 'threshold_cutoff', 'divergence_alert')
    wouldHaveBeen: PolicyVerdict       // what the verdict would be without the override
  }
  finalVerdictRule: string             // e.g. 'structural AND trust'
  reproducibility: string             // e.g. 'structural_by_any_engine, trust_by_originating_engine_only'
}

// ── Decision Artifact ──
// Cross-engine artifact that bundles an intent, its evaluation,
// and semantic decomposition into a single verifiable object.
// Designed for the cross-engine verification matrix.

export interface DecisionArtifact {
  artifactId: string
  artifactType: 'decision'
  version: string                     // artifact format version
  engine: string                      // producing engine identifier
  timestamp: string

  // The decision itself (pre-execution)
  intent: {
    intentId: string
    agentId: string
    action: {
      type: string
      target: string
      scopeRequired: string
    }
    contentHash: ContentHash          // content-addressable reference
  }

  // How it was evaluated
  evaluation: {
    verdict: PolicyVerdict
    evaluationMethod: EvaluationMethod
    principlesChecked: string[]       // principle IDs evaluated
    evaluatorId: string
    decisionId: string
  }

  // Semantic decomposition for cross-engine comparison
  semantics: DecisionSemantics

  // Cryptographic proof
  proof: {
    intentSignature: string
    decisionSignature: string
    artifactSignature: string         // signature over the entire artifact
  }
}

// ── Verification Result ──

export interface DecisionArtifactVerification {
  valid: boolean
  contentHashValid: boolean
  intentSignatureValid: boolean
  decisionSignatureValid: boolean
  artifactSignatureValid: boolean
  errors: string[]
}
