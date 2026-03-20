// Data Source Registration & Access Receipts — Types (Module 36A)
// Foundation layer for data contribution tracking.
// Access is not contribution, and contribution is not value.
// This module specifies only source identity, source terms,
// and gateway-signed proof of access.
//
// Reviewed through 10-round multi-model hostile convergence.
// Spec: ~/aeoess_web/specs/BUILD-SPEC-MODULE-36A.md

// ── Source Attestation Modes ──
// Trust ordering: self_attested > custodian_attested > gateway_observed

export type SourceMode =
  | 'self_attested'        // owner signs directly (trust: high)
  | 'custodian_attested'   // platform signs on behalf (trust: medium)
  | 'gateway_observed'     // gateway records, no upstream sig (trust: low)

export type DataContentType =
  | 'document'         // file, PDF, webpage, article
  | 'structured_data'  // API response, database result, JSON/CSV
  | 'media'            // image, audio, video
  | 'user_input'       // direct human input in conversation
  | 'model_context'    // system prompt, conversation history
  | 'embedding'        // vector representation of source data
  | 'aggregate'        // derived from multiple sources (inherits terms)

// ── Data Purpose (constrained vocabulary, not free-form) ──

export type DataPurpose =
  | 'read' | 'analyze' | 'summarize' | 'generate'
  | 'recommend' | 'train' | 'embed' | 'redistribute' | 'commercial'

// ── Compensation Model ──

export type CompensationModel =
  | { type: 'none' }
  | { type: 'attribution_only' }
  | { type: 'per_access'; amount: number; currency: string }
  | { type: 'revenue_share'; percentage: number }
  | { type: 'pool'; poolId: string }
  | { type: 'negotiate'; contact: string }

// ── Derivative Policy ──

export type DerivativePolicy =
  | 'unrestricted'
  | 'same_terms'
  | 'attribution_required'
  | 'no_derivatives'

// ── Audit Visibility ──

export type AuditVisibility =
  | 'source_only'
  | 'source_and_principal'
  | 'source_principal_auditor'
  | 'public'

// ── Data Terms ──
// Monotonic narrowing: when multiple sources in an execution frame,
// effective terms = intersection of allowed, union of excluded.
// Terms snapshot at access time governs. Source changes later don't affect historical receipts.

export interface DataTerms {
  allowedPurposes: DataPurpose[]
  excludedPurposes?: DataPurpose[]      // overrides allowed
  excludedAgents?: string[]
  excludedPrincipals?: string[]
  requiredTrustLevel?: number           // min agent reputation (0-100)
  requireAttribution: boolean
  requireNotification: boolean
  compensation: CompensationModel
  maxAccessCount?: number               // per-gateway in v1
  retentionLimit?: string               // ISO 8601 duration
  expiresAt?: string
  derivativePolicy: DerivativePolicy
  auditVisibility: AuditVisibility
  revocable: boolean
}

// ── Source Receipt ──
// Establishes: who the data is, who speaks for it, what terms govern use.

export interface SourceReceipt {
  sourceReceiptId: string              // 'srcr_' + uuid
  sourceMode: SourceMode
  // For self_attested: owner's ID. For custodian: owner's ID.
  // For gateway_observed: null (owner unknown).
  sourcePrincipalId: string | null
  signerPublicKey: string              // who actually signed this receipt
  contentCommitment: string            // SHA-256 of data at registration time
  contentType: DataContentType
  contentDescriptor: string            // human-readable, not the data itself
  dataTerms: DataTerms
  issuedAt: string
  issuedBy: string                     // public key of signer
  expiresAt?: string
  revokedAt?: string
  revocationReason?: string
  signature: string                    // Ed25519 by issuedBy
}

// ── Access Method ──

export type AccessMethod =
  | 'api_call' | 'file_read' | 'database_query' | 'web_fetch'
  | 'memory_retrieval' | 'embedding_lookup' | 'stream' | 'human_provided'

// ── Data Access Receipt ──
// Pure evidence. No interpretation. No contribution score.
// Gateway attests: "this agent read this data at this time."

export interface DataAccessReceipt {
  accessReceiptId: string              // 'dacr_' + uuid
  sourceReceiptId: string
  sourceMode: SourceMode               // inherited for quick trust assessment
  dataHash: string                     // SHA-256 of actual data accessed
  agentId: string
  agentPublicKey: string
  delegationId?: string
  principalId: string                  // human at root of delegation chain
  executionFrameId: string
  accessScope: string
  accessMethod: AccessMethod
  declaredPurpose: DataPurpose         // advisory — agent's declared intent
  termsAtAccessTime: DataTerms         // frozen snapshot
  timestamp: string
  gatewayId: string
  gatewayPublicKey: string
  gatewaySignature: string             // gateway signs, NOT the agent
}

// ── Terms Compliance Result ──
// Hard violations = deterministic, can block access.
// Advisory warnings = declared-intent, audit trail only.

export interface TermsComplianceResult {
  compliant: boolean                   // true only if zero hard violations
  hardViolations: string[]             // revocation, expiry, excluded agent/principal, rate limit
  advisoryWarnings: string[]           // purpose mismatch (self-declared, not verifiable)
  accessesRemaining?: number           // maxAccessCount - currentCount
}

// ── Verification Results ──

export interface SourceReceiptVerification {
  valid: boolean
  errors: string[]
  signatureValid: boolean
  termsValid: boolean
  notExpired: boolean
  notRevoked: boolean
  trustLevel: 'high' | 'medium' | 'low'
}

export interface AccessReceiptVerification {
  valid: boolean
  errors: string[]
  gatewaySignatureValid: boolean
  sourceReceiptExists: boolean
  temporalValid: boolean
}
