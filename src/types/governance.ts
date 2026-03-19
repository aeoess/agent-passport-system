// Governance Artifact Provenance — Types
// Module 21: Sign, version, and verify governance artifacts (floor.yaml, policies, configs)

export interface GovernanceArtifact {
  artifactId: string
  artifactType: 'floor' | 'policy' | 'config' | 'delegation-template' | 'custom'
  version: string                    // semver: "1.0.0"
  previousVersion: string | null     // null for initial version
  previousArtifactId: string | null  // forms a version chain
  contentHash: string                // sha256 of raw content
  content: string                    // the actual artifact content
  issuer: string                     // public key of the author
  effectiveFrom: string              // ISO timestamp
  expiresAt: string | null           // null = no expiry
  breaking: boolean                  // requires re-attestation?
  supersedes: string | null          // artifactId this replaces
  rollbackAllowed: boolean
  metadata: Record<string, unknown>  // extensible
  createdAt: string
  signature: string                  // Ed25519 over canonical form (excludes signature + content)
}

export interface GovernanceEnvelope {
  artifact: GovernanceArtifact
  approvals: GovernanceApproval[]    // multi-party approval chain
}

export interface GovernanceApproval {
  approver: string       // public key
  approvedAt: string     // ISO timestamp
  artifactId: string     // what was approved
  contentHash: string    // hash at time of approval
  signature: string      // Ed25519 over canonical approval payload
}

export interface GovernanceVerification {
  valid: boolean
  errors: string[]
  contentIntegrity: boolean    // hash matches content
  signatureValid: boolean      // issuer signature valid
  chainValid: boolean          // version chain is consistent
  notExpired: boolean
  approvalsValid: boolean      // all approval signatures valid
}

export interface GovernanceLoadPolicy {
  requireSignature: boolean        // reject unsigned artifacts
  requireApprovals: number         // min approval count (0 = no requirement)
  allowedIssuers: string[]         // empty = any issuer
  allowExpired: boolean            // default false
  allowBreakingWithoutApproval: boolean  // default false
}

export const DEFAULT_LOAD_POLICY: GovernanceLoadPolicy = {
  requireSignature: true,
  requireApprovals: 0,
  allowedIssuers: [],
  allowExpired: false,
  allowBreakingWithoutApproval: false,
}
