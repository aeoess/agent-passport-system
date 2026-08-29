// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Governance Artifact Provenance — Types
// Module 21: Sign, version, and verify governance artifacts (floor.yaml, policies, configs)
// Gap 8B: Monotonic governance — weakening requires higher approval thresholds

// Change classification for governance updates
// Monotonic governance: strengthening is normal, weakening requires escalation
export type GovernanceChangeType = 'strengthening' | 'neutral' | 'weakening' | 'mixed' | 'initial'

// Diff result from comparing two governance artifacts
export interface GovernanceDiff {
  changeType: GovernanceChangeType
  additions: string[]       // new items added
  modifications: string[]   // changed items
  removals: string[]        // items removed (governance weakening)
  isWeakening: boolean      // true if any removals or enforcement downgrades
  isStrengthening: boolean  // true if only additions or enforcement upgrades
}

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
  // Gap 8B: Change classification — monotonic governance
  changeType: GovernanceChangeType   // how this version relates to previous
  additions: string[]                // new principles/rules added
  modifications: string[]            // changed principles/rules
  removals: string[]                 // removed principles/rules (triggers higher threshold)
  credentialLifecycle?: CredentialLifecyclePolicy  // #1717: session/TTL/revocation policy
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
  weakeningApproved: boolean   // weakening changes have sufficient approvals
}

/** Wildcard entry for GovernanceLoadPolicy.allowedIssuers: accept an
 *  artifact from any issuer. Spelled out so that a policy which trusts
 *  everyone says so, and an empty allowlist can mean what it looks like. */
export const ANY_ISSUER = '*'

export interface GovernanceLoadPolicy {
  requireSignature: boolean        // reject unsigned artifacts
  requireApprovals: number         // min approval count (0 = no requirement)
  /** Issuer public keys this policy accepts. `['*']` (ANY_ISSUER) accepts
   *  any issuer; an EMPTY list accepts none and rejects every artifact.
   *  An empty list used to skip the check entirely, which made "no
   *  anchors" and "all anchors" the same input. */
  allowedIssuers: string[]
  allowExpired: boolean            // default false
  allowBreakingWithoutApproval: boolean  // default false
  // Gap 8B: Differential thresholds for governance weakening
  requireApprovalsForWeakening: number   // min approvals for weakening changes (default: 1)
  requireApprovalsForRemoval: number     // min approvals for removals (default: 2)
  blockWeakeningWithoutApproval: boolean // hard-block weakening with 0 approvals (default: true)
}

export const DEFAULT_LOAD_POLICY: GovernanceLoadPolicy = {
  requireSignature: true,
  requireApprovals: 0,
  // The shipped default has always accepted any issuer. It now says so
  // instead of expressing it as an empty allowlist.
  allowedIssuers: [ANY_ISSUER],
  allowExpired: false,
  allowBreakingWithoutApproval: false,
  requireApprovalsForWeakening: 1,
  requireApprovalsForRemoval: 2,
  blockWeakeningWithoutApproval: true,
}

// ── Credential Lifecycle Policy (#1717) ──

export interface CredentialLifecyclePolicy {
  /** Maximum session duration in seconds before re-authentication required */
  maxSessionDurationSeconds: number
  /** Optional URL for real-time revocation checks */
  revocationEndpoint?: string
  /** Credential time-to-live in seconds from issuance */
  credentialTTLSeconds: number
  /** How often (seconds) to poll revocation endpoint */
  revocationCheckFrequencySeconds: number
}
