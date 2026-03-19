// Governance Artifact Provenance — Module 21
// Sign, version, and verify governance artifacts
// Treats governance files as supply-chain artifacts, not config files

import { v4 as uuidv4 } from 'uuid'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import { createHash } from 'crypto'
import type {
  GovernanceArtifact, GovernanceApproval, GovernanceVerification,
  GovernanceEnvelope, GovernanceLoadPolicy, DEFAULT_LOAD_POLICY
} from '../types/governance.js'

export { DEFAULT_LOAD_POLICY } from '../types/governance.js'

// ══════════════════════════════════════
// CONTENT HASHING
// ══════════════════════════════════════

export function hashContent(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex')
}

// ══════════════════════════════════════
// CREATE GOVERNANCE ARTIFACT
// ══════════════════════════════════════

export interface CreateArtifactOptions {
  artifactType: GovernanceArtifact['artifactType']
  version: string
  content: string
  issuerPrivateKey: string
  issuerPublicKey: string
  effectiveFrom?: string        // defaults to now
  expiresAt?: string | null
  breaking?: boolean
  previousVersion?: string | null
  previousArtifactId?: string | null
  supersedes?: string | null
  rollbackAllowed?: boolean
  metadata?: Record<string, unknown>
}

export function createGovernanceArtifact(opts: CreateArtifactOptions): GovernanceArtifact {
  const now = new Date().toISOString()
  const contentHash = hashContent(opts.content)

  const artifact: Omit<GovernanceArtifact, 'signature'> = {
    artifactId: 'gov_' + uuidv4().slice(0, 12),
    artifactType: opts.artifactType,
    version: opts.version,
    previousVersion: opts.previousVersion ?? null,
    previousArtifactId: opts.previousArtifactId ?? null,
    contentHash,
    content: opts.content,
    issuer: opts.issuerPublicKey,
    effectiveFrom: opts.effectiveFrom ?? now,
    expiresAt: opts.expiresAt ?? null,
    breaking: opts.breaking ?? false,
    supersedes: opts.supersedes ?? null,
    rollbackAllowed: opts.rollbackAllowed ?? true,
    metadata: opts.metadata ?? {},
    createdAt: now,
  }

  // Sign canonical form of everything EXCEPT content and signature
  // Content is verified via contentHash — keeps signatures stable for large artifacts
  const signable = { ...artifact } as Record<string, unknown>
  delete signable.content
  const canonical = canonicalize(signable)
  const signature = sign(canonical, opts.issuerPrivateKey)

  return { ...artifact, signature }
}

// ══════════════════════════════════════
// VERIFY GOVERNANCE ARTIFACT
// ══════════════════════════════════════

export function verifyGovernanceArtifact(
  artifact: GovernanceArtifact,
  previousArtifact?: GovernanceArtifact | null
): GovernanceVerification {
  const errors: string[] = []

  // 1. Content integrity — hash matches content
  const expectedHash = hashContent(artifact.content)
  const contentIntegrity = expectedHash === artifact.contentHash
  if (!contentIntegrity) errors.push('Content hash mismatch')

  // 2. Signature verification
  const { signature, content, ...signable } = artifact
  const canonical = canonicalize(signable)
  let signatureValid = false
  try {
    signatureValid = verify(canonical, signature, artifact.issuer)
  } catch { signatureValid = false }
  if (!signatureValid) errors.push('Invalid issuer signature')

  // 3. Expiry check
  const notExpired = !artifact.expiresAt || new Date(artifact.expiresAt) > new Date()
  if (!notExpired) errors.push('Artifact expired')

  // 4. Version chain consistency
  let chainValid = true
  if (previousArtifact) {
    if (artifact.previousArtifactId !== previousArtifact.artifactId) {
      chainValid = false
      errors.push('Previous artifact ID mismatch')
    }
    if (artifact.previousVersion !== previousArtifact.version) {
      chainValid = false
      errors.push('Previous version mismatch')
    }
    if (new Date(artifact.createdAt) < new Date(previousArtifact.createdAt)) {
      chainValid = false
      errors.push('New artifact predates previous version')
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    contentIntegrity,
    signatureValid,
    chainValid,
    notExpired,
    approvalsValid: true, // checked separately in envelope verification
  }
}

// ══════════════════════════════════════
// APPROVE ARTIFACT (multi-party)
// ══════════════════════════════════════

export function approveArtifact(
  artifact: GovernanceArtifact,
  approverPrivateKey: string,
  approverPublicKey: string
): GovernanceApproval {
  const payload = {
    approvedAt: new Date().toISOString(),
    approver: approverPublicKey,
    artifactId: artifact.artifactId,
    contentHash: artifact.contentHash,
  }
  const canonical = canonicalize(payload)
  const signature = sign(canonical, approverPrivateKey)

  return { ...payload, signature }
}

export function verifyApproval(
  approval: GovernanceApproval,
  artifact: GovernanceArtifact
): boolean {
  // Approval must reference the correct artifact and hash
  if (approval.artifactId !== artifact.artifactId) return false
  if (approval.contentHash !== artifact.contentHash) return false

  const { signature, ...payload } = approval
  const canonical = canonicalize(payload)
  try {
    return verify(canonical, signature, approval.approver)
  } catch { return false }
}

// ══════════════════════════════════════
// CREATE ENVELOPE (artifact + approvals)
// ══════════════════════════════════════

export function createGovernanceEnvelope(
  artifact: GovernanceArtifact,
  approvals: GovernanceApproval[] = []
): GovernanceEnvelope {
  return { artifact, approvals }
}

// ══════════════════════════════════════
// LOAD WITH POLICY ENFORCEMENT
// ══════════════════════════════════════

export function loadGovernanceArtifact(
  envelope: GovernanceEnvelope,
  policy: GovernanceLoadPolicy,
  previousArtifact?: GovernanceArtifact | null
): GovernanceVerification {
  const { artifact, approvals } = envelope
  const errors: string[] = []

  // 1. Verify the artifact itself
  const baseVerification = verifyGovernanceArtifact(artifact, previousArtifact)
  errors.push(...baseVerification.errors)

  // 2. Policy: require signature
  if (policy.requireSignature && !baseVerification.signatureValid) {
    errors.push('Policy requires valid signature')
  }

  // 3. Policy: allowed issuers
  if (policy.allowedIssuers.length > 0 && !policy.allowedIssuers.includes(artifact.issuer)) {
    errors.push(`Issuer ${artifact.issuer.slice(0, 16)}... not in allowed issuers list`)
  }

  // 4. Policy: expiry
  if (!policy.allowExpired && !baseVerification.notExpired) {
    errors.push('Policy rejects expired artifacts')
  }

  // 5. Policy: approvals
  let approvalsValid = true
  if (policy.requireApprovals > 0) {
    const validApprovals = approvals.filter(a => verifyApproval(a, artifact))
    if (validApprovals.length < policy.requireApprovals) {
      approvalsValid = false
      errors.push(
        `Requires ${policy.requireApprovals} approvals, found ${validApprovals.length} valid`
      )
    }
  }

  // 6. Policy: breaking changes need approval
  if (artifact.breaking && !policy.allowBreakingWithoutApproval) {
    const validApprovals = approvals.filter(a => verifyApproval(a, artifact))
    if (validApprovals.length === 0) {
      errors.push('Breaking change requires at least one approval')
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    contentIntegrity: baseVerification.contentIntegrity,
    signatureValid: baseVerification.signatureValid,
    chainValid: baseVerification.chainValid,
    notExpired: baseVerification.notExpired,
    approvalsValid,
  }
}

// ══════════════════════════════════════
// UPGRADE ARTIFACT (create new version)
// ══════════════════════════════════════

export function upgradeGovernanceArtifact(
  previous: GovernanceArtifact,
  opts: Omit<CreateArtifactOptions, 'previousVersion' | 'previousArtifactId' | 'artifactType'> & {
    breaking?: boolean
  }
): GovernanceArtifact {
  return createGovernanceArtifact({
    ...opts,
    artifactType: previous.artifactType,
    previousVersion: previous.version,
    previousArtifactId: previous.artifactId,
    supersedes: previous.artifactId,
    breaking: opts.breaking ?? false,
  })
}
