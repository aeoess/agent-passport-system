// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Governance Artifact Provenance — Module 21
// Sign, version, and verify governance artifacts
// Treats governance files as supply-chain artifacts, not config files
// Gap 8B: Monotonic governance — weakening requires higher approval thresholds

import { v4 as uuidv4 } from 'uuid'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize, canonicalizeForWrite } from './canonical.js'
import { parseRfc3339 } from './rfc3339.js'
import { createHash } from 'crypto'
import type {
  GovernanceArtifact, GovernanceApproval, GovernanceVerification,
  GovernanceEnvelope, GovernanceLoadPolicy, GovernanceChangeType,
  GovernanceDiff, CredentialLifecyclePolicy,
} from '../types/governance.js'

import { ANY_ISSUER } from '../types/governance.js'

export { DEFAULT_LOAD_POLICY, ANY_ISSUER } from '../types/governance.js'

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
  // Gap 8B: Change classification
  changeType?: GovernanceChangeType
  additions?: string[]
  modifications?: string[]
  removals?: string[]
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
    changeType: opts.changeType ?? (opts.previousVersion ? 'neutral' : 'initial'),
    additions: opts.additions ?? [],
    modifications: opts.modifications ?? [],
    removals: opts.removals ?? [],
    metadata: opts.metadata ?? {},
    createdAt: now,
  }

  // Sign canonical form of everything EXCEPT content and signature
  // Content is verified via contentHash — keeps signatures stable for large artifacts
  const signable = { ...artifact } as Record<string, unknown>
  delete signable.content
  const canonical = canonicalizeForWrite(signable)
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

  // 3. Expiry check. An expiry this verifier cannot read is not an expiry it
  // can honour, so a present-but-unparseable expiresAt fails the check the same
  // way a past one does. An absent expiresAt still means "never expires".
  let notExpired = true
  if (artifact.expiresAt) {
    const expiry = parseRfc3339(artifact.expiresAt)
    if (!expiry.ok) {
      notExpired = false
      errors.push(`Invalid expiresAt (${expiry.reason})`)
    } else if (expiry.ms <= Date.now()) {
      notExpired = false
      errors.push('Artifact expired')
    }
  }

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
    // Both createdAt values arrive on artifacts. An ordering this verifier
    // cannot read is not an ordering it can attest to, so an unreadable
    // timestamp breaks the chain instead of passing it.
    const created = parseRfc3339(artifact.createdAt)
    const previousCreated = parseRfc3339(previousArtifact.createdAt)
    if (!created.ok) {
      chainValid = false
      errors.push(`Invalid createdAt (${created.reason})`)
    } else if (!previousCreated.ok) {
      chainValid = false
      errors.push(`Invalid previous artifact createdAt (${previousCreated.reason})`)
    } else if (created.ms < previousCreated.ms) {
      chainValid = false
      errors.push('New artifact predates previous version')
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings: [],
    contentIntegrity,
    signatureValid,
    chainValid,
    notExpired,
    approvalsValid: true, // checked separately in envelope verification
    weakeningApproved: true, // checked separately in load policy
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
  const canonical = canonicalizeForWrite(payload)
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
  const warnings: string[] = []

  // 1. Verify the artifact itself
  const baseVerification = verifyGovernanceArtifact(artifact, previousArtifact)
  errors.push(...baseVerification.errors)
  warnings.push(...baseVerification.warnings)

  // 2. Policy: require signature
  if (policy.requireSignature && !baseVerification.signatureValid) {
    errors.push('Policy requires valid signature')
  }

  // 3. Policy: allowed issuers.
  //
  // Three states, and the list has to distinguish all three without any of
  // them being reachable by accident:
  //
  //   []        no issuer is accepted
  //   ['*']     any issuer is accepted, said out loud
  //   anything  a closed allowlist of the named issuers
  //   else
  //
  // The wildcard counts only as a SOLE entry. `['*', k]` is what comes out
  // of spreading the default and appending a key, which is an operator
  // HARDENING the policy; honouring a concatenated wildcard there would
  // disable the very check they were adding. The dropped wildcard is
  // reported rather than silently applied.
  const named = policy.allowedIssuers.filter(i => i !== ANY_ISSUER)
  const wildcardIsSole = policy.allowedIssuers.length === 1 && named.length === 0
  if (!wildcardIsSole) {
    if (named.length !== policy.allowedIssuers.length) {
      warnings.push(
        'allowedIssuers names explicit issuers, so the "*" wildcard is ignored and the list is read as a closed allowlist',
      )
    }
    if (named.length === 0) {
      errors.push('Policy declares no allowed issuers, so no issuer is accepted; use ["*"] alone to accept any issuer')
    } else if (!named.includes(artifact.issuer)) {
      errors.push(`Issuer ${artifact.issuer.slice(0, 16)}... not in allowed issuers list`)
    }
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

  // 7. Policy: weakening changes need higher approval threshold (Gap 8B)
  let weakeningApproved = true
  const isWeakening = artifact.changeType === 'weakening' || artifact.changeType === 'mixed'
  const hasRemovals = artifact.removals.length > 0

  if (isWeakening && policy.blockWeakeningWithoutApproval) {
    const validApprovals = approvals.filter(a => verifyApproval(a, artifact))
    const required = hasRemovals
      ? policy.requireApprovalsForRemoval
      : policy.requireApprovalsForWeakening
    if (validApprovals.length < required) {
      weakeningApproved = false
      const reason = hasRemovals ? 'Removal' : 'Weakening'
      errors.push(
        `${reason} requires ${required} approvals, found ${validApprovals.length} valid`
      )
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    contentIntegrity: baseVerification.contentIntegrity,
    signatureValid: baseVerification.signatureValid,
    chainValid: baseVerification.chainValid,
    notExpired: baseVerification.notExpired,
    approvalsValid,
    weakeningApproved,
  }
}

// ══════════════════════════════════════
// CLASSIFY GOVERNANCE CHANGE (Gap 8B)
// ══════════════════════════════════════

/**
 * Compare two sets of items (e.g., principle IDs) and classify the change.
 * Items are compared by string identity.
 */
export function classifyGovernanceChange(
  previousItems: string[],
  currentItems: string[]
): GovernanceDiff {
  const prevSet = new Set(previousItems)
  const currSet = new Set(currentItems)

  const additions = currentItems.filter(i => !prevSet.has(i))
  const removals = previousItems.filter(i => !currSet.has(i))
  // Items present in both — could be modified (caller determines)
  const common = previousItems.filter(i => currSet.has(i))

  const hasAdditions = additions.length > 0
  const hasRemovals = removals.length > 0

  let changeType: GovernanceChangeType
  if (hasAdditions && hasRemovals) {
    changeType = 'mixed'
  } else if (hasRemovals) {
    changeType = 'weakening'
  } else if (hasAdditions) {
    changeType = 'strengthening'
  } else {
    changeType = 'neutral'
  }

  return {
    changeType,
    additions,
    modifications: common, // caller can refine (e.g., compare enforcement modes)
    removals,
    isWeakening: hasRemovals,
    isStrengthening: hasAdditions && !hasRemovals,
  }
}

// ══════════════════════════════════════
// UPGRADE ARTIFACT (create new version)
// ══════════════════════════════════════

export function upgradeGovernanceArtifact(
  previous: GovernanceArtifact,
  opts: Omit<CreateArtifactOptions, 'previousVersion' | 'previousArtifactId' | 'artifactType'> & {
    breaking?: boolean
    changeType?: GovernanceChangeType
    additions?: string[]
    modifications?: string[]
    removals?: string[]
  }
): GovernanceArtifact {
  return createGovernanceArtifact({
    ...opts,
    artifactType: previous.artifactType,
    previousVersion: previous.version,
    previousArtifactId: previous.artifactId,
    supersedes: previous.artifactId,
    breaking: opts.breaking ?? false,
    changeType: opts.changeType ?? 'neutral',
    additions: opts.additions ?? [],
    modifications: opts.modifications ?? [],
    removals: opts.removals ?? [],
  })
}

// ── Credential Lifecycle Validation (#1717) ──

export function validateCredentialLifecycle(
  policy: CredentialLifecyclePolicy,
  currentTime: { sessionStartedAt: string; credentialIssuedAt: string; now?: string },
): { valid: boolean; reason?: string } {
  // Every instant below gates the lifecycle decision. A timestamp this
  // validator cannot read is not a time it can measure against, so an
  // unreadable field fails the check rather than skipping past it.
  let nowMs = Date.now()
  if (currentTime.now) {
    const parsedNow = parseRfc3339(currentTime.now)
    if (!parsedNow.ok) {
      return { valid: false, reason: `Invalid now (${parsedNow.reason})` }
    }
    nowMs = parsedNow.ms
  }

  // (a) Session duration check
  const sessionStart = parseRfc3339(currentTime.sessionStartedAt)
  if (!sessionStart.ok) {
    return { valid: false, reason: `Invalid sessionStartedAt (${sessionStart.reason})` }
  }
  const sessionDurationSec = (nowMs - sessionStart.ms) / 1000
  if (sessionDurationSec > policy.maxSessionDurationSeconds) {
    return {
      valid: false,
      reason: `Session duration ${Math.round(sessionDurationSec)}s exceeds max ${policy.maxSessionDurationSeconds}s`,
    }
  }

  // (b) Credential TTL check
  const issued = parseRfc3339(currentTime.credentialIssuedAt)
  if (!issued.ok) {
    return { valid: false, reason: `Invalid credentialIssuedAt (${issued.reason})` }
  }
  const credentialAgeSec = (nowMs - issued.ms) / 1000
  if (credentialAgeSec > policy.credentialTTLSeconds) {
    return {
      valid: false,
      reason: `Credential TTL expired: age ${Math.round(credentialAgeSec)}s exceeds TTL ${policy.credentialTTLSeconds}s`,
    }
  }

  return { valid: true }
}
