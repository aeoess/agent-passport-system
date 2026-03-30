// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Agent Attestation Architecture — Core Functions
// Phase 1: Foundation types + issuance challenge + grade computation + attestation binding

import { createHash } from 'crypto'
import { sign, verify, publicKeyFromPrivate } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type {
  PassportGrade, AttestationFlag,
  IssuanceChallenge, IssuanceChallengeResponse,
  IssuanceEvidenceRecord, IssuanceAssessment,
  IssuanceContext, PassportAttestationSummary,
  RuntimeAttestation, ProviderAttestation,
  AttestedSignal, ObservedContext,
  SignalVerificationResult, DerivedSignal,
  AttestationClass,
  WorkspaceManifest, WorkspaceManifestEntry,
  RecoveryRequest, RecoveryResult,
} from '../types/attestation.js'
import type { SignedPassport } from '../types/passport.js'

// ── SHA-256 helper ──
function sha256Hex(input: string): string {
  return createHash('sha256').update(input).digest('hex')
}

// ── createIssuanceChallenge ──
// Phase 1 of the 5-phase issuance flow.
// Server generates a nonce bound to the agent's public key.
export function createIssuanceChallenge(
  publicKeyHash: string,
  options?: {
    requestedClasses?: AttestationClass[];
    expiresInSeconds?: number;
  }
): IssuanceChallenge {
  const now = new Date()
  const expiry = new Date(now.getTime() + (options?.expiresInSeconds ?? 300) * 1000)

  return {
    challengeId: `ic_${sha256Hex(Date.now().toString() + Math.random().toString()).slice(0, 24)}`,
    nonce: sha256Hex(Math.random().toString() + Date.now().toString()).slice(0, 32),
    requiredPublicKeyHash: publicKeyHash,
    requestedAttestationClasses: options?.requestedClasses ?? ['runtime'],
    expiresAt: expiry.toISOString(),
    issuedAt: now.toISOString(),
  }
}

// ── verifyRuntimeAttestation ──
// Phase 3: verify an infrastructure attestation.
// Checks: attester signature, nonce binding to challenge, key binding, freshness.
export function verifyRuntimeAttestation(
  attestation: RuntimeAttestation,
  challenge: IssuanceChallenge,
  trustedAttesterKeys: Map<string, string> // attester URI -> public key
): SignalVerificationResult {
  const now = new Date()

  // Check freshness
  if (new Date(attestation.expiresAt) < now) {
    return {
      signalKey: 'runtime_attestation',
      status: 'failed',
      detail: 'Runtime attestation has expired',
      verifiedAt: now.toISOString(),
    }
  }

  // Check nonce binding
  if (attestation.nonce !== challenge.nonce) {
    return {
      signalKey: 'runtime_attestation',
      status: 'failed',
      detail: 'Nonce does not match issuance challenge',
      verifiedAt: now.toISOString(),
    }
  }

  // Check key binding
  if (attestation.publicKeyHash !== challenge.requiredPublicKeyHash) {
    return {
      signalKey: 'runtime_attestation',
      status: 'failed',
      detail: 'Public key hash does not match challenge requirement',
      verifiedAt: now.toISOString(),
    }
  }

  // Check attester is trusted
  const attesterKey = trustedAttesterKeys.get(attestation.attester)
  if (!attesterKey) {
    return {
      signalKey: 'runtime_attestation',
      status: 'observed',
      detail: `Attester ${attestation.attester} is not in trusted registry`,
      verifiedAt: now.toISOString(),
    }
  }

  // Verify attester signature
  const payload = canonicalize({
    attester: attestation.attester,
    nonce: attestation.nonce,
    publicKeyHash: attestation.publicKeyHash,
    runtimeClass: attestation.runtimeClass,
    bootEpoch: attestation.bootEpoch,
    runtimeInstanceIdHash: attestation.runtimeInstanceIdHash,
    storageIdentityHash: attestation.storageIdentityHash,
    processIdentityHash: attestation.processIdentityHash,
    issuedAt: attestation.issuedAt,
    expiresAt: attestation.expiresAt,
  })

  const sigValid = verify(payload, attestation.signature, attesterKey)
  if (!sigValid) {
    return {
      signalKey: 'runtime_attestation',
      status: 'failed',
      detail: 'Attester signature verification failed',
      verifiedAt: now.toISOString(),
    }
  }

  return {
    signalKey: 'runtime_attestation',
    status: 'verified',
    detail: `Verified by trusted attester ${attestation.attester}`,
    verifiedAt: now.toISOString(),
  }
}

// ── computePassportGrade ──
// Determines grade from available verified attestations.
// Grade 0: self-signed (bare keypair)
// Grade 1: issuer countersigned
// Grade 2: runtime-bound (issuer + challenge-response + trusted attestation)
// Grade 3: runtime + principal bound
export function computePassportGrade(
  evidence: IssuanceEvidenceRecord,
  options?: {
    hasIssuerSignature?: boolean;
    hasVerifiedRuntime?: boolean;
    hasVerifiedProvider?: boolean;
    hasPrincipalEndorsement?: boolean;
  }
): PassportGrade {
  const has = options ?? {}

  // Check from highest to lowest
  if (has.hasVerifiedRuntime && has.hasPrincipalEndorsement && has.hasIssuerSignature) {
    return 3
  }
  if (has.hasVerifiedRuntime && has.hasIssuerSignature) {
    return 2
  }
  // Provider attestation without runtime can still be Grade 2
  // if the provider is strong enough (e.g., verified cloud tenant)
  if (has.hasVerifiedProvider && has.hasIssuerSignature) {
    return 2
  }
  if (has.hasIssuerSignature) {
    return 1
  }
  return 0
}

// ── computeAttestationFlags ──
// Derive public flags from evidence and grade.
export function computeAttestationFlags(
  grade: PassportGrade,
  evidence: IssuanceEvidenceRecord,
): AttestationFlag[] {
  const flags: AttestationFlag[] = []

  if (grade >= 1) flags.push('issuer_bound')
  if (grade >= 2 && evidence.runtimeAttestations.length > 0) flags.push('runtime_bound')
  if (grade >= 2 && evidence.providerAttestations.length > 0) flags.push('provider_bound')
  if (grade >= 3) flags.push('principal_bound')
  if (evidence.priorPassportRef) flags.push('recovery_linked')
  if (evidence.priorContinuityProof) flags.push('continuity_proven')

  return flags
}

// ── computeAttestationBundleHash ──
// SHA-256 of the canonical evidence record. Allows verifiers to confirm
// the passport's attestation summary matches real evidence without seeing the evidence.
export function computeAttestationBundleHash(evidence: IssuanceEvidenceRecord): string {
  return sha256Hex(canonicalize(evidence))
}

// ── createIssuanceContext ──
// Combine evidence + assessment into a complete issuance record.
export function createIssuanceContext(
  evidence: IssuanceEvidenceRecord,
  options?: {
    hasIssuerSignature?: boolean;
    hasVerifiedRuntime?: boolean;
    hasVerifiedProvider?: boolean;
    hasPrincipalEndorsement?: boolean;
    verificationResults?: SignalVerificationResult[];
    derivedSignals?: DerivedSignal[];
  }
): IssuanceContext {
  const grade = computePassportGrade(evidence, options)
  const flags = computeAttestationFlags(grade, evidence)
  const bundleHash = computeAttestationBundleHash(evidence)

  return {
    evidence,
    assessment: {
      passportGrade: grade,
      attestationBundleHash: bundleHash,
      flags,
      verificationResults: options?.verificationResults ?? [],
      derivedSignals: options?.derivedSignals,
      assessedAt: new Date().toISOString(),
    },
  }
}

// ── bindAttestation ──
// Attach PassportAttestationSummary to a SignedPassport.
// This is backward compatible: the attestation field is optional.
export function bindAttestation(
  signedPassport: SignedPassport,
  context: IssuanceContext
): SignedPassport & { attestation: PassportAttestationSummary } {
  const summary: PassportAttestationSummary = {
    passportGrade: context.assessment.passportGrade,
    attestationBundleHash: context.assessment.attestationBundleHash,
    flags: context.assessment.flags,
  }
  return {
    ...signedPassport,
    attestation: summary,
  }
}

// ── createWorkspaceManifest ──
// Compute a workspace manifest from file entries.
// Hash structure, not content. Privacy-preserving: paths are hashed,
// timestamps floored to hour.
export function createWorkspaceManifest(
  entries: Array<{ path: string; sizeBytes: number; lastModified: Date }>
): WorkspaceManifest {
  const now = new Date()

  // Sort entries deterministically by path hash
  const manifestEntries: WorkspaceManifestEntry[] = entries
    .map(e => {
      const hourFloor = new Date(e.lastModified)
      hourFloor.setMinutes(0, 0, 0)
      return {
        pathHash: sha256Hex(e.path),
        sizeBytes: e.sizeBytes,
        lastModifiedBucket: hourFloor.toISOString(),
      }
    })
    .sort((a, b) => a.pathHash.localeCompare(b.pathHash))

  const totalSize = manifestEntries.reduce((sum, e) => sum + e.sizeBytes, 0)
  const manifestHash = sha256Hex(canonicalize(manifestEntries))

  return {
    entries: manifestEntries,
    totalFiles: manifestEntries.length,
    totalSizeBytes: totalSize,
    computedAt: now.toISOString(),
    manifestHash,
  }
}

// ── createEmptyEvidenceRecord ──
// Initialize a minimal evidence record. The server fills Tier 0 observed signals.
export function createEmptyEvidenceRecord(
  observed?: Partial<ObservedContext>
): IssuanceEvidenceRecord {
  const now = new Date()
  return {
    requestId: `req_${sha256Hex(Date.now().toString() + Math.random().toString()).slice(0, 24)}`,
    requestedAt: now.toISOString(),
    observed: {
      observedAt: now.toISOString(),
      ...observed,
    },
    runtimeAttestations: [],
    providerAttestations: [],
    selfDeclaredSignals: [],
  }
}

// ── isChallengeFresh ──
// Check if an issuance challenge is still valid.
export function isChallengeFresh(challenge: IssuanceChallenge): boolean {
  return new Date(challenge.expiresAt) > new Date()
}

// ── isGradeAtLeast ──
// Check if a passport grade meets a minimum requirement.
export function isGradeAtLeast(grade: PassportGrade, minimum: PassportGrade): boolean {
  return grade >= minimum
}
