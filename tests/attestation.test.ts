// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Agent Attestation Architecture — Phase 1 Tests
// Covers: types, issuance challenge, runtime attestation verification,
//         passport grade computation, attestation binding, workspace manifest

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createIssuanceChallenge, verifyRuntimeAttestation,
  computePassportGrade, computeAttestationFlags, computeAttestationBundleHash,
  createIssuanceContext, bindAttestation,
  createWorkspaceManifest, createEmptyEvidenceRecord,
  isChallengeFresh, isGradeAtLeast, importProviderAttestation, addIdentityBoundary,
  PASSPORT_GRADE_LABELS,
  createPassport, countersignPassport,
  generateKeyPair, sign, canonicalize,
} from '../src/index.js'
import type {
  PassportGrade, RuntimeAttestation, ProviderAttestation,
  AttestedSignal, IssuanceEvidenceRecord, IssuanceChallenge,
  RecoveryRequest, RecoveryResult, GradeChange, ObservedContext,
} from '../src/index.js'

import { createHash } from 'crypto'
function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex')
}

// ── Helper: create a valid runtime attestation signed by a gateway key ──
function createSignedRuntimeAttestation(
  challenge: IssuanceChallenge,
  gatewayKey: { privateKey: string; publicKey: string },
): RuntimeAttestation {
  const now = new Date()
  const expiry = new Date(now.getTime() + 3600_000)
  const attestation: Omit<RuntimeAttestation, 'signature'> = {
    attester: 'openshell://test-gateway',
    nonce: challenge.nonce,
    publicKeyHash: challenge.requiredPublicKeyHash,
    runtimeClass: 'sandbox',
    bootEpoch: new Date(now.getTime() - 60_000).toISOString(),
    runtimeInstanceIdHash: sha256('container-abc123'),
    storageIdentityHash: sha256('/workspace-vol-1'),
    issuedAt: now.toISOString(),
    expiresAt: expiry.toISOString(),
  }
  const payload = canonicalize({
    attester: attestation.attester,
    nonce: attestation.nonce,
    publicKeyHash: attestation.publicKeyHash,
    runtimeClass: attestation.runtimeClass,
    bootEpoch: attestation.bootEpoch,
    runtimeInstanceIdHash: attestation.runtimeInstanceIdHash,
    storageIdentityHash: attestation.storageIdentityHash,
    processIdentityHash: undefined,
    issuedAt: attestation.issuedAt,
    expiresAt: attestation.expiresAt,
  })
  const signature = sign(payload, gatewayKey.privateKey)
  return { ...attestation, signature }
}

// ══════════════════════════════════════════════════════════════
// Type & Constant Tests
// ══════════════════════════════════════════════════════════════

describe('PassportGrade constants', () => {
  it('PASSPORT_GRADE_LABELS covers all grades', () => {
    assert.equal(PASSPORT_GRADE_LABELS[0], 'self_signed')
    assert.equal(PASSPORT_GRADE_LABELS[1], 'issuer_countersigned')
    assert.equal(PASSPORT_GRADE_LABELS[2], 'runtime_bound')
    assert.equal(PASSPORT_GRADE_LABELS[3], 'principal_bound')
  })

  it('grade labels are exhaustive', () => {
    const keys = Object.keys(PASSPORT_GRADE_LABELS).map(Number)
    assert.deepEqual(keys, [0, 1, 2, 3])
  })
})

// ══════════════════════════════════════════════════════════════
// Issuance Challenge Tests
// ══════════════════════════════════════════════════════════════

describe('createIssuanceChallenge', () => {
  const agentKey = generateKeyPair()
  const pubKeyHash = sha256(agentKey.publicKey)

  it('creates challenge bound to public key', () => {
    const ch = createIssuanceChallenge(pubKeyHash)
    assert.equal(ch.requiredPublicKeyHash, pubKeyHash)
    assert.equal(ch.nonce.length, 32)
    assert.ok(ch.challengeId.startsWith('ic_'))
    assert.ok(ch.requestedAttestationClasses.includes('runtime'))
  })

  it('respects custom expiry', () => {
    const ch = createIssuanceChallenge(pubKeyHash, { expiresInSeconds: 60 })
    const diff = new Date(ch.expiresAt).getTime() - new Date(ch.issuedAt).getTime()
    assert.equal(diff, 60_000)
  })

  it('respects requested attestation classes', () => {
    const ch = createIssuanceChallenge(pubKeyHash, {
      requestedClasses: ['runtime', 'provider', 'workspace'],
    })
    assert.deepEqual(ch.requestedAttestationClasses, ['runtime', 'provider', 'workspace'])
  })

  it('generates unique challenges', () => {
    const ch1 = createIssuanceChallenge(pubKeyHash)
    const ch2 = createIssuanceChallenge(pubKeyHash)
    assert.notEqual(ch1.challengeId, ch2.challengeId)
    assert.notEqual(ch1.nonce, ch2.nonce)
  })

  it('isChallengeFresh returns true for valid challenge', () => {
    const ch = createIssuanceChallenge(pubKeyHash, { expiresInSeconds: 300 })
    assert.equal(isChallengeFresh(ch), true)
  })

  it('isChallengeFresh returns false for expired challenge', () => {
    const ch = createIssuanceChallenge(pubKeyHash, { expiresInSeconds: -1 })
    assert.equal(isChallengeFresh(ch), false)
  })
})

// ══════════════════════════════════════════════════════════════
// Runtime Attestation Verification Tests
// ══════════════════════════════════════════════════════════════

describe('verifyRuntimeAttestation', () => {
  const agentKey = generateKeyPair()
  const gatewayKey = generateKeyPair()
  const pubKeyHash = sha256(agentKey.publicKey)
  const trustedKeys = new Map([['openshell://test-gateway', gatewayKey.publicKey]])

  it('verifies a valid runtime attestation', () => {
    const challenge = createIssuanceChallenge(pubKeyHash)
    const attestation = createSignedRuntimeAttestation(challenge, gatewayKey)
    const result = verifyRuntimeAttestation(attestation, challenge, trustedKeys)
    assert.equal(result.status, 'verified')
    assert.equal(result.signalKey, 'runtime_attestation')
  })

  it('rejects wrong nonce', () => {
    const challenge = createIssuanceChallenge(pubKeyHash)
    const attestation = createSignedRuntimeAttestation(challenge, gatewayKey)
    const fakeChallenge = { ...challenge, nonce: 'wrong_nonce_value_here_12345678' }
    const result = verifyRuntimeAttestation(attestation, fakeChallenge, trustedKeys)
    assert.equal(result.status, 'failed')
    assert.ok(result.detail!.toLowerCase().includes('nonce'))
  })

  it('rejects wrong key binding', () => {
    const challenge = createIssuanceChallenge(pubKeyHash)
    const otherKey = generateKeyPair()
    const otherHash = sha256(otherKey.publicKey)
    const fakeChallenge = { ...challenge, requiredPublicKeyHash: otherHash }
    const attestation = createSignedRuntimeAttestation(challenge, gatewayKey)
    const result = verifyRuntimeAttestation(attestation, fakeChallenge, trustedKeys)
    assert.equal(result.status, 'failed')
    assert.ok(result.detail!.toLowerCase().includes('key hash'))
  })

  it('returns observed for unknown attester', () => {
    const challenge = createIssuanceChallenge(pubKeyHash)
    const attestation = createSignedRuntimeAttestation(challenge, gatewayKey)
    const emptyKeys = new Map<string, string>()
    const result = verifyRuntimeAttestation(attestation, challenge, emptyKeys)
    assert.equal(result.status, 'observed')
    assert.ok(result.detail!.includes('not in trusted registry'))
  })

  it('rejects expired attestation', () => {
    const challenge = createIssuanceChallenge(pubKeyHash)
    const attestation = createSignedRuntimeAttestation(challenge, gatewayKey)
    const expired = { ...attestation, expiresAt: new Date(Date.now() - 1000).toISOString() }
    const result = verifyRuntimeAttestation(expired, challenge, trustedKeys)
    assert.equal(result.status, 'failed')
    assert.ok(result.detail!.toLowerCase().includes('expired'))
  })

  it('rejects forged signature', () => {
    const challenge = createIssuanceChallenge(pubKeyHash)
    const attestation = createSignedRuntimeAttestation(challenge, gatewayKey)
    const forged = { ...attestation, signature: 'a'.repeat(128) }
    const result = verifyRuntimeAttestation(forged, challenge, trustedKeys)
    assert.equal(result.status, 'failed')
    assert.ok(result.detail!.toLowerCase().includes('signature'))
  })

  it('rejects attestation signed by wrong key', () => {
    const challenge = createIssuanceChallenge(pubKeyHash)
    const rogueKey = generateKeyPair()
    const attestation = createSignedRuntimeAttestation(challenge, rogueKey)
    const result = verifyRuntimeAttestation(attestation, challenge, trustedKeys)
    assert.equal(result.status, 'failed')
    assert.ok(result.detail!.toLowerCase().includes('signature'))
  })
})

// ══════════════════════════════════════════════════════════════
// Passport Grade Computation Tests
// ══════════════════════════════════════════════════════════════

describe('computePassportGrade', () => {
  const bareEvidence = createEmptyEvidenceRecord()

  it('Grade 0: bare keypair, no issuer', () => {
    assert.equal(computePassportGrade(bareEvidence), 0)
  })

  it('Grade 1: issuer countersigned', () => {
    assert.equal(computePassportGrade(bareEvidence, { hasIssuerSignature: true }), 1)
  })

  it('Grade 2: runtime bound', () => {
    assert.equal(computePassportGrade(bareEvidence, { hasIssuerSignature: true, hasVerifiedRuntime: true }), 2)
  })

  it('Grade 2: provider bound (without runtime)', () => {
    assert.equal(computePassportGrade(bareEvidence, { hasIssuerSignature: true, hasVerifiedProvider: true }), 2)
  })

  it('Grade 3: principal bound', () => {
    assert.equal(computePassportGrade(bareEvidence, { hasIssuerSignature: true, hasVerifiedRuntime: true, hasPrincipalEndorsement: true }), 3)
  })

  it('principal without runtime stays Grade 1', () => {
    assert.equal(computePassportGrade(bareEvidence, { hasIssuerSignature: true, hasPrincipalEndorsement: true }), 1)
  })

  it('runtime without issuer stays Grade 0', () => {
    assert.equal(computePassportGrade(bareEvidence, { hasVerifiedRuntime: true }), 0)
  })

  it('isGradeAtLeast checks correctly', () => {
    assert.equal(isGradeAtLeast(2, 1), true)
    assert.equal(isGradeAtLeast(2, 2), true)
    assert.equal(isGradeAtLeast(1, 2), false)
    assert.equal(isGradeAtLeast(0, 0), true)
    assert.equal(isGradeAtLeast(3, 0), true)
  })
})

// ══════════════════════════════════════════════════════════════
// Attestation Flags Tests
// ══════════════════════════════════════════════════════════════

describe('computeAttestationFlags', () => {
  it('Grade 0 has no flags', () => {
    const evidence = createEmptyEvidenceRecord()
    const flags = computeAttestationFlags(0, evidence)
    assert.deepEqual(flags, [])
  })

  it('Grade 1 has issuer_bound', () => {
    const evidence = createEmptyEvidenceRecord()
    const flags = computeAttestationFlags(1, evidence)
    assert.ok(flags.includes('issuer_bound'))
    assert.ok(!flags.includes('runtime_bound'))
  })

  it('Grade 2 with runtime has runtime_bound', () => {
    const evidence = createEmptyEvidenceRecord()
    evidence.runtimeAttestations = [{ attester: 'test', nonce: 'n', publicKeyHash: 'pk',
      issuedAt: new Date().toISOString(), expiresAt: new Date().toISOString(), signature: 'sig' }]
    const flags = computeAttestationFlags(2, evidence)
    assert.ok(flags.includes('issuer_bound'))
    assert.ok(flags.includes('runtime_bound'))
  })

  it('recovery_linked flag set when priorPassportRef present', () => {
    const evidence = createEmptyEvidenceRecord()
    evidence.priorPassportRef = 'passport_abc123'
    const flags = computeAttestationFlags(1, evidence)
    assert.ok(flags.includes('recovery_linked'))
  })

  it('continuity_proven flag set when priorContinuityProof present', () => {
    const evidence = createEmptyEvidenceRecord()
    evidence.priorContinuityProof = 'signed_proof_abc'
    const flags = computeAttestationFlags(1, evidence)
    assert.ok(flags.includes('continuity_proven'))
  })
})

// ══════════════════════════════════════════════════════════════
// Issuance Context & Bundle Hash Tests
// ══════════════════════════════════════════════════════════════

describe('createIssuanceContext', () => {
  it('creates context with correct grade and flags', () => {
    const evidence = createEmptyEvidenceRecord({ ipHash: sha256('192.168.1.1') })
    const ctx = createIssuanceContext(evidence, { hasIssuerSignature: true })
    assert.equal(ctx.evidence, evidence)
    assert.equal(ctx.assessment.passportGrade, 1)
    assert.ok(ctx.assessment.flags.includes('issuer_bound'))
    assert.equal(ctx.assessment.attestationBundleHash.length, 64)
    assert.ok(ctx.assessment.assessedAt)
  })

  it('includes verification results when provided', () => {
    const evidence = createEmptyEvidenceRecord()
    const result = { signalKey: 'test', status: 'verified' as const, verifiedAt: new Date().toISOString() }
    const ctx = createIssuanceContext(evidence, { verificationResults: [result] })
    assert.equal(ctx.assessment.verificationResults.length, 1)
    assert.equal(ctx.assessment.verificationResults[0].status, 'verified')
  })

  it('includes derived signals when provided', () => {
    const evidence = createEmptyEvidenceRecord()
    const derived = { key: 'issuance_age_ms', value: '150', derivedFrom: ['bootEpoch'], computedAt: new Date().toISOString() }
    const ctx = createIssuanceContext(evidence, { derivedSignals: [derived] })
    assert.equal(ctx.assessment.derivedSignals!.length, 1)
    assert.equal(ctx.assessment.derivedSignals![0].key, 'issuance_age_ms')
  })
})

describe('computeAttestationBundleHash', () => {
  it('produces deterministic hash', () => {
    const evidence = createEmptyEvidenceRecord({ ipHash: sha256('10.0.0.1') })
    const h1 = computeAttestationBundleHash(evidence)
    const h2 = computeAttestationBundleHash(evidence)
    assert.equal(h1, h2)
    assert.equal(h1.length, 64)
  })

  it('different evidence produces different hash', () => {
    const e1 = createEmptyEvidenceRecord({ ipHash: sha256('10.0.0.1') })
    const e2 = createEmptyEvidenceRecord({ ipHash: sha256('10.0.0.2') })
    assert.notEqual(computeAttestationBundleHash(e1), computeAttestationBundleHash(e2))
  })
})

// ══════════════════════════════════════════════════════════════
// Bind Attestation to Passport Tests
// ══════════════════════════════════════════════════════════════

describe('bindAttestation', () => {
  it('attaches attestation summary to signed passport', () => {
    const { signedPassport } = createPassport({
      agentId: 'agent-attest-test', agentName: 'Attestation Test Agent',
      ownerAlias: 'tester', mission: 'test attestation binding',
      capabilities: ['code_execution'],
      runtime: { platform: 'node', models: ['test'], toolsCount: 1, memoryType: 'volatile' },
    })
    const evidence = createEmptyEvidenceRecord({ ipHash: sha256('127.0.0.1') })
    const ctx = createIssuanceContext(evidence, { hasIssuerSignature: true })
    const attested = bindAttestation(signedPassport, ctx)

    assert.ok(attested.attestation)
    assert.equal(attested.attestation.passportGrade, 1)
    assert.ok(attested.attestation.flags.includes('issuer_bound'))
    assert.equal(attested.attestation.attestationBundleHash!.length, 64)
    assert.equal(attested.passport.agentId, 'agent-attest-test')
    assert.equal(attested.signature, signedPassport.signature)
  })

  it('backward compatible: passport without attestation still works', () => {
    const { signedPassport } = createPassport({
      agentId: 'agent-no-attest', agentName: 'No Attestation Agent',
      ownerAlias: 'tester', mission: 'test backward compat',
      capabilities: [],
      runtime: { platform: 'node', models: [], toolsCount: 0, memoryType: 'volatile' },
    })
    assert.equal(signedPassport.attestation, undefined)
  })

  it('works with countersigned passport', () => {
    const issuerKey = generateKeyPair()
    const { signedPassport } = createPassport({
      agentId: 'agent-cs-attest', agentName: 'Countersigned Attestation',
      ownerAlias: 'tester', mission: 'test with countersignature',
      capabilities: ['web_search'],
      runtime: { platform: 'node', models: ['test'], toolsCount: 1, memoryType: 'volatile' },
    })
    const countersigned = countersignPassport(signedPassport, issuerKey.privateKey)
    const evidence = createEmptyEvidenceRecord()
    const ctx = createIssuanceContext(evidence, { hasIssuerSignature: true })
    const attested = bindAttestation(countersigned, ctx)

    assert.ok(attested.issuerSignature)
    assert.equal(attested.attestation.passportGrade, 1)
  })
})

// ══════════════════════════════════════════════════════════════
// Workspace Manifest Tests
// ══════════════════════════════════════════════════════════════

describe('createWorkspaceManifest', () => {
  const now = new Date()
  const entries = [
    { path: '/workspace/MEMORY.md', sizeBytes: 4096, lastModified: new Date(now.getTime() - 7200_000) },
    { path: '/workspace/SOUL.md', sizeBytes: 2048, lastModified: new Date(now.getTime() - 604800_000) },
    { path: '/workspace/task-output-1.json', sizeBytes: 8192, lastModified: now },
  ]

  it('computes manifest with correct counts', () => {
    const manifest = createWorkspaceManifest(entries)
    assert.equal(manifest.totalFiles, 3)
    assert.equal(manifest.totalSizeBytes, 4096 + 2048 + 8192)
    assert.equal(manifest.entries.length, 3)
    assert.equal(manifest.manifestHash.length, 64)
  })

  it('hashes paths for privacy (no raw paths)', () => {
    const manifest = createWorkspaceManifest(entries)
    for (const entry of manifest.entries) {
      assert.equal(entry.pathHash.length, 64)
      assert.ok(!entry.pathHash.includes('workspace'))
      assert.ok(!entry.pathHash.includes('MEMORY'))
    }
  })

  it('floors timestamps to hour for privacy', () => {
    const manifest = createWorkspaceManifest(entries)
    for (const entry of manifest.entries) {
      const d = new Date(entry.lastModifiedBucket)
      assert.equal(d.getMinutes(), 0)
      assert.equal(d.getSeconds(), 0)
      assert.equal(d.getMilliseconds(), 0)
    }
  })

  it('sorts entries deterministically by pathHash', () => {
    const manifest = createWorkspaceManifest(entries)
    for (let i = 1; i < manifest.entries.length; i++) {
      assert.ok(manifest.entries[i].pathHash > manifest.entries[i - 1].pathHash)
    }
  })

  it('produces deterministic hash for same input', () => {
    const m1 = createWorkspaceManifest(entries)
    const m2 = createWorkspaceManifest(entries)
    assert.equal(m1.manifestHash, m2.manifestHash)
  })

  it('different files produce different hash', () => {
    const other = [{ path: '/workspace/OTHER.md', sizeBytes: 1024, lastModified: now }]
    const m1 = createWorkspaceManifest(entries)
    const m2 = createWorkspaceManifest(other)
    assert.notEqual(m1.manifestHash, m2.manifestHash)
  })

  it('empty workspace produces valid manifest', () => {
    const manifest = createWorkspaceManifest([])
    assert.equal(manifest.totalFiles, 0)
    assert.equal(manifest.totalSizeBytes, 0)
    assert.deepEqual(manifest.entries, [])
    assert.equal(manifest.manifestHash.length, 64)
  })
})

// ══════════════════════════════════════════════════════════════
// Evidence Record Tests
// ══════════════════════════════════════════════════════════════

describe('createEmptyEvidenceRecord', () => {
  it('creates minimal evidence with request ID and timestamp', () => {
    const evidence = createEmptyEvidenceRecord()
    assert.ok(evidence.requestId.startsWith('req_'))
    assert.ok(evidence.requestedAt)
    assert.ok(evidence.observed.observedAt)
    assert.deepEqual(evidence.runtimeAttestations, [])
    assert.deepEqual(evidence.providerAttestations, [])
    assert.deepEqual(evidence.selfDeclaredSignals, [])
  })

  it('accepts partial observed context', () => {
    const evidence = createEmptyEvidenceRecord({
      ipHash: sha256('10.0.0.1'), transportType: 'sse', issuanceVelocity: 3,
    })
    assert.equal(evidence.observed.ipHash, sha256('10.0.0.1'))
    assert.equal(evidence.observed.transportType, 'sse')
    assert.equal(evidence.observed.issuanceVelocity, 3)
  })

  it('generates unique request IDs', () => {
    const e1 = createEmptyEvidenceRecord()
    const e2 = createEmptyEvidenceRecord()
    assert.notEqual(e1.requestId, e2.requestId)
  })
})

// ══════════════════════════════════════════════════════════════
// End-to-End: Full 5-Phase Issuance Flow
// ══════════════════════════════════════════════════════════════

describe('Full issuance flow (5 phases)', () => {
  const agentKey = generateKeyPair()
  const issuerKey = generateKeyPair()
  const gatewayKey = generateKeyPair()
  const pubKeyHash = sha256(agentKey.publicKey)
  const trustedKeys = new Map([['openshell://test-gateway', gatewayKey.publicKey]])

  it('Phase 0-5: observe → challenge → attest → verify → derive → issue', () => {
    // Phase 0: Silent observation (Tier 0)
    const observed: Partial<ObservedContext> = {
      ipHash: sha256('203.0.113.42'),
      clientFingerprintHash: sha256('ja3-fingerprint-abc'),
      transportType: 'sse',
      connectionTimingMs: 45,
      issuanceVelocity: 1,
      requestPayloadFingerprint: sha256('{"method":"issue_passport"}'),
      userAgentHash: sha256('Claude-Desktop/1.0'),
    }

    // Phase 1: Challenge
    const challenge = createIssuanceChallenge(pubKeyHash, {
      requestedClasses: ['runtime', 'provider'], expiresInSeconds: 300,
    })
    assert.ok(isChallengeFresh(challenge))

    // Phase 2: Agent returns attestations
    const runtimeAttestation = createSignedRuntimeAttestation(challenge, gatewayKey)

    // Phase 3: Verify
    const runtimeResult = verifyRuntimeAttestation(runtimeAttestation, challenge, trustedKeys)
    assert.equal(runtimeResult.status, 'verified')

    // Phase 4: Derive issuance context
    const evidence = createEmptyEvidenceRecord(observed)
    evidence.runtimeAttestations = [runtimeAttestation]
    const context = createIssuanceContext(evidence, {
      hasIssuerSignature: true, hasVerifiedRuntime: true,
      verificationResults: [runtimeResult],
      derivedSignals: [
        { key: 'issuance_age_ms', value: '150', derivedFrom: ['bootEpoch', 'requestedAt'], computedAt: new Date().toISOString() },
      ],
    })
    assert.equal(context.assessment.passportGrade, 2)
    assert.ok(context.assessment.flags.includes('issuer_bound'))
    assert.ok(context.assessment.flags.includes('runtime_bound'))
    assert.equal(context.assessment.attestationBundleHash.length, 64)
    assert.equal(context.assessment.verificationResults.length, 1)
    assert.equal(context.assessment.derivedSignals!.length, 1)

    // Phase 5: Issue passport with attestation
    const { signedPassport } = createPassport({
      agentId: 'agent-e2e-test', agentName: 'E2E Test Agent',
      ownerAlias: 'tima', mission: 'end-to-end attestation test',
      capabilities: ['code_execution', 'web_search'],
      runtime: { platform: 'openshell', models: ['gemini-3.1-pro'], toolsCount: 22, memoryType: 'persistent' },
    })
    const countersigned = countersignPassport(signedPassport, issuerKey.privateKey)
    const attested = bindAttestation(countersigned, context)

    assert.ok(attested.attestation)
    assert.equal(attested.attestation.passportGrade, 2)
    assert.ok(attested.attestation.flags.includes('runtime_bound'))
    assert.equal(attested.attestation.attestationBundleHash!.length, 64)
    assert.ok(attested.issuerSignature)
    assert.equal(attested.passport.agentId, 'agent-e2e-test')

    // Context internally consistent
    assert.equal(context.evidence.observed.ipHash, sha256('203.0.113.42'))
    assert.equal(context.evidence.runtimeAttestations.length, 1)
    assert.equal(context.evidence.observed.transportType, 'sse')
  })
})

// ══════════════════════════════════════════════════════════════
// Adversarial: Consilium Mandatory Corrections
// ══════════════════════════════════════════════════════════════

describe('Consilium mandatory corrections', () => {
  it('MC1: Recovery requires crypto proof, not just env matching', () => {
    const recoveryRequest: RecoveryRequest = {
      environmentSignals: { ipHash: sha256('10.0.0.1'), transportType: 'sse' },
      workspaceManifestHash: sha256('manifest-abc'),
    }
    assert.equal(recoveryRequest.priorKeySignature, undefined)
    assert.equal(recoveryRequest.recoveryKeySignature, undefined)
    assert.equal(recoveryRequest.principalAuthorization, undefined)

    const result: RecoveryResult = {
      matched: true, matchedPassportId: 'passport_abc',
      confidenceSignals: ['ipHash', 'workspaceManifestHash'],
      recoveryAuthorized: false, // no crypto proof = not authorized
    }
    assert.equal(result.matched, true)
    assert.equal(result.recoveryAuthorized, false)
  })

  it('MC1b: Recovery authorized with prior key signature', () => {
    const result: RecoveryResult = {
      matched: true, matchedPassportId: 'passport_abc',
      confidenceSignals: ['ipHash', 'storageIdentityHash'],
      recoveryAuthorized: true,
      authorizationMethod: 'prior_key',
    }
    assert.equal(result.recoveryAuthorized, true)
    assert.equal(result.authorizationMethod, 'prior_key')
  })

  it('MC2: Workspace is manifest hash (structure), not content hash', () => {
    const manifest = createWorkspaceManifest([
      { path: '/workspace/MEMORY.md', sizeBytes: 4096, lastModified: new Date() },
    ])
    assert.ok(!manifest.entries[0].pathHash.includes('MEMORY'))
    assert.equal(manifest.entries[0].pathHash.length, 64)
    assert.equal(manifest.totalFiles, 1)
    assert.equal(manifest.totalSizeBytes, 4096)
  })

  it('MC3: Evidence and assessment are separated', () => {
    const evidence = createEmptyEvidenceRecord({ ipHash: sha256('10.0.0.1') })
    const ctx = createIssuanceContext(evidence, { hasIssuerSignature: true })
    assert.equal(ctx.evidence.observed.ipHash, sha256('10.0.0.1'))
    assert.equal(ctx.assessment.passportGrade, 1)
    assert.equal(ctx.assessment.attestationBundleHash.length, 64)
    assert.notEqual(ctx.evidence as unknown, ctx.assessment as unknown)
  })

  it('Tier 0 uses closed schema (ObservedContext), not open AttestedSignal[]', () => {
    const evidence = createEmptyEvidenceRecord({
      ipHash: sha256('10.0.0.1'), clientFingerprintHash: sha256('fingerprint'),
      transportType: 'sse', connectionTimingMs: 30,
      issuanceVelocity: 2, requestPayloadFingerprint: sha256('payload'),
    })
    assert.equal(typeof evidence.observed.ipHash, 'string')
    assert.equal(typeof evidence.observed.connectionTimingMs, 'number')
    assert.equal(typeof evidence.observed.issuanceVelocity, 'number')
    assert.equal(typeof evidence.observed.transportType, 'string')
  })

  it('Grade 0 agents still get full evidence tracking (memory not gates)', () => {
    const evidence = createEmptyEvidenceRecord({ ipHash: sha256('bare-metal-agent') })
    const ctx = createIssuanceContext(evidence)
    assert.equal(ctx.assessment.passportGrade, 0)
    assert.deepEqual(ctx.assessment.flags, [])
    assert.equal(ctx.assessment.attestationBundleHash.length, 64)
    assert.ok(ctx.evidence.requestId.startsWith('req_'))
  })

  it('bare metal Python agent gets Grade 1 with issuer', () => {
    const evidence = createEmptyEvidenceRecord({
      userAgentHash: sha256('python-requests/2.31.0'),
      requestPayloadFingerprint: sha256('{"bare":"metal"}'),
      connectionTimingMs: 12,
    })
    const ctx = createIssuanceContext(evidence, { hasIssuerSignature: true })
    assert.equal(ctx.assessment.passportGrade, 1)
    assert.deepEqual(ctx.evidence.runtimeAttestations, [])
    assert.ok(ctx.evidence.observed.userAgentHash)
  })

  it('grade mutability: GradeChange tracks history', () => {
    const evidence = createEmptyEvidenceRecord()
    const ctx = createIssuanceContext(evidence, { hasIssuerSignature: true })
    const change: GradeChange = {
      from: 2, to: 0, reason: 'cluster_analysis_downgrade', changedAt: new Date().toISOString(),
    }
    ctx.assessment.gradeHistory = [change]
    assert.equal(ctx.assessment.gradeHistory.length, 1)
    assert.equal(ctx.assessment.gradeHistory[0].reason, 'cluster_analysis_downgrade')
  })
})


// ════════════════════════════════════════════════════════════
// importProviderAttestation tests (msaleme A2A#1696 integration)
// ════════════════════════════════════════════════════════════

describe('importProviderAttestation', () => {
  it('should import raw JSON attestation', () => {
    const result = importProviderAttestation({
      attestation: { sub: 'agent-001', issued_at: '2026-03-30T12:00:00Z' },
      provider: 'red-team-harness',
      subjectClass: 'agent',
      verificationMethod: 'jwt',
    })
    assert.equal(result.provider, 'red-team-harness')
    assert.equal(result.subjectClass, 'agent')
    assert.ok(result.subjectIdHash.length === 64) // SHA-256 hex
    assert.equal(result.verificationMethod, 'jwt')
  })

  it('should import JSON string attestation', () => {
    const json = JSON.stringify({ sub: 'agent-002', verification_method: 'oauth2' })
    const result = importProviderAttestation({
      attestation: json,
      provider: 'cloud-provider',
    })
    assert.equal(result.provider, 'cloud-provider')
    assert.equal(result.verificationMethod, 'oauth2')
  })

  it('should parse JWS compact format', () => {
    // Create a fake JWS: header.payload.signature
    const header = Buffer.from(JSON.stringify({ alg: 'ES256' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({
      sub: 'agent-003',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      nonce: 'test-nonce-123',
    })).toString('base64url')
    const sig = 'fakesignature123'
    const jws = `${header}.${payload}.${sig}`

    const result = importProviderAttestation({
      attestation: jws,
      provider: 'oauth-issuer',
    })
    assert.equal(result.provider, 'oauth-issuer')
    assert.equal(result.nonce, 'test-nonce-123')
    assert.equal(result.signature, sig)
    assert.ok(result.expiresAt) // should have expiry from JWS exp claim
  })

  it('should hash public key when present', () => {
    const result = importProviderAttestation({
      attestation: { sub: 'a', public_key: 'abc123hexkey' },
      provider: 'provider',
    })
    assert.ok(result.publicKeyHash)
    assert.equal(result.publicKeyHash!.length, 64)
  })

  it('should produce valid ProviderAttestation for evidence record', () => {
    const attestation = importProviderAttestation({
      attestation: { sub: 'agent-test', subject_class: 'tenant' },
      provider: 'security-scanner',
      verificationMethod: 'api_key',
    })
    // Can be added to evidence record
    const evidence = createEmptyEvidenceRecord({
      transportType: 'sse',
      issuanceVelocity: 1,
      requestPayloadFingerprint: 'test',
    })
    evidence.providerAttestations.push(attestation)
    assert.equal(evidence.providerAttestations.length, 1)
    assert.equal(evidence.providerAttestations[0].provider, 'security-scanner')
  })
})


// ════════════════════════════════════════════════════════════
// addIdentityBoundary tests (xsa520 decision artifact insight)
// ════════════════════════════════════════════════════════════

describe('addIdentityBoundary', () => {
  it('should add boundary and content hash', () => {
    const receipt = {
      agentId: 'agent-001',
      sourceId: 'data-source-x',
      amount: 0.003,
    }
    const result = addIdentityBoundary(receipt)
    assert.ok(result._identityBoundary)
    assert.ok(result._contentHash)
    assert.equal(result._contentHash.length, 64) // SHA-256
    assert.deepEqual(result._identityBoundary, ['agentId', 'amount', 'sourceId']) // sorted
  })

  it('should produce same hash for same data regardless of field order', () => {
    const a = addIdentityBoundary({ x: 1, y: 2, z: 3 })
    const b = addIdentityBoundary({ z: 3, x: 1, y: 2 })
    assert.equal(a._contentHash, b._contentHash)
  })

  it('should produce different hash for different data', () => {
    const a = addIdentityBoundary({ x: 1 })
    const b = addIdentityBoundary({ x: 2 })
    assert.notEqual(a._contentHash, b._contentHash)
  })

  it('should support custom field selection', () => {
    const obj = { agentId: 'a', sourceId: 's', timestamp: '2026-01-01', noise: 'irrelevant' }
    const result = addIdentityBoundary(obj, ['agentId', 'sourceId'])
    assert.deepEqual(result._identityBoundary, ['agentId', 'sourceId'])
    // Hash should not change if noise changes
    const obj2 = { ...obj, noise: 'different' }
    const result2 = addIdentityBoundary(obj2, ['agentId', 'sourceId'])
    assert.equal(result._contentHash, result2._contentHash)
  })

  it('should exclude _ prefixed fields from auto boundary', () => {
    const obj = { x: 1, _internal: 'skip', y: 2 }
    const result = addIdentityBoundary(obj)
    assert.deepEqual(result._identityBoundary, ['x', 'y'])
  })
})
