import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import {
  createGovernanceArtifact, verifyGovernanceArtifact,
  approveArtifact, verifyApproval,
  createGovernanceEnvelope, loadGovernanceArtifact,
  upgradeGovernanceArtifact, hashContent,
  DEFAULT_LOAD_POLICY,
} from '../src/core/governance.js'
import type { GovernanceLoadPolicy } from '../src/types/governance.js'

const FLOOR_CONTENT = `
principles:
  - id: F-001
    name: Traceability
    enforcement: mandatory
  - id: F-002
    name: Honest Identity
    enforcement: mandatory
`

describe('Governance Artifact Provenance', () => {
  const issuer = generateKeyPair()
  const approver1 = generateKeyPair()
  const approver2 = generateKeyPair()

  describe('createGovernanceArtifact', () => {
    it('creates a signed artifact with content hash', () => {
      const artifact = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      assert.ok(artifact.artifactId.startsWith('gov_'))
      assert.equal(artifact.artifactType, 'floor')
      assert.equal(artifact.version, '1.0.0')
      assert.equal(artifact.contentHash, hashContent(FLOOR_CONTENT))
      assert.equal(artifact.issuer, issuer.publicKey)
      assert.ok(artifact.signature.length > 0)
      assert.equal(artifact.previousVersion, null)
      assert.equal(artifact.breaking, false)
    })

    it('includes metadata and expiry fields', () => {
      const artifact = createGovernanceArtifact({
        artifactType: 'policy', version: '2.1.0', content: 'policy content',
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
        expiresAt: '2026-12-31T23:59:59.000Z', breaking: true,
        rollbackAllowed: false, metadata: { region: 'eu' },
      })
      assert.equal(artifact.breaking, true)
      assert.equal(artifact.rollbackAllowed, false)
      assert.deepEqual(artifact.metadata, { region: 'eu' })
    })
  })

  describe('verifyGovernanceArtifact', () => {
    it('verifies a valid artifact', () => {
      const artifact = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      const result = verifyGovernanceArtifact(artifact)
      assert.equal(result.valid, true)
      assert.equal(result.contentIntegrity, true)
      assert.equal(result.signatureValid, true)
      assert.equal(result.notExpired, true)
      assert.deepEqual(result.errors, [])
    })

    it('detects tampered content', () => {
      const artifact = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      artifact.content = 'TAMPERED'
      const result = verifyGovernanceArtifact(artifact)
      assert.equal(result.valid, false)
      assert.equal(result.contentIntegrity, false)
    })

    it('detects tampered signature', () => {
      const artifact = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      artifact.signature = 'deadbeef'.repeat(16)
      const result = verifyGovernanceArtifact(artifact)
      assert.equal(result.valid, false)
      assert.equal(result.signatureValid, false)
    })

    it('detects expired artifact', () => {
      const artifact = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
        expiresAt: '2020-01-01T00:00:00.000Z',
      })
      const result = verifyGovernanceArtifact(artifact)
      assert.equal(result.valid, false)
      assert.equal(result.notExpired, false)
    })

    it('validates version chain', () => {
      const v1 = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      const v2 = upgradeGovernanceArtifact(v1, {
        version: '2.0.0', content: FLOOR_CONTENT + '\nnew',
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      const result = verifyGovernanceArtifact(v2, v1)
      assert.equal(result.valid, true)
      assert.equal(result.chainValid, true)
    })

    it('detects broken version chain', () => {
      const v1 = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      const fake = createGovernanceArtifact({
        artifactType: 'floor', version: '0.9.0', content: 'fake',
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      const v2 = upgradeGovernanceArtifact(v1, {
        version: '2.0.0', content: 'new',
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      const result = verifyGovernanceArtifact(v2, fake)
      assert.equal(result.chainValid, false)
    })
  })

  describe('approvals', () => {
    it('creates and verifies an approval', () => {
      const artifact = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      const approval = approveArtifact(artifact, approver1.privateKey, approver1.publicKey)
      assert.equal(approval.artifactId, artifact.artifactId)
      assert.ok(verifyApproval(approval, artifact))
    })

    it('rejects approval for wrong artifact', () => {
      const a1 = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: 'a',
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      const a2 = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: 'b',
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      const approval = approveArtifact(a1, approver1.privateKey, approver1.publicKey)
      assert.equal(verifyApproval(approval, a2), false)
    })

    it('rejects tampered approval', () => {
      const artifact = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      const approval = approveArtifact(artifact, approver1.privateKey, approver1.publicKey)
      approval.signature = 'deadbeef'.repeat(16)
      assert.equal(verifyApproval(approval, artifact), false)
    })
  })

  describe('loadGovernanceArtifact (policy enforcement)', () => {
    it('loads with default policy', () => {
      const artifact = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      const envelope = createGovernanceEnvelope(artifact)
      const result = loadGovernanceArtifact(envelope, DEFAULT_LOAD_POLICY)
      assert.equal(result.valid, true)
    })

    it('rejects issuer not in allowed list', () => {
      const artifact = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      const envelope = createGovernanceEnvelope(artifact)
      const policy: GovernanceLoadPolicy = {
        ...DEFAULT_LOAD_POLICY, allowedIssuers: [approver1.publicKey],
      }
      const result = loadGovernanceArtifact(envelope, policy)
      assert.equal(result.valid, false)
      assert.ok(result.errors.some(e => e.includes('not in allowed issuers')))
    })

    it('requires N approvals', () => {
      const artifact = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      const a1 = approveArtifact(artifact, approver1.privateKey, approver1.publicKey)
      const policy: GovernanceLoadPolicy = { ...DEFAULT_LOAD_POLICY, requireApprovals: 2 }

      // 1 approval — should fail
      const r1 = loadGovernanceArtifact(createGovernanceEnvelope(artifact, [a1]), policy)
      assert.equal(r1.valid, false)

      // 2 approvals — should pass
      const a2 = approveArtifact(artifact, approver2.privateKey, approver2.publicKey)
      const r2 = loadGovernanceArtifact(createGovernanceEnvelope(artifact, [a1, a2]), policy)
      assert.equal(r2.valid, true)
    })

    it('rejects breaking change without approval', () => {
      const artifact = createGovernanceArtifact({
        artifactType: 'floor', version: '2.0.0', content: 'breaking',
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
        breaking: true,
      })
      const envelope = createGovernanceEnvelope(artifact)
      const policy: GovernanceLoadPolicy = {
        ...DEFAULT_LOAD_POLICY, allowBreakingWithoutApproval: false,
      }
      const result = loadGovernanceArtifact(envelope, policy)
      assert.equal(result.valid, false)
      assert.ok(result.errors.some(e => e.includes('Breaking change')))
    })

    it('allows breaking change with approval', () => {
      const artifact = createGovernanceArtifact({
        artifactType: 'floor', version: '2.0.0', content: 'breaking',
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
        breaking: true,
      })
      const a1 = approveArtifact(artifact, approver1.privateKey, approver1.publicKey)
      const envelope = createGovernanceEnvelope(artifact, [a1])
      const policy: GovernanceLoadPolicy = {
        ...DEFAULT_LOAD_POLICY, allowBreakingWithoutApproval: false,
      }
      const result = loadGovernanceArtifact(envelope, policy)
      assert.equal(result.valid, true)
    })
  })

  describe('upgradeGovernanceArtifact', () => {
    it('creates linked version chain', () => {
      const v1 = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      const v2 = upgradeGovernanceArtifact(v1, {
        version: '1.1.0', content: FLOOR_CONTENT + '\nnew',
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      assert.equal(v2.previousVersion, '1.0.0')
      assert.equal(v2.previousArtifactId, v1.artifactId)
      assert.equal(v2.supersedes, v1.artifactId)
      assert.equal(v2.artifactType, 'floor')

      const result = verifyGovernanceArtifact(v2, v1)
      assert.equal(result.valid, true)
      assert.equal(result.chainValid, true)
    })
  })
})
