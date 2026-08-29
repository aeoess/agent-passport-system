// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import {
  createGovernanceArtifact, verifyGovernanceArtifact,
  approveArtifact, verifyApproval,
  createGovernanceEnvelope, loadGovernanceArtifact,
  upgradeGovernanceArtifact, hashContent, classifyGovernanceChange,
  DEFAULT_LOAD_POLICY, ANY_ISSUER,
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

  // ══════════════════════════════════════
  // Gap 8B: Monotonic Governance — Weakening Controls
  // ══════════════════════════════════════

  describe('classifyGovernanceChange', () => {
    it('detects strengthening (additions only)', () => {
      const diff = classifyGovernanceChange(
        ['F-001', 'F-002'],
        ['F-001', 'F-002', 'F-003']
      )
      assert.equal(diff.changeType, 'strengthening')
      assert.deepEqual(diff.additions, ['F-003'])
      assert.deepEqual(diff.removals, [])
      assert.equal(diff.isStrengthening, true)
      assert.equal(diff.isWeakening, false)
    })

    it('detects weakening (removals)', () => {
      const diff = classifyGovernanceChange(
        ['F-001', 'F-002', 'F-003'],
        ['F-001', 'F-002']
      )
      assert.equal(diff.changeType, 'weakening')
      assert.deepEqual(diff.removals, ['F-003'])
      assert.deepEqual(diff.additions, [])
      assert.equal(diff.isWeakening, true)
      assert.equal(diff.isStrengthening, false)
    })

    it('detects mixed (additions + removals)', () => {
      const diff = classifyGovernanceChange(
        ['F-001', 'F-002'],
        ['F-001', 'F-003']
      )
      assert.equal(diff.changeType, 'mixed')
      assert.deepEqual(diff.additions, ['F-003'])
      assert.deepEqual(diff.removals, ['F-002'])
      assert.equal(diff.isWeakening, true)
      assert.equal(diff.isStrengthening, false)
    })

    it('detects neutral (no changes)', () => {
      const diff = classifyGovernanceChange(
        ['F-001', 'F-002'],
        ['F-001', 'F-002']
      )
      assert.equal(diff.changeType, 'neutral')
      assert.deepEqual(diff.additions, [])
      assert.deepEqual(diff.removals, [])
    })
  })

  describe('weakening controls (policy enforcement)', () => {
    it('blocks weakening without approval', () => {
      const v1 = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      const v2 = upgradeGovernanceArtifact(v1, {
        version: '2.0.0', content: 'weakened',
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
        changeType: 'weakening', removals: ['F-002'],
      })
      const envelope = createGovernanceEnvelope(v2)
      const result = loadGovernanceArtifact(envelope, DEFAULT_LOAD_POLICY, v1)
      assert.equal(result.valid, false)
      assert.equal(result.weakeningApproved, false)
      assert.ok(result.errors.some(e => e.includes('Removal requires')))
    })

    it('allows weakening with sufficient approvals for removal', () => {
      const v1 = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      const v2 = upgradeGovernanceArtifact(v1, {
        version: '2.0.0', content: 'weakened',
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
        changeType: 'weakening', removals: ['F-002'],
      })
      // DEFAULT_LOAD_POLICY requires 2 approvals for removal
      const a1 = approveArtifact(v2, approver1.privateKey, approver1.publicKey)
      const a2 = approveArtifact(v2, approver2.privateKey, approver2.publicKey)
      const envelope = createGovernanceEnvelope(v2, [a1, a2])
      const result = loadGovernanceArtifact(envelope, DEFAULT_LOAD_POLICY, v1)
      assert.equal(result.valid, true)
      assert.equal(result.weakeningApproved, true)
    })

    it('requires fewer approvals for weakening without removal', () => {
      const v1 = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      const v2 = upgradeGovernanceArtifact(v1, {
        version: '2.0.0', content: 'softened enforcement',
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
        changeType: 'weakening', modifications: ['F-001'],
      })
      // DEFAULT_LOAD_POLICY: requireApprovalsForWeakening = 1 (less than removal = 2)
      const a1 = approveArtifact(v2, approver1.privateKey, approver1.publicKey)
      const envelope = createGovernanceEnvelope(v2, [a1])
      const result = loadGovernanceArtifact(envelope, DEFAULT_LOAD_POLICY, v1)
      assert.equal(result.valid, true)
      assert.equal(result.weakeningApproved, true)
    })

    it('allows strengthening without extra approvals', () => {
      const v1 = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      const v2 = upgradeGovernanceArtifact(v1, {
        version: '2.0.0', content: FLOOR_CONTENT + '\nF-003: new principle',
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
        changeType: 'strengthening', additions: ['F-003'],
      })
      const envelope = createGovernanceEnvelope(v2)
      const result = loadGovernanceArtifact(envelope, DEFAULT_LOAD_POLICY, v1)
      assert.equal(result.valid, true)
      assert.equal(result.weakeningApproved, true)
    })

    it('stores change classification in artifact', () => {
      const v1 = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      assert.equal(v1.changeType, 'initial')
      assert.deepEqual(v1.additions, [])
      assert.deepEqual(v1.removals, [])

      const v2 = upgradeGovernanceArtifact(v1, {
        version: '2.0.0', content: 'new',
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
        changeType: 'weakening', removals: ['F-007'], modifications: ['F-006'],
      })
      assert.equal(v2.changeType, 'weakening')
      assert.deepEqual(v2.removals, ['F-007'])
      assert.deepEqual(v2.modifications, ['F-006'])
    })

    it('mixed change requires removal-level approvals', () => {
      const v1 = createGovernanceArtifact({
        artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      })
      const v2 = upgradeGovernanceArtifact(v1, {
        version: '2.0.0', content: 'mixed',
        issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
        changeType: 'mixed', additions: ['F-008'], removals: ['F-002'],
      })
      // 1 approval — insufficient for removal (needs 2)
      const a1 = approveArtifact(v2, approver1.privateKey, approver1.publicKey)
      const envelope = createGovernanceEnvelope(v2, [a1])
      const result = loadGovernanceArtifact(envelope, DEFAULT_LOAD_POLICY, v1)
      assert.equal(result.valid, false)
      assert.ok(result.errors.some(e => e.includes('Removal requires 2')))
    })
  })
})

// ══════════════════════════════════════════════════════════════════
// Invariant: an empty trust-anchor set does not mean "trust anyone".
// ══════════════════════════════════════════════════════════════════
// GovernanceLoadPolicy.allowedIssuers was guarded with
// `allowedIssuers.length > 0 && ...`, so an empty list skipped the check
// and admitted any issuer. DEFAULT_LOAD_POLICY shipped with [], which is
// the shape a caller writes when they mean "none", so the permissive
// reading was invisible at the call site. Wildcard trust is now spelled
// ['*'] and an empty list rejects.

describe('Governance load policy: wildcard issuer trust is written down', () => {
  const issuer = generateKeyPair()

  function envelope() {
    const artifact = createGovernanceArtifact({
      artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
      issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
    })
    return createGovernanceEnvelope(artifact)
  }

  it('the shipped default states wildcard trust explicitly', () => {
    assert.deepEqual(DEFAULT_LOAD_POLICY.allowedIssuers, ['*'])
  })

  it('an empty allowedIssuers list rejects every issuer', () => {
    const policy: GovernanceLoadPolicy = { ...DEFAULT_LOAD_POLICY, allowedIssuers: [] }
    const result = loadGovernanceArtifact(envelope(), policy)
    assert.equal(result.valid, false)
    assert.ok(
      result.errors.some(e => e.includes('no allowed issuers')),
      `expected an empty-allowlist error, got ${JSON.stringify(result.errors)}`,
    )
  })

  it("['*'] admits any issuer", () => {
    const policy: GovernanceLoadPolicy = { ...DEFAULT_LOAD_POLICY, allowedIssuers: ['*'] }
    const result = loadGovernanceArtifact(envelope(), policy)
    assert.equal(result.valid, true, result.errors.join(' | '))
  })

  it('a named allowlist still admits the named issuer and only that one', () => {
    const other = generateKeyPair()
    const named: GovernanceLoadPolicy = { ...DEFAULT_LOAD_POLICY, allowedIssuers: [issuer.publicKey] }
    assert.equal(loadGovernanceArtifact(envelope(), named).valid, true)
    const wrong: GovernanceLoadPolicy = { ...DEFAULT_LOAD_POLICY, allowedIssuers: [other.publicKey] }
    assert.equal(loadGovernanceArtifact(envelope(), wrong).valid, false)
  })
})

// ══════════════════════════════════════════════════════════════════
// Invariant: appending your key to the shipped default must HARDEN
// the policy, never disable it.
// ══════════════════════════════════════════════════════════════════
// Round 1 of this work moved DEFAULT_LOAD_POLICY.allowedIssuers from []
// to ['*'] so that wildcard trust was written down. That fixed the
// "empty means everyone" reading and introduced a worse one: '*' survives
// concatenation, so the idiom an operator uses to harden a policy,
// spreading the default and appending their own key, produced
// ['*', myKey] and admitted every issuer. This file spreads the default
// at eight other sites, so the idiom is native here.
//
// The wildcard is now honoured ONLY when it is the sole entry. Any other
// entry alongside it means the operator named issuers, and naming issuers
// is a closed allowlist.

describe('Governance load policy: the wildcard cannot be extended into', () => {
  const issuer = generateKeyPair()
  const operator = generateKeyPair()

  function envelope(byKey = issuer) {
    const artifact = createGovernanceArtifact({
      artifactType: 'floor', version: '1.0.0', content: FLOOR_CONTENT,
      issuerPrivateKey: byKey.privateKey, issuerPublicKey: byKey.publicKey,
    })
    return createGovernanceEnvelope(artifact)
  }

  it('appending a key to the default admits ONLY that key', () => {
    const hardened: GovernanceLoadPolicy = {
      ...DEFAULT_LOAD_POLICY,
      allowedIssuers: [...DEFAULT_LOAD_POLICY.allowedIssuers, operator.publicKey],
    }
    const unlisted = loadGovernanceArtifact(envelope(issuer), hardened)
    assert.equal(unlisted.valid, false, 'an unlisted issuer must not load under a hardened policy')
    assert.ok(unlisted.errors.some(e => e.includes('not in allowed issuers')))

    const listed = loadGovernanceArtifact(envelope(operator), hardened)
    assert.equal(listed.valid, true, listed.errors.join(' | '))
  })

  it('the wildcard alongside named issuers is reported, not silently dropped', () => {
    const hardened: GovernanceLoadPolicy = {
      ...DEFAULT_LOAD_POLICY,
      allowedIssuers: [...DEFAULT_LOAD_POLICY.allowedIssuers, operator.publicKey],
    }
    const result = loadGovernanceArtifact(envelope(operator), hardened)
    assert.ok(
      result.warnings.some(w => w.includes('wildcard')),
      `expected the ignored wildcard to be reported, got ${JSON.stringify(result.warnings)}`,
    )
  })

  it('an artifact whose issuer literally is "*" cannot match a named allowlist', () => {
    const policy: GovernanceLoadPolicy = {
      ...DEFAULT_LOAD_POLICY,
      allowedIssuers: [ANY_ISSUER, operator.publicKey],
    }
    const env = envelope(operator)
    env.artifact.issuer = ANY_ISSUER
    const result = loadGovernanceArtifact(env, policy)
    assert.equal(result.valid, false)
  })

  it('the sole wildcard still admits any issuer, so the shipped default is unchanged', () => {
    assert.deepEqual(DEFAULT_LOAD_POLICY.allowedIssuers, [ANY_ISSUER])
    assert.equal(loadGovernanceArtifact(envelope(issuer), DEFAULT_LOAD_POLICY).valid, true)
    assert.equal(loadGovernanceArtifact(envelope(operator), DEFAULT_LOAD_POLICY).valid, true)
  })

  it('spreading the default and emptying the list still admits nobody', () => {
    const closed: GovernanceLoadPolicy = { ...DEFAULT_LOAD_POLICY, allowedIssuers: [] }
    assert.equal(loadGovernanceArtifact(envelope(issuer), closed).valid, false)
  })
})
