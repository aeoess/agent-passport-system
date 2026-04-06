// Trust Bootstrap Adapters — API key, GitHub, CI with upgrade path
// Every adapter creates a FRESH keypair. External credentials are trust
// inputs, not identity material. Raw credentials NEVER touch the SDK.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  bootstrapFromAPIKey, bootstrapFromGitHub, bootstrapFromCIKey,
  upgradeBootstrappedPassport,
} from '../src/core/trust-adapters.js'
import { verify } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import type { ImportEvidence } from '../src/core/trust-adapters.js'

describe('Trust Bootstrap — bootstrapFromAPIKey', () => {
  it('creates valid passport with fresh keypair', () => {
    const result = bootstrapFromAPIKey({
      identifierHash: 'abc123hash',
      provider: 'openai',
      name: 'my-agent',
      owner: 'tester',
    })

    assert.ok(result.passport)
    assert.ok(result.keyPair.publicKey)
    assert.ok(result.keyPair.privateKey)
    assert.equal(result.passport.passport.publicKey, result.keyPair.publicKey)
    // Verify signature
    const valid = verify(
      canonicalize(result.passport.passport),
      result.passport.signature,
      result.keyPair.publicKey,
    )
    assert.ok(valid)
  })

  it('identifierHash stored in metadata, raw key never present', () => {
    const result = bootstrapFromAPIKey({
      identifierHash: 'hmac_sha256_of_my_api_key',
      provider: 'anthropic',
    })

    const meta = result.passport.passport.metadata as any
    assert.ok(meta.importedFrom)
    assert.equal(meta.importedFrom.identifier_hash, 'hmac_sha256_of_my_api_key')
    assert.equal(meta.importedFrom.source, 'api_key_hash')
    // No raw key anywhere
    const fullJson = JSON.stringify(result)
    assert.ok(!fullJson.includes('raw_api_key'))
  })

  it('different identifierHash produces different agentId (fresh keypair)', () => {
    const r1 = bootstrapFromAPIKey({ identifierHash: 'hash1', provider: 'x' })
    const r2 = bootstrapFromAPIKey({ identifierHash: 'hash2', provider: 'x' })

    assert.notEqual(r1.keyPair.publicKey, r2.keyPair.publicKey)
    assert.notEqual(r1.passport.passport.agentId, r2.passport.passport.agentId)
  })

  it('suggestedGrade = 0 (no cryptographic proof)', () => {
    const result = bootstrapFromAPIKey({ identifierHash: 'h', provider: 'test' })
    assert.equal(result.suggestedGrade, 0)
  })

  it('warning strings present and actionable', () => {
    const result = bootstrapFromAPIKey({ identifierHash: 'h', provider: 'openai' })
    assert.ok(result.warnings.length > 0)
    assert.ok(result.warnings[0].includes('Bootstrapped'))
    assert.ok(result.warnings[0].includes('Grade 2+'))
  })
})

describe('Trust Bootstrap — bootstrapFromGitHub', () => {
  it('without token: verified=false, warns, suggestedGrade=0', async () => {
    const result = await bootstrapFromGitHub({
      username: 'testuser',
      org: 'testorg',
    })

    assert.equal(result.importEvidence.verified, false)
    assert.equal(result.suggestedGrade, 0)
    assert.ok(result.warnings.some(w => w.includes('UNVERIFIED')))
    assert.equal(result.importEvidence.assurance_input, 'low')
  })

  it('creates valid signed passport', async () => {
    const result = await bootstrapFromGitHub({
      username: 'aeoess',
      org: 'aeoess',
    })

    const valid = verify(
      canonicalize(result.passport.passport),
      result.passport.signature,
      result.keyPair.publicKey,
    )
    assert.ok(valid)
    assert.equal(result.passport.passport.agentName, 'aeoess@aeoess')
  })

  it('importEvidence in metadata with org and username', async () => {
    const result = await bootstrapFromGitHub({
      username: 'user1',
      org: 'myorg',
    })

    const meta = result.passport.passport.metadata as any
    assert.ok(meta.importedFrom)
    assert.equal(meta.importedFrom.source, 'github_org')
    assert.equal((meta.importedFrom.metadata as any).org, 'myorg')
    assert.equal((meta.importedFrom.metadata as any).username, 'user1')
  })
})

describe('Trust Bootstrap — bootstrapFromCIKey', () => {
  it('CI evidence attached, suggestedGrade=2', () => {
    const result = bootstrapFromCIKey({
      publicKeyHex: 'a'.repeat(64),
      provider: 'github-actions',
      workflowId: 'deploy-prod',
      repoUrl: 'https://github.com/test/repo',
    })

    assert.equal(result.suggestedGrade, 2)
    assert.equal(result.importEvidence.source, 'ci_signing_key')
    assert.equal(result.importEvidence.verified, true)
    assert.equal(result.importEvidence.assurance_input, 'high')
  })

  it('CI public key in evidence metadata, fresh APS keypair', () => {
    const ciKey = 'b'.repeat(64)
    const result = bootstrapFromCIKey({
      publicKeyHex: ciKey,
      provider: 'gitlab-ci',
    })

    assert.notEqual(result.keyPair.publicKey, ciKey)
    const meta = result.passport.passport.metadata as any
    assert.equal((meta.importedFrom.metadata as any).ci_public_key, ciKey)
  })

  it('warning includes upgrade path', () => {
    const result = bootstrapFromCIKey({
      publicKeyHex: 'c'.repeat(64),
      provider: 'circleci',
    })
    assert.ok(result.warnings[0].includes('Grade 2+'))
  })
})

describe('Trust Bootstrap — upgradeBootstrappedPassport', () => {
  it('links old identity to new, preserves history', () => {
    const original = bootstrapFromAPIKey({
      identifierHash: 'upgrade_test',
      provider: 'test',
      name: 'original-agent',
    })

    const { upgradedPassport, previousAgentId } = upgradeBootstrappedPassport({
      existingPassport: original.passport,
      existingKeyPair: original.keyPair,
      newAttestation: { type: 'runtime', score: 0.95 },
    })

    assert.equal(previousAgentId, original.passport.passport.agentId)
    const meta = upgradedPassport.passport.metadata as any
    assert.equal(meta.upgradedFrom, previousAgentId)
    assert.ok(meta.upgradeAttestation)
    assert.ok(meta.upgradedAt)
  })

  it('upgraded passport passes signature verification', () => {
    const original = bootstrapFromAPIKey({
      identifierHash: 'verify_upgrade',
      provider: 'test',
    })

    const { upgradedPassport } = upgradeBootstrappedPassport({
      existingPassport: original.passport,
      existingKeyPair: original.keyPair,
      newAttestation: { verified: true },
    })

    const valid = verify(
      canonicalize(upgradedPassport.passport),
      upgradedPassport.signature,
      original.keyPair.publicKey,
    )
    assert.ok(valid)
  })
})

describe('Trust Bootstrap — Cross-cutting', () => {
  it('all bootstrapped passports have importEvidence in metadata, NOT in SignedPassport type', () => {
    const r1 = bootstrapFromAPIKey({ identifierHash: 'h', provider: 'x' })
    // importEvidence is in metadata, not a top-level field on SignedPassport
    assert.equal((r1.passport as any).importEvidence, undefined)
    assert.ok((r1.passport.passport.metadata as any).importedFrom)
  })

  it('importEvidence interface has all required fields', () => {
    const ev: ImportEvidence = {
      source: 'api_key_hash',
      identifier_hash: 'test',
      verified: false,
      assurance_input: 'low',
    }
    assert.ok(ev.source)
    assert.ok(ev.identifier_hash)
    assert.equal(ev.verified, false)
    assert.equal(ev.assurance_input, 'low')
  })
})
