// Principal Identity Tests
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  createPrincipalIdentity, endorseAgent, verifyEndorsement,
  revokeEndorsement, createDisclosure, verifyDisclosure,
  createFleet, addToFleet, getFleetStatus, revokeFromFleet,
  endorsePassport, verifyPassportEndorsement, hasPrincipalEndorsement
} from '../src/core/principal.js'
import { createPassport } from '../src/core/passport.js'
import { generateKeyPair } from '../src/crypto/keys.js'

describe('Principal Identity', () => {
  describe('createPrincipalIdentity', () => {
    it('creates a principal with keypair', () => {
      const { principal, keyPair } = createPrincipalIdentity({
        displayName: 'Tima',
        domain: 'aeoess.com',
        jurisdiction: 'US',
        contactChannel: 'telegram:@aeoess'
      })
      assert.ok(principal.principalId.startsWith('principal-'))
      assert.equal(principal.displayName, 'Tima')
      assert.equal(principal.domain, 'aeoess.com')
      assert.equal(principal.jurisdiction, 'US')
      assert.equal(principal.disclosureLevel, 'public')
      assert.ok(keyPair.publicKey)
      assert.ok(keyPair.privateKey)
    })

    it('defaults to public disclosure', () => {
      const { principal } = createPrincipalIdentity({ displayName: 'Test' })
      assert.equal(principal.disclosureLevel, 'public')
    })

    it('respects custom disclosure level', () => {
      const { principal } = createPrincipalIdentity({
        displayName: 'Test',
        disclosureLevel: 'minimal'
      })
      assert.equal(principal.disclosureLevel, 'minimal')
    })
  })

  describe('endorseAgent + verifyEndorsement', () => {
    it('creates a valid endorsement', () => {
      const { principal, keyPair } = createPrincipalIdentity({ displayName: 'Owner' })
      const { signedPassport } = createPassport({
        agentId: 'agent-001', agentName: 'Bot',
        ownerAlias: 'owner', mission: 'Help',
        capabilities: ['web_search'],
        runtime: { platform: 'node', models: [], toolsCount: 1, memoryType: 'none' }
      })

      const endorsement = endorseAgent({
        principal, principalPrivateKey: keyPair.privateKey,
        agentId: 'agent-001', agentPublicKey: signedPassport.passport.publicKey,
        scope: ['web_search', 'code_execution'],
        relationship: 'creator'
      })

      assert.ok(endorsement.endorsementId.startsWith('endorsement-'))
      assert.equal(endorsement.principalId, principal.principalId)
      assert.equal(endorsement.agentId, 'agent-001')
      assert.equal(endorsement.relationship, 'creator')
      assert.equal(endorsement.revoked, false)
      assert.ok(endorsement.signature)

      const result = verifyEndorsement(endorsement)
      assert.equal(result.valid, true)
      assert.equal(result.errors.length, 0)
    })

    it('rejects tampered endorsement', () => {
      const { principal, keyPair } = createPrincipalIdentity({ displayName: 'Owner' })
      const endorsement = endorseAgent({
        principal, principalPrivateKey: keyPair.privateKey,
        agentId: 'agent-001', agentPublicKey: 'a'.repeat(64),
        scope: ['web_search'], relationship: 'operator'
      })

      // Tamper with scope
      endorsement.scope = ['admin']
      const result = verifyEndorsement(endorsement)
      assert.equal(result.valid, false)
      assert.ok(result.errors.includes('Invalid signature'))
    })
  })

  describe('revokeEndorsement', () => {
    it('marks endorsement as revoked', () => {
      const { principal, keyPair } = createPrincipalIdentity({ displayName: 'Owner' })
      const endorsement = endorseAgent({
        principal, principalPrivateKey: keyPair.privateKey,
        agentId: 'agent-001', agentPublicKey: 'b'.repeat(64),
        scope: ['web_search'], relationship: 'creator'
      })

      const revoked = revokeEndorsement(endorsement, 'Agent compromised')
      assert.equal(revoked.revoked, true)
      assert.ok(revoked.revokedAt)
      assert.equal(revoked.revokedReason, 'Agent compromised')

      const result = verifyEndorsement(revoked)
      assert.equal(result.valid, false)
      assert.equal(result.revoked, true)
    })
  })

  describe('Selective Disclosure', () => {
    it('creates public disclosure with all fields', () => {
      const { principal, keyPair } = createPrincipalIdentity({
        displayName: 'Tima', domain: 'aeoess.com',
        jurisdiction: 'US', contactChannel: 'telegram:@aeoess'
      })

      const disclosure = createDisclosure(principal, keyPair.privateKey, 'public')
      assert.equal(disclosure.level, 'public')
      assert.ok(disclosure.revealedFields.displayName)
      assert.ok(disclosure.revealedFields.domain)
      assert.ok(disclosure.revealedFields.jurisdiction)
      assert.ok(disclosure.revealedFields.contactChannel)
      assert.ok(disclosure.proof)
    })

    it('creates minimal disclosure with only hash + DID', () => {
      const { principal, keyPair } = createPrincipalIdentity({
        displayName: 'Tima', domain: 'aeoess.com'
      })

      const disclosure = createDisclosure(principal, keyPair.privateKey, 'minimal')
      assert.equal(disclosure.level, 'minimal')
      assert.ok(disclosure.revealedFields.idHash)
      assert.ok(disclosure.revealedFields.did)
      assert.equal(disclosure.revealedFields.displayName, undefined)
      assert.equal(disclosure.revealedFields.domain, undefined)
    })

    it('creates verified-only disclosure with limited fields', () => {
      const { principal, keyPair } = createPrincipalIdentity({
        displayName: 'Tima', domain: 'aeoess.com'
      })

      const disclosure = createDisclosure(principal, keyPair.privateKey, 'verified-only')
      assert.equal(disclosure.level, 'verified-only')
      assert.ok(disclosure.revealedFields.principalId)
      assert.ok(disclosure.revealedFields.publicKey)
      assert.ok(disclosure.revealedFields.domain)
      assert.equal(disclosure.revealedFields.displayName, undefined)
    })

    it('verifies valid disclosure', () => {
      const { principal, keyPair } = createPrincipalIdentity({ displayName: 'Test' })
      const disclosure = createDisclosure(principal, keyPair.privateKey, 'public')
      const result = verifyDisclosure(disclosure)
      assert.equal(result.valid, true)
    })

    it('rejects tampered disclosure', () => {
      const { principal, keyPair } = createPrincipalIdentity({ displayName: 'Test' })
      const disclosure = createDisclosure(principal, keyPair.privateKey, 'public')
      disclosure.revealedFields.displayName = 'HACKED'
      const result = verifyDisclosure(disclosure)
      assert.equal(result.valid, false)
    })
  })

  describe('Fleet Management', () => {
    it('creates and populates a fleet', () => {
      const { principal, keyPair } = createPrincipalIdentity({ displayName: 'Fleet Owner' })
      let fleet = createFleet(principal)
      assert.equal(fleet.agents.length, 0)

      const e1 = endorseAgent({
        principal, principalPrivateKey: keyPair.privateKey,
        agentId: 'bot-1', agentPublicKey: 'a'.repeat(64),
        scope: ['web_search'], relationship: 'creator'
      })
      const e2 = endorseAgent({
        principal, principalPrivateKey: keyPair.privateKey,
        agentId: 'bot-2', agentPublicKey: 'b'.repeat(64),
        scope: ['code_execution'], relationship: 'operator'
      })

      fleet = addToFleet(fleet, e1)
      fleet = addToFleet(fleet, e2)

      const status = getFleetStatus(fleet)
      assert.equal(status.totalAgents, 2)
      assert.equal(status.activeAgents, 2)
      assert.equal(status.revokedAgents, 0)
    })

    it('revokes an agent from fleet', () => {
      const { principal, keyPair } = createPrincipalIdentity({ displayName: 'Owner' })
      let fleet = createFleet(principal)

      const e1 = endorseAgent({
        principal, principalPrivateKey: keyPair.privateKey,
        agentId: 'bot-1', agentPublicKey: 'c'.repeat(64),
        scope: ['web_search'], relationship: 'creator'
      })
      fleet = addToFleet(fleet, e1)
      fleet = revokeFromFleet(fleet, 'bot-1')

      const status = getFleetStatus(fleet)
      assert.equal(status.activeAgents, 0)
      assert.equal(status.revokedAgents, 1)
    })
  })

  describe('Passport Endorsement', () => {
    it('endorses a passport and embeds principal identity', () => {
      const { principal, keyPair: principalKP } = createPrincipalIdentity({
        displayName: 'Tima', domain: 'aeoess.com'
      })
      const { signedPassport } = createPassport({
        agentId: 'agent-001', agentName: 'Helper Bot',
        ownerAlias: 'tima', mission: 'Assist with tasks',
        capabilities: ['web_search', 'code_execution'],
        runtime: { platform: 'node', models: ['gpt-4'], toolsCount: 5, memoryType: 'session' }
      })

      const { endorsement, endorsedPassport } = endorsePassport({
        principal, principalPrivateKey: principalKP.privateKey,
        signedPassport, scope: ['web_search', 'code_execution'],
        relationship: 'creator'
      })

      // Endorsement is valid
      assert.ok(endorsement.signature)
      const result = verifyEndorsement(endorsement)
      assert.equal(result.valid, true)

      // Passport has endorsement in metadata
      assert.ok(hasPrincipalEndorsement(endorsedPassport))
      const meta = endorsedPassport.passport.metadata.principalEndorsement as any
      assert.equal(meta.principalId, principal.principalId)
      assert.ok(meta.principalDID.startsWith('did:aps:'))
    })

    it('verifies passport endorsement from metadata', () => {
      const { principal, keyPair: principalKP } = createPrincipalIdentity({
        displayName: 'Owner'
      })
      const { signedPassport } = createPassport({
        agentId: 'agent-002', agentName: 'Bot',
        ownerAlias: 'owner', mission: 'Work',
        capabilities: ['web_search'],
        runtime: { platform: 'node', models: [], toolsCount: 1, memoryType: 'none' }
      })

      const { endorsedPassport } = endorsePassport({
        principal, principalPrivateKey: principalKP.privateKey,
        signedPassport, scope: ['web_search'], relationship: 'operator'
      })

      const result = verifyPassportEndorsement(endorsedPassport)
      assert.equal(result.valid, true)
      assert.equal(result.principalId, principal.principalId)
    })

    it('returns invalid for passport without endorsement', () => {
      const { signedPassport } = createPassport({
        agentId: 'agent-003', agentName: 'Naked Bot',
        ownerAlias: 'nobody', mission: 'Exist',
        capabilities: [],
        runtime: { platform: 'node', models: [], toolsCount: 0, memoryType: 'none' }
      })

      assert.equal(hasPrincipalEndorsement(signedPassport), false)
      const result = verifyPassportEndorsement(signedPassport)
      assert.equal(result.valid, false)
      assert.ok(result.errors[0].includes('No principal endorsement'))
    })

    it('verifies endorsement even when passport timestamps differ (NW-PX2 HIGH fix)', () => {
      const { principal, keyPair: principalKP } = createPrincipalIdentity({
        displayName: 'Owner'
      })
      const { signedPassport } = createPassport({
        agentId: 'agent-timing', agentName: 'Timing Bot',
        ownerAlias: 'owner', mission: 'Test timing',
        capabilities: ['web_search'],
        runtime: { platform: 'node', models: [], toolsCount: 1, memoryType: 'none' }
      })

      // Deliberately set passport timestamps to be DIFFERENT from what endorsePassport will create
      const alteredPassport = {
        ...signedPassport,
        signedAt: '2020-01-01T00:00:00.000Z',
        passport: {
          ...signedPassport.passport,
          expiresAt: '2020-12-31T00:00:00.000Z'
        }
      }

      const { endorsedPassport } = endorsePassport({
        principal, principalPrivateKey: principalKP.privateKey,
        signedPassport: alteredPassport, scope: ['web_search'], relationship: 'operator'
      })

      // This MUST pass because we now use the endorsement's own timestamps
      // from metadata, not the passport's timestamps
      const result = verifyPassportEndorsement(endorsedPassport)
      assert.equal(result.valid, true, 'Endorsement should verify using its own timestamps, not passport timestamps')
      assert.equal(result.principalId, principal.principalId)
    })
  })

  describe('Minimal Disclosure Hash Strength (NW-PX2 HIGH fix)', () => {
    it('simpleHash produces SHA-256 output (64 hex chars)', () => {
      const { principal, keyPair } = createPrincipalIdentity({
        displayName: 'Test', domain: 'test.com'
      })
      const disclosure = createDisclosure(principal, keyPair.privateKey, 'minimal')
      const idHash = disclosure.revealedFields.idHash as string
      // SHA-256 produces 64 hex characters. Old 32-bit hash produced 8.
      assert.equal(idHash.length, 64, 'idHash should be SHA-256 (64 hex chars), not 32-bit (8 chars)')
      assert.match(idHash, /^[0-9a-f]{64}$/, 'idHash should be valid hex')
    })

    it('different principals produce different hashes', () => {
      const { principal: p1, keyPair: k1 } = createPrincipalIdentity({ displayName: 'Alice' })
      const { principal: p2, keyPair: k2 } = createPrincipalIdentity({ displayName: 'Bob' })
      const d1 = createDisclosure(p1, k1.privateKey, 'minimal')
      const d2 = createDisclosure(p2, k2.privateKey, 'minimal')
      assert.notEqual(d1.revealedFields.idHash, d2.revealedFields.idHash)
    })
  })

  describe('Entity Binding (Corpo integration)', () => {
    it('creates principal without entityBinding (backwards compatible)', () => {
      const { principal } = createPrincipalIdentity({ displayName: 'No Entity' })
      assert.equal(principal.entityBinding, undefined)
    })

    it('creates principal with entityBinding', () => {
      const { principal } = createPrincipalIdentity({
        displayName: 'Entity-Bound Principal',
        metadata: {
          entityBinding: {
            entityId: 'corpo_ent_7f3a1234',
            jurisdiction: 'WY',
            entityType: 'dao_llc',
            operatingAgreementHash: 'sha256:abc123def456',
            verificationEndpoint: 'https://api.corpo.llc/api/v1/entities/corpo_ent_7f3a1234',
            boundAt: '2026-03-23T00:00:00Z'
          }
        }
      })
      // entityBinding is on the type but stored via metadata for now
      assert.ok(principal.metadata.entityBinding)
      const binding = principal.metadata.entityBinding as any
      assert.equal(binding.entityId, 'corpo_ent_7f3a1234')
      assert.equal(binding.jurisdiction, 'WY')
      assert.equal(binding.entityType, 'dao_llc')
    })

    it('endorsement works with entity-bound principal', () => {
      const { principal, keyPair } = createPrincipalIdentity({
        displayName: 'Entity Principal',
        metadata: {
          entityBinding: {
            entityId: 'corpo_ent_test',
            jurisdiction: 'WY',
            entityType: 'dao_llc',
            boundAt: '2026-03-23T00:00:00Z'
          }
        }
      })
      const agentKeys = generateKeyPair()
      const endorsement = endorseAgent({
        principal, principalPrivateKey: keyPair.privateKey,
        agentId: 'agent-entity-test',
        agentPublicKey: agentKeys.publicKey,
        scope: ['hold_assets', 'enter_contracts'],
        relationship: 'operator'
      })
      const verified = verifyEndorsement(endorsement)
      assert.equal(verified.valid, true)
      // Entity binding preserved in the principal that created the endorsement
      assert.ok(principal.metadata.entityBinding)
    })
  })
})
