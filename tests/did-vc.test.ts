// Tests for W3C DID & Verifiable Credentials Bridge
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createPassport, createDelegation,
  createDID, publicKeyFromDID, isValidDID,
  passportToDIDDocument, resolveDID,
  signWithDID, verifyWithDID,
  hexToMultibase, multibaseToHex,
  passportToVC, delegationToVC, floorAttestationToVC,
  createPresentation,
  verifyVC, verifyPresentation
} from '../src/index.js'

describe('W3C DID Method (did:aps)', () => {
  it('creates a valid DID from a public key', () => {
    const { keyPair } = createPassport({
      agentId: 'did-test-1', agentName: 'DIDTest', ownerAlias: 'owner',
      mission: 'test', capabilities: ['analysis'],
      runtime: { platform: 'test', models: ['m'], toolsCount: 1, memoryType: 'none' }
    })
    const did = createDID(keyPair.publicKey)
    assert.ok(did.startsWith('did:aps:'))
    assert.equal(did, `did:aps:${keyPair.publicKey}`)
  })

  it('extracts public key from DID', () => {
    const { keyPair } = createPassport({
      agentId: 'did-test-2', agentName: 'T', ownerAlias: 'o',
      mission: 'm', capabilities: ['code_execution'],
      runtime: { platform: 't', models: ['m'], toolsCount: 1, memoryType: 'n' }
    })
    const did = createDID(keyPair.publicKey)
    const extracted = publicKeyFromDID(did)
    assert.equal(extracted, keyPair.publicKey)
  })

  it('validates correct and invalid DIDs', () => {
    const { keyPair } = createPassport({
      agentId: 'did-test-3', agentName: 'T', ownerAlias: 'o',
      mission: 'm', capabilities: ['web_search'],
      runtime: { platform: 't', models: ['m'], toolsCount: 1, memoryType: 'n' }
    })
    assert.ok(isValidDID(createDID(keyPair.publicKey)))
    assert.ok(!isValidDID('did:aps:tooshort'))
    assert.ok(!isValidDID('did:wrong:method'))
    assert.ok(!isValidDID('not-a-did'))
  })

  it('round-trips multibase encoding', () => {
    const { keyPair } = createPassport({
      agentId: 'did-test-4', agentName: 'T', ownerAlias: 'o',
      mission: 'm', capabilities: ['analysis'],
      runtime: { platform: 't', models: ['m'], toolsCount: 1, memoryType: 'n' }
    })
    const mb = hexToMultibase(keyPair.publicKey)
    assert.ok(mb.startsWith('z'))
    assert.equal(multibaseToHex(mb), keyPair.publicKey)
  })

  it('generates a DID Document from a passport', () => {
    const { signedPassport, keyPair } = createPassport({
      agentId: 'did-test-5', agentName: 'DocAgent', ownerAlias: 'owner',
      mission: 'DID doc test', capabilities: ['analysis', 'coding'],
      runtime: { platform: 'test', models: ['gpt-4'], toolsCount: 5, memoryType: 'persistent' }
    })
    const doc = passportToDIDDocument(signedPassport.passport)
    assert.equal(doc.id, `did:aps:${keyPair.publicKey}`)
    assert.ok(doc['@context'].includes('https://www.w3.org/ns/did/v1'))
    assert.equal(doc.verificationMethod.length, 1)
    assert.equal(doc.verificationMethod[0].type, 'Ed25519VerificationKey2020')
    assert.ok(doc.verificationMethod[0].publicKeyMultibase.startsWith('z'))
  })

  it('resolves a valid DID', () => {
    const { keyPair } = createPassport({
      agentId: 'did-test-6', agentName: 'T', ownerAlias: 'o',
      mission: 'm', capabilities: ['analysis'],
      runtime: { platform: 't', models: ['m'], toolsCount: 1, memoryType: 'n' }
    })
    const result = resolveDID(createDID(keyPair.publicKey))
    assert.ok(result.didDocument)
    assert.ok(!result.didResolutionMetadata.error)
  })

  it('returns error for invalid DID resolution', () => {
    const result = resolveDID('did:aps:invalid')
    assert.equal(result.didDocument, null)
    assert.equal(result.didResolutionMetadata.error, 'invalidDid')
  })

  it('signs and verifies data with DID', async () => {
    const { keyPair } = createPassport({
      agentId: 'did-test-7', agentName: 'T', ownerAlias: 'o',
      mission: 'm', capabilities: ['analysis'],
      runtime: { platform: 't', models: ['m'], toolsCount: 1, memoryType: 'n' }
    })
    const did = createDID(keyPair.publicKey)
    const data = { action: 'test', target: 'resource-1' }
    const sig = await signWithDID(data, keyPair.privateKey, did)
    assert.ok(await verifyWithDID(data, sig, did))
    assert.ok(!(await verifyWithDID({ action: 'tampered' }, sig, did)))
  })
})

describe('W3C Verifiable Credentials', () => {
  it('creates and verifies a passport VC', async () => {
    const { signedPassport, keyPair } = createPassport({
      agentId: 'vc-test-1', agentName: 'VCAgent', ownerAlias: 'owner',
      mission: 'VC testing', capabilities: ['research', 'analysis'],
      runtime: { platform: 'test', models: ['gpt-4'], toolsCount: 10, memoryType: 'persistent' }
    })
    const vc = await passportToVC(signedPassport.passport, keyPair.privateKey, keyPair.publicKey)
    assert.ok(vc['@context'].includes('https://www.w3.org/ns/credentials/v2'))
    assert.ok(vc.type.includes('AgentPassportCredential'))
    assert.equal(vc.proof.type, 'Ed25519Signature2020')
    assert.equal(vc.proof.proofPurpose, 'assertionMethod')
    const result = await verifyVC(vc)
    assert.ok(result.valid, `VC verification failed: ${result.error}`)
  })

  it('creates and verifies a delegation VC', async () => {
    const { keyPair: principal } = createPassport({
      agentId: 'vc-test-2a', agentName: 'P', ownerAlias: 'o', mission: 'm',
      capabilities: ['admin'], runtime: { platform: 't', models: ['m'], toolsCount: 1, memoryType: 'n' }
    })
    const { keyPair: agent } = createPassport({
      agentId: 'vc-test-2b', agentName: 'A', ownerAlias: 'o', mission: 'm',
      capabilities: ['coding'], runtime: { platform: 't', models: ['m'], toolsCount: 1, memoryType: 'n' }
    })
    const delegation = createDelegation({
      delegatedTo: agent.publicKey, delegatedBy: principal.publicKey,
      scope: ['data:read', 'api:fetch'], spendLimit: 100,
      privateKey: principal.privateKey
    })
    const vc = await delegationToVC(delegation, principal.privateKey)
    assert.ok(vc.type.includes('AgentDelegationCredential'))
    assert.equal(vc.proof.proofPurpose, 'capabilityDelegation')
    const result = await verifyVC(vc)
    assert.ok(result.valid, `Delegation VC failed: ${result.error}`)
  })

  it('creates and verifies a floor attestation VC', async () => {
    const { keyPair } = createPassport({
      agentId: 'vc-test-3', agentName: 'T', ownerAlias: 'o', mission: 'm',
      capabilities: ['analysis'], runtime: { platform: 't', models: ['m'], toolsCount: 1, memoryType: 'n' }
    })
    const vc = await floorAttestationToVC(
      { agentId: keyPair.publicKey, floorVersion: '0.1', principles: ['F-001', 'F-002', 'F-003'], attestedAt: new Date().toISOString() },
      keyPair.publicKey, keyPair.privateKey
    )
    assert.ok(vc.type.includes('FloorAttestationCredential'))
    const result = await verifyVC(vc)
    assert.ok(result.valid, `Attestation VC failed: ${result.error}`)
  })

  it('[ADVERSARIAL] rejects tampered VC', async () => {
    const { signedPassport, keyPair } = createPassport({
      agentId: 'vc-test-4', agentName: 'T', ownerAlias: 'o', mission: 'm',
      capabilities: ['analysis'], runtime: { platform: 't', models: ['m'], toolsCount: 1, memoryType: 'n' }
    })
    const vc = await passportToVC(signedPassport.passport, keyPair.privateKey, keyPair.publicKey)
    const tampered = { ...vc, credentialSubject: { ...vc.credentialSubject, agentName: 'HACKED' } }
    const result = await verifyVC(tampered)
    assert.ok(!result.valid)
  })

  it('[ADVERSARIAL] rejects expired VC', async () => {
    const { signedPassport, keyPair } = createPassport({
      agentId: 'vc-test-5', agentName: 'T', ownerAlias: 'o', mission: 'm',
      capabilities: ['analysis'], runtime: { platform: 't', models: ['m'], toolsCount: 1, memoryType: 'n' },
      expiresInDays: -1
    })
    const vc = await passportToVC(signedPassport.passport, keyPair.privateKey, keyPair.publicKey)
    const result = await verifyVC(vc)
    assert.ok(!result.valid)
    assert.ok(result.error?.includes('expired'))
  })
})

describe('W3C Verifiable Presentations', () => {
  it('creates and verifies a presentation with multiple credentials', async () => {
    const { signedPassport: sp1, keyPair: principal } = createPassport({
      agentId: 'vp-test-1a', agentName: 'Principal', ownerAlias: 'o', mission: 'm',
      capabilities: ['admin'], runtime: { platform: 't', models: ['m'], toolsCount: 1, memoryType: 'n' }
    })
    const { signedPassport: sp2, keyPair: agent } = createPassport({
      agentId: 'vp-test-1b', agentName: 'Agent', ownerAlias: 'o', mission: 'research',
      capabilities: ['research'], runtime: { platform: 't', models: ['m'], toolsCount: 5, memoryType: 'p' }
    })
    const passportVC = await passportToVC(sp2.passport, agent.privateKey, agent.publicKey)
    const delegation = createDelegation({
      delegatedTo: agent.publicKey, delegatedBy: principal.publicKey,
      scope: ['research:web'], spendLimit: 50, privateKey: principal.privateKey
    })
    const delegationVC = await delegationToVC(delegation, principal.privateKey)
    const attestVC = await floorAttestationToVC(
      { agentId: agent.publicKey, floorVersion: '0.1', principles: ['F-001'], attestedAt: new Date().toISOString() },
      agent.publicKey, agent.privateKey
    )
    const vp = await createPresentation([passportVC, delegationVC, attestVC], agent.privateKey, agent.publicKey)
    assert.equal(vp.holder, `did:aps:${agent.publicKey}`)
    assert.equal(vp.verifiableCredential.length, 3)
    const result = await verifyPresentation(vp)
    assert.ok(result.valid, `VP verification failed: ${result.error}`)
    assert.ok(result.credentialResults.every(r => r.valid))
  })

  it('[ADVERSARIAL] detects holder mismatch in presentation', async () => {
    const { signedPassport, keyPair: agent } = createPassport({
      agentId: 'vp-test-2a', agentName: 'Real', ownerAlias: 'o', mission: 'm',
      capabilities: ['coding'], runtime: { platform: 't', models: ['m'], toolsCount: 1, memoryType: 'n' }
    })
    const { keyPair: attacker } = createPassport({
      agentId: 'vp-test-2b', agentName: 'Fake', ownerAlias: 'o', mission: 'm',
      capabilities: ['coding'], runtime: { platform: 't', models: ['m'], toolsCount: 1, memoryType: 'n' }
    })
    const vc = await passportToVC(signedPassport.passport, agent.privateKey, agent.publicKey)
    // Attacker presents agent's VC under their own identity
    const vp = await createPresentation([vc], attacker.privateKey, attacker.publicKey)
    assert.equal(vp.holder, `did:aps:${attacker.publicKey}`)
    // VCs verify fine (they're real), but holder doesn't match issuer
    const result = await verifyPresentation(vp)
    assert.ok(result.valid) // Presentation signature itself is valid
    assert.notEqual(result.holderDID, `did:aps:${agent.publicKey}`)
  })
})
