// Tests for A2A Protocol Bridge
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createPassport, createDID,
  passportToAgentCard, verifyAgentCard,
  agentCardToCapabilities, hasPassportIdentity,
  getDIDFromAgentCard
} from '../src/index.js'

describe('A2A Protocol Bridge', () => {
  it('generates an A2A Agent Card from a passport', async () => {
    const { signedPassport, keyPair } = createPassport({
      agentId: 'a2a-test-1', agentName: 'ResearchBot', ownerAlias: 'owner',
      mission: 'Research and analysis agent', capabilities: ['web_search', 'data_analysis', 'report_generation'],
      runtime: { platform: 'claude', models: ['claude-4'], toolsCount: 30, memoryType: 'persistent' }
    })
    const card = await passportToAgentCard(signedPassport.passport, keyPair.privateKey, {
      url: 'https://agents.example.com/research-bot',
      provider: { organization: 'AEOESS', url: 'https://aeoess.com' },
      capabilities: { streaming: true, pushNotifications: false }
    })
    assert.equal(card.name, 'ResearchBot')
    assert.equal(card.description, 'Research and analysis agent')
    assert.equal(card.url, 'https://agents.example.com/research-bot')
    assert.equal(card.skills.length, 3)
    assert.ok(card.skills.some(s => s.id === 'web_search'))
    assert.ok(card.agentPassport)
    assert.ok(card.agentPassport?.did.startsWith('did:aps:'))
    assert.ok(card.agentPassport?.passportSignature)
  })

  it('maps passport capabilities to A2A skills', async () => {
    const { signedPassport, keyPair } = createPassport({
      agentId: 'a2a-test-2', agentName: 'T', ownerAlias: 'o',
      mission: 'Test', capabilities: ['code_execution', 'web_search'],
      runtime: { platform: 't', models: ['m'], toolsCount: 1, memoryType: 'n' }
    })
    const card = await passportToAgentCard(signedPassport.passport, keyPair.privateKey, {
      url: 'http://localhost:8000'
    })
    const caps = agentCardToCapabilities(card)
    assert.deepEqual(caps, ['code_execution', 'web_search'])
  })

  it('detects passport identity in agent card', async () => {
    const { signedPassport, keyPair } = createPassport({
      agentId: 'a2a-test-3', agentName: 'T', ownerAlias: 'o',
      mission: 'Test', capabilities: ['analysis'],
      runtime: { platform: 't', models: ['m'], toolsCount: 1, memoryType: 'n' }
    })
    const card = await passportToAgentCard(signedPassport.passport, keyPair.privateKey, {
      url: 'http://localhost:8000'
    })
    assert.ok(hasPassportIdentity(card))
    const did = getDIDFromAgentCard(card)
    assert.ok(did?.startsWith('did:aps:'))
    assert.equal(did, createDID(keyPair.publicKey))
  })

  it('returns false for cards without passport identity', () => {
    const plainCard = {
      name: 'PlainAgent', description: 'No passport',
      url: 'http://localhost:9000', version: '1.0.0',
      capabilities: {}, defaultInputModes: ['text/plain'],
      defaultOutputModes: ['text/plain'], skills: []
    }
    assert.ok(!hasPassportIdentity(plainCard))
    assert.equal(getDIDFromAgentCard(plainCard), null)
  })

  it('verifies agent card with passport extension', async () => {
    const { signedPassport, keyPair } = createPassport({
      agentId: 'a2a-test-4', agentName: 'VerifyBot', ownerAlias: 'owner',
      mission: 'Verification test', capabilities: ['verify'],
      runtime: { platform: 'test', models: ['m'], toolsCount: 1, memoryType: 'n' }
    })
    const card = await passportToAgentCard(signedPassport.passport, keyPair.privateKey, {
      url: 'http://localhost:8000'
    })
    const result = await verifyAgentCard(card)
    assert.ok(result.valid)
    assert.ok(result.did?.startsWith('did:aps:'))
  })

  it('rejects card without passport extension', async () => {
    const result = await verifyAgentCard({
      name: 'Fake', description: 'No passport',
      url: 'http://localhost', version: '1.0',
      capabilities: {}, defaultInputModes: [],
      defaultOutputModes: [], skills: []
    })
    assert.ok(!result.valid)
    assert.ok(result.error?.includes('No agentPassport'))
  })

  it('includes custom skills when provided', async () => {
    const { signedPassport, keyPair } = createPassport({
      agentId: 'a2a-test-5', agentName: 'CustomBot', ownerAlias: 'owner',
      mission: 'Custom skills', capabilities: ['general'],
      runtime: { platform: 'test', models: ['m'], toolsCount: 5, memoryType: 'n' }
    })
    const customSkills = [
      { id: 'translate', name: 'Translation', description: 'Translate between languages', tags: ['i18n'], inputModes: ['text/plain'], outputModes: ['text/plain'] },
      { id: 'summarize', name: 'Summarization', description: 'Summarize documents', tags: ['nlp'] }
    ]
    const card = await passportToAgentCard(signedPassport.passport, keyPair.privateKey, {
      url: 'http://localhost:8000',
      skills: customSkills
    })
    assert.equal(card.skills.length, 2)
    assert.equal(card.skills[0].id, 'translate')
    assert.equal(card.skills[1].id, 'summarize')
  })

  it('includes security scheme for Agent Passport auth', async () => {
    const { signedPassport, keyPair } = createPassport({
      agentId: 'a2a-test-6', agentName: 'SecureBot', ownerAlias: 'owner',
      mission: 'Security test', capabilities: ['secure'],
      runtime: { platform: 'test', models: ['m'], toolsCount: 1, memoryType: 'n' }
    })
    const card = await passportToAgentCard(signedPassport.passport, keyPair.privateKey, {
      url: 'http://localhost:8000'
    })
    assert.ok(card.securitySchemes?.agentPassport)
    assert.equal(card.securitySchemes?.agentPassport.bearerFormat, 'AgentPassport')
  })
})
