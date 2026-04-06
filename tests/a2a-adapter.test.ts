// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createPassport, createDelegation,
  passportToA2ACard, a2aCardToPassportMeta, verifyA2AIdentity,
  a2aSkillsToScope, embedA2ATrustSignal,
} from '../src/index.js'
import type { A2AAgentCardV2 } from '../src/index.js'

const pk = generateKeyPair()
const ak = generateKeyPair()
const { signedPassport } = createPassport({
  agentId: 'agent-a2a-test', agentName: 'A2A Test Agent', ownerAlias: 'tima',
  mission: 'A2A interop test', capabilities: ['a2a'], runtime: { platform: 'node', version: process.version },
})
function mkDel(scopes: string[]) {
  return createDelegation({ delegatedTo: ak.publicKey, delegatedBy: pk.publicKey, scope: scopes, privateKey: pk.privateKey })
}

describe('A2A Adapter v2', () => {
  it('passport to agent card conversion', () => {
    const card = passportToA2ACard(signedPassport, { url: 'https://example.com' })
    assert.equal(card.name, 'A2A Test Agent')
    assert.equal(card.description, 'A2A interop test')
    assert.equal(card.url, 'https://example.com')
    assert.ok(card.securitySchemes?.aps_ed25519)
  })

  it('agent card to passport metadata', () => {
    const card: A2AAgentCardV2 = { name: 'My Agent', description: 'Test', url: 'https://x.com' }
    const meta = a2aCardToPassportMeta(card)
    assert.equal(meta.agentId, 'my-agent')
    assert.equal(meta.metadata.a2a_name, 'My Agent')
    assert.equal(meta.metadata.a2a_url, 'https://x.com')
  })

  it('round-trip: passport -> card -> metadata preserves identity', () => {
    const card = passportToA2ACard(signedPassport)
    const meta = a2aCardToPassportMeta(card)
    assert.equal(meta.metadata.a2a_name, 'A2A Test Agent')
    assert.equal(meta.metadata.a2a_description, 'A2A interop test')
  })

  it('delegation scope to skills mapping', () => {
    const del = mkDel(['data:read', 'comms:send'])
    const card = passportToA2ACard(signedPassport, { delegation: del })
    assert.ok(card.skills)
    assert.equal(card.skills!.length, 2)
    assert.equal(card.skills![0].id, 'data:read')
  })

  it('skills to scope extraction', () => {
    const skills = [{ id: 'search', name: 'Search' }, { id: 'translate', name: 'Translate' }]
    const scopes = a2aSkillsToScope(skills)
    assert.deepStrictEqual(scopes, ['a2a:search', 'a2a:translate'])
  })

  it('verify matching passport and card', () => {
    const card = passportToA2ACard(signedPassport)
    const r = verifyA2AIdentity(card, signedPassport)
    assert.equal(r.valid, true)
    assert.equal(r.errors.length, 0)
  })

  it('verify mismatched passport and card', () => {
    const card: A2AAgentCardV2 = { name: 'Wrong Agent' }
    const r = verifyA2AIdentity(card, signedPassport)
    assert.equal(r.valid, false)
    assert.ok(r.errors.some(e => e.includes('does not match')))
  })

  it('embed trust signal with endpoint', () => {
    const card = passportToA2ACard(signedPassport)
    const enhanced = embedA2ATrustSignal(card, signedPassport, 'https://gw.example.com/trust/agent-a2a-test')
    assert.ok(enhanced.extensions?.aps_trust)
    const trust = enhanced.extensions!.aps_trust as Record<string, unknown>
    assert.equal(trust.trustEndpoint, 'https://gw.example.com/trust/agent-a2a-test')
    assert.equal(trust.protocol, 'agent-passport-system')
  })

  it('embed trust signal without endpoint uses default', () => {
    const card = passportToA2ACard(signedPassport)
    const enhanced = embedA2ATrustSignal(card, signedPassport)
    const trust = enhanced.extensions!.aps_trust as Record<string, unknown>
    assert.ok((trust.trustEndpoint as string).includes('gateway.aeoess.com'))
  })

  it('card with no skills returns empty scope', () => {
    assert.deepStrictEqual(a2aSkillsToScope(undefined), [])
    assert.deepStrictEqual(a2aSkillsToScope([]), [])
  })

  it('card with capabilities preserved', () => {
    const card = passportToA2ACard(signedPassport, { capabilities: { streaming: true, pushNotifications: false } })
    assert.equal(card.capabilities?.streaming, true)
    assert.equal(card.capabilities?.pushNotifications, false)
  })

  it('provider info from passport owner', () => {
    const card = passportToA2ACard(signedPassport)
    assert.equal(card.provider?.organization, 'tima')
  })

  it('security schemes from public key', () => {
    const card = passportToA2ACard(signedPassport)
    const scheme = card.securitySchemes?.aps_ed25519 as Record<string, unknown>
    assert.equal(scheme.type, 'ed25519')
    assert.equal(scheme.publicKey, signedPassport.passport.publicKey)
  })

  it('empty card handling', () => {
    const meta = a2aCardToPassportMeta({ name: '' })
    assert.equal(meta.agentId, '')
    assert.equal(meta.metadata.a2a_skill_count, 0)
  })

  it('special characters in agent name', () => {
    const meta = a2aCardToPassportMeta({ name: 'My Agent (v2.0) [test]' })
    assert.equal(meta.agentId, 'my-agent--v2-0---test-')
  })

  it('multiple skills scope aggregation', () => {
    const skills = [
      { id: 'read', name: 'Read' },
      { id: 'write', name: 'Write' },
      { id: 'search', name: 'Search' },
    ]
    const scopes = a2aSkillsToScope(skills)
    assert.equal(scopes.length, 3)
    assert.ok(scopes.every(s => s.startsWith('a2a:')))
  })

  it('explicit skills override delegation-derived skills', () => {
    const del = mkDel(['data:read'])
    const skills = [{ id: 'custom', name: 'Custom Skill' }]
    const card = passportToA2ACard(signedPassport, { delegation: del, skills })
    assert.equal(card.skills!.length, 1)
    assert.equal(card.skills![0].id, 'custom')
  })
})
