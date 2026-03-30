// ══════════════════════════════════════════════════════════════════
// Gateway Identity Verification — Tests
// ══════════════════════════════════════════════════════════════════
// Validates: DID resolution, principal endorsement chain verification,
// identity strength levels, minimum strength enforcement at registration,
// and constraint vector identity headroom.
// Wires 4 previously orphaned modules (did, principal, entity-verification, vc)
// into the gateway enforcement pipeline.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createProxyGateway } from '../src/core/gateway.js'
import { joinSocialContract, delegate } from '../src/contract.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { loadFloor } from '../src/core/values.js'
import { clearStores } from '../src/core/delegation.js'
import { createPrincipalIdentity, endorsePassport } from '../src/core/principal.js'
import { createDID, isValidDID } from '../src/core/did.js'
import {
  verifyAgentIdentitySync, strengthMeetsMinimum,
  DEFAULT_IDENTITY_CONFIG,
} from '../src/core/gateway-identity.js'
import type { GatewayConfig } from '../src/types/gateway.js'
import { readFileSync } from 'fs'
import { dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(__dirname + '/../values/floor.yaml', 'utf-8')
const floor = loadFloor(floorYaml)

// ── Setup Helpers ──

function createIdentitySetup(opts: {
  enableIdentityVerification: boolean
  minimumStrength?: 'key_only' | 'did_resolved' | 'principal_endorsed' | 'entity_verified'
  withPrincipal?: boolean
}) {
  clearStores()
  const gwKeys = generateKeyPair()
  const principal = joinSocialContract({
    name: 'id-principal', mission: 'Test', owner: 'admin',
    capabilities: ['data_read'], platform: 'node', models: ['test'], floor,
  })
  const agent = joinSocialContract({
    name: 'id-agent', mission: 'Test', owner: 'admin',
    capabilities: ['data_read'], platform: 'node', models: ['test'], floor,
  })

  // Optionally create a principal endorsement
  let passport = agent.passport
  let endorsement: ReturnType<typeof endorsePassport>['endorsement'] | undefined
  if (opts.withPrincipal) {
    const { principal: principalId, keyPair: pKeys } = createPrincipalIdentity({
      displayName: 'Test Human',
    })
    const result = endorsePassport({
      signedPassport: agent.passport,
      principal: principalId,
      principalPrivateKey: pKeys.privateKey,
      scope: ['data_read'],
      relationship: 'owner',
    })
    endorsement = result.endorsement
    // Keep original passport (signature valid) — endorsement passed separately
  }

  const del = delegate({
    from: principal, toPublicKey: agent.publicKey,
    scope: ['data_read'], spendLimit: 100,
    maxDepth: 2, expiresInHours: 1,
  })

  const config: GatewayConfig = {
    gatewayId: 'gw-identity',
    gatewayPublicKey: gwKeys.publicKey,
    gatewayPrivateKey: gwKeys.privateKey,
    floor,
    enableIdentityVerification: opts.enableIdentityVerification,
    identityConfig: {
      ...DEFAULT_IDENTITY_CONFIG,
      minimumStrength: opts.minimumStrength ?? 'key_only',
    },
  }

  const gateway = createProxyGateway(config, async () => ({ success: true, result: {} }))

  let reqCounter = 0
  function makeRequest() {
    const requestId = `id-req-${++reqCounter}-${Date.now()}`
    const payload = canonicalize({
      requestId, agentId: agent.agentId, tool: 'data_read',
      params: {}, scopeRequired: 'data_read',
    })
    return {
      requestId, agentId: agent.agentId, agentPublicKey: agent.publicKey,
      tool: 'data_read', params: {}, scopeRequired: 'data_read',
      signature: sign(payload, agent.keyPair.privateKey),
    }
  }

  return { gateway, agent, passport, endorsement, del, makeRequest }
}

// ── Unit Tests: verifyAgentIdentitySync ──

describe('Gateway Identity — DID Resolution', () => {
  it('derives DID from public key on registration', () => {
    clearStores()
    const agent = joinSocialContract({
      name: 'did-test', mission: 'Test', owner: 'admin',
      capabilities: ['test'], platform: 'node', models: ['test'], floor,
    })
    const result = verifyAgentIdentitySync(agent.passport, DEFAULT_IDENTITY_CONFIG)
    assert.ok(result.did, 'Should have a DID')
    assert.ok(isValidDID(result.did), 'DID should be valid')
    assert.strictEqual(result.didResolved, true, 'DID should resolve')
    assert.ok(result.didDocument, 'Should have DID Document')
    assert.strictEqual(result.strength, 'did_resolved')
  })

  it('DID contains agent public key', () => {
    clearStores()
    const agent = joinSocialContract({
      name: 'did-key-test', mission: 'Test', owner: 'admin',
      capabilities: ['test'], platform: 'node', models: ['test'], floor,
    })
    const result = verifyAgentIdentitySync(agent.passport, DEFAULT_IDENTITY_CONFIG)
    const expectedDid = createDID(agent.passport.passport.publicKey)
    assert.strictEqual(result.did, expectedDid)
  })
})

describe('Gateway Identity — Principal Endorsement', () => {
  it('detects principal endorsement and verifies chain', () => {
    clearStores()
    const agent = joinSocialContract({
      name: 'principal-test', mission: 'Test', owner: 'admin',
      capabilities: ['test'], platform: 'node', models: ['test'], floor,
    })
    const { principal: principalId, keyPair: pKeys } = createPrincipalIdentity({
      displayName: 'Test Owner',
    })
    const endorsed = endorsePassport({
      signedPassport: agent.passport,
      principal: principalId,
      principalPrivateKey: pKeys.privateKey,
      scope: ['test'],
      relationship: 'owner',
    })
    const result = verifyAgentIdentitySync(endorsed.endorsedPassport, DEFAULT_IDENTITY_CONFIG)
    assert.strictEqual(result.hasPrincipalEndorsement, true)
    assert.ok(result.principalVerification, 'Should have principal verification')
    assert.strictEqual(result.principalVerification.valid, true)
    assert.strictEqual(result.strength, 'principal_endorsed')
  })

  it('key_only strength when no principal endorsement', () => {
    clearStores()
    const agent = joinSocialContract({
      name: 'no-principal', mission: 'Test', owner: 'admin',
      capabilities: ['test'], platform: 'node', models: ['test'], floor,
    })
    // Disable DID resolution to isolate principal check
    const result = verifyAgentIdentitySync(agent.passport, {
      ...DEFAULT_IDENTITY_CONFIG, resolveDID: false,
    })
    assert.strictEqual(result.hasPrincipalEndorsement, false)
    assert.strictEqual(result.strength, 'key_only')
  })
})

// ── Strength Ordering Tests ──

describe('Gateway Identity — Strength Ordering', () => {
  it('strength ordering: key_only < did_resolved < principal_endorsed < entity_verified', () => {
    assert.strictEqual(strengthMeetsMinimum('key_only', 'key_only'), true)
    assert.strictEqual(strengthMeetsMinimum('did_resolved', 'key_only'), true)
    assert.strictEqual(strengthMeetsMinimum('principal_endorsed', 'did_resolved'), true)
    assert.strictEqual(strengthMeetsMinimum('entity_verified', 'principal_endorsed'), true)
  })

  it('lower strength does not meet higher minimum', () => {
    assert.strictEqual(strengthMeetsMinimum('key_only', 'did_resolved'), false)
    assert.strictEqual(strengthMeetsMinimum('did_resolved', 'principal_endorsed'), false)
    assert.strictEqual(strengthMeetsMinimum('principal_endorsed', 'entity_verified'), false)
  })
})

// ── Gateway Integration Tests ──

describe('Gateway Identity — Registration with Verification', () => {
  it('registers agent with identity verification enabled', () => {
    const { gateway, passport, agent, del } = createIdentitySetup({
      enableIdentityVerification: true,
    })
    const result = gateway.registerAgent(passport, agent.attestation, [del])
    assert.strictEqual(result.registered, true)

    // Identity verification should be stored
    const identity = gateway.getAgentIdentity(agent.agentId)
    assert.ok(identity, 'Should have identity verification')
    assert.ok(identity.did, 'Should have DID')
    assert.strictEqual(identity.didResolved, true)
    assert.ok(identity.strength === 'did_resolved' || identity.strength === 'principal_endorsed')
  })

  it('registers agent with principal endorsement', () => {
    const { gateway, passport, agent, del, endorsement } = createIdentitySetup({
      enableIdentityVerification: true,
      withPrincipal: true,
    })
    const result = gateway.registerAgent(passport, agent.attestation, [del], 'executor', { endorsement })
    assert.strictEqual(result.registered, true)

    const identity = gateway.getAgentIdentity(agent.agentId)
    assert.ok(identity)
    assert.strictEqual(identity.hasPrincipalEndorsement, true)
    assert.strictEqual(identity.strength, 'principal_endorsed')
  })

  it('rejects registration when identity strength below minimum', () => {
    const { gateway, passport, agent, del } = createIdentitySetup({
      enableIdentityVerification: true,
      minimumStrength: 'principal_endorsed',
      withPrincipal: false,  // No principal → strength will be did_resolved
    })
    const result = gateway.registerAgent(passport, agent.attestation, [del])
    assert.strictEqual(result.registered, false)
    assert.ok(result.error?.includes('below required'))
  })

  it('accepts registration when strength meets minimum', () => {
    const { gateway, passport, agent, del, endorsement } = createIdentitySetup({
      enableIdentityVerification: true,
      minimumStrength: 'principal_endorsed',
      withPrincipal: true,
    })
    const result = gateway.registerAgent(passport, agent.attestation, [del], 'executor', { endorsement })
    assert.strictEqual(result.registered, true)
  })

  it('skips identity verification when disabled', () => {
    const { gateway, passport, agent, del } = createIdentitySetup({
      enableIdentityVerification: false,
    })
    const result = gateway.registerAgent(passport, agent.attestation, [del])
    assert.strictEqual(result.registered, true)
    const identity = gateway.getAgentIdentity(agent.agentId)
    assert.strictEqual(identity, undefined)
  })

  it('identity strength appears in constraint vector headroom', async () => {
    const { gateway, passport, agent, del, endorsement, makeRequest } = createIdentitySetup({
      enableIdentityVerification: true,
      withPrincipal: true,
    })
    gateway.registerAgent(passport, agent.attestation, [del], 'executor', { endorsement })
    const result = await gateway.processToolCall(makeRequest())
    assert.strictEqual(result.executed, true)
    const idFacet = result.constraintVector?.facets.find(f => f.facet === 'identity')
    assert.ok(idFacet, 'Should have identity facet')
    assert.strictEqual(idFacet.status, 'pass')
    assert.strictEqual(idFacet.headroom, 'principal_endorsed')
  })

  it('getAgentIdentity returns undefined for unknown agent', () => {
    const { gateway } = createIdentitySetup({ enableIdentityVerification: true })
    assert.strictEqual(gateway.getAgentIdentity('nonexistent'), undefined)
  })
})
