// ══════════════════════════════════════════════════════════════════
// Substrate Fidelity Gating — Tests
// ══════════════════════════════════════════════════════════════════
// Validates: fidelity as a constraint facet in the product lattice.
// When an agent migrates to a different LLM substrate, its behavior
// may drift even though identity and reputation don't change.
// The gateway can require a minimum fidelity score before permitting
// high-authority actions.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createProxyGateway } from '../src/core/gateway.js'
import { joinSocialContract, delegate } from '../src/contract.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { loadFloor } from '../src/core/values.js'
import { clearStores } from '../src/core/delegation.js'
import type { GatewayConfig, FidelityAttestation } from '../src/types/gateway.js'
import { readFileSync } from 'fs'
import { dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(__dirname + '/../values/floor.yaml', 'utf-8')
const floor = loadFloor(floorYaml)

function createFidelitySetup(opts: {
  enableFidelityGating: boolean
  minFidelityScore?: number
  fidelityMaxAge?: number
  fidelityDefaultPolicy?: 'deny' | 'warn' | 'ignore'
}) {
  clearStores()
  const gwKeys = generateKeyPair()
  const principal = joinSocialContract({
    name: 'fid-principal', mission: 'Test', owner: 'admin',
    capabilities: ['data_read'], platform: 'node', models: ['test'], floor,
  })
  const agent = joinSocialContract({
    name: 'fid-agent', mission: 'Test', owner: 'admin',
    capabilities: ['data_read'], platform: 'node', models: ['test'], floor,
  })
  const agentKeys = agent.keyPair

  const del = delegate({
    from: principal, toPublicKey: agent.publicKey,
    scope: ['data_read'], spendLimit: 100,
    maxDepth: 2, expiresInHours: 1,
  })

  const config: GatewayConfig = {
    gatewayId: 'gw-fidelity',
    gatewayPublicKey: gwKeys.publicKey,
    gatewayPrivateKey: gwKeys.privateKey,
    floor,
    recheckRevocationOnExecute: true,
    ...opts,
  }

  const gateway = createProxyGateway(config, async () => ({ success: true, result: {} }))
  gateway.registerAgent(agent.passport, agent.attestation, [del])

  let reqCounter = 0
  function makeRequest() {
    const requestId = `fid-req-${++reqCounter}-${Date.now()}`
    const payload = canonicalize({
      requestId, agentId: agent.agentId, tool: 'data_read',
      params: {}, scopeRequired: 'data_read',
    })
    return {
      requestId, agentId: agent.agentId, agentPublicKey: agent.publicKey,
      tool: 'data_read', params: {}, scopeRequired: 'data_read',
      signature: sign(payload, agentKeys.privateKey),
    }
  }

  function makeFidelityAttestation(score: number, ageSeconds = 0): FidelityAttestation {
    const measurer = generateKeyPair()
    const measuredAt = new Date(Date.now() - ageSeconds * 1000).toISOString()
    return {
      attestationId: `fa_${Date.now()}`,
      agentId: agent.agentId,
      fidelity: {
        score,
        substrate: 'claude-3-opus',
        measuredAt,
        method: 'relational-fidelity-v1',
        dimensions: { voice: score, reasoning: score, boundaries: score * 0.9, quality: score },
      },
      measuredBy: `did:aps:${measurer.publicKey.slice(0, 32)}`,
      signature: sign(canonicalize({ score, measuredAt }), measurer.privateKey),
    }
  }

  return { gateway, agent, del, makeRequest, makeFidelityAttestation }
}

describe('Substrate Fidelity Gating — High Fidelity', () => {
  it('permits action when fidelity score exceeds threshold', async () => {
    const { gateway, agent, makeRequest, makeFidelityAttestation } = createFidelitySetup({
      enableFidelityGating: true, minFidelityScore: 0.5,
    })
    gateway.setFidelityAttestation(agent.agentId, makeFidelityAttestation(0.85))
    const result = await gateway.processToolCall(makeRequest())
    assert.strictEqual(result.executed, true)
  })

  it('fidelity facet appears in constraint vector on success', async () => {
    const { gateway, agent, makeRequest, makeFidelityAttestation } = createFidelitySetup({
      enableFidelityGating: true, minFidelityScore: 0.5,
    })
    gateway.setFidelityAttestation(agent.agentId, makeFidelityAttestation(0.85))
    const result = await gateway.processToolCall(makeRequest())
    assert.ok(result.constraintVector, 'must have constraint vector')
    const fid = result.constraintVector.facets.find(f => f.facet === 'fidelity')
    assert.ok(fid, 'must have fidelity facet')
    assert.strictEqual(fid.status, 'pass')
    assert.ok(fid.headroom !== undefined, 'must have headroom')
    assert.ok(typeof fid.headroom === 'number' && fid.headroom > 0, 'headroom should be positive')
  })
})

describe('Substrate Fidelity Gating — Denials', () => {
  it('denies action when fidelity score below threshold', async () => {
    const { gateway, agent, makeRequest, makeFidelityAttestation } = createFidelitySetup({
      enableFidelityGating: true, minFidelityScore: 0.7,
    })
    gateway.setFidelityAttestation(agent.agentId, makeFidelityAttestation(0.3))
    const result = await gateway.processToolCall(makeRequest())
    assert.strictEqual(result.executed, false)
    assert.ok(result.constraintFailures, 'must have failures')
    assert.strictEqual(result.constraintFailures[0].facet, 'fidelity')
    assert.strictEqual(result.constraintFailures[0].code, 'BELOW_THRESHOLD')
  })

  it('denies when no attestation and defaultPolicy=deny', async () => {
    const { gateway, makeRequest } = createFidelitySetup({
      enableFidelityGating: true, fidelityDefaultPolicy: 'deny',
    })
    // No attestation set
    const result = await gateway.processToolCall(makeRequest())
    assert.strictEqual(result.executed, false)
    assert.ok(result.constraintFailures)
    assert.strictEqual(result.constraintFailures[0].code, 'NO_ATTESTATION')
  })

  it('denies when attestation is stale and defaultPolicy=deny', async () => {
    const { gateway, agent, makeRequest, makeFidelityAttestation } = createFidelitySetup({
      enableFidelityGating: true, fidelityDefaultPolicy: 'deny', fidelityMaxAge: 3600,
    })
    // Attestation from 2 hours ago (7200s > 3600s maxAge)
    gateway.setFidelityAttestation(agent.agentId, makeFidelityAttestation(0.9, 7200))
    const result = await gateway.processToolCall(makeRequest())
    assert.strictEqual(result.executed, false)
    assert.strictEqual(result.constraintFailures![0].code, 'STALE_ATTESTATION')
  })
})

describe('Substrate Fidelity Gating — Default Policies', () => {
  it('permits with no attestation when defaultPolicy=warn (default)', async () => {
    const { gateway, makeRequest } = createFidelitySetup({
      enableFidelityGating: true,
    })
    // No attestation, default policy is 'warn' — should pass
    const result = await gateway.processToolCall(makeRequest())
    assert.strictEqual(result.executed, true)
    // Fidelity facet should show 'unknown' (no attestation, but not denied)
    const fid = result.constraintVector?.facets.find(f => f.facet === 'fidelity')
    assert.ok(fid, 'fidelity facet should appear')
    assert.strictEqual(fid.status, 'unknown')
  })

  it('permits with no attestation when defaultPolicy=ignore', async () => {
    const { gateway, makeRequest } = createFidelitySetup({
      enableFidelityGating: true, fidelityDefaultPolicy: 'ignore',
    })
    const result = await gateway.processToolCall(makeRequest())
    assert.strictEqual(result.executed, true)
    const fid = result.constraintVector?.facets.find(f => f.facet === 'fidelity')
    assert.ok(fid)
    assert.strictEqual(fid.status, 'not_applicable')
  })
})

describe('Substrate Fidelity Gating — Disabled & Stats', () => {
  it('does not check fidelity when gating is disabled', async () => {
    const { gateway, makeRequest } = createFidelitySetup({
      enableFidelityGating: false,
    })
    // No attestation, gating disabled — should pass with no fidelity facet
    const result = await gateway.processToolCall(makeRequest())
    assert.strictEqual(result.executed, true)
    const fid = result.constraintVector?.facets.find(f => f.facet === 'fidelity')
    assert.ok(!fid, 'fidelity facet should NOT appear when gating disabled')
  })

  it('tracks fidelity denial stats', async () => {
    const { gateway, agent, makeRequest, makeFidelityAttestation } = createFidelitySetup({
      enableFidelityGating: true, minFidelityScore: 0.8,
    })
    gateway.setFidelityAttestation(agent.agentId, makeFidelityAttestation(0.3))
    await gateway.processToolCall(makeRequest())
    const stats = gateway.getStats()
    assert.ok((stats.fidelityDenials ?? 0) > 0, 'should track fidelity denials')
  })

  it('setFidelityAttestation returns false for unknown agent', () => {
    const { gateway, makeFidelityAttestation } = createFidelitySetup({
      enableFidelityGating: true,
    })
    const result = gateway.setFidelityAttestation('nonexistent-agent', makeFidelityAttestation(0.9))
    assert.strictEqual(result, false)
  })
})
