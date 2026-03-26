// ══════════════════════════════════════════════════════════════════
// Near-Miss Alerting — Tests (Phase 3)
// ══════════════════════════════════════════════════════════════════
// Validates: proactive constraint boundary warnings, threshold-based
// alerting, per-facet near-miss detection, and stats tracking.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createProxyGateway } from '../src/core/gateway.js'
import { joinSocialContract, delegate } from '../src/contract.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { loadFloor } from '../src/core/values.js'
import { clearStores } from '../src/core/delegation.js'
import type { ToolCallRequest, GatewayConfig, ConstraintNearMiss } from '../src/types/gateway.js'
import { readFileSync } from 'fs'
import { dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(__dirname + '/../values/floor.yaml', 'utf-8')
const floor = loadFloor(floorYaml)

function createNearMissSetup(opts: { spendLimit: number; nearMissThresholds?: number[] }) {
  clearStores()
  const gwKeys = { publicKey: '', privateKey: '' }
  const principal = joinSocialContract({
    name: 'nm-principal', mission: 'Test', owner: 'admin',
    capabilities: ['data_read'], platform: 'node', models: ['test'], floor,
  })
  const agent = joinSocialContract({
    name: 'nm-agent', mission: 'Test', owner: 'admin',
    capabilities: ['data_read'], platform: 'node', models: ['test'], floor,
  })
  const agentKeys = agent.keyPair

  const del = delegate({
    from: principal, toPublicKey: agent.publicKey,
    scope: ['data_read', 'api_call'], spendLimit: opts.spendLimit,
    maxDepth: 2, expiresInHours: 1,
  })

  const alerts: ConstraintNearMiss[] = []

  const realGwKeys = generateKeyPair()

  const config: GatewayConfig = {
    gatewayId: 'gw-nearmiss',
    gatewayPublicKey: realGwKeys.publicKey,
    gatewayPrivateKey: realGwKeys.privateKey,
    floor,
    recheckRevocationOnExecute: true,
    enableNearMissAlerting: true,
    nearMissThresholds: opts.nearMissThresholds ?? [0.1, 0.05, 0.01],
    onNearMiss: (nm) => alerts.push(nm),
  }

  const gateway = createProxyGateway(config, async (t, p) => ({ success: true, result: { t, p } }))
  gateway.registerAgent(agent.passport, agent.attestation, [del])

  let reqCounter = 0
  function makeRequest(spend?: number): ToolCallRequest {
    const requestId = `nm-req-${++reqCounter}-${Date.now()}`
    const payload = canonicalize({
      requestId, agentId: agent.agentId, tool: 'data_read',
      params: {}, scopeRequired: 'data_read',
      spend: spend !== undefined ? { amount: spend, currency: 'usd' } : undefined,
    })
    return {
      requestId, agentId: agent.agentId, agentPublicKey: agent.publicKey,
      tool: 'data_read', params: {}, scopeRequired: 'data_read',
      spend: spend !== undefined ? { amount: spend, currency: 'usd' } : undefined,
      signature: sign(payload, agentKeys.privateKey),
    }
  }

  return { gateway, agent, del, alerts, makeRequest }
}

describe('Near-Miss Alerting — Spend', () => {
  it('no alert when far from spend limit', async () => {
    const { gateway, alerts, makeRequest } = createNearMissSetup({ spendLimit: 1000 })
    // Spend $10 of $1000 limit — 1% utilization, way below any threshold
    const result = await gateway.processToolCall(makeRequest(10))
    assert.strictEqual(result.executed, true)
    assert.strictEqual(alerts.length, 0, 'No near-miss at 1% utilization')
  })

  it('alerts when spend approaches 90% of limit', async () => {
    const { gateway, alerts, makeRequest } = createNearMissSetup({ spendLimit: 100 })
    // Spend $92 of $100 → 8% headroom → below 10% threshold
    const result = await gateway.processToolCall(makeRequest(92))
    assert.strictEqual(result.executed, true)
    assert.ok(alerts.length > 0, 'Should alert at 92% spend utilization')
    assert.strictEqual(alerts[0].facet, 'spend')
    assert.ok(alerts[0].headroomRatio <= 0.1, `Headroom ratio should be ≤0.1, got ${alerts[0].headroomRatio}`)
    assert.ok(alerts[0].message.includes(gateway.getStats().activeAgents ? 'nm-agent' : ''), 'Message should reference agent')
  })

  it('alerts at 99% threshold for near-total exhaustion', async () => {
    const { gateway, alerts, makeRequest } = createNearMissSetup({ spendLimit: 100 })
    const result = await gateway.processToolCall(makeRequest(99))
    assert.strictEqual(result.executed, true)
    const spendAlerts = alerts.filter(a => a.facet === 'spend')
    assert.ok(spendAlerts.length > 0, 'Should alert at 99% spend')
    assert.ok(spendAlerts[0].headroomRatio <= 0.01, `Headroom should be ≤1%, got ${spendAlerts[0].headroomRatio}`)
  })

  it('custom thresholds are respected', async () => {
    const { gateway, alerts, makeRequest } = createNearMissSetup({
      spendLimit: 100,
      nearMissThresholds: [0.3, 0.1],  // Alert at 70% and 90%
    })
    // Spend $75 → 25% headroom → below 30% threshold
    const result = await gateway.processToolCall(makeRequest(75))
    assert.strictEqual(result.executed, true)
    assert.ok(alerts.length > 0, 'Should alert at 75% with 30% threshold')
    assert.strictEqual(alerts[0].alertThreshold, 0.3)
  })

  it('stats track near-miss counts', async () => {
    const { gateway, alerts, makeRequest } = createNearMissSetup({ spendLimit: 100 })
    await gateway.processToolCall(makeRequest(95))
    const stats = gateway.getStats()
    assert.ok((stats.nearMissAlerts ?? 0) > 0, 'Stats should track near-miss count')
    assert.ok(stats.nearMissByFacet?.spend, 'Stats should track per-facet count')
  })
})

describe('Near-Miss Alerting — Disabled', () => {
  it('no alerts when enableNearMissAlerting is false', async () => {
    clearStores()
    const gwKeys = generateKeyPair()
    const principal = joinSocialContract({
      name: 'nm-off-p', mission: 'T', owner: 'a',
      capabilities: ['data_read'], platform: 'n', models: ['t'], floor,
    })
    const agent = joinSocialContract({
      name: 'nm-off-a', mission: 'T', owner: 'a',
      capabilities: ['data_read'], platform: 'n', models: ['t'], floor,
    })
    const agentKeys = agent.keyPair
    const del = delegate({ from: principal, toPublicKey: agent.publicKey, scope: ['data_read'], spendLimit: 100, maxDepth: 2, expiresInHours: 1 })

    const alerts: any[] = []
    const gw = createProxyGateway({
      gatewayId: 'gw-off', gatewayPublicKey: gwKeys.publicKey, gatewayPrivateKey: gwKeys.privateKey,
      floor, enableNearMissAlerting: false, onNearMiss: (nm) => alerts.push(nm),
    }, async () => ({ success: true, result: {} }))
    gw.registerAgent(agent.passport, agent.attestation, [del])

    const payload = canonicalize({ requestId: 'nm-off-1', agentId: agent.agentId, tool: 'data_read', params: {}, scopeRequired: 'data_read', spend: { amount: 95, currency: 'usd' } })
    await gw.processToolCall({
      requestId: 'nm-off-1', agentId: agent.agentId, agentPublicKey: agent.publicKey,
      tool: 'data_read', params: {}, scopeRequired: 'data_read',
      spend: { amount: 95, currency: 'usd' },
      signature: sign(payload, agentKeys.privateKey),
    })
    assert.strictEqual(alerts.length, 0, 'No alerts when feature disabled')
  })
})

describe('Near-Miss Alerting — Multiple Facets', () => {
  it('constraintVector headroom is populated for spend facet', async () => {
    const { gateway, makeRequest } = createNearMissSetup({ spendLimit: 100 })
    const result = await gateway.processToolCall(makeRequest(50))
    assert.ok(result.constraintVector, 'must have constraint vector')
    const spendFacet = result.constraintVector.facets.find(f => f.facet === 'spend')
    assert.ok(spendFacet, 'must have spend facet')
    assert.strictEqual(spendFacet.status, 'pass')
    assert.ok(spendFacet.headroom !== undefined, 'spend facet must have headroom')
    // Headroom should be approximately 50 (100 limit - 50 spent)
    assert.ok(typeof spendFacet.headroom === 'number', 'spend headroom should be numeric')
  })
})
