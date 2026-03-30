// ══════════════════════════════════════════════════════════════════
// Gateway Data Enforcement — Tests
// ══════════════════════════════════════════════════════════════════
// Validates: data access terms checking through the gateway,
// data access receipts alongside ActionReceipts, denial on
// terms violation, stats tracking.
// Wires data-source, data-contribution, data-enforcement,
// data-gateway into the gateway enforcement pipeline.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createProxyGateway } from '../src/core/gateway.js'
import { joinSocialContract, delegate } from '../src/contract.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { loadFloor } from '../src/core/values.js'
import { clearStores } from '../src/core/delegation.js'
import { DataGateway } from '../src/core/data-gateway.js'
import { registerSelfAttestedSource } from '../src/core/data-source.js'
import type { GatewayConfig } from '../src/types/gateway.js'
import { readFileSync } from 'fs'
import { dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(__dirname + '/../values/floor.yaml', 'utf-8')
const floor = loadFloor(floorYaml)

function createDataSetup() {
  clearStores()
  const gwKeys = generateKeyPair()
  const ownerKeys = generateKeyPair()

  const principal = joinSocialContract({
    name: 'data-principal', mission: 'Test', owner: 'admin',
    capabilities: ['data_read'], platform: 'node', models: ['test'], floor,
  })
  const agent = joinSocialContract({
    name: 'data-agent', mission: 'Test', owner: 'admin',
    capabilities: ['data_read'], platform: 'node', models: ['test'], floor,
  })

  const del = delegate({
    from: principal, toPublicKey: agent.publicKey,
    scope: ['data_read'], spendLimit: 100,
    maxDepth: 2, expiresInHours: 1,
  })

  // Register a data source
  const sourceReceipt = registerSelfAttestedSource({
    ownerPrincipalId: 'owner-001',
    ownerPublicKey: ownerKeys.publicKey,
    ownerPrivateKey: ownerKeys.privateKey,
    contentCommitment: 'sha256:abc123',
    contentType: 'document',
    contentDescriptor: 'Test dataset',
    dataTerms: {
      allowedPurposes: ['read', 'analyze'],
      requireAttribution: true,
      requireNotification: false,
      compensation: { type: 'none' },
      derivativePolicy: 'attribution_required',
      auditVisibility: 'public',
      revocable: true,
    },
  })

  // Create data gateway
  const dataGw = new DataGateway({
    gatewayId: 'data-gw-test',
    gatewayPublicKey: gwKeys.publicKey,
    gatewayPrivateKey: gwKeys.privateKey,
    enforcementMode: 'enforce',
    requireTermsAcceptance: true,
  })
  dataGw.registerSource(sourceReceipt, 'Test dataset')

  // Create proxy gateway with data enforcement
  const config: GatewayConfig = {
    gatewayId: 'gw-data-test',
    gatewayPublicKey: gwKeys.publicKey,
    gatewayPrivateKey: gwKeys.privateKey,
    floor,
    enableDataEnforcement: true,
    dataGateway: dataGw,
  }
  const gateway = createProxyGateway(config, async () => ({ success: true, result: {} }))
  gateway.registerAgent(agent.passport, agent.attestation, [del])

  let reqCounter = 0
  function makeRequest(dataSourceIds?: string[]) {
    const requestId = `data-req-${++reqCounter}-${Date.now()}`
    const payload = canonicalize({
      requestId, agentId: agent.agentId, tool: 'data_read',
      params: {}, scopeRequired: 'data_read',
    })
    return {
      requestId, agentId: agent.agentId, agentPublicKey: agent.publicKey,
      tool: 'data_read', params: {}, scopeRequired: 'data_read',
      signature: sign(payload, agent.keyPair.privateKey),
      dataSourceIds,
    }
  }

  return { gateway, dataGw, agent, sourceReceipt, makeRequest }
}

describe('Gateway Data Enforcement — Terms Check', () => {
  it('denies access when terms not accepted', async () => {
    const { gateway, sourceReceipt, makeRequest } = createDataSetup()
    const result = await gateway.processToolCall(makeRequest([sourceReceipt.sourceReceiptId]))
    assert.strictEqual(result.executed, false)
    assert.ok(result.constraintFailures)
    assert.strictEqual(result.constraintFailures[0].facet, 'data')
    assert.strictEqual(result.constraintFailures[0].code, 'DATA_ACCESS_DENIED')
    assert.ok(result.dataAccessDecisions)
    assert.strictEqual(result.dataAccessDecisions[0].allowed, false)
  })

  it('permits access after terms accepted', async () => {
    const { gateway, dataGw, agent, sourceReceipt, makeRequest } = createDataSetup()
    dataGw.acceptTerms({
      agentId: agent.agentId,
      agentPublicKey: agent.publicKey,
      sourceReceiptId: sourceReceipt.sourceReceiptId,
    })
    const result = await gateway.processToolCall(makeRequest([sourceReceipt.sourceReceiptId]))
    assert.strictEqual(result.executed, true)
    assert.ok(result.dataAccessDecisions)
    assert.strictEqual(result.dataAccessDecisions[0].allowed, true)
  })
})

describe('Gateway Data Enforcement — No Data Sources', () => {
  it('skips data check when no dataSourceIds on request', async () => {
    const { gateway, makeRequest } = createDataSetup()
    const result = await gateway.processToolCall(makeRequest())  // no dataSourceIds
    assert.strictEqual(result.executed, true)
    assert.strictEqual(result.dataAccessDecisions, undefined)
  })

  it('skips data check when data enforcement disabled', async () => {
    clearStores()
    const gwKeys = generateKeyPair()
    const principal = joinSocialContract({
      name: 'nodata-p', mission: 'Test', owner: 'admin',
      capabilities: ['data_read'], platform: 'node', models: ['test'], floor,
    })
    const agent = joinSocialContract({
      name: 'nodata-a', mission: 'Test', owner: 'admin',
      capabilities: ['data_read'], platform: 'node', models: ['test'], floor,
    })
    const del = delegate({
      from: principal, toPublicKey: agent.publicKey,
      scope: ['data_read'], spendLimit: 100, maxDepth: 2, expiresInHours: 1,
    })
    const gateway = createProxyGateway({
      gatewayId: 'gw-nodata', gatewayPublicKey: gwKeys.publicKey,
      gatewayPrivateKey: gwKeys.privateKey, floor,
      // enableDataEnforcement NOT set
    }, async () => ({ success: true, result: {} }))
    gateway.registerAgent(agent.passport, agent.attestation, [del])
    const requestId = `nodata-${Date.now()}`
    const payload = canonicalize({ requestId, agentId: agent.agentId, tool: 'data_read', params: {}, scopeRequired: 'data_read' })
    const result = await gateway.processToolCall({
      requestId, agentId: agent.agentId, agentPublicKey: agent.publicKey,
      tool: 'data_read', params: {}, scopeRequired: 'data_read',
      signature: sign(payload, agent.keyPair.privateKey),
      dataSourceIds: ['some-source'],
    })
    assert.strictEqual(result.executed, true)
    assert.strictEqual(result.dataAccessDecisions, undefined)
  })
})

describe('Gateway Data Enforcement — Stats & Dynamic Wiring', () => {
  it('tracks data access denial stats', async () => {
    const { gateway, sourceReceipt, makeRequest } = createDataSetup()
    await gateway.processToolCall(makeRequest([sourceReceipt.sourceReceiptId]))
    const stats = gateway.getStats()
    assert.ok((stats.dataAccessDenials ?? 0) > 0, 'should track data denials')
  })

  it('tracks data access granted stats', async () => {
    const { gateway, dataGw, agent, sourceReceipt, makeRequest } = createDataSetup()
    dataGw.acceptTerms({
      agentId: agent.agentId, agentPublicKey: agent.publicKey,
      sourceReceiptId: sourceReceipt.sourceReceiptId,
    })
    await gateway.processToolCall(makeRequest([sourceReceipt.sourceReceiptId]))
    const stats = gateway.getStats()
    assert.ok((stats.dataAccessGranted ?? 0) > 0, 'should track data grants')
  })

  it('setDataGateway enables data enforcement dynamically', async () => {
    clearStores()
    const gwKeys = generateKeyPair()
    const ownerKeys = generateKeyPair()
    const principal = joinSocialContract({
      name: 'dyn-p', mission: 'Test', owner: 'admin',
      capabilities: ['data_read'], platform: 'node', models: ['test'], floor,
    })
    const agent = joinSocialContract({
      name: 'dyn-a', mission: 'Test', owner: 'admin',
      capabilities: ['data_read'], platform: 'node', models: ['test'], floor,
    })

    const del = delegate({
      from: principal, toPublicKey: agent.publicKey,
      scope: ['data_read'], spendLimit: 100, maxDepth: 2, expiresInHours: 1,
    })
    // Start WITHOUT data enforcement
    const gateway = createProxyGateway({
      gatewayId: 'gw-dyn', gatewayPublicKey: gwKeys.publicKey,
      gatewayPrivateKey: gwKeys.privateKey, floor,
    }, async () => ({ success: true, result: {} }))
    gateway.registerAgent(agent.passport, agent.attestation, [del])

    // Create data gateway and wire in dynamically
    const sourceReceipt = registerSelfAttestedSource({
      ownerPrincipalId: 'owner-dyn', ownerPublicKey: ownerKeys.publicKey,
      ownerPrivateKey: ownerKeys.privateKey, contentCommitment: 'sha256:dyn',
      contentType: 'document', contentDescriptor: 'Dynamic source',
      dataTerms: {
        allowedPurposes: ['read'], requireAttribution: false, requireNotification: false,
        compensation: { type: 'none' }, derivativePolicy: 'unrestricted',
        auditVisibility: 'public', revocable: true,
      },
    })
    const dataGw = new DataGateway({
      gatewayId: 'data-gw-dyn', gatewayPublicKey: gwKeys.publicKey,
      gatewayPrivateKey: gwKeys.privateKey, enforcementMode: 'enforce',
      requireTermsAcceptance: true,
    })
    dataGw.registerSource(sourceReceipt, 'Dynamic source')

    // Wire it in
    gateway.setDataGateway(dataGw)

    // Now data enforcement should work — deny without terms
    let reqCounter = 0
    function makeReq(dataSourceIds?: string[]) {
      const requestId = `dyn-req-${++reqCounter}-${Date.now()}`
      const payload = canonicalize({ requestId, agentId: agent.agentId, tool: 'data_read', params: {}, scopeRequired: 'data_read' })
      return {
        requestId, agentId: agent.agentId, agentPublicKey: agent.publicKey,
        tool: 'data_read', params: {}, scopeRequired: 'data_read',
        signature: sign(payload, agent.keyPair.privateKey), dataSourceIds,
      }
    }

    const r1 = await gateway.processToolCall(makeReq([sourceReceipt.sourceReceiptId]))
    assert.strictEqual(r1.executed, false, 'Should deny after dynamic wiring')
    assert.strictEqual(r1.constraintFailures![0].facet, 'data')

    // Accept terms and retry
    dataGw.acceptTerms({
      agentId: agent.agentId, agentPublicKey: agent.publicKey,
      sourceReceiptId: sourceReceipt.sourceReceiptId,
    })
    const r2 = await gateway.processToolCall(makeReq([sourceReceipt.sourceReceiptId]))
    assert.strictEqual(r2.executed, true, 'Should permit after terms accepted')
  })
})
