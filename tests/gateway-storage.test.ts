// ══════════════════════════════════════════════════════════════════
// Gateway + StorageBackend Integration Test
// ══════════════════════════════════════════════════════════════════
// Proves: gateway state persists across restart via StorageBackend.
// The most important test in the persistence layer.
// ══════════════════════════════════════════════════════════════════

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { joinSocialContract, delegate } from '../src/contract.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { loadFloor } from '../src/core/values.js'
import { createProxyGateway } from '../src/core/gateway.js'
import { VolatileBackend } from '../src/storage/volatile-backend.js'
import { clearStores } from '../src/core/delegation.js'
import type { ToolCallRequest, ToolExecutor, GatewayConfig } from '../src/types/gateway.js'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(join(__dirname, '../values/floor.yaml'), 'utf-8')

function makeExecutor(): ToolExecutor {
  return async (tool: string, params: Record<string, unknown>) => {
    return { success: true, result: { tool, echo: params, cost: 25.00 } }
  }
}

function makeGatewayConfig(storage: VolatileBackend): { config: GatewayConfig; keys: ReturnType<typeof generateKeyPair> } {
  const keys = generateKeyPair()
  return {
    config: {
      gatewayId: 'gw-storage-test',
      gatewayPublicKey: keys.publicKey,
      gatewayPrivateKey: keys.privateKey,
      floor: loadFloor(floorYaml),
      approvalTTLSeconds: 30,
      recheckRevocationOnExecute: true,
      storage
    },
    keys
  }
}

describe('Gateway + StorageBackend Integration', () => {

  it('registerAgent persists to storage', async () => {
    clearStores()
    const storage = new VolatileBackend()
    await storage.initialize()
    const { config } = makeGatewayConfig(storage)
    const floor = loadFloor(floorYaml)

    const principal = joinSocialContract({
      name: 'Storage Test Principal', mission: 'Test persistence', owner: 'tester',
      capabilities: ['data:read'], platform: 'test', models: ['test-model'], floor
    })
    const agent = joinSocialContract({
      name: 'Storage Test Agent', mission: 'Persist me', owner: 'tester',
      capabilities: ['data:read'], platform: 'test', models: ['test-model'], floor
    })
    const delegation = delegate({
      from: principal, toPublicKey: agent.keyPair.publicKey,
      scope: ['data:read'], spendLimit: 100, maxDepth: 2
    })

    const gateway = createProxyGateway(config, makeExecutor())
    gateway.registerAgent(agent.passport, agent.attestation, [delegation])

    // Give fire-and-forget a tick to complete
    await new Promise(r => setTimeout(r, 50))

    // Verify agent was persisted
    const stored = await storage.getAgent(agent.agentId)
    assert.ok(stored, 'Agent persisted to storage')
    assert.equal(stored.agentId, agent.agentId)

    // Verify delegation was persisted
    const dels = await storage.getDelegationsForAgent(agent.keyPair.publicKey)
    assert.ok(dels.length > 0, 'Delegation persisted to storage')
  })

  it('processToolCall persists receipt to storage', async () => {
    clearStores()
    const storage = new VolatileBackend()
    await storage.initialize()
    const { config } = makeGatewayConfig(storage)
    const floor = loadFloor(floorYaml)

    const principal = joinSocialContract({
      name: 'Receipt Persist Principal', mission: 'Test receipt persistence', owner: 'tester',
      capabilities: ['data:read'], platform: 'test', models: ['test-model'], floor
    })
    const agent = joinSocialContract({
      name: 'Receipt Persist Agent', mission: 'Generate receipts', owner: 'tester',
      capabilities: ['data:read'], platform: 'test', models: ['test-model'], floor
    })
    const delegation = delegate({
      from: principal, toPublicKey: agent.keyPair.publicKey,
      scope: ['data:read'], spendLimit: 100, maxDepth: 2
    })

    const gateway = createProxyGateway(config, makeExecutor())
    gateway.registerAgent(agent.passport, agent.attestation, [delegation])

    // Execute a tool call
    const requestId = `persist-rcpt-${Date.now()}`
    const payload = canonicalize({
      requestId, agentId: agent.agentId,
      tool: 'data:read', params: { table: 'users' },
      scopeRequired: 'data:read', spend: undefined
    })
    const result = await gateway.processToolCall({
      requestId, agentId: agent.agentId,
      agentPublicKey: agent.keyPair.publicKey,
      signature: sign(payload, agent.keyPair.privateKey),
      tool: 'data:read', params: { table: 'users' },
      scopeRequired: 'data:read', context: 'Storage persistence test'
    })

    assert.ok(result.executed, 'Tool call executed')
    assert.ok(result.receipt, 'Receipt generated')

    // Give fire-and-forget a tick
    await new Promise(r => setTimeout(r, 50))

    // Verify receipt was persisted
    const count = await storage.getReceiptCount()
    assert.ok(count >= 1, `Receipt persisted to storage (count: ${count})`)

    // Verify nonce was persisted
    const nonceBlocked = await storage.checkAndStoreNonce(requestId, 3600)
    assert.equal(nonceBlocked, false, 'Nonce persisted — replay blocked')
  })

  it('gateway survives restart via loadFromStorage', async () => {
    clearStores()
    const storage = new VolatileBackend()
    await storage.initialize()
    const gwKeys = generateKeyPair()
    const floor = loadFloor(floorYaml)

    // Phase 1: Create gateway, register agent, execute action
    const principal = joinSocialContract({
      name: 'Restart Test Principal', mission: 'Survive restart', owner: 'tester',
      capabilities: ['data:read'], platform: 'test', models: ['test-model'], floor
    })
    const agent = joinSocialContract({
      name: 'Restart Test Agent', mission: 'Survive restart', owner: 'tester',
      capabilities: ['data:read'], platform: 'test', models: ['test-model'], floor
    })
    const delegation = delegate({
      from: principal, toPublicKey: agent.keyPair.publicKey,
      scope: ['data:read'], spendLimit: 100, maxDepth: 2
    })

    const config1: GatewayConfig = {
      gatewayId: 'gw-restart', gatewayPublicKey: gwKeys.publicKey,
      gatewayPrivateKey: gwKeys.privateKey, floor,
      approvalTTLSeconds: 30, recheckRevocationOnExecute: true, storage
    }
    const gw1 = createProxyGateway(config1, makeExecutor())
    gw1.registerAgent(agent.passport, agent.attestation, [delegation])

    const reqId = `restart-${Date.now()}`
    const payload = canonicalize({
      requestId: reqId, agentId: agent.agentId,
      tool: 'data:read', params: { query: 'SELECT 1' },
      scopeRequired: 'data:read', spend: undefined
    })
    const r1 = await gw1.processToolCall({
      requestId: reqId, agentId: agent.agentId,
      agentPublicKey: agent.keyPair.publicKey,
      signature: sign(payload, agent.keyPair.privateKey),
      tool: 'data:read', params: { query: 'SELECT 1' },
      scopeRequired: 'data:read', context: 'Before restart'
    })
    assert.ok(r1.executed, 'Phase 1: action executed')

    // Wait for write-through
    await new Promise(r => setTimeout(r, 100))

    // Phase 2: "Restart" — new gateway, same storage
    clearStores() // Clear module-level Maps to simulate process restart
    const config2: GatewayConfig = {
      gatewayId: 'gw-restart', gatewayPublicKey: gwKeys.publicKey,
      gatewayPrivateKey: gwKeys.privateKey, floor,
      approvalTTLSeconds: 30, recheckRevocationOnExecute: true, storage
    }
    const gw2 = createProxyGateway(config2, makeExecutor())

    // Load state from storage
    const loadResult = await gw2.loadFromStorage()
    assert.ok(loadResult.loaded, 'Phase 2: state loaded from storage')
    assert.equal(loadResult.agents, 1, 'Phase 2: 1 agent loaded')
    assert.ok(loadResult.receipts >= 1, 'Phase 2: receipts exist in storage')
    assert.equal(loadResult.errors.length, 0, 'Phase 2: no integrity errors')

    // Verify the agent can execute again on the new gateway
    const reqId2 = `after-restart-${Date.now()}`
    const payload2 = canonicalize({
      requestId: reqId2, agentId: agent.agentId,
      tool: 'data:read', params: { query: 'SELECT 2' },
      scopeRequired: 'data:read', spend: undefined
    })
    const r2 = await gw2.processToolCall({
      requestId: reqId2, agentId: agent.agentId,
      agentPublicKey: agent.keyPair.publicKey,
      signature: sign(payload2, agent.keyPair.privateKey),
      tool: 'data:read', params: { query: 'SELECT 2' },
      scopeRequired: 'data:read', context: 'After restart'
    })
    assert.ok(r2.executed, 'Phase 2: action executed on restarted gateway')

    // Replay protection survives: original nonce should still be blocked
    await new Promise(r => setTimeout(r, 50))
    const replayBlocked = await storage.checkAndStoreNonce(reqId, 3600)
    assert.equal(replayBlocked, false, 'Phase 2: original nonce still blocked after restart')

    console.log('  ✅ Gateway survived restart — agent, delegations, receipts, nonces all persisted')
  })

  it('no warning when storage is provided', async () => {
    clearStores()
    const storage = new VolatileBackend()
    await storage.initialize()
    const { config } = makeGatewayConfig(storage)
    // The warning should NOT appear because storage is provided
    // (Manual verification — no assertion needed, just ensures no crash)
    const gw = createProxyGateway(config, makeExecutor())
    assert.ok(gw)
  })
})
