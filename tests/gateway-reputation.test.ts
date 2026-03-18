// ══════════════════════════════════════════════════════════════════
// Gateway — Reputation-Gated Authority Tests
// ══════════════════════════════════════════════════════════════════
//
// Core invariant: effectiveAuthority = min(delegation, tier)
// A delegation granting $10,000 means nothing to a recruit.
// They have to earn it.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { ProxyGateway, createProxyGateway } from '../src/core/gateway.js'
import { joinSocialContract, delegate } from '../src/contract.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { loadFloor } from '../src/core/values.js'
import { clearStores } from '../src/core/delegation.js'
import type { ToolCallRequest, GatewayConfig, ToolExecutor } from '../src/types/gateway.js'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(join(__dirname, '../values/floor.yaml'), 'utf-8')
const floor = loadFloor(floorYaml)

// ── Setup (mirrors gateway.test.ts proven pattern) ──

function makeExecutor(behavior: 'success' | 'fail' = 'success'): ToolExecutor {
  return async () => {
    if (behavior === 'fail') return { success: false, error: 'Tool failed' }
    return { success: true, result: 'ok' }
  }
}

function setup(opts: { reputation?: boolean; executor?: ToolExecutor } = {}) {
  clearStores()
  const gatewayKeys = generateKeyPair()

  const principal = joinSocialContract({
    name: 'Principal', mission: 'Testing', owner: 'tester',
    capabilities: ['testing'], platform: 'test', models: ['test-model'], floor
  })
  const agent = joinSocialContract({
    name: 'Rep Agent', mission: 'Reputation test', owner: 'tester',
    capabilities: ['data:read', 'data:write'], platform: 'test', models: ['test-model'], floor
  })

  const delegation = delegate({
    from: principal, toPublicKey: agent.publicKey,
    scope: ['data:read', 'data:write'], spendLimit: 5000, maxDepth: 2
  })

  const config: GatewayConfig = {
    gatewayId: 'gw-rep-test',
    gatewayPublicKey: gatewayKeys.publicKey,
    gatewayPrivateKey: gatewayKeys.privateKey,
    floor,
    enableReputationGating: opts.reputation ?? true,
    defaultEvidenceClass: 'standard',
  }

  const gw = new ProxyGateway(config, opts.executor ?? makeExecutor())
  const regResult = gw.registerAgent(agent.passport, agent.attestation!, [delegation])
  assert.ok(regResult.registered, `Registration failed: ${regResult.error}`)

  function req(tool: string, scope: string, id?: string, spend?: number): ToolCallRequest {
    const requestId = id ?? `req-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    const payload = canonicalize({
      requestId, agentId: agent.agentId, tool, params: {},
      scopeRequired: scope, spend: spend !== undefined ? { amount: spend, currency: 'usd' } : undefined
    })
    return {
      requestId, agentId: agent.agentId,
      agentPublicKey: agent.publicKey,
      signature: sign(payload, agent.keyPair.privateKey),
      tool, params: {}, scopeRequired: scope,
      spend: spend !== undefined ? { amount: spend, currency: 'usd' } : undefined,
    }
  }

  return { gw, agent, principal, delegation, req, gatewayKeys }
}

// ══════════════════════════════════════════════
// TESTS
// ══════════════════════════════════════════════

describe('Gateway Integration — Reputation-Gated Authority', () => {

  it('new agent starts as recruit (tier 0)', () => {
    const { gw, agent } = setup()
    const tier = gw.getAgentTier(agent.agentId)
    assert.ok(tier, 'tier should exist after registration')
    assert.equal(tier.tier, 0)
    assert.equal(tier.name, 'recruit')
    assert.equal(tier.maxSpendPerAction, 0)
    const rep = gw.getAgentReputation(agent.agentId)
    assert.ok(rep, 'reputation should exist')
    assert.equal(rep.mu, 25)  // INITIAL_MU
    assert.equal(rep.sigma, 25) // MAX_SIGMA
  })

  it('recruit BLOCKED on any spend (tier 0 = $0 max)', async () => {
    const { gw, req } = setup()
    const result = await gw.processToolCall(req('write_file', 'data:write', 'r1', 50))
    assert.equal(result.executed, false, `Should be denied, got: ${result.denialReason}`)
    assert.ok(result.denialReason, 'Should have denial reason')
    // Tier check should be present (either in denialReason or tierCheck)
    assert.ok(
      result.denialReason.includes('Tier') || result.denialReason.includes('tier') || result.tierCheck,
      `Denial should mention tier or include tierCheck: ${result.denialReason}`
    )
  })

  it('recruit CAN execute zero-spend actions (earns reputation)', async () => {
    const { gw, agent, req } = setup()
    const result = await gw.processToolCall(req('read_file', 'data:read'))
    assert.equal(result.executed, true, `Should execute zero-spend: ${result.denialReason}`)
    const rep = gw.getAgentReputation(agent.agentId)
    assert.ok(rep, 'Reputation should exist after execution')
    assert.ok(rep.mu > 25, `mu should increase from 25, got ${rep.mu}`)
    assert.ok(rep.sigma < 25, `sigma should decrease from 25, got ${rep.sigma}`)
  })

  it('repeated success promotes recruit → operator ($100 max)', async () => {
    const { gw, agent, req } = setup()
    for (let i = 0; i < 30; i++) {
      const r = await gw.processToolCall(req('read_file', 'data:read'))
      assert.equal(r.executed, true, `Action ${i} should execute: ${r.denialReason}`)
    }
    const tier = gw.getAgentTier(agent.agentId)
    assert.ok(tier, 'Tier should exist after 30 successes')
    assert.ok(tier.tier >= 1, `Should be at least operator (tier 1), got tier ${tier.tier} (${tier.name})`)
    assert.ok(tier.maxSpendPerAction >= 100, `Operator allows $100, got $${tier.maxSpendPerAction}`)
    // Now a $50 spend should work
    const spendResult = await gw.processToolCall(req('write_file', 'data:write', undefined, 50))
    assert.equal(spendResult.executed, true, `Operator should spend $50: ${spendResult.denialReason}`)
  })

  it('failed executions decrease reputation', async () => {
    const { agent, delegation, gatewayKeys } = setup()
    // Create a new gateway with failing executor
    const failGw = new ProxyGateway({
      gatewayId: 'gw-fail', gatewayPublicKey: gatewayKeys.publicKey,
      gatewayPrivateKey: gatewayKeys.privateKey, floor,
      enableReputationGating: true,
    }, makeExecutor('fail'))
    const regResult = failGw.registerAgent(agent.passport, agent.attestation!, [delegation])
    assert.ok(regResult.registered, `Fail gw registration: ${regResult.error}`)

    // Inject specialist-level reputation so we can see it drop
    failGw.setAgentReputation(agent.agentId, {
      principalId: 'pk', agentId: agent.agentId, scope: '*',
      mu: 50, sigma: 5, receiptCount: 30, lastUpdatedAt: new Date().toISOString()
    })
    const muBefore = failGw.getAgentReputation(agent.agentId)!.mu

    // Execute failures
    for (let i = 0; i < 5; i++) {
      const requestId = `fail-${i}-${Date.now()}`
      const payload = canonicalize({
        requestId, agentId: agent.agentId, tool: 'read', params: {},
        scopeRequired: 'data:read'
      })
      await failGw.processToolCall({
        requestId, agentId: agent.agentId,
        agentPublicKey: agent.publicKey,
        signature: sign(payload, agent.keyPair.privateKey),
        tool: 'read', params: {}, scopeRequired: 'data:read'
      })
    }
    const repAfter = failGw.getAgentReputation(agent.agentId)
    assert.ok(repAfter!.mu < muBefore, `mu should drop from ${muBefore}, got ${repAfter!.mu}`)
  })

  it('backward compatible: no tier check without enableReputationGating', async () => {
    const { gw, agent, req } = setup({ reputation: false })
    // With reputation disabled, any spend should pass (delegation allows $5000)
    const result = await gw.processToolCall(req('write_file', 'data:write', undefined, 500))
    assert.equal(result.executed, true, `Should execute without rep gating: ${result.denialReason}`)
    assert.ok(!result.tierCheck, 'No tier check in result')
    assert.equal(gw.getAgentTier(agent.agentId), undefined, 'No tier stored')
    assert.equal(gw.getAgentReputation(agent.agentId), undefined, 'No reputation stored')
  })

  it('setAgentReputation() allows external injection', async () => {
    const { gw, agent, req } = setup()
    const success = gw.setAgentReputation(agent.agentId, {
      principalId: 'pk', agentId: agent.agentId, scope: '*',
      mu: 85, sigma: 2, receiptCount: 100, lastUpdatedAt: new Date().toISOString()
    })
    assert.equal(success, true, 'setAgentReputation should return true')
    const tier = gw.getAgentTier(agent.agentId)
    assert.ok(tier, 'Tier should exist after injection')
    assert.ok(tier.tier >= 3, `Should be captain+ (tier 3+), got ${tier.tier} (${tier.name})`)
    // Captain can spend up to $2000
    const result = await gw.processToolCall(req('write_file', 'data:write', undefined, 1500))
    assert.equal(result.executed, true, `Captain should handle $1500: ${result.denialReason}`)
  })

  it('stats track tier denials and reputation updates', async () => {
    const { gw, req } = setup()
    // Recruit tries spend → denied
    await gw.processToolCall(req('write_file', 'data:write', 'stat-1', 100))
    // Recruit does zero-spend → success + rep update
    await gw.processToolCall(req('read_file', 'data:read', 'stat-2'))
    const stats = gw.getStats()
    assert.ok((stats.tierDenials ?? 0) >= 1, `Should have tier denials, got ${stats.tierDenials}`)
    assert.ok((stats.reputationUpdates ?? 0) >= 1, `Should have rep updates, got ${stats.reputationUpdates}`)
  })

  it('core invariant: effectiveAuthority = min(delegation, tier)', async () => {
    const { gw, agent, req } = setup()
    // Inject operator reputation (tier 1, $100 max)
    gw.setAgentReputation(agent.agentId, {
      principalId: 'pk', agentId: agent.agentId, scope: '*',
      mu: 50, sigma: 5, receiptCount: 30, lastUpdatedAt: new Date().toISOString()
    })
    const tier = gw.getAgentTier(agent.agentId)
    assert.ok(tier, 'Tier should exist after injection')
    // Delegation allows $5000. Operator tier allows $100. Min = $100.
    const pass = await gw.processToolCall(req('write_file', 'data:write', undefined, 80))
    assert.equal(pass.executed, true, `$80 within operator $100 limit: ${pass.denialReason}`)
    const fail = await gw.processToolCall(req('write_file', 'data:write', undefined, 150))
    assert.equal(fail.executed, false, '$150 exceeds operator $100 limit')
    assert.ok(fail.denialReason, 'Should have denial reason for over-tier spend')
  })
})
