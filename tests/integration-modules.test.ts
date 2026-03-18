// ══════════════════════════════════════════════════════════════════
// Cross-Module Integration Tests
// Proves Modules 18 (cross-chain) + 20 (obligations) work through
// the ProxyGateway enforcement boundary — not just in isolation.
// ══════════════════════════════════════════════════════════════════

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { ProxyGateway, createProxyGateway } from '../src/core/gateway.js'
import { joinSocialContract, delegate } from '../src/contract.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { loadFloor } from '../src/core/values.js'
import { clearStores } from '../src/core/delegation.js'
import { createCrossChainPermit, countersignPermit } from '../src/core/cross-chain.js'
import { createObligation } from '../src/core/obligations.js'
import type { ToolCallRequest, ToolExecutor, GatewayConfig } from '../src/types/gateway.js'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(join(__dirname, '../values/floor.yaml'), 'utf-8')
const floor = loadFloor(floorYaml)

// ── Helpers ──

function makeToolExecutor(): ToolExecutor {
  return async (tool: string, params: Record<string, unknown>) => {
    return { success: true, result: { tool, echo: params } }
  }
}

async function setupCrossChainScenario(opts?: {
  enableCrossChain?: boolean
  enableObligations?: boolean
}) {
  clearStores()
  const gatewayKeys = generateKeyPair()

  const principalA = joinSocialContract({
    name: 'Principal A', mission: 'Data provider', owner: 'owner-a',
    capabilities: ['data:read'], platform: 'test', models: ['test'], floor
  })
  const principalB = joinSocialContract({
    name: 'Principal B', mission: 'Action executor', owner: 'owner-b',
    capabilities: ['data:write', 'api:send'], platform: 'test', models: ['test'], floor
  })
  // The agent gets delegations from BOTH principals
  const agent = joinSocialContract({
    name: 'Shared Agent', mission: 'Multi-principal ops', owner: 'owner-agent',
    capabilities: ['data:read', 'data:write', 'api:send'], platform: 'test', models: ['test'], floor
  })

  // Delegation A: data:read from Principal A
  const delegationA = delegate({
    from: principalA, toPublicKey: agent.keyPair.publicKey,
    scope: ['data:read'], spendLimit: 100, maxDepth: 2
  })

  // Delegation B: data:write, api:send from Principal B
  const delegationB = delegate({
    from: principalB, toPublicKey: agent.keyPair.publicKey,
    scope: ['data:write', 'api:send'], spendLimit: 100, maxDepth: 2
  })

  const config: GatewayConfig = {
    gatewayId: 'gw-integration-test',
    gatewayPublicKey: gatewayKeys.publicKey,
    gatewayPrivateKey: gatewayKeys.privateKey,
    floor,
    approvalTTLSeconds: 30,
    recheckRevocationOnExecute: true,
    enableCrossChainEnforcement: opts?.enableCrossChain ?? true,
    enableObligationMonitoring: opts?.enableObligations ?? true
  }

  const gateway = createProxyGateway(config, makeToolExecutor())
  gateway.registerAgent(agent.passport, agent.attestation!, [delegationA, delegationB])

  function makeRequest(overrides: {
    tool?: string; params?: Record<string, unknown>
    scopeRequired?: string; delegationId?: string; spend?: { amount: number; currency: string }
  } = {}): ToolCallRequest {
    const requestId = `req-${Date.now()}-${Math.random().toString(36).slice(2)}`
    const tool = overrides.tool || 'data:fetch'
    const params = overrides.params || { query: 'test' }
    const scopeRequired = overrides.scopeRequired || 'data:read'
    const spend = overrides.spend

    const payload = canonicalize({
      requestId, agentId: agent.agentId, tool, params, scopeRequired, spend
    })
    return {
      requestId, agentId: agent.agentId,
      agentPublicKey: agent.keyPair.publicKey,
      signature: sign(payload, agent.keyPair.privateKey),
      tool, params, scopeRequired, spend,
      delegationId: overrides.delegationId,
      context: 'Integration test'
    }
  }

  return {
    gateway, config, principalA, principalB, agent,
    delegationA, delegationB, gatewayKeys, makeRequest
  }
}

// ══════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════

describe('Gateway + Module 18 (Cross-Chain Enforcement)', () => {

  it('creates execution frame on agent registration when cross-chain enabled', async () => {
    const { gateway, agent } = await setupCrossChainScenario()
    const frame = gateway.getAgentFrame(agent.agentId)
    assert.ok(frame, 'Frame should exist')
    assert.equal(frame.agentId, agent.agentId)
    assert.equal(frame.active, true)
    assert.equal(frame.frameTaint.labels.length, 0, 'Frame starts with no taint')
  })

  it('wraps tool result in SAO after execution', async () => {
    const { gateway, makeRequest } = await setupCrossChainScenario()
    const r = await gateway.processToolCall(makeRequest({
      tool: 'data:fetch', scopeRequired: 'data:read'
    }))
    assert.ok(r.executed, 'Should execute')
    assert.ok(r.sao, 'Result should include SAO')
    assert.ok(r.sao.saoId.startsWith('sao-'), 'SAO should have valid ID')
    assert.ok(r.sao.taint.principalId, 'SAO taint should have principal ID')
    assert.ok(r.sao.dataHash, 'SAO should have data hash')
  })

  it('BLOCKS confused deputy — read under A, send under B', async () => {
    const { gateway, makeRequest, delegationA, delegationB } = await setupCrossChainScenario()

    // Step 1: Read under delegation A (taints frame with principal A)
    const r1 = await gateway.processToolCall(makeRequest({
      tool: 'data:fetch', scopeRequired: 'data:read', delegationId: delegationA.delegationId
    }))
    assert.ok(r1.executed, 'Read should succeed')

    // Step 2: Try to send under delegation B (different principal)
    // This is the confused deputy — agent uses A's data in B's action
    const r2 = await gateway.processToolCall(makeRequest({
      tool: 'api:send', scopeRequired: 'api:send', delegationId: delegationB.delegationId,
      params: { payload: 'data from principal A' }
    }))
    assert.equal(r2.executed, false, 'Send should be BLOCKED')
    assert.ok(r2.denialReason?.includes('Cross-chain blocked'), 'Denial reason should mention cross-chain')
    assert.ok(r2.flowCheck, 'Should include flow check result')
    assert.equal(r2.flowCheck?.verdict, 'blocked')

    const stats = gateway.getStats()
    assert.ok((stats.crossChainBlocked || 0) >= 1, 'Should track blocked cross-chain attempts')
  })

  it('ALLOWS cross-chain with valid permit', async () => {
    const { gateway, agent, makeRequest, principalA, principalB,
            delegationA, delegationB } = await setupCrossChainScenario()

    // Create permit: A authorizes data flow to B's actions
    const permitUnsigned = createCrossChainPermit({
      sourcePrincipalId: principalA.publicKey,
      sourcePrincipalPublicKey: principalA.publicKey,
      sourceDataClasses: ['data:read'],
      destPrincipalId: principalB.publicKey,
      destPrincipalPublicKey: principalB.publicKey,
      destAllowedScopes: ['api:send'],
      purpose: 'Integration test: allow A data to flow to B actions',
      sourcePrivateKey: principalA.keyPair.privateKey
    })
    const permit = countersignPermit(permitUnsigned, principalB.keyPair.privateKey)
    gateway.registerPermit(agent.agentId, permit)

    // Read under A
    const r1 = await gateway.processToolCall(makeRequest({
      tool: 'data:fetch', scopeRequired: 'data:read', delegationId: delegationA.delegationId
    }))
    assert.ok(r1.executed)

    // Send under B — should succeed because permit exists
    const r2 = await gateway.processToolCall(makeRequest({
      tool: 'api:send', scopeRequired: 'api:send', delegationId: delegationB.delegationId
    }))
    assert.ok(r2.executed, 'Send should SUCCEED with permit')

    const stats = gateway.getStats()
    assert.ok((stats.crossChainPermitted || 0) >= 1, 'Should track permitted cross-chain flows')
  })
})

describe('Gateway + Module 20 (Obligation Enforcement)', () => {

  it('fulfills obligation when matching receipt is produced', async () => {
    const { gateway, agent, makeRequest, principalA, delegationA } = await setupCrossChainScenario()

    // Create obligation: agent must perform a data:fetch within deadline
    const obligation = createObligation({
      delegationId: delegationA.delegationId,
      obligorAgentId: agent.agentId,
      obligorPublicKey: agent.publicKey,
      action: { type: 'gateway:data:fetch', scope: 'data:read', description: 'Must fetch data' },
      deadline: new Date(Date.now() + 3600000).toISOString(), // 1 hour from now
      evidence: {
        type: 'action_receipt',
        matchCriteria: { toolMatch: 'gateway:data:fetch', scopeMatch: 'data:read' }
      },
      penalty: { type: 'warning', severity: 'minor', gracePeriodMinutes: 5, autoExecute: false },
      principalPrivateKey: principalA.keyPair.privateKey,
      principalPublicKey: principalA.publicKey
    })
    gateway.registerObligation(agent.agentId, obligation)

    // Verify obligation is pending
    const before = gateway.getAgentObligations(agent.agentId)
    assert.ok(before?.some(o => o.status === 'pending'))

    // Execute the matching tool call
    const r = await gateway.processToolCall(makeRequest({
      tool: 'data:fetch', scopeRequired: 'data:read', delegationId: delegationA.delegationId
    }))
    assert.ok(r.executed, 'Tool call should succeed')
    assert.ok(r.obligationResolutions, 'Should have obligation resolutions')
    assert.equal(r.obligationResolutions!.length, 1)
    assert.equal(r.obligationResolutions![0].outcome, 'fulfilled')

    // Verify obligation status updated
    const after = gateway.getAgentObligations(agent.agentId)
    assert.ok(after?.some(o => o.status === 'fulfilled'))

    const stats = gateway.getStats()
    assert.ok((stats.obligationsFulfilled || 0) >= 1)
  })

  it('terminates obligations when delegation is revoked', async () => {
    const { gateway, agent, principalA, delegationA } = await setupCrossChainScenario()

    const obligation = createObligation({
      delegationId: delegationA.delegationId,
      obligorAgentId: agent.agentId,
      obligorPublicKey: agent.publicKey,
      action: { type: 'gateway:data:fetch', scope: 'data:read', description: 'Must fetch' },
      deadline: new Date(Date.now() + 3600000).toISOString(),
      evidence: {
        type: 'action_receipt',
        matchCriteria: { toolMatch: 'gateway:data:fetch' }
      },
      penalty: { type: 'warning', severity: 'minor', gracePeriodMinutes: 5, autoExecute: false },
      survivesTermination: false,
      principalPrivateKey: principalA.keyPair.privateKey,
      principalPublicKey: principalA.publicKey
    })
    gateway.registerObligation(agent.agentId, obligation)

    // Verify pending
    assert.ok(gateway.getAgentObligations(agent.agentId)?.some(o => o.status === 'pending'))

    // Revoke the delegation — should terminate the obligation
    gateway.revokeDelegation(agent.agentId, delegationA.delegationId)

    // Verify terminated
    const after = gateway.getAgentObligations(agent.agentId)
    assert.ok(after?.some(o => o.status === 'terminated_by_revocation'),
      'Obligation should be terminated by revocation')

    const stats = gateway.getStats()
    assert.ok((stats.obligationsTerminated || 0) >= 1)
  })
})

describe('Gateway — Backward Compatibility', () => {

  it('works without cross-chain or obligation flags (old behavior)', async () => {
    const { gateway, makeRequest, delegationA, delegationB } = await setupCrossChainScenario({
      enableCrossChain: false, enableObligations: false
    })

    // Read under A, then send under B — should work because cross-chain is off
    const r1 = await gateway.processToolCall(makeRequest({
      tool: 'data:fetch', scopeRequired: 'data:read', delegationId: delegationA.delegationId
    }))
    assert.ok(r1.executed)
    assert.equal(r1.sao, undefined, 'No SAO when cross-chain disabled')

    const r2 = await gateway.processToolCall(makeRequest({
      tool: 'api:send', scopeRequired: 'api:send', delegationId: delegationB.delegationId
    }))
    assert.ok(r2.executed, 'Should succeed — no cross-chain enforcement')
    assert.equal(r2.flowCheck, undefined, 'No flow check when disabled')

    // No frame should exist
    const frame = gateway.getAgentFrame(gateway.getStats().activeAgents > 0 ? r1.requestId : '')
    // getAgentFrame returns undefined for non-existent agent
  })
})
