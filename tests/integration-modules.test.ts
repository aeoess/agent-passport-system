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

// ── Test Helpers ──

function makeExecutor(): ToolExecutor {
  return async (tool: string, params: Record<string, unknown>) => {
    return { success: true, result: { tool, echo: params } }
  }
}

function makeRequest(
  agent: ReturnType<typeof joinSocialContract>,
  overrides: Partial<ToolCallRequest> = {}
): ToolCallRequest {
  const requestId = overrides.requestId || `req-${Date.now()}-${Math.random().toString(36).slice(2)}`
  const tool = overrides.tool || 'api:fetch'
  const params = overrides.params || { url: 'https://example.com' }
  const scopeRequired = overrides.scopeRequired || 'data:read'
  const spend = overrides.spend

  const payload = canonicalize({
    requestId, agentId: agent.agentId, tool, params, scopeRequired, spend
  })
  return {
    requestId,
    agentId: overrides.agentId || agent.agentId,
    agentPublicKey: overrides.agentPublicKey || agent.keyPair.publicKey,
    signature: overrides.signature || sign(payload, agent.keyPair.privateKey),
    tool, params, scopeRequired, spend,
    context: overrides.context || 'Integration test'
  }
}

// ══════════════════════════════════════════════════════════════════
// TEST 1: Backward compatibility — no cross-chain flags = old behavior
// ══════════════════════════════════════════════════════════════════

describe('Gateway Integration — Backward Compatibility', () => {
  it('works without cross-chain or obligation flags', async () => {
    clearStores()
    const gk = generateKeyPair()
    const principal = joinSocialContract({
      name: 'P', mission: 'test', owner: 'o',
      capabilities: ['data:read'], platform: 'test', models: ['m'], floor
    })
    const agent = joinSocialContract({
      name: 'A', mission: 'test', owner: 'o',
      capabilities: ['data:read'], platform: 'test', models: ['m'], floor
    })
    const d = delegate({
      from: principal, toPublicKey: agent.keyPair.publicKey,
      scope: ['data:read'], spendLimit: 100, maxDepth: 2
    })
    const gw = createProxyGateway({
      gatewayId: 'gw', gatewayPublicKey: gk.publicKey,
      gatewayPrivateKey: gk.privateKey, floor
    }, makeExecutor())
    gw.registerAgent(agent.passport, agent.attestation, [d])
    const r = await gw.processToolCall(makeRequest(agent))
    assert.equal(r.executed, true)
    assert.equal(r.sao, undefined, 'No SAO without cross-chain flag')
    assert.equal(r.flowCheck, undefined, 'No flow check without cross-chain flag')
  })
})

// ══════════════════════════════════════════════════════════════════
// TESTS 2-5: Cross-chain enforcement through gateway
// ══════════════════════════════════════════════════════════════════

describe('Gateway Integration — Cross-Chain Enforcement (Module 18)', () => {
  let gw: ProxyGateway
  let agent: ReturnType<typeof joinSocialContract>
  let principalA: ReturnType<typeof joinSocialContract>
  let principalB: ReturnType<typeof joinSocialContract>
  let delegationA: ReturnType<typeof delegate>
  let delegationB: ReturnType<typeof delegate>
  let gk: ReturnType<typeof generateKeyPair>

  beforeEach(() => {
    clearStores()
    gk = generateKeyPair()
    principalA = joinSocialContract({
      name: 'Principal A', mission: 'data', owner: 'a',
      capabilities: ['data:read'], platform: 'test', models: ['m'], floor
    })
    principalB = joinSocialContract({
      name: 'Principal B', mission: 'actions', owner: 'b',
      capabilities: ['data:write', 'api:send'], platform: 'test', models: ['m'], floor
    })
    agent = joinSocialContract({
      name: 'Shared Agent', mission: 'multi', owner: 'shared',
      capabilities: ['data:read', 'data:write', 'api:send'], platform: 'test', models: ['m'], floor
    })
    delegationA = delegate({
      from: principalA, toPublicKey: agent.keyPair.publicKey,
      scope: ['data:read'], spendLimit: 100, maxDepth: 2
    })
    delegationB = delegate({
      from: principalB, toPublicKey: agent.keyPair.publicKey,
      scope: ['data:write', 'api:send'], spendLimit: 100, maxDepth: 2
    })
    gw = createProxyGateway({
      gatewayId: 'gw-xchain', gatewayPublicKey: gk.publicKey,
      gatewayPrivateKey: gk.privateKey, floor,
      enableCrossChainEnforcement: true
    }, makeExecutor())
    gw.registerAgent(agent.passport, agent.attestation, [delegationA, delegationB])
  })

  it('creates execution frame on registration', () => {
    const frame = gw.getAgentFrame(agent.agentId)
    assert.ok(frame, 'Frame should exist')
    assert.equal(frame!.agentId, agent.agentId)
    assert.equal(frame!.frameTaint.labels.length, 0, 'Fresh frame has no taint')
    assert.equal(frame!.active, true)
  })

  it('wraps results in SAO after execution', async () => {
    const r = await gw.processToolCall(makeRequest(agent, {
      tool: 'read-data', scopeRequired: 'data:read',
      delegationId: delegationA.delegationId
    }))
    assert.equal(r.executed, true)
    assert.ok(r.sao, 'Result should be wrapped in SAO')
    assert.equal(r.sao!.taint.principalId, principalA.publicKey)
  })

  it('BLOCKS confused deputy — cross-chain without permit', async () => {
    // Step 1: Agent reads data under delegation A (taint: principal A)
    const r1 = await gw.processToolCall(makeRequest(agent, {
      tool: 'read-data', scopeRequired: 'data:read',
      delegationId: delegationA.delegationId
    }))
    assert.equal(r1.executed, true, 'Read should succeed')

    // Step 2: Agent tries to write under delegation B (principal B)
    // Frame is tainted with principal A → confused deputy → BLOCKED
    const r2 = await gw.processToolCall(makeRequest(agent, {
      tool: 'send-data', scopeRequired: 'data:write',
      delegationId: delegationB.delegationId
    }))
    assert.equal(r2.executed, false, 'Write should be BLOCKED')
    assert.ok(r2.denialReason?.includes('Cross-chain'), 'Should cite cross-chain as reason')
    assert.ok(r2.flowCheck, 'Should include flow check result')
    assert.equal(r2.flowCheck!.verdict, 'blocked')

    // Verify stats
    const stats = gw.getStats()
    assert.ok((stats.crossChainChecks || 0) > 0, 'Should have performed cross-chain checks')
    assert.ok((stats.crossChainBlocked || 0) > 0, 'Should have blocked at least one')
  })

  it('ALLOWS cross-chain with valid permit', async () => {
    // Create a permit: principal A allows data to flow to principal B
    const halfPermit = createCrossChainPermit({
      sourcePrincipalId: principalA.publicKey,
      sourcePrincipalPublicKey: principalA.publicKey,
      sourceDataClasses: ['data:read'],
      destPrincipalId: principalB.publicKey,
      destPrincipalPublicKey: principalB.publicKey,
      destAllowedScopes: ['data:write', 'api:send'],
      purpose: 'Authorized data sharing',
      sourcePrivateKey: principalA.keyPair.privateKey
    })
    const permit = countersignPermit(halfPermit, principalB.keyPair.privateKey)
    gw.registerPermit(agent.agentId, permit)

    // Step 1: Read under delegation A (taint: principal A)
    const r1 = await gw.processToolCall(makeRequest(agent, {
      tool: 'read-data', scopeRequired: 'data:read',
      delegationId: delegationA.delegationId
    }))
    assert.equal(r1.executed, true)

    // Step 2: Write under delegation B — should be PERMITTED (not blocked)
    const r2 = await gw.processToolCall(makeRequest(agent, {
      tool: 'send-data', scopeRequired: 'data:write',
      delegationId: delegationB.delegationId
    }))
    assert.equal(r2.executed, true, 'Write should succeed with permit')
    assert.ok(r2.flowCheck, 'Should include flow check')
    assert.equal(r2.flowCheck!.verdict, 'permitted')

    const stats = gw.getStats()
    assert.ok((stats.crossChainPermitted || 0) > 0, 'Should count permitted flows')
  })
})

// ══════════════════════════════════════════════════════════════════
// TESTS 6-7: Obligation monitoring through gateway
// ══════════════════════════════════════════════════════════════════

describe('Gateway Integration — Obligation Monitoring (Module 20)', () => {
  let gw: ProxyGateway
  let agent: ReturnType<typeof joinSocialContract>
  let principal: ReturnType<typeof joinSocialContract>
  let delegation: ReturnType<typeof delegate>
  let gk: ReturnType<typeof generateKeyPair>

  beforeEach(() => {
    clearStores()
    gk = generateKeyPair()
    principal = joinSocialContract({
      name: 'Principal', mission: 'test', owner: 'o',
      capabilities: ['data:read', 'data:write', 'reporting:submit'],
      platform: 'test', models: ['m'], floor
    })
    agent = joinSocialContract({
      name: 'Agent', mission: 'work', owner: 'o',
      capabilities: ['data:read', 'data:write', 'reporting:submit'],
      platform: 'test', models: ['m'], floor
    })
    delegation = delegate({
      from: principal, toPublicKey: agent.keyPair.publicKey,
      scope: ['data:read', 'data:write', 'reporting:submit'],
      spendLimit: 100, maxDepth: 2
    })
    gw = createProxyGateway({
      gatewayId: 'gw-obl', gatewayPublicKey: gk.publicKey,
      gatewayPrivateKey: gk.privateKey, floor,
      enableObligationMonitoring: true
    }, makeExecutor())
    gw.registerAgent(agent.passport, agent.attestation, [delegation])
  })

  it('fulfills obligation when matching receipt is produced', async () => {
    // Create obligation: agent must submit a report
    const obligation = createObligation({
      delegationId: delegation.delegationId,
      obligorAgentId: agent.agentId,
      obligorPublicKey: agent.keyPair.publicKey,
      action: {
        type: 'reporting:submit',
        scope: 'reporting:submit',
        description: 'Submit weekly report'
      },
      deadline: new Date(Date.now() + 86400000).toISOString(),
      evidence: {
        type: 'action_receipt',
        matchCriteria: {
          toolMatch: 'gateway:submit-report',
          scopeMatch: 'reporting:submit'
        }
      },
      penalty: {
        type: 'reputation_penalty',
        severity: 'minor',
        reputationImpact: -10,
        gracePeriodMinutes: 60,
        autoExecute: false
      },
      principalPrivateKey: principal.keyPair.privateKey,
      principalPublicKey: principal.publicKey
    })
    gw.registerObligation(agent.agentId, obligation)

    // Verify obligation is pending
    const oblsBefore = gw.getAgentObligations(agent.agentId)
    assert.ok(oblsBefore)
    assert.equal(oblsBefore!.length, 1)
    assert.equal(oblsBefore![0].status, 'pending')

    // Agent submits the report — this should auto-fulfill
    const r = await gw.processToolCall(makeRequest(agent, {
      tool: 'submit-report',
      scopeRequired: 'reporting:submit',
      params: { title: 'Weekly Report' }
    }))
    assert.equal(r.executed, true)

    // Obligation should now be fulfilled
    assert.ok(r.obligationResolutions, 'Should have obligation resolutions')
    assert.equal(r.obligationResolutions!.length, 1)
    assert.equal(r.obligationResolutions![0].outcome, 'fulfilled')

    // Verify obligation status was updated in the registry
    const oblsAfter = gw.getAgentObligations(agent.agentId)
    assert.equal(oblsAfter![0].status, 'fulfilled')

    // Verify stats
    const stats = gw.getStats()
    assert.ok((stats.obligationsFulfilled || 0) > 0)
    assert.ok((stats.obligationsRegistered || 0) > 0)
  })

  it('terminates obligations when delegation is revoked', async () => {
    const obligation = createObligation({
      delegationId: delegation.delegationId,
      obligorAgentId: agent.agentId,
      obligorPublicKey: agent.keyPair.publicKey,
      action: {
        type: 'data:write',
        scope: 'data:write',
        description: 'Write data periodically'
      },
      deadline: new Date(Date.now() + 86400000).toISOString(),
      evidence: {
        type: 'action_receipt',
        matchCriteria: { toolMatch: 'gateway:write-data', scopeMatch: 'data:write' }
      },
      penalty: {
        type: 'warning',
        severity: 'minor',
        gracePeriodMinutes: 30,
        autoExecute: false
      },
      survivesTermination: false,
      principalPrivateKey: principal.keyPair.privateKey,
      principalPublicKey: principal.publicKey
    })
    gw.registerObligation(agent.agentId, obligation)

    // Verify pending
    assert.equal(gw.getAgentObligations(agent.agentId)![0].status, 'pending')

    // Revoke the delegation — obligation should be terminated
    gw.revokeDelegation(agent.agentId, delegation.delegationId)

    // Obligation should be terminated_by_revocation
    const obls = gw.getAgentObligations(agent.agentId)
    assert.equal(obls![0].status, 'terminated_by_revocation')

    const stats = gw.getStats()
    assert.ok((stats.obligationsTerminated || 0) > 0)
  })
})


// ══════════════════════════════════════════════════════════════════
// TEST 8: Execution envelope production from gateway
// ══════════════════════════════════════════════════════════════════

describe('Gateway Integration — Execution Envelope (Fix 6)', () => {
  it('produces envelope when produceEnvelope is enabled', async () => {
    clearStores()
    const gk = generateKeyPair()
    const principal = joinSocialContract({
      name: 'P', mission: 'test', owner: 'o',
      capabilities: ['data:read'], platform: 'test', models: ['m'], floor
    })
    const agent = joinSocialContract({
      name: 'A', mission: 'test', owner: 'o',
      capabilities: ['data:read'], platform: 'test', models: ['m'], floor
    })
    const d = delegate({
      from: principal, toPublicKey: agent.keyPair.publicKey,
      scope: ['data:read'], spendLimit: 100, maxDepth: 2
    })
    const gw = createProxyGateway({
      gatewayId: 'gw-env', gatewayPublicKey: gk.publicKey,
      gatewayPrivateKey: gk.privateKey, floor,
      produceEnvelope: true
    }, makeExecutor())
    gw.registerAgent(agent.passport, agent.attestation, [d])
    const r = await gw.processToolCall(makeRequest(agent))
    assert.equal(r.executed, true)
    assert.ok(r.envelope, 'Should produce execution envelope')
    assert.equal(r.envelope!.schema, 'execution-envelope.v0.1')
    assert.equal(r.envelope!.agent_did, `did:aps:${agent.keyPair.publicKey}`)
    assert.ok(r.envelope!.signature.value, 'Envelope should be signed')
    assert.ok(r.envelope!.capability_ref.scope.includes('data:read'))
  })

  it('does NOT produce envelope when flag is off', async () => {
    clearStores()
    const gk = generateKeyPair()
    const principal = joinSocialContract({
      name: 'P', mission: 'test', owner: 'o',
      capabilities: ['data:read'], platform: 'test', models: ['m'], floor
    })
    const agent = joinSocialContract({
      name: 'A', mission: 'test', owner: 'o',
      capabilities: ['data:read'], platform: 'test', models: ['m'], floor
    })
    const d = delegate({
      from: principal, toPublicKey: agent.keyPair.publicKey,
      scope: ['data:read'], spendLimit: 100, maxDepth: 2
    })
    const gw = createProxyGateway({
      gatewayId: 'gw-noenv', gatewayPublicKey: gk.publicKey,
      gatewayPrivateKey: gk.privateKey, floor
      // produceEnvelope NOT set — defaults to false
    }, makeExecutor())
    gw.registerAgent(agent.passport, agent.attestation, [d])
    const r = await gw.processToolCall(makeRequest(agent))
    assert.equal(r.executed, true)
    assert.equal(r.envelope, undefined, 'No envelope without flag')
  })
})
