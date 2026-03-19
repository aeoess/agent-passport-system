// ══════════════════════════════════════════════════════════════════
// Gateway — Escalation Enforcement Tests (Module 27 / INV-4)
// ══════════════════════════════════════════════════════════════════
//
// Core invariant: exception authority is pre-committed, bounded,
// temporary, and challengeable. When normal delegation fails,
// escalation provides a controlled fallback — not an open bypass.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { ProxyGateway } from '../src/core/gateway.js'
import { joinSocialContract, delegate } from '../src/contract.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { loadFloor } from '../src/core/values.js'
import { clearStores } from '../src/core/delegation.js'
import {
  createEscalationGrant, requestEscalation, activateEscalation,
  revokeEscalation, type ActiveEscalation
} from '../src/core/escalation.js'
import type { GatewayConfig, ToolExecutor, ToolCallRequest } from '../src/types/gateway.js'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(join(__dirname, '../values/floor.yaml'), 'utf-8')
const floor = loadFloor(floorYaml)

const makeExecutor = (): ToolExecutor =>
  async () => ({ success: true, result: 'ok' })

function setup() {
  clearStores()
  const gatewayKeys = generateKeyPair()
  const principalKeys = generateKeyPair()

  const principal = joinSocialContract({
    name: 'Principal', mission: 'Esc test', owner: 'tester',
    capabilities: ['testing'], platform: 'test', models: ['test-model'], floor
  })
  const agent = joinSocialContract({
    name: 'Esc Agent', mission: 'Escalation test', owner: 'tester',
    capabilities: ['data:read'], platform: 'test', models: ['test-model'], floor
  })

  // Delegation only covers data:read — NOT admin:*
  const delegation = delegate({
    from: principal, toPublicKey: agent.publicKey,
    scope: ['data:read'], spendLimit: 1000, maxDepth: 2
  })

  const config: GatewayConfig = {
    gatewayId: 'gw-esc-test',
    gatewayPublicKey: gatewayKeys.publicKey,
    gatewayPrivateKey: gatewayKeys.privateKey,
    floor,
    enableEscalation: true,
    maxConcurrentEscalations: 2,
  }

  const gw = new ProxyGateway(config, makeExecutor())
  const regResult = gw.registerAgent(agent.passport, agent.attestation!, [delegation])
  assert.ok(regResult.registered, `Registration failed: ${regResult.error}`)

  // Create escalation grant: principal authorizes agent for admin:* temporarily
  const escGrant = createEscalationGrant({
    delegationId: delegation.delegationId,
    grantedTo: agent.publicKey,
    grantedBy: principal.publicKey,
    granterPrivateKey: principal.keyPair.privateKey,
    ceiling: { scope: ['admin:*'], maxSpend: 500, maxDurationMs: 60_000 },
    allowedTriggers: ['human_authorized'],
    allowedActionClasses: ['tentative'],
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  })

  // Human approval signature for the escalation
  const approvalPayload = canonicalize({ approve: escGrant.grantId, grantedTo: escGrant.grantedTo })
  const humanApprovalSig = sign(approvalPayload, principal.keyPair.privateKey)

  function makeRequest(scope: string, spend?: number): ToolCallRequest {
    const requestId = 'req-' + Math.random().toString(36).slice(2, 8)
    const payload = canonicalize({
      requestId, agentId: agent.agentId, tool: 'action',
      params: {}, scopeRequired: scope, spend: spend ? { amount: spend, currency: 'usd' } : undefined
    })
    return {
      requestId, agentId: agent.agentId, agentPublicKey: agent.publicKey,
      signature: sign(payload, agent.keyPair.privateKey),
      tool: 'action', params: {}, scopeRequired: scope,
      spend: spend ? { amount: spend, currency: 'usd' } : undefined,
    }
  }

  // Helper: activate a standard escalation for this agent
  function activateStandardEscalation(): ActiveEscalation {
    const escReq = requestEscalation({
      grant: escGrant, agentPrivateKey: agent.keyPair.privateKey,
      agentPublicKey: agent.publicKey,
      trigger: { type: 'human_authorized', evidence: 'test', humanApprovalSignature: humanApprovalSig }
    })
    const active = activateEscalation({
      grant: escGrant, request: escReq, gatewayPrivateKey: gatewayKeys.privateKey
    })
    gw.addEscalationGrant(agent.agentId, escGrant)
    gw.activateAgentEscalation(agent.agentId, active)
    return active
  }

  return { gw, agent, principal, delegation, escGrant, gatewayKeys, makeRequest, activateStandardEscalation, humanApprovalSig }
}

describe('Gateway — Escalation Enforcement (INV-4)', () => {

  it('normal delegation works without escalation', async () => {
    const { gw, makeRequest } = setup()
    const result = await gw.processToolCall(makeRequest('data:read'))
    assert.equal(result.executed, true)
    assert.equal(result.viaEscalation, undefined)
  })

  it('action denied when delegation insufficient and no escalation', async () => {
    const { gw, makeRequest } = setup()
    const result = await gw.processToolCall(makeRequest('admin:delete'))
    assert.equal(result.executed, false)
    assert.ok(result.denialReason?.includes('No valid delegation'))
  })

  it('action ALLOWED via escalation when delegation insufficient', async () => {
    const { gw, makeRequest, activateStandardEscalation } = setup()
    activateStandardEscalation()
    const result = await gw.processToolCall(makeRequest('admin:*'))
    assert.equal(result.executed, true)
    assert.equal(result.viaEscalation, true)
    assert.ok(result.escalationId)
  })

  it('expired escalation does NOT grant access', async () => {
    const { gw, agent, principal, escGrant, gatewayKeys, makeRequest } = setup()

    // Create escalation with 1ms duration (immediately expires)
    const shortGrant = createEscalationGrant({
      delegationId: escGrant.delegationId,
      grantedTo: agent.publicKey,
      grantedBy: principal.publicKey,
      granterPrivateKey: principal.keyPair.privateKey,
      ceiling: { scope: ['admin:*'], maxSpend: 500, maxDurationMs: 1 },
      allowedTriggers: ['human_authorized'],
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    })

    // Create fresh approval for THIS grant
    const shortApprovalPayload = canonicalize({ approve: shortGrant.grantId, grantedTo: shortGrant.grantedTo })
    const shortApprovalSig = sign(shortApprovalPayload, principal.keyPair.privateKey)

    const escReq = requestEscalation({
      grant: shortGrant, agentPrivateKey: agent.keyPair.privateKey,
      agentPublicKey: agent.publicKey,
      trigger: { type: 'human_authorized', evidence: 'test', humanApprovalSignature: shortApprovalSig }
    })
    const active = activateEscalation({
      grant: shortGrant, request: escReq, gatewayPrivateKey: gatewayKeys.privateKey
    })

    // Wait for expiry
    await new Promise(r => setTimeout(r, 5))

    gw.addEscalationGrant(agent.agentId, shortGrant)
    gw.activateAgentEscalation(agent.agentId, active)

    const result = await gw.processToolCall(makeRequest('admin:*'))
    assert.equal(result.executed, false)
  })

  it('escalation scope is checked — wrong scope denied', async () => {
    const { gw, makeRequest, activateStandardEscalation } = setup()
    activateStandardEscalation()  // grants admin:*
    // Request something outside escalation scope
    const result = await gw.processToolCall(makeRequest('finance:transfer'))
    assert.equal(result.executed, false)
  })

  it('max concurrent escalations enforced', async () => {
    const { gw, agent, escGrant, gatewayKeys, humanApprovalSig, activateStandardEscalation } = setup()
    // Activate 2 (the max)
    activateStandardEscalation()
    activateStandardEscalation()
    // Third should fail
    const escReq = requestEscalation({
      grant: escGrant, agentPrivateKey: agent.keyPair.privateKey,
      agentPublicKey: agent.publicKey,
      trigger: { type: 'human_authorized', evidence: 'test3', humanApprovalSignature: humanApprovalSig }
    })
    const active3 = activateEscalation({
      grant: escGrant, request: escReq, gatewayPrivateKey: gatewayKeys.privateKey
    })
    const result = gw.activateAgentEscalation(agent.agentId, active3)
    assert.equal(result.activated, false)
    assert.ok(result.error?.includes('Max concurrent'))
  })

  it('revoked escalation stops granting access', async () => {
    const { gw, agent, makeRequest, activateStandardEscalation } = setup()
    const active = activateStandardEscalation()

    // Verify it works first
    const r1 = await gw.processToolCall(makeRequest('admin:*'))
    assert.equal(r1.executed, true)
    assert.equal(r1.viaEscalation, true)

    // Revoke it on the agent's record
    const agentEscalations = gw.getAgentEscalations(agent.agentId)
    for (const esc of agentEscalations) {
      esc.status = 'revoked'
    }

    const r2 = await gw.processToolCall(makeRequest('admin:*'))
    assert.equal(r2.executed, false)
  })

  it('escalation stats tracked', async () => {
    const { gw, makeRequest, activateStandardEscalation } = setup()
    activateStandardEscalation()

    await gw.processToolCall(makeRequest('admin:*'))

    const stats = gw.getStats()
    assert.equal(stats.escalationsActivated, 1)
    assert.equal(stats.escalationsUsed, 1)
  })

  it('getAgentEscalations returns only active ones', async () => {
    const { gw, agent, activateStandardEscalation } = setup()
    activateStandardEscalation()
    const active = gw.getAgentEscalations(agent.agentId)
    assert.equal(active.length, 1)
    assert.equal(active[0].status, 'active')
  })

  it('escalation disabled — no fallback attempted', async () => {
    clearStores()
    const gatewayKeys = generateKeyPair()
    const principal = joinSocialContract({
      name: 'P', mission: 'test', owner: 'tester',
      capabilities: ['t'], platform: 'test', models: ['test-model'], floor
    })
    const agent = joinSocialContract({
      name: 'A', mission: 'test', owner: 'tester',
      capabilities: ['data:read'], platform: 'test', models: ['test-model'], floor
    })
    const d = delegate({ from: principal, toPublicKey: agent.publicKey, scope: ['data:read'], spendLimit: 100, maxDepth: 1 })
    const gw = new ProxyGateway({
      gatewayId: 'gw-no-esc', gatewayPublicKey: gatewayKeys.publicKey,
      gatewayPrivateKey: gatewayKeys.privateKey, floor,
      enableEscalation: false,
    }, makeExecutor())
    gw.registerAgent(agent.passport, agent.attestation!, [d])

    const requestId = 'req-noesc'
    const payload = canonicalize({ requestId, agentId: agent.agentId, tool: 'act', params: {}, scopeRequired: 'admin:delete', spend: undefined })
    const result = await gw.processToolCall({
      requestId, agentId: agent.agentId, agentPublicKey: agent.publicKey,
      signature: sign(payload, agent.keyPair.privateKey),
      tool: 'act', params: {}, scopeRequired: 'admin:delete',
    })
    assert.equal(result.executed, false)
    assert.ok(result.denialReason?.includes('No valid delegation'))
  })

  it('escalation spend tracked across calls', async () => {
    const { gw, agent, makeRequest, activateStandardEscalation } = setup()
    activateStandardEscalation()  // ceiling: maxSpend 500

    // First call: spend 200
    const r1 = await gw.processToolCall(makeRequest('admin:*', 200))
    assert.equal(r1.executed, true)
    assert.equal(r1.viaEscalation, true)

    // Second call: spend 200 (total 400, within 500 limit)
    const r2 = await gw.processToolCall(makeRequest('admin:*', 200))
    assert.equal(r2.executed, true)

    // Third call: spend 200 (total 600, exceeds 500 limit) — should fail escalation check
    const r3 = await gw.processToolCall(makeRequest('admin:*', 200))
    assert.equal(r3.executed, false)
  })
})
