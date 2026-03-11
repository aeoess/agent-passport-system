// ══════════════════════════════════════════════════════════════════
// Proxy Gateway — Tests
// ══════════════════════════════════════════════════════════════════

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { ProxyGateway, createProxyGateway } from '../src/core/gateway.js'
import { joinSocialContract, delegate } from '../src/contract.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { loadFloor } from '../src/core/values.js'
import { revokeDelegation, clearStores } from '../src/core/delegation.js'
import type { ToolCallRequest, ToolExecutor, GatewayConfig } from '../src/types/gateway.js'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(join(__dirname, '../values/floor.yaml'), 'utf-8')
const floor = loadFloor(floorYaml)

// ── Test Helpers ──

function makeToolExecutor(behavior: 'success' | 'error' | 'throw' = 'success'): ToolExecutor {
  return async (tool: string, params: Record<string, unknown>) => {
    if (behavior === 'throw') throw new Error('Tool crashed')
    if (behavior === 'error') return { success: false, error: 'Tool returned error' }
    return { success: true, result: { tool, echo: params } }
  }
}

async function setupGatewayWithAgent(executorBehavior: 'success' | 'error' | 'throw' = 'success') {
  clearStores()
  const gatewayKeys = generateKeyPair()

  const principal = joinSocialContract({
    name: 'Test Principal', mission: 'Testing gateway', owner: 'tester',
    capabilities: ['testing'], platform: 'test', models: ['test-model'], floor
  })
  const agent = joinSocialContract({
    name: 'Test Agent', mission: 'Tool execution', owner: 'tester',
    capabilities: ['data:read', 'data:write', 'api:fetch'], platform: 'test', models: ['test-model'], floor
  })

  const agentKeys = agent.keyPair
  const principalKeys = principal.keyPair

  const delegation = delegate({
    from: principal, toPublicKey: agentKeys.publicKey,
    scope: ['data:read', 'data:write', 'api:fetch'], spendLimit: 100, maxDepth: 2
  })

  const config: GatewayConfig = {
    gatewayId: 'gateway-test-001', gatewayPublicKey: gatewayKeys.publicKey,
    gatewayPrivateKey: gatewayKeys.privateKey, floor, approvalTTLSeconds: 5, recheckRevocationOnExecute: true
  }

  const gateway = createProxyGateway(config, makeToolExecutor(executorBehavior))
  gateway.registerAgent(agent.passport, agent.attestation, [delegation])

  function makeRequest(overrides: Partial<ToolCallRequest> = {}): ToolCallRequest {
    const requestId = overrides.requestId || `req-${Date.now()}-${Math.random().toString(36).slice(2)}`
    const tool = overrides.tool || 'api:fetch'
    const params = overrides.params || { url: 'https://example.com' }
    const scopeRequired = overrides.scopeRequired || 'data:read'
    const spend = overrides.spend

    const payload = canonicalize({ requestId, agentId: agent.agentId, tool, params, scopeRequired, spend })
    return {
      requestId, agentId: overrides.agentId || agent.agentId,
      agentPublicKey: overrides.agentPublicKey || agentKeys.publicKey,
      signature: overrides.signature || sign(payload, agentKeys.privateKey),
      tool, params, scopeRequired, spend, context: overrides.context || 'Test request'
    }
  }

  return { gateway, config, principal, agent, delegation, agentKeys, principalKeys, gatewayKeys, makeRequest }
}


// ══════════════════════════════════════════════════════════════════
// TEST SUITES
// ══════════════════════════════════════════════════════════════════

describe('ProxyGateway — Core Flow', () => {
  it('should execute a valid tool call end-to-end', async () => {
    const { gateway, makeRequest } = await setupGatewayWithAgent()
    const result = await gateway.processToolCall(makeRequest())
    assert.equal(result.executed, true)
    assert.ok(result.result)
    assert.ok(result.proof)
    assert.ok(result.receipt)
    assert.ok(result.decision)
    assert.equal(result.decision!.verdict, 'permit')
  })

  it('should return tool result in the response', async () => {
    const { gateway, makeRequest } = await setupGatewayWithAgent()
    const result = await gateway.processToolCall(makeRequest({ params: { key: 'value' } }))
    assert.equal(result.executed, true)
    const toolResult = result.result as { tool: string; echo: Record<string, unknown> }
    assert.equal(toolResult.tool, 'api:fetch')
    assert.deepEqual(toolResult.echo, { key: 'value' })
  })

  it('should produce a complete 3-signature proof chain', async () => {
    const { gateway, makeRequest } = await setupGatewayWithAgent()
    const result = await gateway.processToolCall(makeRequest())
    assert.ok(result.proof)
    assert.ok(result.proof!.requestSignature)
    assert.ok(result.proof!.decisionSignature)
    assert.ok(result.proof!.receiptSignature)
    assert.ok(result.proof!.policyReceipt)
    assert.ok(result.proof!.policyReceipt.policyReceiptId)
  })

  it('receipt should be signed by gateway, not agent', async () => {
    const { gateway, makeRequest, config } = await setupGatewayWithAgent()
    const result = await gateway.processToolCall(makeRequest())
    assert.equal(result.receipt!.agentId, config.gatewayId)
  })

  it('receipt action should reference the tool via gateway prefix', async () => {
    const { gateway, makeRequest } = await setupGatewayWithAgent()
    const result = await gateway.processToolCall(makeRequest())
    assert.ok(result.receipt!.action.type.startsWith('gateway:'))
    assert.equal(result.receipt!.action.type, 'gateway:api:fetch')
    assert.equal(result.receipt!.action.scopeUsed, 'data:read')
  })
})

describe('ProxyGateway — Property 1: Gateway is Executor', () => {
  it('should handle tool execution errors gracefully', async () => {
    const { gateway, makeRequest } = await setupGatewayWithAgent('error')
    const result = await gateway.processToolCall(makeRequest())
    assert.equal(result.executed, true)
    assert.ok(result.toolError)
    assert.equal(result.toolError, 'Tool returned error')
  })

  it('should handle tool exceptions gracefully', async () => {
    const { gateway, makeRequest } = await setupGatewayWithAgent('throw')
    const result = await gateway.processToolCall(makeRequest())
    assert.equal(result.executed, true)
    assert.ok(result.toolError)
    assert.match(result.toolError!, /Tool crashed/)
  })
})

describe('ProxyGateway — Property 2: Exact Parameter Binding', () => {
  it('should deny when scope does not match delegation', async () => {
    const { gateway, makeRequest } = await setupGatewayWithAgent()
    const result = await gateway.processToolCall(makeRequest({ scopeRequired: 'admin:delete' }))
    assert.equal(result.executed, false)
    assert.ok(result.denialReason)
    assert.match(result.denialReason!, /No valid delegation/)
  })

  it('should deny when spend exceeds delegation limit', async () => {
    const { gateway, makeRequest } = await setupGatewayWithAgent()
    const result = await gateway.processToolCall(makeRequest({ spend: { amount: 999, currency: 'USD' } }))
    assert.equal(result.executed, false)
    assert.ok(result.denialReason)
  })
})

describe('ProxyGateway — Property 3: Revocation Recheck', () => {
  it('should deny when delegation is revoked between registration and call', async () => {
    const { gateway, makeRequest, delegation, principal, principalKeys } = await setupGatewayWithAgent()
    revokeDelegation(delegation.delegationId, principal.agentId, 'Compromised', principalKeys.privateKey)
    const result = await gateway.processToolCall(makeRequest())
    assert.equal(result.executed, false)
  })

  it('should deny two-phase execution when delegation revoked between approve and execute', async () => {
    const { gateway, makeRequest, delegation, agent } = await setupGatewayWithAgent()
    const approvalResult = gateway.approve(makeRequest())
    assert.equal(approvalResult.approved, true)
    gateway.revokeDelegation(agent.agentId, delegation.delegationId)
    const result = await gateway.executeApproval(approvalResult.approval!.approvalId)
    assert.equal(result.executed, false)
    assert.match(result.denialReason!, /removed since approval|invalidated/)
  })
})

describe('ProxyGateway — Property 4: Gateway Signs Receipt', () => {
  it('receipt agentId is the gateway, not the requesting agent', async () => {
    const { gateway, makeRequest, config, agent } = await setupGatewayWithAgent()
    const result = await gateway.processToolCall(makeRequest())
    assert.equal(result.receipt!.agentId, config.gatewayId)
    assert.notEqual(result.receipt!.agentId, agent.agentId)
  })
})

describe('ProxyGateway — Property 5: Replay Protection', () => {
  it('should block duplicate requestIds', async () => {
    const { gateway, makeRequest } = await setupGatewayWithAgent()
    const request = makeRequest({ requestId: 'fixed-id-001' })
    const first = await gateway.processToolCall(request)
    assert.equal(first.executed, true)
    const second = await gateway.processToolCall(request)
    assert.equal(second.executed, false)
    assert.match(second.denialReason!, /[Rr]eplay/)
  })

  it('should block consuming an approval twice', async () => {
    const { gateway, makeRequest } = await setupGatewayWithAgent()
    const approval = gateway.approve(makeRequest())
    assert.equal(approval.approved, true)
    const first = await gateway.executeApproval(approval.approval!.approvalId)
    assert.equal(first.executed, true)
    const second = await gateway.executeApproval(approval.approval!.approvalId)
    assert.equal(second.executed, false)
    assert.match(second.denialReason!, /consumed|replay/)
  })

  it('should track replay attempts in stats', async () => {
    const { gateway, makeRequest } = await setupGatewayWithAgent()
    const request = makeRequest({ requestId: 'replay-test' })
    await gateway.processToolCall(request)
    await gateway.processToolCall(request)
    const stats = gateway.getStats()
    assert.ok(stats.replayAttemptsBlocked >= 1)
  })
})

describe('ProxyGateway — Property 6: Approval Timeout', () => {
  it('should reject expired approvals', async () => {
    clearStores()
    const gatewayKeys = generateKeyPair()
    const principal = joinSocialContract({ name: 'P', mission: 'T', owner: 'tester', capabilities: ['testing'], platform: 'test', models: ['test-model'], floor })
    const agent = joinSocialContract({ name: 'A', mission: 'T', owner: 'tester', capabilities: ['data:read'], platform: 'test', models: ['test-model'], floor })
    const principalKeys = principal.keyPair
    const agentKeys = agent.keyPair
    const delegation = delegate({ from: principal, toPublicKey: agentKeys.publicKey, scope: ['data:read'], maxDepth: 2 })

    const gateway = createProxyGateway({
      gatewayId: 'gw-ttl-test', gatewayPublicKey: gatewayKeys.publicKey, gatewayPrivateKey: gatewayKeys.privateKey,
      floor, approvalTTLSeconds: 0
    }, makeToolExecutor())
    gateway.registerAgent(agent.passport, agent.attestation, [delegation])

    const requestId = `req-ttl-${Date.now()}`
    const payload = canonicalize({ requestId, agentId: agent.agentId, tool: 'api:fetch', params: {}, scopeRequired: 'data:read', spend: undefined })
    const request: ToolCallRequest = {
      requestId, agentId: agent.agentId, agentPublicKey: agentKeys.publicKey,
      signature: sign(payload, agentKeys.privateKey), tool: 'api:fetch', params: {}, scopeRequired: 'data:read'
    }

    const approval = gateway.approve(request)
    assert.equal(approval.approved, true)
    await new Promise(r => setTimeout(r, 10))
    const result = await gateway.executeApproval(approval.approval!.approvalId)
    assert.equal(result.executed, false)
    assert.match(result.denialReason!, /expired/)
  })

  it('clearExpired should remove stale approvals', async () => {
    clearStores()
    const gatewayKeys = generateKeyPair()
    const principal = joinSocialContract({ name: 'P', mission: 'T', owner: 'tester', capabilities: ['testing'], platform: 'test', models: ['test-model'], floor })
    const agent = joinSocialContract({ name: 'A', mission: 'T', owner: 'tester', capabilities: ['data:read'], platform: 'test', models: ['test-model'], floor })
    const principalKeys = principal.keyPair
    const agentKeys = agent.keyPair
    const delegation = delegate({ from: principal, toPublicKey: agentKeys.publicKey, scope: ['data:read'], maxDepth: 2 })

    const gateway = createProxyGateway({
      gatewayId: 'gw-cleanup', gatewayPublicKey: gatewayKeys.publicKey, gatewayPrivateKey: gatewayKeys.privateKey,
      floor, approvalTTLSeconds: 0
    }, makeToolExecutor())
    gateway.registerAgent(agent.passport, agent.attestation, [delegation])

    for (let i = 0; i < 3; i++) {
      const rid = `req-cleanup-${i}`
      const payload = canonicalize({ requestId: rid, agentId: agent.agentId, tool: 'api:fetch', params: {}, scopeRequired: 'data:read', spend: undefined })
      gateway.approve({ requestId: rid, agentId: agent.agentId, agentPublicKey: agentKeys.publicKey, signature: sign(payload, agentKeys.privateKey), tool: 'api:fetch', params: {}, scopeRequired: 'data:read' })
    }
    await new Promise(r => setTimeout(r, 10))
    const cleared = gateway.clearExpired()
    assert.ok(cleared >= 3)
  })
})

describe('ProxyGateway — Identity Verification', () => {
  it('should reject unregistered agents', async () => {
    const { gateway, makeRequest } = await setupGatewayWithAgent()
    const result = await gateway.processToolCall(makeRequest({ agentId: 'unknown-agent-999' }))
    assert.equal(result.executed, false)
    assert.match(result.denialReason!, /not registered/)
  })

  it('should reject invalid signatures', async () => {
    const { gateway, makeRequest } = await setupGatewayWithAgent()
    const result = await gateway.processToolCall(makeRequest({ signature: 'deadbeef'.repeat(16) }))
    assert.equal(result.executed, false)
    assert.match(result.denialReason!, /[Ss]ignature/)
  })

  it('should reject signatures from wrong key', async () => {
    const { gateway, makeRequest } = await setupGatewayWithAgent()
    const wrongKeys = generateKeyPair()
    const requestId = `req-wrong-key-${Date.now()}`
    const payload = canonicalize({ requestId, agentId: 'agent-id', tool: 'api:fetch', params: {}, scopeRequired: 'data:read', spend: undefined })
    const result = await gateway.processToolCall(makeRequest({ requestId, signature: sign(payload, wrongKeys.privateKey) }))
    assert.equal(result.executed, false)
  })
})

describe('ProxyGateway — Agent Management', () => {
  it('should register and unregister agents', async () => {
    const { gateway, agent } = await setupGatewayWithAgent()
    assert.equal(gateway.getStats().activeAgents, 1)
    gateway.unregisterAgent(agent.agentId)
    assert.equal(gateway.getStats().activeAgents, 0)
  })

  it('should add delegations to registered agents', async () => {
    const { gateway, agent, agentKeys, principal } = await setupGatewayWithAgent()
    const newDelegation = delegate({ from: principal, toPublicKey: agentKeys.publicKey, scope: ['admin:read'], maxDepth: 1 })
    const result = gateway.addDelegation(agent.agentId, newDelegation)
    assert.equal(result.added, true)
  })

  it('should reject adding delegation for unknown agent', async () => {
    const { gateway } = await setupGatewayWithAgent()
    const result = gateway.addDelegation('nonexistent-agent', {} as any)
    assert.equal(result.added, false)
  })

  it('unregistering clears pending approvals for that agent', async () => {
    const { gateway, makeRequest, agent } = await setupGatewayWithAgent()
    gateway.approve(makeRequest())
    assert.ok(gateway.getStats().pendingApprovals >= 1)
    gateway.unregisterAgent(agent.agentId)
    assert.equal(gateway.getStats().pendingApprovals, 0)
  })
})

describe('ProxyGateway — Two-Phase Approve/Execute', () => {
  it('should approve and then execute separately', async () => {
    const { gateway, makeRequest } = await setupGatewayWithAgent()
    const approval = gateway.approve(makeRequest())
    assert.equal(approval.approved, true)
    assert.ok(approval.approval)
    assert.ok(approval.approval!.nonce)
    const result = await gateway.executeApproval(approval.approval!.approvalId)
    assert.equal(result.executed, true)
    assert.ok(result.proof)
    assert.ok(result.receipt)
  })

  it('should reject execution of nonexistent approval', async () => {
    const { gateway } = await setupGatewayWithAgent()
    const result = await gateway.executeApproval('nonexistent-approval')
    assert.equal(result.executed, false)
    assert.match(result.denialReason!, /not found/)
  })

  it('should enforce max pending approvals per agent', async () => {
    clearStores()
    const gatewayKeys = generateKeyPair()
    const principal = joinSocialContract({ name: 'P', mission: 'T', owner: 'tester', capabilities: ['testing'], platform: 'test', models: ['test-model'], floor })
    const agent = joinSocialContract({ name: 'A', mission: 'T', owner: 'tester', capabilities: ['data:read'], platform: 'test', models: ['test-model'], floor })
    const principalKeys = principal.keyPair
    const agentKeys = agent.keyPair
    const delegation = delegate({ from: principal, toPublicKey: agentKeys.publicKey, scope: ['data:read'], maxDepth: 2 })

    const gateway = createProxyGateway({
      gatewayId: 'gw-limit', gatewayPublicKey: gatewayKeys.publicKey, gatewayPrivateKey: gatewayKeys.privateKey,
      floor, maxPendingPerAgent: 2, approvalTTLSeconds: 60
    }, makeToolExecutor())
    gateway.registerAgent(agent.passport, agent.attestation, [delegation])

    for (let i = 0; i < 2; i++) {
      const rid = `req-limit-${i}`
      const payload = canonicalize({ requestId: rid, agentId: agent.agentId, tool: 'api:fetch', params: {}, scopeRequired: 'data:read', spend: undefined })
      const r = gateway.approve({ requestId: rid, agentId: agent.agentId, agentPublicKey: agentKeys.publicKey, signature: sign(payload, agentKeys.privateKey), tool: 'api:fetch', params: {}, scopeRequired: 'data:read' })
      assert.equal(r.approved, true)
    }

    const rid = 'req-limit-overflow'
    const payload = canonicalize({ requestId: rid, agentId: agent.agentId, tool: 'api:fetch', params: {}, scopeRequired: 'data:read', spend: undefined })
    const overflow = gateway.approve({ requestId: rid, agentId: agent.agentId, agentPublicKey: agentKeys.publicKey, signature: sign(payload, agentKeys.privateKey), tool: 'api:fetch', params: {}, scopeRequired: 'data:read' })
    assert.equal(overflow.approved, false)
    assert.match(overflow.denial!.reason, /pending/)
  })
})

describe('ProxyGateway — Stats & Callbacks', () => {
  it('should track all counters accurately', async () => {
    const { gateway, makeRequest } = await setupGatewayWithAgent()
    await gateway.processToolCall(makeRequest())
    await gateway.processToolCall(makeRequest({ scopeRequired: 'admin:nuke' }))
    const req = makeRequest({ requestId: 'stats-replay' })
    await gateway.processToolCall(req)
    await gateway.processToolCall(req)
    const stats = gateway.getStats()
    assert.ok(stats.totalRequests >= 4)
    assert.ok(stats.totalPermitted >= 2)
    assert.ok(stats.totalDenied >= 1)
    assert.ok(stats.totalExecuted >= 2)
    assert.ok(stats.replayAttemptsBlocked >= 1)
  })

  it('should fire onToolCall for every request', async () => {
    clearStores()
    const gatewayKeys = generateKeyPair()
    const principal = joinSocialContract({ name: 'P', mission: 'T', owner: 'tester', capabilities: ['testing'], platform: 'test', models: ['test-model'], floor })
    const agent = joinSocialContract({ name: 'A', mission: 'T', owner: 'tester', capabilities: ['data:read'], platform: 'test', models: ['test-model'], floor })
    const principalKeys = principal.keyPair
    const agentKeys = agent.keyPair
    const delegation = delegate({ from: principal, toPublicKey: agentKeys.publicKey, scope: ['data:read'], maxDepth: 2 })
    const calls: Array<{ request: any; result: any }> = []
    const gateway = createProxyGateway({
      gatewayId: 'gw-callback', gatewayPublicKey: gatewayKeys.publicKey, gatewayPrivateKey: gatewayKeys.privateKey,
      floor, onToolCall: (req, res) => calls.push({ request: req, result: res })
    }, makeToolExecutor())
    gateway.registerAgent(agent.passport, agent.attestation, [delegation])

    const rid = `req-cb-${Date.now()}`
    const payload = canonicalize({ requestId: rid, agentId: agent.agentId, tool: 'api:fetch', params: {}, scopeRequired: 'data:read', spend: undefined })
    await gateway.processToolCall({ requestId: rid, agentId: agent.agentId, agentPublicKey: agentKeys.publicKey, signature: sign(payload, agentKeys.privateKey), tool: 'api:fetch', params: {}, scopeRequired: 'data:read' })
    assert.equal(calls.length, 1)
    assert.equal(calls[0].result.executed, true)
  })

  it('should fire onSuspicious for replay attempts', async () => {
    clearStores()
    const gatewayKeys = generateKeyPair()
    const principal = joinSocialContract({ name: 'P', mission: 'T', owner: 'tester', capabilities: ['testing'], platform: 'test', models: ['test-model'], floor })
    const agent = joinSocialContract({ name: 'A', mission: 'T', owner: 'tester', capabilities: ['data:read'], platform: 'test', models: ['test-model'], floor })
    const principalKeys = principal.keyPair
    const agentKeys = agent.keyPair
    const delegation = delegate({ from: principal, toPublicKey: agentKeys.publicKey, scope: ['data:read'], maxDepth: 2 })
    const suspicious: string[] = []
    const gateway = createProxyGateway({
      gatewayId: 'gw-suspicious', gatewayPublicKey: gatewayKeys.publicKey, gatewayPrivateKey: gatewayKeys.privateKey,
      floor, onSuspicious: (_id, reason) => suspicious.push(reason)
    }, makeToolExecutor())
    gateway.registerAgent(agent.passport, agent.attestation, [delegation])

    const rid = 'req-suspicious'
    const payload = canonicalize({ requestId: rid, agentId: agent.agentId, tool: 'api:fetch', params: {}, scopeRequired: 'data:read', spend: undefined })
    const request = { requestId: rid, agentId: agent.agentId, agentPublicKey: agentKeys.publicKey, signature: sign(payload, agentKeys.privateKey), tool: 'api:fetch', params: {}, scopeRequired: 'data:read' }
    await gateway.processToolCall(request)
    await gateway.processToolCall(request)
    assert.ok(suspicious.length >= 1)
    assert.match(suspicious[0], /[Rr]eplay/)
  })
})
