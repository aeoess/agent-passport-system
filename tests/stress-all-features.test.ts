import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { ProxyGateway } from '../src/core/gateway.js'
import { joinSocialContract, delegate } from '../src/contract.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { loadFloor } from '../src/core/values.js'
import { clearStores } from '../src/core/delegation.js'
import { createGovernanceArtifact, createGovernanceEnvelope } from '../src/core/governance.js'
import { DEFAULT_LOAD_POLICY } from '../src/types/governance.js'
import { createEscalationGrant, requestEscalation, activateEscalation } from '../src/core/escalation.js'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(join(__dirname, '../values/floor.yaml'), 'utf-8')
const floor = loadFloor(floorYaml)

describe('Stress: ALL gateway features enabled simultaneously', () => {
  function setup() {
    clearStores()
    const gwKeys = generateKeyPair()
    const issuer = generateKeyPair()
    const govArt = createGovernanceArtifact({
      artifactType: 'floor', version: '1.0.0', content: floorYaml,
      issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      changeType: 'initial', additions: ['F-001','F-002','F-003','F-004','F-005','F-006','F-007','F-008'],
    })
    const principal = joinSocialContract({ name: 'P', mission: 't', owner: 'o', capabilities: ['*'], platform: 'test', models: ['m'], floor })
    const agent = joinSocialContract({ name: 'A', mission: 't', owner: 'o', capabilities: ['data:read'], platform: 'test', models: ['m'], floor })
    const d = delegate({ from: principal, toPublicKey: agent.publicKey, scope: ['data:read', 'data:write'], spendLimit: 5000, maxDepth: 2 })

    const gw = new ProxyGateway({
      gatewayId: 'gw-stress', gatewayPublicKey: gwKeys.publicKey, gatewayPrivateKey: gwKeys.privateKey,
      floor,
      enableGovernanceEnforcement: true,
      governanceEnvelope: createGovernanceEnvelope(govArt),
      governanceLoadPolicy: { ...DEFAULT_LOAD_POLICY, allowedIssuers: [issuer.publicKey] },
      enableEscalation: true, maxConcurrentEscalations: 2,
      enableCrossChainEnforcement: true,
      enableObligationMonitoring: true,
      enableReputationGating: true,
      maxReversibility: 'compensable',
      defaultEvidenceClass: 'standard',
    }, async () => ({ success: true, result: 'ok' }))
    gw.registerAgent(agent.passport, agent.attestation!, [d])

    function req(scope: string, opts?: { reversibility?: string; spend?: number }) {
      const requestId = 'stress-' + Math.random().toString(36).slice(2, 8)
      const payload = canonicalize({
        requestId, agentId: agent.agentId, tool: 'action', params: {},
        scopeRequired: scope, spend: opts?.spend ? { amount: opts.spend, currency: 'usd' } : undefined
      })
      return {
        requestId, agentId: agent.agentId, agentPublicKey: agent.publicKey,
        signature: sign(payload, agent.keyPair.privateKey),
        tool: 'action', params: {}, scopeRequired: scope,
        spend: opts?.spend ? { amount: opts.spend, currency: 'usd' } : undefined,
        reversibility: opts?.reversibility,
      } as any
    }
    return { gw, agent, principal, d, gwKeys, issuer, req }
  }

  it('all features: normal action with tentative reversibility', async () => {
    const { gw, req } = setup()
    const r = await gw.processToolCall(req('data:read', { reversibility: 'tentative' }))
    assert.equal(r.executed, true)
    assert.equal(r.reversibility, 'tentative')
    assert.equal(r.viaEscalation, undefined)
  })

  it('all features: irreversible blocked by maxReversibility', async () => {
    const { gw, req } = setup()
    const r = await gw.processToolCall(req('data:read', { reversibility: 'irreversible' }))
    assert.equal(r.executed, false)
    assert.ok(r.denialReason?.includes('reversibility'))
  })

  it('all features: escalation works alongside governance + reputation + cross-chain', async () => {
    const { gw, agent, principal, d, gwKeys, req } = setup()

    const grant = createEscalationGrant({
      delegationId: d.delegationId, grantedTo: agent.publicKey,
      grantedBy: principal.publicKey, granterPrivateKey: principal.keyPair.privateKey,
      ceiling: { scope: ['admin:*'], maxSpend: 500, maxDurationMs: 60_000 },
      allowedTriggers: ['human_authorized'],
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    })
    const ap = canonicalize({ approve: grant.grantId, grantedTo: grant.grantedTo })
    const humanSig = sign(ap, principal.keyPair.privateKey)
    const escReq = requestEscalation({
      grant, agentPrivateKey: agent.keyPair.privateKey, agentPublicKey: agent.publicKey,
      trigger: { type: 'human_authorized', evidence: 'test', humanApprovalSignature: humanSig }
    })
    const active = activateEscalation({ grant, request: escReq, gatewayPrivateKey: gwKeys.privateKey })
    gw.addEscalationGrant(agent.agentId, grant)
    gw.activateAgentEscalation(agent.agentId, active)

    const r = await gw.processToolCall(req('admin:*', { reversibility: 'tentative' }))
    assert.equal(r.executed, true, 'Escalation should work with all features: ' + r.denialReason)
    assert.equal(r.viaEscalation, true)
    assert.ok(r.escalationId)
    assert.ok(r.proof, 'Should have 3-sig proof')
    assert.ok(r.receipt, 'Should have receipt')
  })

  it('all features: stats track all dimensions', async () => {
    const { gw, req } = setup()
    // One normal action
    await gw.processToolCall(req('data:read', { reversibility: 'tentative' }))
    // One denied by reversibility
    await gw.processToolCall(req('data:read', { reversibility: 'irreversible' }))

    const stats = gw.getStats()
    assert.equal(stats.totalRequests, 2)
    assert.equal(stats.totalPermitted! >= 1, true)
    assert.equal(stats.totalDenied! >= 1, true)
    assert.equal(stats.reversibilityDenied! >= 1, true)
    assert.ok(stats.crossChainChecks !== undefined, 'Cross-chain stats should exist')
    assert.ok(stats.obligationsRegistered !== undefined, 'Obligations stats should exist')
    assert.ok(stats.governanceUpdates !== undefined, 'Governance stats should exist')
    assert.ok(stats.escalationsActivated !== undefined, 'Escalation stats should exist')
  })
})
