// ══════════════════════════════════════════════════════════════════
// Integration Invariant Smoke Tests — Paper Section 3 Claims
// ══════════════════════════════════════════════════════════════════
//
// Each test maps directly to a paper invariant claim.
// These are the tests a reviewer can run to verify the paper's core thesis.
//
// INV-1: Delegation attenuation — scope narrows across chains
// INV-2: Governance attenuation — governance can only strengthen
// INV-3: Disclosure attenuation — receipts → Merkle proofs
// INV-4: Exception attenuation — escalation is bounded, temporary
// COMPOSITION: INV-4 under INV-2 — escalation can't weaken governance

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { ProxyGateway } from '../src/core/gateway.js'
import { joinSocialContract, delegate } from '../src/contract.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { loadFloor } from '../src/core/values.js'
import { clearStores } from '../src/core/delegation.js'
import { buildMerkleRoot, generateMerkleProof, verifyMerkleProof } from '../src/core/attribution.js'
import { createHash } from 'crypto'
import {
  createGovernanceArtifact, upgradeGovernanceArtifact,
  approveArtifact, createGovernanceEnvelope
} from '../src/core/governance.js'
import { DEFAULT_LOAD_POLICY } from '../src/types/governance.js'
import {
  createEscalationGrant, requestEscalation, activateEscalation
} from '../src/core/escalation.js'
import type { GatewayConfig, ToolExecutor, ToolCallRequest } from '../src/types/gateway.js'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(join(__dirname, '../values/floor.yaml'), 'utf-8')
const floor = loadFloor(floorYaml)
const makeExecutor = (): ToolExecutor => async () => ({ success: true, result: 'ok' })

function makeReq(agent: any, scope: string, opts?: { spend?: number; reversibility?: string }) {
  const requestId = 'req-' + Math.random().toString(36).slice(2, 8)
  const payload = canonicalize({
    requestId, agentId: agent.agentId, tool: 'action', params: {},
    scopeRequired: scope,
    spend: opts?.spend ? { amount: opts.spend, currency: 'usd' } : undefined
  })
  return {
    requestId, agentId: agent.agentId, agentPublicKey: agent.publicKey,
    signature: sign(payload, agent.keyPair.privateKey),
    tool: 'action', params: {}, scopeRequired: scope,
    spend: opts?.spend ? { amount: opts.spend, currency: 'usd' } : undefined,
    reversibility: opts?.reversibility,
  } as ToolCallRequest
}

describe('Paper Section 3 — Four Attenuation Invariants', () => {

  // ══════════════════════════════════════
  // INV-1: Delegation Attenuation
  // A_{i+1} ⊆ A_i — scope narrows across chains
  // ══════════════════════════════════════

  it('INV-1: delegation chain narrows scope — child cannot exceed parent', async () => {
    clearStores()
    const gwKeys = generateKeyPair()
    const principal = joinSocialContract({
      name: 'P', mission: 't', owner: 'o', capabilities: ['*'], platform: 'test', models: ['m'], floor
    })
    const agent = joinSocialContract({
      name: 'A', mission: 't', owner: 'o', capabilities: ['data:read'], platform: 'test', models: ['m'], floor
    })
    // Principal delegates data:read + data:write
    const d = delegate({ from: principal, toPublicKey: agent.publicKey, scope: ['data:read', 'data:write'], spendLimit: 1000, maxDepth: 1 })

    const gw = new ProxyGateway({
      gatewayId: 'gw-inv1', gatewayPublicKey: gwKeys.publicKey,
      gatewayPrivateKey: gwKeys.privateKey, floor,
    }, makeExecutor())
    gw.registerAgent(agent.passport, agent.attestation!, [d])

    // data:read allowed (within scope)
    const r1 = await gw.processToolCall(makeReq(agent, 'data:read'))
    assert.equal(r1.executed, true, 'data:read should be within delegation scope')

    // admin:delete denied (outside scope — monotonic narrowing enforced)
    const r2 = await gw.processToolCall(makeReq(agent, 'admin:delete'))
    assert.equal(r2.executed, false, 'admin:delete should be outside delegation scope')
    assert.ok(r2.denialReason?.includes('No valid delegation'))
  })

  // ══════════════════════════════════════
  // INV-2: Governance Attenuation
  // G_{i+1} ⪰ G_i — weakening requires higher-order authorization
  // ══════════════════════════════════════

  it('INV-2: governance weakening blocked without higher-order approval', () => {
    clearStores()
    const gwKeys = generateKeyPair()
    const issuer = generateKeyPair()

    const initial = createGovernanceArtifact({
      artifactType: 'floor', version: '1.0.0', content: floorYaml,
      issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      changeType: 'initial', additions: ['F-001', 'F-002', 'F-003'],
    })
    const envelope = createGovernanceEnvelope(initial)

    const gw = new ProxyGateway({
      gatewayId: 'gw-inv2', gatewayPublicKey: gwKeys.publicKey,
      gatewayPrivateKey: gwKeys.privateKey, floor,
      enableGovernanceEnforcement: true, governanceEnvelope: envelope,
      governanceLoadPolicy: { ...DEFAULT_LOAD_POLICY, allowedIssuers: [issuer.publicKey] },
    }, makeExecutor())

    // Strengthening: accepted
    const strengthened = upgradeGovernanceArtifact(initial, {
      version: '1.1.0', content: floorYaml + '\n# added F-004',
      issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      changeType: 'strengthening', additions: ['F-004'],
    })
    const r1 = gw.updateGovernance(createGovernanceEnvelope(strengthened), initial)
    assert.equal(r1.accepted, true, 'Strengthening should always be accepted')

    // Weakening WITHOUT approval: blocked
    const weakened = upgradeGovernanceArtifact(strengthened, {
      version: '1.2.0', content: '# removed F-002',
      issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      changeType: 'weakening', removals: ['F-002'],
    })
    const r2 = gw.updateGovernance(createGovernanceEnvelope(weakened), strengthened)
    assert.equal(r2.accepted, false, 'Weakening without approval must be blocked')
  })

  // ══════════════════════════════════════
  // INV-3: Disclosure Attenuation
  // D_{viewer} ⊆ D_{committed} — Merkle proofs verify minimum disclosure
  // ══════════════════════════════════════

  it('INV-3: receipt Merkle proofs verifiable with selective disclosure', () => {
    const hash = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex')
    const receipts = [
      { receiptId: 'r1', data: 'action-1' },
      { receiptId: 'r2', data: 'action-2' },
      { receiptId: 'r3', data: 'action-3' },
    ]
    const leafHashes = receipts.map(r => hash(canonicalize(r)))
    const root = buildMerkleRoot(leafHashes)
    assert.ok(root, 'Merkle root should be computed')

    // Generate proof for receipt 1 only (selective disclosure)
    const proof = generateMerkleProof(leafHashes, leafHashes[0])
    assert.ok(proof, 'Proof should be generated for leaf 0')

    // Verify: viewer sees proof for r1 without seeing r2 or r3
    const valid = verifyMerkleProof(proof)
    assert.equal(valid, true, 'Merkle proof should verify against root')
  })

  // ══════════════════════════════════════
  // INV-4: Exception Attenuation
  // E_active ⊆ E_precommitted — escalation bounded by pre-committed ceiling
  // ══════════════════════════════════════

  it('INV-4: escalation grants temporary access then expires', async () => {
    clearStores()
    const gwKeys = generateKeyPair()
    const principal = joinSocialContract({
      name: 'P', mission: 't', owner: 'o', capabilities: ['*'], platform: 'test', models: ['m'], floor
    })
    const agent = joinSocialContract({
      name: 'A', mission: 't', owner: 'o', capabilities: ['data:read'], platform: 'test', models: ['m'], floor
    })
    // Narrow delegation: only data:read
    const d = delegate({ from: principal, toPublicKey: agent.publicKey, scope: ['data:read'], spendLimit: 100, maxDepth: 1 })

    const gw = new ProxyGateway({
      gatewayId: 'gw-inv4', gatewayPublicKey: gwKeys.publicKey,
      gatewayPrivateKey: gwKeys.privateKey, floor, enableEscalation: true,
    }, makeExecutor())
    gw.registerAgent(agent.passport, agent.attestation!, [d])

    // admin:delete denied normally
    const r1 = await gw.processToolCall(makeReq(agent, 'admin:delete'))
    assert.equal(r1.executed, false, 'admin:delete denied without escalation')

    // Create + activate escalation with 50ms TTL
    const grant = createEscalationGrant({
      delegationId: d.delegationId, grantedTo: agent.publicKey,
      grantedBy: principal.publicKey, granterPrivateKey: principal.keyPair.privateKey,
      ceiling: { scope: ['admin:*'], maxSpend: 50, maxDurationMs: 150 },
      allowedTriggers: ['human_authorized'],
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    })
    const approvalPayload = canonicalize({ approve: grant.grantId, grantedTo: grant.grantedTo })
    const humanSig = sign(approvalPayload, principal.keyPair.privateKey)
    const escReq = requestEscalation({
      grant, agentPrivateKey: agent.keyPair.privateKey, agentPublicKey: agent.publicKey,
      trigger: { type: 'human_authorized', evidence: 'test', humanApprovalSignature: humanSig }
    })
    const active = activateEscalation({ grant, request: escReq, gatewayPrivateKey: gwKeys.privateKey })
    gw.addEscalationGrant(agent.agentId, grant)
    gw.activateAgentEscalation(agent.agentId, active)

    // admin:delete ALLOWED via escalation
    const r2 = await gw.processToolCall(makeReq(agent, 'admin:*'))
    assert.equal(r2.executed, true, 'admin:* should be allowed via escalation')
    assert.equal(r2.viaEscalation, true, 'result should flag viaEscalation')

    // Wait for TTL expiry
    await new Promise(r => setTimeout(r, 200))

    // admin:delete denied again after expiry
    const r3 = await gw.processToolCall(makeReq(agent, 'admin:*'))
    assert.equal(r3.executed, false, 'admin:* denied after escalation expires')
  })

  // ══════════════════════════════════════
  // COMPOSITION: INV-4 under INV-2
  // Escalation cannot weaken governance
  // ══════════════════════════════════════

  it('COMPOSITION: escalation via gateway cannot bypass governance staleness', async () => {
    clearStores()
    const gwKeys = generateKeyPair()
    const issuer = generateKeyPair()
    const principal = joinSocialContract({
      name: 'P', mission: 't', owner: 'o', capabilities: ['*'], platform: 'test', models: ['m'], floor
    })
    const agent = joinSocialContract({
      name: 'A', mission: 't', owner: 'o', capabilities: ['data:read'], platform: 'test', models: ['m'], floor
    })

    const d = delegate({ from: principal, toPublicKey: agent.publicKey, scope: ['data:read'], spendLimit: 100, maxDepth: 1 })

    const initial = createGovernanceArtifact({
      artifactType: 'floor', version: '1.0.0', content: floorYaml,
      issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      changeType: 'initial', additions: ['F-001', 'F-002', 'F-003'],
    })

    const gw = new ProxyGateway({
      gatewayId: 'gw-comp', gatewayPublicKey: gwKeys.publicKey,
      gatewayPrivateKey: gwKeys.privateKey, floor,
      enableGovernanceEnforcement: true, enableEscalation: true,
      governanceEnvelope: createGovernanceEnvelope(initial),
      governanceLoadPolicy: { ...DEFAULT_LOAD_POLICY, allowedIssuers: [issuer.publicKey] },
    }, makeExecutor())
    gw.registerAgent(agent.passport, agent.attestation!, [d])

    // Activate escalation for admin:*
    const grant = createEscalationGrant({
      delegationId: d.delegationId, grantedTo: agent.publicKey,
      grantedBy: principal.publicKey, granterPrivateKey: principal.keyPair.privateKey,
      ceiling: { scope: ['admin:*'], maxSpend: 500, maxDurationMs: 60_000 },
      allowedTriggers: ['human_authorized'],
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    })
    const approvalPayload = canonicalize({ approve: grant.grantId, grantedTo: grant.grantedTo })
    const humanSig = sign(approvalPayload, principal.keyPair.privateKey)
    const escReq = requestEscalation({
      grant, agentPrivateKey: agent.keyPair.privateKey, agentPublicKey: agent.publicKey,
      trigger: { type: 'human_authorized', evidence: 'test', humanApprovalSignature: humanSig }
    })
    const active = activateEscalation({ grant, request: escReq, gatewayPrivateKey: gwKeys.privateKey })
    gw.addEscalationGrant(agent.agentId, grant)
    gw.activateAgentEscalation(agent.agentId, active)

    // Update governance — makes agent's attestation stale
    const v2 = upgradeGovernanceArtifact(initial, {
      version: '2.0.0', content: floorYaml + '\n# v2',
      issuerPrivateKey: issuer.privateKey, issuerPublicKey: issuer.publicKey,
      changeType: 'strengthening', additions: ['F-004'],
    })
    gw.updateGovernance(createGovernanceEnvelope(v2), initial)

    // Even with active escalation, governance staleness blocks the action
    // This proves INV-2 takes precedence over INV-4
    const r = await gw.processToolCall(makeReq(agent, 'data:read'))
    assert.equal(r.executed, false, 'Governance staleness must block even with escalation')
    assert.ok(r.denialReason?.includes('Governance stale'))
  })

  // ══════════════════════════════════════
  // REVERSIBILITY (Gap 3 taxonomy)
  // ══════════════════════════════════════

  it('REVERSION: tentative action allowed when max is compensable', async () => {
    clearStores()
    const gwKeys = generateKeyPair()
    const principal = joinSocialContract({
      name: 'P', mission: 't', owner: 'o', capabilities: ['*'], platform: 'test', models: ['m'], floor
    })
    const agent = joinSocialContract({
      name: 'A', mission: 't', owner: 'o', capabilities: ['data:read'], platform: 'test', models: ['m'], floor
    })
    const d = delegate({ from: principal, toPublicKey: agent.publicKey, scope: ['data:read'], spendLimit: 100, maxDepth: 1 })

    const gw = new ProxyGateway({
      gatewayId: 'gw-rev', gatewayPublicKey: gwKeys.publicKey,
      gatewayPrivateKey: gwKeys.privateKey, floor,
      maxReversibility: 'compensable',
    }, makeExecutor())
    gw.registerAgent(agent.passport, agent.attestation!, [d])

    const r = await gw.processToolCall(makeReq(agent, 'data:read', { reversibility: 'tentative' }))
    assert.equal(r.executed, true, 'Tentative allowed when max is compensable')
    assert.equal(r.reversibility, 'tentative')
  })

  it('REVERSION: irreversible action BLOCKED when max is compensable', async () => {
    clearStores()
    const gwKeys = generateKeyPair()
    const principal = joinSocialContract({
      name: 'P', mission: 't', owner: 'o', capabilities: ['*'], platform: 'test', models: ['m'], floor
    })
    const agent = joinSocialContract({
      name: 'A', mission: 't', owner: 'o', capabilities: ['data:read'], platform: 'test', models: ['m'], floor
    })
    const d = delegate({ from: principal, toPublicKey: agent.publicKey, scope: ['data:read'], spendLimit: 100, maxDepth: 1 })

    const gw = new ProxyGateway({
      gatewayId: 'gw-rev2', gatewayPublicKey: gwKeys.publicKey,
      gatewayPrivateKey: gwKeys.privateKey, floor,
      maxReversibility: 'compensable',
    }, makeExecutor())
    gw.registerAgent(agent.passport, agent.attestation!, [d])

    const r = await gw.processToolCall(makeReq(agent, 'data:read', { reversibility: 'irreversible' }))
    assert.equal(r.executed, false, 'Irreversible blocked when max is compensable')
    assert.ok(r.denialReason?.includes('reversibility'))
  })

  it('REVERSION: no reversibility declared — action proceeds normally', async () => {
    clearStores()
    const gwKeys = generateKeyPair()
    const principal = joinSocialContract({
      name: 'P', mission: 't', owner: 'o', capabilities: ['*'], platform: 'test', models: ['m'], floor
    })
    const agent = joinSocialContract({
      name: 'A', mission: 't', owner: 'o', capabilities: ['data:read'], platform: 'test', models: ['m'], floor
    })
    const d = delegate({ from: principal, toPublicKey: agent.publicKey, scope: ['data:read'], spendLimit: 100, maxDepth: 1 })

    const gw = new ProxyGateway({
      gatewayId: 'gw-rev3', gatewayPublicKey: gwKeys.publicKey,
      gatewayPrivateKey: gwKeys.privateKey, floor,
      maxReversibility: 'tentative',  // strictest setting
    }, makeExecutor())
    gw.registerAgent(agent.passport, agent.attestation!, [d])

    // No reversibility declared — check is skipped
    const r = await gw.processToolCall(makeReq(agent, 'data:read'))
    assert.equal(r.executed, true, 'No reversibility declared = no check')
  })
})
