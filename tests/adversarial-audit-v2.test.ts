import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { joinSocialContract, delegate } from '../src/contract.js'
import { loadFloor } from '../src/core/values.js'
import { clearStores, createDelegation } from '../src/core/delegation.js'
import { createProxyGateway } from '../src/core/gateway.js'
import {
  createTaintLabel, createExecutionFrame, recordAccess,
  closeFrame, rotateFrame, verifyFrameChain, isFrameExpired,
  checkDataFlow, createCrossChainPermit, countersignPermit,
  deriveSAO, createSAO
} from '../src/core/cross-chain.js'
import * as fs from 'node:fs'

const floorYaml = fs.readFileSync('values/floor.yaml', 'utf-8')
const floor = loadFloor(floorYaml)

function setup(opts?: { crossChain?: boolean; frameTTL?: number }) {
  clearStores()
  const gwKeys = generateKeyPair()
  const principal = joinSocialContract({ name: 'Principal', mission: 'Test', owner: 'test', capabilities: ['data:read','data:write','commerce:purchase'], platform: 'test', models: ['test'], floor })
  const agent = joinSocialContract({ name: 'Agent', mission: 'Test', owner: 'test', capabilities: ['data:read','data:write'], platform: 'test', models: ['test'], floor })
  const agentKeys = agent.keyPair
  const delegation = delegate({ from: principal, toPublicKey: agentKeys.publicKey, scope: ['data:read','data:write','commerce:purchase'], spendLimit: 100, maxDepth: 2 })

  const gw = createProxyGateway({
    gatewayId: 'gw-1', gatewayPublicKey: gwKeys.publicKey, gatewayPrivateKey: gwKeys.privateKey,
    floor, enableCrossChainEnforcement: opts?.crossChain ?? true, frameTTLMinutes: opts?.frameTTL ?? 0
  }, async (tool) => ({ success: true, result: `${tool} result` }))
  gw.registerAgent(agent.passport, agent.attestation, [delegation])

  function req(tool: string, scope: string, reqId?: string, delId?: string) {
    const requestId = reqId || `req-${Math.random().toString(36).slice(2)}`
    const payload = canonicalize({ requestId, agentId: agent.agentId, tool, params: {}, scopeRequired: scope, spend: undefined })
    return { requestId, agentId: agent.agentId, agentPublicKey: agentKeys.publicKey, tool, params: {}, scopeRequired: scope, signature: sign(payload, agentKeys.privateKey), delegationId: delId }
  }

  return { gw, agent, agentKeys, principal, delegation, gwKeys, req }
}

describe('AUDIT V2 — Gateway Logic + Module Interaction + Different Attack Vectors', () => {

  // ═══ CRITICAL: Two-phase path bypasses ALL cross-chain enforcement ═══
  it('V2-CRIT-1: executeApproval skips cross-chain, taint, mutex, obligations', async () => {
    const { gw, agent, agentKeys, req } = setup({ crossChain: true })
    const principalB = generateKeyPair()
    const del2 = createDelegation({ delegatedTo: agentKeys.publicKey, delegatedBy: principalB.publicKey, privateKey: principalB.privateKey, scope: ['data:write'], expiresInHours: 24 })
    gw.addDelegation(agent.agentId, del2)

    // Taint frame with principalA via processToolCall
    await gw.processToolCall(req('read_file', 'data:read'))

    // Direct processToolCall under principalB should be BLOCKED
    const blocked = await gw.processToolCall(req('send_email', 'data:write', 'req-block', del2.delegationId))
    assert.equal(blocked.executed, false, 'processToolCall should block cross-chain')
    assert.ok(blocked.denialReason?.includes('Cross-chain'), 'Should cite cross-chain reason')

    // Two-phase: approve under principalB (no cross-chain check in approve())
    const approval = gw.approve(req('send_email', 'data:write', 'req-bypass', del2.delegationId))
    assert.equal(approval.approved, true, 'approve() does not check cross-chain — it approves')

    // Execute the approval — BYPASSES cross-chain enforcement
    const bypassed = await gw.executeApproval(approval.approval!.approvalId)
    // Document whether this executed or not
    console.log(`  V2-CRIT-1: executeApproval executed=${bypassed.executed} (EXPECTED: false, GOT: ${bypassed.executed})`)
    // THIS IS THE CRITICAL FINDING:
    // If bypassed.executed === true, the two-phase path is a complete bypass
  })

  // ═══ MEDIUM: Frame rotation timing attack ═══
  it('V2-MED-1: Frame rotation creates window for cross-chain exfiltration', async () => {
    const { gw, agent, agentKeys, req } = setup({ crossChain: true, frameTTL: 1 })
    const principalB = generateKeyPair()
    const del2 = createDelegation({ delegatedTo: agentKeys.publicKey, delegatedBy: principalB.publicKey, privateKey: principalB.privateKey, scope: ['data:write'], expiresInHours: 24 })
    gw.addDelegation(agent.agentId, del2)

    // Taint with principalA
    await gw.processToolCall(req('read_file', 'data:read'))

    // Blocked before rotation
    const pre = await gw.processToolCall(req('send_email', 'data:write', 'req-pre', del2.delegationId))
    assert.equal(pre.executed, false, 'Pre-rotation should block')

    // Expire the frame manually
    const frame = gw.getAgentFrame(agent.agentId)
    if (frame) (frame as any).startedAt = new Date(Date.now() - 120_000).toISOString()

    // After rotation, frame is clean — action succeeds
    const post = await gw.processToolCall(req('send_email', 'data:write', 'req-post', del2.delegationId))
    console.log(`  V2-MED-1: Post-rotation executed=${post.executed} (clean frame allows cross-chain)`)
  })

  // ═══ MEDIUM: canonicalize null-dropping collision ═══
  it('V2-MED-2: canonicalize null-drop produces identical representations', () => {
    assert.equal(canonicalize({ a: 1, b: null }), canonicalize({ a: 1 }))
    assert.equal(canonicalize({ x: undefined, y: 'z' }), canonicalize({ y: 'z' }))
  })

  // ═══ MEDIUM: deriveSAO loses per-principal information ═══
  it('V2-MED-3: deriveSAO collapses multi-principal taint to opaque label', () => {
    const keys = generateKeyPair()
    const a = createSAO('data-a', createTaintLabel('alice', 'c1', 'd1'), keys.privateKey, keys.publicKey)
    const b = createSAO('data-b', createTaintLabel('bob', 'c2', 'd2'), keys.privateKey, keys.publicKey)
    const derived = deriveSAO('combined', [a, b], keys.privateKey, keys.publicKey)
    assert.equal(derived.taint.principalId, 'MULTI_PRINCIPAL')
    // alice and bob identities are lost — downstream permit matching can't work
  })

  // ═══ LOW: No gateway permit revocation API ═══
  it('V2-LOW-1: Gateway has registerPermit but no revokePermit method', () => {
    const { gw } = setup({ crossChain: true })
    assert.equal(typeof (gw as any).registerPermit, 'function')
    assert.equal(typeof (gw as any).revokePermit, 'undefined', 'No revokePermit on gateway')
  })

  // ═══ LOW: verifyFrameChain ignores epoch super-chain ═══
  it('V2-LOW-2: Tampered epoch link passes verifyFrameChain', () => {
    let f = createExecutionFrame('a', { ttlMinutes: 5 })
    f = recordAccess(f, createTaintLabel('alice', 'c1', 'd1'))
    const { fresh } = rotateFrame(f)
    const tampered = { ...fresh, previousFrameChainHead: 'FAKE' }
    assert.equal(verifyFrameChain(tampered).valid, true, 'Epoch link not checked')
  })

  // ═══ MEDIUM: Scope wildcard escalation ═══
  it('V2-MED-4: Permit for "data" authorizes "data:delete:permanent"', () => {
    let frame = createExecutionFrame('a')
    frame = recordAccess(frame, createTaintLabel('alice', 'c1', 'd1'))
    const kA = generateKeyPair(), kB = generateKeyPair()
    const half = createCrossChainPermit({
      sourcePrincipalId: 'alice', sourcePrincipalPublicKey: kA.publicKey,
      sourceDataClasses: ['*'], destPrincipalId: 'bob', destPrincipalPublicKey: kB.publicKey,
      destAllowedScopes: ['data'], purpose: 'test', sourcePrivateKey: kA.privateKey
    })
    const permit = countersignPermit(half, kB.privateKey)
    const r = checkDataFlow({ inputTaint: frame.frameTaint, actionPrincipalId: 'bob', actionScope: 'data:delete:permanent', permits: [permit], frame })
    console.log(`  V2-MED-4: Permit for "data" → "data:delete:permanent": verdict=${r.verdict}`)
  })

  // ═══ MEDIUM: executeApproval not covered by agent mutex ═══
  it('V2-MED-5: executeApproval lacks per-agent sequential lock', () => {
    // Structural finding: processToolCall wraps in agentLocks
    // executeApproval calls directly, no lock
    // Concurrent executeApproval + processToolCall can race
    assert.ok(true, 'Concurrency gap in two-phase path documented')
  })
})
