// ══════════════════════════════════════════════════════════════════
// Transactional Integrity Layer — Tests (Session 3)
// ══════════════════════════════════════════════════════════════════
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createProxyGateway } from '../src/core/gateway.js'
import { joinSocialContract, delegate } from '../src/contract.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { loadFloor } from '../src/core/values.js'
import { clearStores } from '../src/core/delegation.js'
import {
  createEscrowHold, verifyEscrowHold,
  createDisputeArtifact, verifyDisputeArtifact,
  createWitnessAttestation, verifyWitnessAttestation,
  evaluateDisputeOverlay,
} from '../src/core/transactional.js'
import type { ToolCallRequest, GatewayConfig } from '../src/types/gateway.js'
import type { DisputeArtifact } from '../src/types/dispute.js'
import { readFileSync } from 'fs'
import { dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(__dirname + '/../values/floor.yaml', 'utf-8')
const floor = loadFloor(floorYaml)

function createTransactionalSetup() {
  clearStores()
  const gwKeys = generateKeyPair()
  const principal = joinSocialContract({
    name: 'tx-principal', mission: 'Test', owner: 'admin',
    capabilities: ['data_read', 'data_write'], platform: 'node', models: ['test'], floor,
  })
  const agentA = joinSocialContract({
    name: 'tx-buyer', mission: 'Test', owner: 'admin',
    capabilities: ['data_read'], platform: 'node', models: ['test'], floor,
  })
  const agentB = joinSocialContract({
    name: 'tx-seller', mission: 'Test', owner: 'admin',
    capabilities: ['data_write'], platform: 'node', models: ['test'], floor,
  })
  const delA = delegate({ from: principal, toPublicKey: agentA.publicKey, scope: ['data_read', 'data_write'], spendLimit: 200, maxDepth: 2, expiresInHours: 1 })
  const delB = delegate({ from: principal, toPublicKey: agentB.publicKey, scope: ['data_read', 'data_write'], spendLimit: 200, maxDepth: 2, expiresInHours: 1 })
  const config: GatewayConfig = { gatewayId: 'gw-tx-test', gatewayPublicKey: gwKeys.publicKey, gatewayPrivateKey: gwKeys.privateKey, floor, recheckRevocationOnExecute: true, escrowTimeoutThreshold: 50 }
  const gateway = createProxyGateway(config, async () => ({ success: true, result: {} }))
  gateway.registerAgent(agentA.passport, agentA.attestation, [delA])
  gateway.registerAgent(agentB.passport, agentB.attestation, [delB])
  let reqCounter = 0
  function makeRequest(agentId: string, agentKeys: any, scope = 'data_read'): ToolCallRequest {
    const requestId = `tx-req-${++reqCounter}-${Date.now()}`
    const payload = canonicalize({ requestId, agentId, tool: scope, params: {}, scopeRequired: scope })
    return { requestId, agentId, agentPublicKey: agentKeys.publicKey, tool: scope, params: {}, scopeRequired: scope, signature: sign(payload, agentKeys.privateKey) }
  }
  return { gateway, gwKeys, agentA, agentB, delA, delB, makeRequest }
}

function makeEscrow(s: any, amount = 50, expiresInSeconds = 3600) {
  return createEscrowHold({ initiatorAgentId: s.agentA.agentId, counterpartyAgentId: s.agentB.agentId, delegationId: s.delA.delegationId, amount: { value: amount, currency: 'usd' }, fulfillmentCondition: { type: 'manual_release' }, expiresInSeconds, gatewayId: 'gw-tx-test', initiatorPrivateKey: s.agentA.keyPair.privateKey, gatewayPrivateKey: s.gwKeys.privateKey })
}
function makeDispute(s: any, escrowId: string, severity: 'hard' | 'soft' | 'warning' = 'hard', scopes = ['data_write']) {
  return createDisputeArtifact({ claimantId: s.agentA.agentId, claimantPrivateKey: s.agentA.keyPair.privateKey, bond: { amount: 5, delegationId: s.delA.delegationId, slashable: true }, subject: 'quality', challengedArtifactId: escrowId, challengedArtifactType: 'escrow', claim: 'Test dispute', evidence: [{ evidenceId: 'ev1', type: 'receipt', artifactId: 'r1', submittedBy: s.agentA.agentId, submittedAt: new Date().toISOString() }], respondentId: s.agentB.agentId, resolutionTTLSeconds: 3600, freezeScope: { escrowIds: [escrowId], actionScopes: scopes }, freezeSeverity: severity, gatewayId: 'gw-tx-test', gatewayPrivateKey: s.gwKeys.privateKey })
}

describe('Escrow — Lifecycle', () => {
  it('creates escrow with hard reservation', () => {
    const s = createTransactionalSetup()
    const escrow = makeEscrow(s)
    assert.ok(escrow.escrowId.startsWith('esc_'))
    assert.strictEqual(escrow.status, 'held')
    assert.strictEqual(escrow.finality.status, 'provisional')
    assert.strictEqual(s.gateway.createGatewayEscrow(escrow).success, true)
  })
  it('verifies escrow signatures', () => {
    const s = createTransactionalSetup()
    const escrow = makeEscrow(s)
    const v = verifyEscrowHold(escrow, s.agentA.publicKey, s.gwKeys.publicKey)
    assert.strictEqual(v.valid, true)
  })
  it('rejects escrow exceeding delegation spend', () => {
    const s = createTransactionalSetup()
    const escrow = makeEscrow(s, 250)
    assert.strictEqual(s.gateway.createGatewayEscrow(escrow).success, false)
  })
  it('tracks cumulative escrow spend', () => {
    const s = createTransactionalSetup()
    assert.strictEqual(s.gateway.createGatewayEscrow(makeEscrow(s, 120)).success, true)
    assert.strictEqual(s.gateway.createGatewayEscrow(makeEscrow(s, 120)).success, false) // 240 > 200
  })
  it('fulfills escrow → released + finalized', () => {
    const s = createTransactionalSetup()
    const escrow = makeEscrow(s)
    s.gateway.createGatewayEscrow(escrow)
    assert.strictEqual(s.gateway.fulfillEscrow(escrow.escrowId, 'receipt-1').success, true)
    assert.strictEqual(s.gateway.getEscrow(escrow.escrowId)?.status, 'released')
    assert.strictEqual(s.gateway.getEscrow(escrow.escrowId)?.finality.status, 'finalized')
  })
  it('expires escrow → expired', () => {
    const s = createTransactionalSetup()
    const escrow = makeEscrow(s)
    s.gateway.createGatewayEscrow(escrow)
    assert.strictEqual(s.gateway.expireEscrow(escrow.escrowId).success, true)
    assert.strictEqual(s.gateway.getEscrow(escrow.escrowId)?.status, 'expired')
  })
  it('cannot expire disputed escrow', () => {
    const s = createTransactionalSetup()
    const escrow = makeEscrow(s)
    s.gateway.createGatewayEscrow(escrow)
    s.gateway.fileGatewayDispute(makeDispute(s, escrow.escrowId))
    assert.strictEqual(s.gateway.expireEscrow(escrow.escrowId).success, false)
  })
})

describe('Dispute — Filing + Resolution', () => {
  it('files dispute with bond → escrow frozen', () => {
    const s = createTransactionalSetup()
    const escrow = makeEscrow(s)
    s.gateway.createGatewayEscrow(escrow)
    const dispute = makeDispute(s, escrow.escrowId)
    assert.strictEqual(s.gateway.fileGatewayDispute(dispute).success, true)
    assert.strictEqual(s.gateway.getEscrow(escrow.escrowId)?.status, 'disputed')
    assert.strictEqual(s.gateway.getEscrow(escrow.escrowId)?.finality.status, 'frozen')
  })
  it('verifies dispute signatures', () => {
    const s = createTransactionalSetup()
    const dispute = makeDispute(s, 'esc_test')
    const v = verifyDisputeArtifact(dispute, s.agentA.publicKey, s.gwKeys.publicKey)
    assert.strictEqual(v.valid, true)
  })
  it('resolves upheld → refund + bond returned', () => {
    const s = createTransactionalSetup()
    const escrow = makeEscrow(s)
    s.gateway.createGatewayEscrow(escrow)
    const dispute = makeDispute(s, escrow.escrowId)
    s.gateway.fileGatewayDispute(dispute)
    s.gateway.resolveGatewayDispute(dispute.disputeId, {
      outcome: 'upheld', resolvedBy: 'p1', resolverRole: 'initiating_principal',
      resolvedAt: new Date().toISOString(), reasoning: 'No delivery',
      enforcement: { escrowAction: 'refund', bondAction: 'return' },
    })
    assert.strictEqual(s.gateway.getEscrow(escrow.escrowId)?.status, 'refunded')
  })
  it('resolves dismissed → release + bond slashed', () => {
    const s = createTransactionalSetup()
    const escrow = makeEscrow(s)
    s.gateway.createGatewayEscrow(escrow)
    const dispute = makeDispute(s, escrow.escrowId)
    s.gateway.fileGatewayDispute(dispute)
    s.gateway.resolveGatewayDispute(dispute.disputeId, {
      outcome: 'dismissed', resolvedBy: 'p1', resolverRole: 'initiating_principal',
      resolvedAt: new Date().toISOString(), reasoning: 'Frivolous',
      enforcement: { escrowAction: 'release', bondAction: 'slash', bondSlashRatio: 1.0 },
    })
    assert.strictEqual(s.gateway.getEscrow(escrow.escrowId)?.status, 'released')
    assert.strictEqual(s.gateway.getDispute(dispute.disputeId)?.resolution?.enforcement.bondAction, 'slash')
  })
  it('timeout low-value → dismissed (ESS: favor respondent)', () => {
    const s = createTransactionalSetup()
    const escrow = makeEscrow(s, 20) // below threshold of 50
    s.gateway.createGatewayEscrow(escrow)
    const dispute = makeDispute(s, escrow.escrowId)
    s.gateway.fileGatewayDispute(dispute)
    const result = s.gateway.timeoutDispute(dispute.disputeId)
    assert.strictEqual(result.outcome, 'dismissed')
    assert.strictEqual(s.gateway.getEscrow(escrow.escrowId)?.status, 'released')
  })
  it('timeout high-value → upheld (ESS: favor claimant)', () => {
    const s = createTransactionalSetup()
    const escrow = makeEscrow(s, 100) // above threshold of 50
    s.gateway.createGatewayEscrow(escrow)
    const dispute = makeDispute(s, escrow.escrowId)
    s.gateway.fileGatewayDispute(dispute)
    const result = s.gateway.timeoutDispute(dispute.disputeId)
    assert.strictEqual(result.outcome, 'upheld')
    assert.strictEqual(s.gateway.getEscrow(escrow.escrowId)?.status, 'refunded')
  })
})

describe('Defeasible Dispute Overlay', () => {
  it('hard freeze blocks processToolCall in frozen scope', async () => {
    const s = createTransactionalSetup()
    const escrow = makeEscrow(s)
    s.gateway.createGatewayEscrow(escrow)
    s.gateway.fileGatewayDispute(makeDispute(s, escrow.escrowId, 'hard', ['data_write']))
    const result = await s.gateway.processToolCall(s.makeRequest(s.agentB.agentId, s.agentB.keyPair, 'data_write'))
    assert.strictEqual(result.executed, false)
    assert.ok(result.denialReason?.includes('dispute'))
    assert.ok(result.constraintVector?.disputeOverlay?.actionAffected)
  })
  it('allows processToolCall outside frozen scope', async () => {
    const s = createTransactionalSetup()
    const escrow = makeEscrow(s)
    s.gateway.createGatewayEscrow(escrow)
    s.gateway.fileGatewayDispute(makeDispute(s, escrow.escrowId, 'hard', ['data_write']))
    const result = await s.gateway.processToolCall(s.makeRequest(s.agentB.agentId, s.agentB.keyPair, 'data_read'))
    assert.strictEqual(result.executed, true)
  })
  it('dismissed dispute lifts overlay → action permitted', async () => {
    const s = createTransactionalSetup()
    const escrow = makeEscrow(s)
    s.gateway.createGatewayEscrow(escrow)
    const dispute = makeDispute(s, escrow.escrowId, 'hard', ['data_write'])
    s.gateway.fileGatewayDispute(dispute)
    // Dismiss
    s.gateway.resolveGatewayDispute(dispute.disputeId, {
      outcome: 'dismissed', resolvedBy: 'p1', resolverRole: 'initiating_principal',
      resolvedAt: new Date().toISOString(), reasoning: 'Dismissed',
      enforcement: { escrowAction: 'release', bondAction: 'slash' },
    })
    const result = await s.gateway.processToolCall(s.makeRequest(s.agentB.agentId, s.agentB.keyPair, 'data_write'))
    assert.strictEqual(result.executed, true, 'Defeater removed — action should pass')
  })
  it('evaluateDisputeOverlay pure function works correctly', () => {
    const disputes: DisputeArtifact[] = [{
      disputeId: 'dsp_test', claimantId: 'a1', claimantSignature: 'sig',
      bond: { amount: 5, delegationId: 'd1', slashable: true },
      subject: 'quality', challengedArtifactId: 'esc1', challengedArtifactType: 'escrow',
      claim: 'Test', evidence: [], respondentId: 'b1',
      status: 'investigating', finality: { status: 'frozen', since: new Date().toISOString() },
      filedAt: new Date().toISOString(), resolutionTTL: new Date(Date.now() + 3600000).toISOString(),
      freezeScope: { escrowIds: ['esc1'], actionScopes: ['data_write'] },
      freezeSeverity: 'hard', gatewayId: 'gw1', gatewaySignature: 'sig',
    }]
    const o1 = evaluateDisputeOverlay(disputes, 'data_write', 'b1')
    assert.strictEqual(o1.hasActiveDispute, true)
    assert.strictEqual(o1.actionAffected, true)
    assert.strictEqual(o1.effectiveSeverity, 'hard')
    const o2 = evaluateDisputeOverlay(disputes, 'data_read', 'b1')
    assert.strictEqual(o2.actionAffected, false)
    const o3 = evaluateDisputeOverlay(disputes, 'data_write', 'c1')
    assert.strictEqual(o3.hasActiveDispute, false)
  })
})

describe('Witness Attestation', () => {
  it('creates and verifies witness attestation', () => {
    const wk = generateKeyPair()
    const att = createWitnessAttestation({ witnessId: 'w1', witnessPrivateKey: wk.privateKey, witnessRole: 'notary', receiptId: 'r1', receiptHash: 'hash1', attestation: { executionObserved: true, receiptConsistent: true, constraintsVerified: true }, observationBasis: 'direct_observation' })
    assert.strictEqual(verifyWitnessAttestation(att, wk.publicKey), true)
    assert.strictEqual(att.observationBasis, 'direct_observation')
  })
  it('rejects tampered witness attestation', () => {
    const wk = generateKeyPair()
    const att = createWitnessAttestation({ witnessId: 'w1', witnessPrivateKey: wk.privateKey, witnessRole: 'auditor', receiptId: 'r2', receiptHash: 'hash2', attestation: { executionObserved: true, receiptConsistent: true, constraintsVerified: false }, observationBasis: 'replay_verification' })
    att.attestation.constraintsVerified = true // tamper
    assert.strictEqual(verifyWitnessAttestation(att, wk.publicKey), false)
  })
  it('supports prediction error field', () => {
    const wk = generateKeyPair()
    const att = createWitnessAttestation({ witnessId: 'w2', witnessPrivateKey: wk.privateKey, witnessRole: 'auditor', receiptId: 'r3', receiptHash: 'hash3', attestation: { executionObserved: true, receiptConsistent: false, constraintsVerified: true }, observationBasis: 'independent_recomputation', predictionError: { expectedOutcome: 'success', observedOutcome: 'partial', divergence: 0.4 } })
    assert.ok(att.predictionError)
    assert.strictEqual(att.predictionError.divergence, 0.4)
    assert.strictEqual(verifyWitnessAttestation(att, wk.publicKey), true)
  })
})

describe('DangerSignal Detection', () => {
  it('detects escrow approaching TTL', () => {
    const s = createTransactionalSetup()
    const escrow = makeEscrow(s, 50, 3600)
    // Simulate an escrow that's 95% through its TTL by backdating createdAt
    escrow.createdAt = new Date(Date.now() - 3600 * 1000 * 0.95).toISOString()
    escrow.expiresAt = new Date(Date.now() + 3600 * 1000 * 0.05).toISOString()
    s.gateway.createGatewayEscrow(escrow)
    const signals = s.gateway.scanForDangerSignals()
    const ttl = signals.filter(sg => sg.type === 'escrow_ttl_approaching')
    assert.ok(ttl.length > 0, 'Should detect approaching TTL')
    assert.strictEqual(ttl[0].agentId, s.agentB.agentId)
  })
  it('no signal for healthy escrows', () => {
    const s = createTransactionalSetup()
    s.gateway.createGatewayEscrow(makeEscrow(s, 50, 86400))
    const signals = s.gateway.scanForDangerSignals()
    assert.strictEqual(signals.filter(sg => sg.type === 'escrow_ttl_approaching').length, 0)
  })
  it('tracks escrow and dispute stats', () => {
    const s = createTransactionalSetup()
    const escrow = makeEscrow(s)
    s.gateway.createGatewayEscrow(escrow)
    s.gateway.fulfillEscrow(escrow.escrowId, 'r1')
    const stats = s.gateway.getStats() as any
    assert.ok(stats.escrowsCreated >= 1)
    assert.ok(stats.escrowsReleased >= 1)
  })
})

describe('Integration — Full Flows', () => {
  it('happy path: escrow → fulfill → release', () => {
    const s = createTransactionalSetup()
    const escrow = makeEscrow(s, 75)
    assert.strictEqual(s.gateway.createGatewayEscrow(escrow).success, true)
    assert.strictEqual(s.gateway.getEscrow(escrow.escrowId)?.status, 'held')
    assert.strictEqual(s.gateway.fulfillEscrow(escrow.escrowId, 'receipt-final').success, true)
    assert.strictEqual(s.gateway.getEscrow(escrow.escrowId)?.status, 'released')
    assert.strictEqual(s.gateway.getEscrow(escrow.escrowId)?.finality.status, 'finalized')
  })
  it('dispute path: escrow → dispute → freeze → resolve → release', () => {
    const s = createTransactionalSetup()
    const escrow = makeEscrow(s, 60)
    s.gateway.createGatewayEscrow(escrow)
    assert.strictEqual(s.gateway.getEscrow(escrow.escrowId)?.status, 'held')
    const dispute = makeDispute(s, escrow.escrowId)
    s.gateway.fileGatewayDispute(dispute)
    assert.strictEqual(s.gateway.getEscrow(escrow.escrowId)?.status, 'disputed')
    assert.strictEqual(s.gateway.getEscrow(escrow.escrowId)?.finality.status, 'frozen')
    s.gateway.resolveGatewayDispute(dispute.disputeId, {
      outcome: 'compromise', resolvedBy: 'both', resolverRole: 'joint_resolution',
      resolvedAt: new Date().toISOString(), reasoning: 'Partial delivery',
      enforcement: { escrowAction: 'split', splitRatio: 0.6, bondAction: 'return' },
    })
    assert.strictEqual(s.gateway.getEscrow(escrow.escrowId)?.status, 'released')
    assert.strictEqual(s.gateway.getEscrow(escrow.escrowId)?.finality.status, 'finalized')
    assert.strictEqual(s.gateway.getDispute(dispute.disputeId)?.status, 'resolved')
    assert.strictEqual(s.gateway.getDispute(dispute.disputeId)?.resolution?.enforcement.splitRatio, 0.6)
  })
})
