// Bilateral Receipt + Evidence Commitments + Compromise Window Tests
// Three ecosystem-sourced engineering improvements.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair,
  createBilateralReceipt,
  verifyBilateralReceipt,
  createEvidenceCommitment,
  verifyEvidenceCommitment,
  checkCompromiseWindow,
} from '../src/index.js'
import type { InteractionOutcome, RevocationReason } from '../src/index.js'

const agentA = generateKeyPair()  // requesting agent
const agentB = generateKeyPair()  // serving agent
const gateway = generateKeyPair() // witnessing gateway
const stranger = generateKeyPair()

function makeOutcome(overrides?: Partial<InteractionOutcome>): InteractionOutcome {
  return {
    toolName: 'web_search',
    requestHash: 'abc123',
    responseHash: 'def456',
    status: 'success',
    summary: 'Searched for weather data',
    ...overrides,
  }
}

// ══════════════════════════════════════════════════════════════════
// 1. Bilateral Receipt — co-signed interaction records
// ══════════════════════════════════════════════════════════════════

describe('Bilateral Receipt', () => {

  describe('creation and verification', () => {
    it('creates receipt signed by both agents', () => {
      const receipt = createBilateralReceipt({
        requestingAgentId: 'agent-a',
        servingAgentId: 'agent-b',
        outcome: makeOutcome(),
        requestedAt: '2026-04-01T10:00:00Z',
        completedAt: '2026-04-01T10:00:01Z',
        requestingAgentPrivateKey: agentA.privateKey,
        servingAgentPrivateKey: agentB.privateKey,
      })

      assert.ok(receipt.receiptId)
      assert.equal(receipt.version, '1.0')
      assert.ok(receipt.requestingAgentSignature)
      assert.ok(receipt.servingAgentSignature)
      assert.equal(receipt.gatewaySignature, undefined)
    })

    it('verifies valid bilateral receipt', () => {
      const receipt = createBilateralReceipt({
        requestingAgentId: 'agent-a',
        servingAgentId: 'agent-b',
        outcome: makeOutcome(),
        requestedAt: '2026-04-01T10:00:00Z',
        completedAt: '2026-04-01T10:00:01Z',
        requestingAgentPrivateKey: agentA.privateKey,
        servingAgentPrivateKey: agentB.privateKey,
      })

      const result = verifyBilateralReceipt(receipt, agentA.publicKey, agentB.publicKey)
      assert.equal(result.valid, true)
      assert.equal(result.requestingAgentSignatureValid, true)
      assert.equal(result.servingAgentSignatureValid, true)
      assert.equal(result.outcomeConsistent, true)
      assert.equal(result.timingValid, true)
    })

    it('includes gateway witness signature when provided', () => {
      const receipt = createBilateralReceipt({
        requestingAgentId: 'agent-a',
        servingAgentId: 'agent-b',
        outcome: makeOutcome(),
        requestedAt: '2026-04-01T10:00:00Z',
        completedAt: '2026-04-01T10:00:01Z',
        requestingAgentPrivateKey: agentA.privateKey,
        servingAgentPrivateKey: agentB.privateKey,
        gatewayPrivateKey: gateway.privateKey,
      })

      assert.ok(receipt.gatewaySignature)
      const result = verifyBilateralReceipt(receipt, agentA.publicKey, agentB.publicKey, gateway.publicKey)
      assert.equal(result.valid, true)
      assert.equal(result.gatewaySignatureValid, true)
    })

    it('rejects when requesting agent key is wrong', () => {
      const receipt = createBilateralReceipt({
        requestingAgentId: 'agent-a',
        servingAgentId: 'agent-b',
        outcome: makeOutcome(),
        requestedAt: '2026-04-01T10:00:00Z',
        completedAt: '2026-04-01T10:00:01Z',
        requestingAgentPrivateKey: agentA.privateKey,
        servingAgentPrivateKey: agentB.privateKey,
      })

      const result = verifyBilateralReceipt(receipt, stranger.publicKey, agentB.publicKey)
      assert.equal(result.valid, false)
      assert.equal(result.requestingAgentSignatureValid, false)
      assert.equal(result.servingAgentSignatureValid, true)
    })

    it('rejects when serving agent key is wrong', () => {
      const receipt = createBilateralReceipt({
        requestingAgentId: 'agent-a',
        servingAgentId: 'agent-b',
        outcome: makeOutcome(),
        requestedAt: '2026-04-01T10:00:00Z',
        completedAt: '2026-04-01T10:00:01Z',
        requestingAgentPrivateKey: agentA.privateKey,
        servingAgentPrivateKey: agentB.privateKey,
      })

      const result = verifyBilateralReceipt(receipt, agentA.publicKey, stranger.publicKey)
      assert.equal(result.valid, false)
      assert.equal(result.requestingAgentSignatureValid, true)
      assert.equal(result.servingAgentSignatureValid, false)
    })

    it('rejects tampered outcome', () => {
      const receipt = createBilateralReceipt({
        requestingAgentId: 'agent-a',
        servingAgentId: 'agent-b',
        outcome: makeOutcome(),
        requestedAt: '2026-04-01T10:00:00Z',
        completedAt: '2026-04-01T10:00:01Z',
        requestingAgentPrivateKey: agentA.privateKey,
        servingAgentPrivateKey: agentB.privateKey,
      })

      const tampered = { ...receipt, outcome: { ...receipt.outcome, summary: 'TAMPERED' } }
      const result = verifyBilateralReceipt(tampered, agentA.publicKey, agentB.publicKey)
      assert.equal(result.valid, false)
    })

    it('generates unique receipt IDs', () => {
      const r1 = createBilateralReceipt({
        requestingAgentId: 'a', servingAgentId: 'b',
        outcome: makeOutcome(),
        requestedAt: '2026-04-01T10:00:00Z', completedAt: '2026-04-01T10:00:01Z',
        requestingAgentPrivateKey: agentA.privateKey, servingAgentPrivateKey: agentB.privateKey,
      })
      const r2 = createBilateralReceipt({
        requestingAgentId: 'a', servingAgentId: 'b',
        outcome: makeOutcome(),
        requestedAt: '2026-04-01T10:00:00Z', completedAt: '2026-04-01T10:00:01Z',
        requestingAgentPrivateKey: agentA.privateKey, servingAgentPrivateKey: agentB.privateKey,
      })
      assert.notEqual(r1.receiptId, r2.receiptId)
    })

    it('includes evidence commitments when provided', () => {
      const commitment = createEvidenceCommitment({
        type: 'wallet_state', credential: '{"pass": true, "balance": 1000}',
        issuerKid: 'insumer-attest-v1', pass: true,
      })
      const receipt = createBilateralReceipt({
        requestingAgentId: 'a', servingAgentId: 'b',
        outcome: makeOutcome(), requestedAt: '2026-04-01T10:00:00Z',
        completedAt: '2026-04-01T10:00:01Z',
        requestingAgentPrivateKey: agentA.privateKey,
        servingAgentPrivateKey: agentB.privateKey,
        evidenceCommitments: [commitment],
      })
      assert.equal(receipt.evidenceCommitments!.length, 1)
      assert.equal(receipt.evidenceCommitments![0].type, 'wallet_state')
    })
  })
})


// ══════════════════════════════════════════════════════════════════
// 2. Evidence Commitments — bind external attestations by hash
// ══════════════════════════════════════════════════════════════════

describe('Evidence Commitments', () => {
  const fakeJwt = 'eyJhbGciOiJFZDI1NTE5In0.eyJzdWIiOiJ3YWxsZXQtMHgxMjMifQ.signature'

  it('creates commitment with SHA-256 hash of credential', () => {
    const commitment = createEvidenceCommitment({
      type: 'wallet_state',
      credential: fakeJwt,
      issuerKid: 'insumer-attest-v1',
      jwks: 'https://api.insumermodel.com/v1/jwks',
      pass: true,
    })
    assert.equal(commitment.type, 'wallet_state')
    assert.ok(commitment.credentialHash.length === 64) // SHA-256 hex
    assert.equal(commitment.issuerKid, 'insumer-attest-v1')
    assert.equal(commitment.pass, true)
    assert.ok(commitment.committedAt)
  })

  it('verifies matching credential against commitment', () => {
    const commitment = createEvidenceCommitment({
      type: 'compliance', credential: fakeJwt,
    })
    assert.equal(verifyEvidenceCommitment(commitment, fakeJwt), true)
  })

  it('rejects mismatched credential', () => {
    const commitment = createEvidenceCommitment({
      type: 'compliance', credential: fakeJwt,
    })
    assert.equal(verifyEvidenceCommitment(commitment, 'TAMPERED-JWT'), false)
  })

  it('produces different hashes for different credentials', () => {
    const c1 = createEvidenceCommitment({ type: 'a', credential: 'cred-1' })
    const c2 = createEvidenceCommitment({ type: 'a', credential: 'cred-2' })
    assert.notEqual(c1.credentialHash, c2.credentialHash)
  })

  it('produces same hash for same credential', () => {
    const c1 = createEvidenceCommitment({ type: 'a', credential: fakeJwt })
    const c2 = createEvidenceCommitment({ type: 'a', credential: fakeJwt })
    assert.equal(c1.credentialHash, c2.credentialHash)
  })
})


// ══════════════════════════════════════════════════════════════════
// 3. Compromise Window — breach time vs detection time
// ══════════════════════════════════════════════════════════════════

describe('Compromise Window', () => {

  describe('non-compromise revocations', () => {
    it('marks pre-revocation proofs as safe for key_rotation', () => {
      const result = checkCompromiseWindow({
        proofTimestamp: '2026-03-01T00:00:00Z',
        revokedAt: '2026-04-01T00:00:00Z',
        revocationReason: 'key_rotation',
      })
      assert.equal(result.status, 'safe')
    })

    it('marks post-revocation proofs as error for key_rotation', () => {
      const result = checkCompromiseWindow({
        proofTimestamp: '2026-04-02T00:00:00Z',
        revokedAt: '2026-04-01T00:00:00Z',
        revocationReason: 'key_rotation',
      })
      assert.equal(result.status, 'error')
    })

    it('marks pre-revocation proofs as safe for decommission', () => {
      const result = checkCompromiseWindow({
        proofTimestamp: '2026-03-15T00:00:00Z',
        revokedAt: '2026-04-01T00:00:00Z',
        revocationReason: 'decommission',
      })
      assert.equal(result.status, 'safe')
    })

    it('treats all non-compromise reasons the same', () => {
      for (const reason of ['key_rotation', 'decommission', 'policy_violation', 'manual'] as const) {
        const result = checkCompromiseWindow({
          proofTimestamp: '2026-03-01T00:00:00Z',
          revokedAt: '2026-04-01T00:00:00Z',
          revocationReason: reason,
        })
        assert.equal(result.status, 'safe', `Expected safe for ${reason}`)
      }
    })
  })

  describe('compromise with known window', () => {
    it('marks proof before breach as safe', () => {
      const result = checkCompromiseWindow({
        proofTimestamp: '2026-02-01T00:00:00Z',
        revokedAt: '2026-04-01T00:00:00Z',
        revocationReason: 'compromise',
        compromisedSince: '2026-03-15T00:00:00Z',
      })
      assert.equal(result.status, 'safe')
    })

    it('marks proof within breach window as error', () => {
      const result = checkCompromiseWindow({
        proofTimestamp: '2026-03-20T00:00:00Z',
        revokedAt: '2026-04-01T00:00:00Z',
        revocationReason: 'compromise',
        compromisedSince: '2026-03-15T00:00:00Z',
      })
      assert.equal(result.status, 'error')
    })

    it('marks proof after revocation as error', () => {
      const result = checkCompromiseWindow({
        proofTimestamp: '2026-04-05T00:00:00Z',
        revokedAt: '2026-04-01T00:00:00Z',
        revocationReason: 'compromise',
        compromisedSince: '2026-03-15T00:00:00Z',
      })
      assert.equal(result.status, 'error')
    })
  })

  describe('compromise with unknown window', () => {
    it('warns on all proofs when compromisedSince is absent', () => {
      const result = checkCompromiseWindow({
        proofTimestamp: '2026-01-01T00:00:00Z',
        revokedAt: '2026-04-01T00:00:00Z',
        revocationReason: 'compromise',
      })
      assert.equal(result.status, 'warn')
      assert.ok(result.reason.includes('unknown'))
    })

    it('warns even for very old proofs when window unknown', () => {
      const result = checkCompromiseWindow({
        proofTimestamp: '2025-01-01T00:00:00Z',
        revokedAt: '2026-04-01T00:00:00Z',
        revocationReason: 'compromise',
      })
      assert.equal(result.status, 'warn')
    })
  })
})
