// ══════════════════════════════════════════════════════════════════
// Execution Envelope — Tests
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import {
  createExecutionEnvelope,
  verifyExecutionEnvelope,
  createMinimalEnvelope
} from '../src/index.js'
import type { ActionIntent, PolicyDecision, PolicyReceipt } from '../src/types/policy.js'
import type { Delegation } from '../src/types/passport.js'

const agent = generateKeyPair()
const evaluator = generateKeyPair()
const gateway = generateKeyPair()

// ── Mock APS objects ──

function createMockIntent(): ActionIntent {
  const payload = canonicalize({
    intentId: 'intent-001', agentId: 'agent-001', agentPublicKey: agent.publicKey,
    delegationId: 'del-001',
    action: { type: 'commerce:purchase', target: 'widget-store', scopeRequired: 'commerce:purchase' },
    createdAt: new Date().toISOString()
  })
  return {
    intentId: 'intent-001', agentId: 'agent-001', agentPublicKey: agent.publicKey,
    delegationId: 'del-001',
    action: { type: 'commerce:purchase', target: 'widget-store', scopeRequired: 'commerce:purchase' },
    createdAt: new Date().toISOString(),
    signature: sign(payload, agent.privateKey)
  }
}

function createMockDecision(): PolicyDecision {
  const payload = canonicalize({
    decisionId: 'dec-001', intentId: 'intent-001',
    evaluatorId: 'evaluator-001', evaluatorPublicKey: evaluator.publicKey,
    verdict: 'permit',
    principlesEvaluated: [{ principleId: 'F-001', principleName: 'Traceability', status: 'pass', detail: 'OK' }],
    reason: 'All checks passed', floorVersion: 'floor-v0.2',
    evaluatedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3600000).toISOString()
  })
  return {
    decisionId: 'dec-001', intentId: 'intent-001',
    evaluatorId: 'evaluator-001', evaluatorPublicKey: evaluator.publicKey,
    verdict: 'permit',
    principlesEvaluated: [{ principleId: 'F-001', principleName: 'Traceability', status: 'pass', detail: 'OK' }],
    reason: 'All checks passed', floorVersion: 'floor-v0.2',
    evaluatedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3600000).toISOString(),
    signature: sign(payload, evaluator.privateKey)
  }
}

function createMockReceipt(): PolicyReceipt {
  const intent = createMockIntent()
  const decision = createMockDecision()
  const payload = canonicalize({
    receiptId: 'receipt-001', intentId: intent.intentId, decisionId: decision.decisionId,
    verifierId: 'gateway-001', verifierPublicKey: gateway.publicKey,
    chain: { intentSignature: intent.signature, decisionSignature: decision.signature },
    createdAt: new Date().toISOString()
  })
  return {
    receiptId: 'receipt-001', intentId: intent.intentId, decisionId: decision.decisionId,
    verifierId: 'gateway-001', verifierPublicKey: gateway.publicKey,
    chain: { intentSignature: intent.signature, decisionSignature: decision.signature },
    createdAt: new Date().toISOString(),
    signature: sign(payload, gateway.privateKey)
  }
}

function createMockDelegation(): Delegation {
  return {
    delegationId: 'del-001', delegatedTo: agent.publicKey, delegatedBy: gateway.publicKey,
    scope: ['commerce:purchase', 'data:read'], expiresAt: new Date(Date.now() + 86400000).toISOString(),
    spendLimit: 500, maxDepth: 3, currentDepth: 1, createdAt: new Date().toISOString(),
    signature: sign(canonicalize({ delegationId: 'del-001' }), gateway.privateKey)
  }
}

// ── Tests ──

describe('Execution Envelope', () => {
  it('creates a valid envelope with correct schema', () => {
    const envelope = createExecutionEnvelope({
      intent: createMockIntent(),
      decision: createMockDecision(),
      receipt: createMockReceipt(),
      delegation: createMockDelegation(),
      runId: 'run-001',
      agentDid: `did:aps:${agent.publicKey}`,
      evaluatorDid: `did:aps:${evaluator.publicKey}`,
      revocationStatus: 'active',
      chainDepth: 1,
      evaluationMethod: 'deterministic',
      signerPrivateKey: gateway.privateKey,
      signerPublicKey: gateway.publicKey
    })
    assert.equal(envelope.schema, 'execution-envelope.v0.1')
    assert.equal(envelope.agent_did, `did:aps:${agent.publicKey}`)
    assert.equal(envelope.run_id, 'run-001')
    assert.ok(envelope.signature.value, 'Should be signed')
    assert.equal(envelope.signature.algorithm, 'Ed25519')
    assert.equal(envelope.signature.public_key, gateway.publicKey)
    assert.ok(envelope.capability_ref.scope.includes('commerce:purchase'))
    assert.equal(envelope.capability_ref.revocation_status, 'active')
    assert.equal(envelope.capability_ref.delegation_chain_depth, 1)
    assert.equal(envelope.decision.verdict, 'permit')
    assert.equal(envelope.decision.evaluation_method, 'deterministic')
  })

  it('verifies a valid envelope', () => {
    const envelope = createExecutionEnvelope({
      intent: createMockIntent(),
      decision: createMockDecision(),
      receipt: createMockReceipt(),
      delegation: createMockDelegation(),
      runId: 'run-002',
      agentDid: `did:aps:${agent.publicKey}`,
      evaluatorDid: `did:aps:${evaluator.publicKey}`,
      revocationStatus: 'active',
      chainDepth: 1,
      evaluationMethod: 'deterministic',
      signerPrivateKey: gateway.privateKey,
      signerPublicKey: gateway.publicKey
    })
    const result = verifyExecutionEnvelope(envelope)
    assert.equal(result.valid, true)
    assert.equal(result.signatureValid, true)
    assert.equal(result.capabilityActive, true)
  })

  it('rejects tampered envelope', () => {
    const envelope = createExecutionEnvelope({
      intent: createMockIntent(),
      decision: createMockDecision(),
      receipt: createMockReceipt(),
      delegation: createMockDelegation(),
      runId: 'run-003',
      agentDid: `did:aps:${agent.publicKey}`,
      evaluatorDid: `did:aps:${evaluator.publicKey}`,
      revocationStatus: 'active',
      chainDepth: 1,
      evaluationMethod: 'deterministic',
      signerPrivateKey: gateway.privateKey,
      signerPublicKey: gateway.publicKey
    })
    // Tamper with the run_id
    const tampered = { ...envelope, run_id: 'TAMPERED' }
    const result = verifyExecutionEnvelope(tampered)
    assert.equal(result.signatureValid, false)
  })

  it('detects revoked capability status', () => {
    const envelope = createExecutionEnvelope({
      intent: createMockIntent(),
      decision: createMockDecision(),
      receipt: createMockReceipt(),
      delegation: createMockDelegation(),
      runId: 'run-004',
      agentDid: `did:aps:${agent.publicKey}`,
      evaluatorDid: `did:aps:${evaluator.publicKey}`,
      revocationStatus: 'revoked',
      chainDepth: 1,
      evaluationMethod: 'deterministic',
      signerPrivateKey: gateway.privateKey,
      signerPublicKey: gateway.publicKey
    })
    const result = verifyExecutionEnvelope(envelope)
    assert.equal(result.capabilityActive, false)
  })

  it('creates minimal envelope without full APS objects', () => {
    const decision = createMockDecision()
    const receipt = createMockReceipt()
    const envelope = createMinimalEnvelope({
      agentDid: `did:aps:${agent.publicKey}`,
      runId: 'run-005',
      actionId: 'action-005',
      scope: ['data:read'],
      revocationStatus: 'active',
      decisionHash: 'abc123',
      policyRef: 'floor-v0.2',
      evaluationMethod: 'deterministic',
      verdict: 'permit',
      evaluatedAt: new Date().toISOString(),
      evaluatorDid: `did:aps:${evaluator.publicKey}`,
      evaluatorSignature: decision.signature,
      receiptHash: 'def456',
      signerPrivateKey: gateway.privateKey,
      signerPublicKey: gateway.publicKey
    })
    assert.equal(envelope.schema, 'execution-envelope.v0.1')
    assert.equal(envelope.run_id, 'run-005')
    assert.ok(envelope.signature.value)
    assert.equal(envelope.decision.verdict, 'permit')
    const result = verifyExecutionEnvelope(envelope)
    assert.equal(result.signatureValid, true)
  })
})
