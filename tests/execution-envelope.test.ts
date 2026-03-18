import { describe, it, expect } from 'vitest'
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
    intentId: 'intent-001',
    agentId: 'agent-001',
    agentPublicKey: agent.publicKey,
    delegationId: 'del-001',
    action: { type: 'commerce:purchase', target: 'widget-store', scopeRequired: 'commerce:purchase' },
    createdAt: new Date().toISOString()
  })
  return {
    intentId: 'intent-001',
    agentId: 'agent-001',
    agentPublicKey: agent.publicKey,
    delegationId: 'del-001',
    action: { type: 'commerce:purchase', target: 'widget-store', scopeRequired: 'commerce:purchase' },
    createdAt: new Date().toISOString(),
    signature: sign(payload, agent.privateKey)
  }
}

function createMockDecision(): PolicyDecision {
  const payload = canonicalize({
    decisionId: 'dec-001',
    intentId: 'intent-001',
    evaluatorId: 'evaluator-001',
    evaluatorPublicKey: evaluator.publicKey,
    verdict: 'permit',
    principlesEvaluated: [{ principleId: 'F-001', principleName: 'Traceability', status: 'pass', detail: 'OK' }],
    reason: 'All checks passed',
    floorVersion: 'floor-v0.2',
    evaluatedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3600000).toISOString()
  })
  return {
    decisionId: 'dec-001',
    intentId: 'intent-001',
    evaluatorId: 'evaluator-001',
    evaluatorPublicKey: evaluator.publicKey,
    verdict: 'permit',
    principlesEvaluated: [{ principleId: 'F-001', principleName: 'Traceability', status: 'pass', detail: 'OK' }],
    reason: 'All checks passed',
    floorVersion: 'floor-v0.2',
    evaluatedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3600000).toISOString(),
    signature: sign(payload, evaluator.privateKey)
  }
}

