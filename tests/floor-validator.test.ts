// Values Floor Validator — Three-Signature Chain Tests
// Layer 5: ActionIntent → PolicyDecision → ActionReceipt

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createDelegation, createReceipt, clearStores,
  loadFloor,
  createActionIntent, verifyActionIntent,
  v1Evaluator, evaluateIntent,
  verifyPolicyDecision, assembleValidatedReceipt
} from '../src/index.js'
import type { EvaluationContext, ActionIntent, ValuesFloor } from '../src/index.js'

const human = generateKeyPair()
const agent = generateKeyPair()
const evaluator = generateKeyPair()

const FLOOR_JSON: ValuesFloor = {
  version: '0.1',
  schema: 'agent-social-contract/values-floor',
  lastUpdated: '2026-02-25',
  governanceUri: 'https://aeoess.com/protocol.html',
  floor: [
    { id: 'F-001', name: 'Traceability', principle: 'Every action traceable', enforcement: { technical: true, mechanism: 'Delegation chains' }, weight: 'mandatory' },
    { id: 'F-002', name: 'Honest Identity', principle: 'No misrepresentation', enforcement: { technical: true, mechanism: 'Passport verification' }, weight: 'mandatory' },
    { id: 'F-003', name: 'Scoped Authority', principle: 'Within scope', enforcement: { technical: true, mechanism: 'Scope enforcement' }, weight: 'mandatory' },
    { id: 'F-004', name: 'Revocability', principle: 'Can be revoked', enforcement: { technical: true, mechanism: 'Revocation cascade' }, weight: 'mandatory' },
    { id: 'F-005', name: 'Auditability', principle: 'Auditable actions', enforcement: { technical: true, mechanism: 'Signed receipts' }, weight: 'mandatory' },
    { id: 'F-006', name: 'Non-Deception', principle: 'No manipulation', enforcement: { technical: false, mechanism: 'Reputation' }, weight: 'strong_consideration' },
    { id: 'F-007', name: 'Proportionality', principle: 'Proportional autonomy', enforcement: { technical: false, mechanism: 'Reputation' }, weight: 'strong_consideration' }
  ]
}

let delegation: ReturnType<typeof createDelegation>

beforeEach(() => {
  clearStores()
  delegation = createDelegation({
    delegatedTo: agent.publicKey,
    delegatedBy: human.publicKey,
    scope: ['read', 'write', 'api_call'],
    spendLimit: 100,
    maxDepth: 2,
    expiresInHours: 24,
    privateKey: human.privateKey
  })
})

function makeContext(overrides?: Partial<EvaluationContext>): EvaluationContext {
  return {
    floor: FLOOR_JSON,
    delegation: {
      scope: ['read', 'write', 'api_call'],
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      revoked: false,
      spendLimit: 100,
      spentAmount: 0,
      maxDepth: 2,
      currentDepth: 0
    },
    agentRegistered: true,
    agentActive: true,
    evaluatorKeyPair: evaluator,
    ...overrides
  }
}

// ══════════════════════════════════════
// INTENT CREATION & VERIFICATION
// ══════════════════════════════════════

describe('ActionIntent', () => {
  it('creates a signed intent', () => {
    const intent = createActionIntent({
      agentId: 'agent-test',
      publicKey: agent.publicKey,
      privateKey: agent.privateKey,
      delegationId: delegation.delegationId,
      action: { type: 'api_call', target: 'https://api.example.com', scopeRequired: 'api_call', description: 'Fetch user data' },
      floorVersion: '0.1'
    })
    assert.ok(intent.intentId.startsWith('int_'))
    assert.equal(intent.version, '1.0')
    assert.equal(intent.agentId, 'agent-test')
    assert.ok(intent.signature.length > 0)
  })

  it('verifies a valid intent', () => {
    const intent = createActionIntent({
      agentId: 'agent-test',
      publicKey: agent.publicKey,
      privateKey: agent.privateKey,
      delegationId: delegation.delegationId,
      action: { type: 'api_call', target: 'example.com', scopeRequired: 'api_call', description: 'Test' },
      floorVersion: '0.1'
    })
    assert.ok(verifyActionIntent(intent))
  })

  it('rejects a tampered intent', () => {
    const intent = createActionIntent({
      agentId: 'agent-test',
      publicKey: agent.publicKey,
      privateKey: agent.privateKey,
      delegationId: delegation.delegationId,
      action: { type: 'api_call', target: 'example.com', scopeRequired: 'api_call', description: 'Test' },
      floorVersion: '0.1'
    })
    intent.action.scopeRequired = 'admin'  // tamper
    assert.ok(!verifyActionIntent(intent))
  })
})

// ══════════════════════════════════════
// v1 EVALUATOR
// ══════════════════════════════════════

describe('v1Evaluator', () => {
  it('permits a valid intent', async () => {
    const intent = createActionIntent({
      agentId: 'agent-test',
      publicKey: agent.publicKey,
      privateKey: agent.privateKey,
      delegationId: delegation.delegationId,
      action: { type: 'api_call', target: 'example.com', scopeRequired: 'api_call', description: 'Fetch data' },
      floorVersion: '0.1'
    })
    const decision = await evaluateIntent(intent, v1Evaluator, makeContext())
    assert.equal(decision.verdict, 'permit')
    assert.ok(decision.principlesEvaluated.length >= 5)
    assert.ok(verifyPolicyDecision(decision))
  })

  it('denies unregistered agent', async () => {
    const intent = createActionIntent({
      agentId: 'agent-rogue',
      publicKey: agent.publicKey,
      privateKey: agent.privateKey,
      delegationId: delegation.delegationId,
      action: { type: 'api_call', target: 'example.com', scopeRequired: 'api_call', description: 'Test' },
      floorVersion: '0.1'
    })
    const decision = await evaluateIntent(intent, v1Evaluator, makeContext({ agentRegistered: false }))
    assert.equal(decision.verdict, 'deny')
    assert.ok(decision.reason.includes('Unregistered'))
  })

  it('denies out-of-scope action', async () => {
    const intent = createActionIntent({
      agentId: 'agent-test',
      publicKey: agent.publicKey,
      privateKey: agent.privateKey,
      delegationId: delegation.delegationId,
      action: { type: 'admin', target: 'system', scopeRequired: 'admin', description: 'Delete everything' },
      floorVersion: '0.1'
    })
    const decision = await evaluateIntent(intent, v1Evaluator, makeContext())
    assert.equal(decision.verdict, 'deny')
    assert.ok(decision.reason.includes('Scope escalation'))
  })

  it('denies revoked delegation', async () => {
    const intent = createActionIntent({
      agentId: 'agent-test',
      publicKey: agent.publicKey,
      privateKey: agent.privateKey,
      delegationId: delegation.delegationId,
      action: { type: 'read', target: 'file', scopeRequired: 'read', description: 'Read file' },
      floorVersion: '0.1'
    })
    const ctx = makeContext()
    ctx.delegation!.revoked = true
    const decision = await evaluateIntent(intent, v1Evaluator, ctx)
    assert.equal(decision.verdict, 'deny')
    assert.ok(decision.reason.includes('Revoked'))
  })

  it('denies expired delegation', async () => {
    const intent = createActionIntent({
      agentId: 'agent-test',
      publicKey: agent.publicKey,
      privateKey: agent.privateKey,
      delegationId: delegation.delegationId,
      action: { type: 'read', target: 'file', scopeRequired: 'read', description: 'Read' },
      floorVersion: '0.1'
    })
    const ctx = makeContext()
    ctx.delegation!.expiresAt = '2020-01-01T00:00:00Z'
    const decision = await evaluateIntent(intent, v1Evaluator, ctx)
    assert.equal(decision.verdict, 'deny')
    assert.ok(decision.reason.includes('Expired'))
  })

  it('narrows when spend exceeds remaining', async () => {
    const intent = createActionIntent({
      agentId: 'agent-test',
      publicKey: agent.publicKey,
      privateKey: agent.privateKey,
      delegationId: delegation.delegationId,
      action: { type: 'api_call', target: 'api', scopeRequired: 'api_call', description: 'Buy', estimatedSpend: { amount: 80, currency: 'USD' } },
      floorVersion: '0.1'
    })
    const ctx = makeContext()
    ctx.delegation!.spentAmount = 50  // 50 spent of 100 limit, requesting 80
    const decision = await evaluateIntent(intent, v1Evaluator, ctx)
    assert.equal(decision.verdict, 'narrow')
    assert.ok(decision.constraints!.length > 0)
  })

  it('denies tampered intent', async () => {
    const intent = createActionIntent({
      agentId: 'agent-test',
      publicKey: agent.publicKey,
      privateKey: agent.privateKey,
      delegationId: delegation.delegationId,
      action: { type: 'read', target: 'file', scopeRequired: 'read', description: 'Read' },
      floorVersion: '0.1'
    })
    intent.agentId = 'agent-impersonator'  // tamper
    const decision = await evaluateIntent(intent, v1Evaluator, makeContext())
    assert.equal(decision.verdict, 'deny')
    assert.ok(decision.reason.includes('signature invalid'))
  })
})

// ══════════════════════════════════════
// VALIDATED RECEIPT — Full Chain
// ══════════════════════════════════════

describe('ValidatedReceipt — Three-Signature Chain', () => {
  it('assembles a valid chain: intent → decision → receipt', async () => {
    const intent = createActionIntent({
      agentId: 'agent-test',
      publicKey: agent.publicKey,
      privateKey: agent.privateKey,
      delegationId: delegation.delegationId,
      action: { type: 'write', target: 'database', scopeRequired: 'write', description: 'Update record' },
      floorVersion: '0.1'
    })

    const decision = await evaluateIntent(intent, v1Evaluator, makeContext())
    assert.equal(decision.verdict, 'permit')

    const receipt = createReceipt({
      agentId: 'agent-test',
      delegationId: delegation.delegationId,
      action: { type: 'write', target: 'database', scopeUsed: 'write' },
      result: { status: 'success', summary: 'Record updated' },
      delegationChain: [human.publicKey, agent.publicKey],
      privateKey: agent.privateKey
    })

    const chain = assembleValidatedReceipt(intent, decision, receipt)
    assert.ok(chain.chainValid, 'Chain should be valid')
    assert.ok(chain.chainId.startsWith('chain_'))
    assert.equal(chain.intent.intentId, intent.intentId)
    assert.equal(chain.decision.intentId, intent.intentId)
  })

  it('rejects chain with mismatched delegation', async () => {
    const intent = createActionIntent({
      agentId: 'agent-test',
      publicKey: agent.publicKey,
      privateKey: agent.privateKey,
      delegationId: delegation.delegationId,
      action: { type: 'read', target: 'file', scopeRequired: 'read', description: 'Read' },
      floorVersion: '0.1'
    })
    const decision = await evaluateIntent(intent, v1Evaluator, makeContext())

    // Create receipt with DIFFERENT delegation
    const otherDelegation = createDelegation({
      delegatedTo: agent.publicKey,
      delegatedBy: human.publicKey,
      scope: ['read'],
      privateKey: human.privateKey
    })
    const receipt = createReceipt({
      agentId: 'agent-test',
      delegationId: otherDelegation.delegationId,
      action: { type: 'read', target: 'file', scopeUsed: 'read' },
      result: { status: 'success', summary: 'Done' },
      delegationChain: [human.publicKey, agent.publicKey],
      privateKey: agent.privateKey
    })

    const chain = assembleValidatedReceipt(intent, decision, receipt)
    assert.ok(!chain.chainValid, 'Chain should be invalid — delegation mismatch')
  })

  it('rejects chain when decision was deny', async () => {
    const intent = createActionIntent({
      agentId: 'agent-test',
      publicKey: agent.publicKey,
      privateKey: agent.privateKey,
      delegationId: delegation.delegationId,
      action: { type: 'admin', target: 'system', scopeRequired: 'admin', description: 'Escalate' },
      floorVersion: '0.1'
    })
    const decision = await evaluateIntent(intent, v1Evaluator, makeContext())
    assert.equal(decision.verdict, 'deny')

    const receipt = createReceipt({
      agentId: 'agent-test',
      delegationId: delegation.delegationId,
      action: { type: 'admin', target: 'system', scopeUsed: 'admin' },
      result: { status: 'success', summary: 'Escalated anyway' },
      delegationChain: [human.publicKey, agent.publicKey],
      privateKey: agent.privateKey
    })

    const chain = assembleValidatedReceipt(intent, decision, receipt)
    assert.ok(!chain.chainValid, 'Chain should be invalid — deny verdict but action executed')
  })
})
