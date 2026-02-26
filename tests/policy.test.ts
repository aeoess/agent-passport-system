// Values Floor Policy Engine — Three-Signature Chain Tests
// ActionIntent → PolicyDecision → ActionReceipt
// Tests cover the full chain, v1 validator, and adversarial scenarios

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, clearStores,
  createDelegation, createReceipt,
  loadFloor,
  createActionIntent, verifyActionIntent,
  evaluateIntent, verifyPolicyDecision,
  createPolicyReceipt, verifyPolicyReceipt,
  FloorValidatorV1, requestAction,
} from '../src/index.js'
import type { ValidationContext } from '../src/index.js'

const human = generateKeyPair()
const agent = generateKeyPair()
const evaluator = generateKeyPair()
const verifier = generateKeyPair()
const validator = new FloorValidatorV1()

const FLOOR_YAML = `
version: "0.1"
schema: "agent-social-contract/values-floor"
last_updated: "2026-02-20"
governance_uri: "https://aeoess.com/protocol.html"
floor:
  - id: "F-001"
    name: "Traceability"
    principle: "Every action traceable"
    enforcement:
      technical: true
      mechanism: "Delegation chains"
    weight: "mandatory"
  - id: "F-002"
    name: "Honest Identity"
    principle: "No identity misrepresentation"
    enforcement:
      technical: true
      mechanism: "Passport verification"
    weight: "mandatory"
  - id: "F-003"
    name: "Scoped Authority"
    principle: "Act within delegated scope"
    enforcement:
      technical: true
      mechanism: "Delegation scope limits"
    weight: "mandatory"
  - id: "F-004"
    name: "Revocability"
    principle: "Humans can revoke authority"
    enforcement:
      technical: true
      mechanism: "Revocation registry"
    weight: "mandatory"
  - id: "F-005"
    name: "Auditability"
    principle: "All actions auditable"
    enforcement:
      technical: true
      mechanism: "Action receipts"
    weight: "mandatory"
  - id: "F-006"
    name: "Non-Deception"
    principle: "No deception"
    enforcement:
      technical: false
      mechanism: "Reputation"
    weight: "strong_consideration"
  - id: "F-007"
    name: "Proportionality"
    principle: "Autonomy proportional to trust"
    enforcement:
      technical: false
      mechanism: "Reputation"
    weight: "strong_consideration"
`

function makeContext(overrides?: Partial<ValidationContext>): ValidationContext {
  const floor = loadFloor(FLOOR_YAML)
  return {
    floorVersion: '0.1',
    floorPrinciples: floor.floor.map(p => ({
      id: p.id, name: p.name,
      enforcement: p.enforcement,
      weight: p.weight
    })),
    delegation: {
      scope: ['code_execution', 'web_search'],
      spendLimit: 500,
      spentAmount: 0,
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      revoked: false,
      currentDepth: 0,
      maxDepth: 2
    },
    agentRegistered: true,
    agentAttestationValid: true,
    ...overrides
  }
}

// ══════════════════════════════════════
// SIGNATURE 1: Action Intent
// ══════════════════════════════════════

describe('ActionIntent — Signature 1', () => {
  it('creates and verifies a valid intent', () => {
    const intent = createActionIntent({
      agentId: 'agent-a',
      agentPublicKey: agent.publicKey,
      delegationId: 'del_test',
      action: { type: 'execute', target: 'task', scopeRequired: 'code_execution' },
      context: 'Running unit tests',
      privateKey: agent.privateKey
    })
    assert.ok(intent.intentId.startsWith('intent_'))
    assert.equal(intent.agentId, 'agent-a')
    assert.ok(intent.signature.length > 0)

    const v = verifyActionIntent(intent)
    assert.ok(v.valid, `Expected valid but got errors: ${v.errors}`)
  })

  it('[ADVERSARIAL] rejects tampered intent', () => {
    const intent = createActionIntent({
      agentId: 'agent-a',
      agentPublicKey: agent.publicKey,
      delegationId: 'del_test',
      action: { type: 'execute', target: 'task', scopeRequired: 'code_execution' },
      privateKey: agent.privateKey
    })
    intent.action.scopeRequired = 'admin_access'  // tamper
    const v = verifyActionIntent(intent)
    assert.ok(!v.valid)
    assert.ok(v.errors.some(e => e.includes('Invalid intent signature')))
  })

  it('[ADVERSARIAL] rejects intent signed with wrong key', () => {
    const other = generateKeyPair()
    const intent = createActionIntent({
      agentId: 'agent-a',
      agentPublicKey: agent.publicKey,  // claims to be agent
      delegationId: 'del_test',
      action: { type: 'execute', target: 'task', scopeRequired: 'code_execution' },
      privateKey: other.privateKey       // but signed by someone else
    })
    const v = verifyActionIntent(intent)
    assert.ok(!v.valid)
  })
})

// ══════════════════════════════════════
// SIGNATURE 2: Policy Decision (V1 Validator)
// ══════════════════════════════════════

describe('PolicyDecision — Signature 2 (V1 Validator)', () => {
  it('permits valid intent within scope', () => {
    const intent = createActionIntent({
      agentId: 'agent-a',
      agentPublicKey: agent.publicKey,
      delegationId: 'del_test',
      action: { type: 'execute', target: 'task', scopeRequired: 'code_execution' },
      privateKey: agent.privateKey
    })
    const ctx = makeContext()
    const decision = evaluateIntent({
      intent, validator, validationContext: ctx,
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey
    })
    assert.equal(decision.verdict, 'permit')
    assert.ok(decision.decisionId.startsWith('pdec_'))
    assert.equal(decision.floorVersion, '0.1')

    // All mandatory principles should pass
    const mandatory = decision.principlesEvaluated.filter(
      e => e.principleId.match(/F-00[1-5]/)
    )
    assert.ok(mandatory.every(e => e.status === 'pass'))

    // Verify the signature
    const v = verifyPolicyDecision(decision)
    assert.ok(v.valid, `Expected valid but got errors: ${v.errors}`)
  })

  it('[ADVERSARIAL] denies intent outside scope', () => {
    const intent = createActionIntent({
      agentId: 'agent-a',
      agentPublicKey: agent.publicKey,
      delegationId: 'del_test',
      action: { type: 'admin', target: 'system', scopeRequired: 'admin_access' },
      privateKey: agent.privateKey
    })
    const ctx = makeContext()  // scope is [code_execution, web_search]
    const decision = evaluateIntent({
      intent, validator, validationContext: ctx,
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey
    })
    assert.equal(decision.verdict, 'deny')
    assert.ok(decision.reason.includes('Scoped Authority'))
    const f003 = decision.principlesEvaluated.find(e => e.principleId === 'F-003')
    assert.equal(f003!.status, 'fail')
  })

  it('[ADVERSARIAL] denies intent from unregistered agent', () => {
    const intent = createActionIntent({
      agentId: 'rogue-agent',
      agentPublicKey: agent.publicKey,
      delegationId: 'del_test',
      action: { type: 'execute', target: 'task', scopeRequired: 'code_execution' },
      privateKey: agent.privateKey
    })
    const ctx = makeContext({ agentRegistered: false })
    const decision = evaluateIntent({
      intent, validator, validationContext: ctx,
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey
    })
    assert.equal(decision.verdict, 'deny')
    assert.ok(decision.reason.includes('Traceability'))
  })

  it('[ADVERSARIAL] denies intent on revoked delegation', () => {
    const intent = createActionIntent({
      agentId: 'agent-a',
      agentPublicKey: agent.publicKey,
      delegationId: 'del_revoked',
      action: { type: 'execute', target: 'task', scopeRequired: 'code_execution' },
      privateKey: agent.privateKey
    })
    const ctx = makeContext({
      delegation: {
        scope: ['code_execution'], spendLimit: 500, spentAmount: 0,
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
        revoked: true, currentDepth: 0, maxDepth: 2
      }
    })
    const decision = evaluateIntent({
      intent, validator, validationContext: ctx,
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey
    })
    assert.equal(decision.verdict, 'deny')
    assert.ok(decision.reason.includes('Revocability'))
  })

  it('[ADVERSARIAL] denies intent with expired delegation', () => {
    const intent = createActionIntent({
      agentId: 'agent-a',
      agentPublicKey: agent.publicKey,
      delegationId: 'del_expired',
      action: { type: 'execute', target: 'task', scopeRequired: 'code_execution' },
      privateKey: agent.privateKey
    })
    const ctx = makeContext({
      delegation: {
        scope: ['code_execution'], spendLimit: 500, spentAmount: 0,
        expiresAt: new Date(Date.now() - 86400000).toISOString(),  // yesterday
        revoked: false, currentDepth: 0, maxDepth: 2
      }
    })
    const decision = evaluateIntent({
      intent, validator, validationContext: ctx,
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey
    })
    assert.equal(decision.verdict, 'deny')
    assert.ok(decision.reason.includes('Auditability'))
  })

  it('[ADVERSARIAL] denies intent with invalid attestation', () => {
    const intent = createActionIntent({
      agentId: 'agent-a',
      agentPublicKey: agent.publicKey,
      delegationId: 'del_test',
      action: { type: 'execute', target: 'task', scopeRequired: 'code_execution' },
      privateKey: agent.privateKey
    })
    const ctx = makeContext({ agentAttestationValid: false })
    const decision = evaluateIntent({
      intent, validator, validationContext: ctx,
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey
    })
    assert.equal(decision.verdict, 'deny')
    assert.ok(decision.reason.includes('Honest Identity'))
  })

  it('narrows intent when spend exceeds remaining budget', () => {
    const intent = createActionIntent({
      agentId: 'agent-a',
      agentPublicKey: agent.publicKey,
      delegationId: 'del_test',
      action: {
        type: 'execute', target: 'task', scopeRequired: 'code_execution',
        spend: { amount: 300, currency: 'USD' }
      },
      privateKey: agent.privateKey
    })
    const ctx = makeContext({
      delegation: {
        scope: ['code_execution'], spendLimit: 500, spentAmount: 400,
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
        revoked: false, currentDepth: 0, maxDepth: 2
      }
    })
    const decision = evaluateIntent({
      intent, validator, validationContext: ctx,
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey
    })
    assert.equal(decision.verdict, 'narrow')
    assert.ok(decision.constraints!.some(c => c.startsWith('max_spend:')))
  })

  it('[ADVERSARIAL] rejects tampered decision', () => {
    const intent = createActionIntent({
      agentId: 'agent-a',
      agentPublicKey: agent.publicKey,
      delegationId: 'del_test',
      action: { type: 'execute', target: 'task', scopeRequired: 'code_execution' },
      privateKey: agent.privateKey
    })
    const decision = evaluateIntent({
      intent, validator, validationContext: makeContext(),
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey
    })
    decision.verdict = 'permit'  // tamper (might already be permit, but change reason)
    decision.reason = 'HACKED — skip all checks'
    const v = verifyPolicyDecision(decision)
    assert.ok(!v.valid)
  })
})

// ══════════════════════════════════════
// FULL THREE-SIGNATURE CHAIN
// ══════════════════════════════════════

describe('Three-Signature Chain — Intent → Decision → Receipt', () => {
  beforeEach(() => clearStores())

  it('complete chain: intent → permit → execute → policy receipt', () => {
    // Step 1: Agent creates intent
    const intent = createActionIntent({
      agentId: 'agent-a',
      agentPublicKey: agent.publicKey,
      delegationId: 'del_chain_test',
      action: { type: 'execute', target: 'build', scopeRequired: 'code_execution' },
      context: 'Building the three-signature chain',
      privateKey: agent.privateKey
    })

    // Step 2: Evaluator checks against floor
    const decision = evaluateIntent({
      intent, validator, validationContext: makeContext(),
      evaluatorId: 'floor-evaluator',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey
    })
    assert.equal(decision.verdict, 'permit')

    // Step 3: Agent executes (creates receipt via existing system)
    const delegation = createDelegation({
      delegatedTo: agent.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution', 'web_search'],
      privateKey: human.privateKey
    })
    const receipt = createReceipt({
      agentId: 'agent-a',
      delegationId: delegation.delegationId,
      delegation,
      action: { type: 'execute', target: 'build', scopeUsed: 'code_execution' },
      result: { status: 'success', summary: 'Three-signature chain built' },
      delegationChain: [human.publicKey, agent.publicKey],
      privateKey: agent.privateKey
    })

    // Step 4: Create policy receipt linking all three
    const policyReceipt = createPolicyReceipt({
      intent, decision, receipt,
      verifierPrivateKey: verifier.privateKey
    })
    assert.ok(policyReceipt.policyReceiptId.startsWith('prec_'))
    assert.equal(policyReceipt.intentId, intent.intentId)
    assert.equal(policyReceipt.decisionId, decision.decisionId)
    assert.equal(policyReceipt.receiptId, receipt.receiptId)

    // All three signatures are present
    assert.equal(policyReceipt.chain.intentSignature, intent.signature)
    assert.equal(policyReceipt.chain.decisionSignature, decision.signature)
    assert.equal(policyReceipt.chain.receiptSignature, receipt.signature)

    // Verify the policy receipt itself
    const v = verifyPolicyReceipt(policyReceipt, verifier.publicKey)
    assert.ok(v.valid, `Expected valid but got errors: ${v.errors}`)
  })

  it('[ADVERSARIAL] cannot create policy receipt for denied intent', () => {
    const intent = createActionIntent({
      agentId: 'agent-a',
      agentPublicKey: agent.publicKey,
      delegationId: 'del_test',
      action: { type: 'admin', target: 'system', scopeRequired: 'admin_access' },
      privateKey: agent.privateKey
    })
    const decision = evaluateIntent({
      intent, validator, validationContext: makeContext(),
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey
    })
    assert.equal(decision.verdict, 'deny')

    // Try to create a receipt anyway
    const delegation = createDelegation({
      delegatedTo: agent.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      privateKey: human.privateKey
    })
    const receipt = createReceipt({
      agentId: 'agent-a',
      delegationId: delegation.delegationId,
      delegation,
      action: { type: 'execute', target: 'task', scopeUsed: 'code_execution' },
      result: { status: 'success', summary: 'done' },
      delegationChain: [human.publicKey, agent.publicKey],
      privateKey: agent.privateKey
    })

    assert.throws(() => {
      createPolicyReceipt({
        intent, decision, receipt,
        verifierPrivateKey: verifier.privateKey
      })
    }, /denied intent/)
  })

  it('[ADVERSARIAL] rejects policy receipt with wrong verifier key', () => {
    const intent = createActionIntent({
      agentId: 'agent-a',
      agentPublicKey: agent.publicKey,
      delegationId: 'del_test',
      action: { type: 'execute', target: 'task', scopeRequired: 'code_execution' },
      privateKey: agent.privateKey
    })
    const decision = evaluateIntent({
      intent, validator, validationContext: makeContext(),
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey
    })
    const delegation = createDelegation({
      delegatedTo: agent.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      privateKey: human.privateKey
    })
    const receipt = createReceipt({
      agentId: 'agent-a',
      delegationId: delegation.delegationId,
      delegation,
      action: { type: 'execute', target: 'task', scopeUsed: 'code_execution' },
      result: { status: 'success', summary: 'done' },
      delegationChain: [human.publicKey, agent.publicKey],
      privateKey: agent.privateKey
    })
    const policyReceipt = createPolicyReceipt({
      intent, decision, receipt,
      verifierPrivateKey: verifier.privateKey
    })

    // Verify with wrong key
    const other = generateKeyPair()
    const v = verifyPolicyReceipt(policyReceipt, other.publicKey)
    assert.ok(!v.valid)
  })
})

// ══════════════════════════════════════
// CONVENIENCE: requestAction
// ══════════════════════════════════════

describe('requestAction — Convenience', () => {
  it('creates intent + decision in one call', () => {
    const { intent, decision } = requestAction({
      agentId: 'agent-a',
      agentPublicKey: agent.publicKey,
      agentPrivateKey: agent.privateKey,
      delegationId: 'del_test',
      action: { type: 'search', target: 'web', scopeRequired: 'web_search' },
      context: 'Looking up documentation',
      validator,
      validationContext: makeContext(),
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey
    })
    assert.ok(intent.intentId)
    assert.equal(decision.intentId, intent.intentId)
    assert.equal(decision.verdict, 'permit')
  })
})

// ══════════════════════════════════════
// V1 VALIDATOR METADATA
// ══════════════════════════════════════

describe('FloorValidatorV1 — Metadata', () => {
  it('has correct version and name', () => {
    assert.equal(validator.version, '1.0')
    assert.equal(validator.name, 'floor-validator-v1')
  })

  it('evaluates all 7 floor principles', () => {
    const intent = createActionIntent({
      agentId: 'agent-a',
      agentPublicKey: agent.publicKey,
      delegationId: 'del_test',
      action: { type: 'execute', target: 'task', scopeRequired: 'code_execution' },
      privateKey: agent.privateKey
    })
    const decision = evaluateIntent({
      intent, validator, validationContext: makeContext(),
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey
    })
    assert.equal(decision.principlesEvaluated.length, 7)
    // F-006 and F-007 should be not_applicable in v1
    const f006 = decision.principlesEvaluated.find(e => e.principleId === 'F-006')
    assert.equal(f006!.status, 'not_applicable')
    const f007 = decision.principlesEvaluated.find(e => e.principleId === 'F-007')
    assert.equal(f007!.status, 'not_applicable')
  })

  it('[ADVERSARIAL] denies when spend budget fully exhausted', () => {
    const intent = createActionIntent({
      agentId: 'agent-a',
      agentPublicKey: agent.publicKey,
      delegationId: 'del_test',
      action: {
        type: 'execute', target: 'task', scopeRequired: 'code_execution',
        spend: { amount: 10, currency: 'USD' }
      },
      privateKey: agent.privateKey
    })
    const ctx = makeContext({
      delegation: {
        scope: ['code_execution'], spendLimit: 500, spentAmount: 500,
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
        revoked: false, currentDepth: 0, maxDepth: 2
      }
    })
    const decision = evaluateIntent({
      intent, validator, validationContext: ctx,
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey
    })
    assert.equal(decision.verdict, 'deny')
    assert.ok(decision.reason.includes('No spend budget remaining'))
  })
})
