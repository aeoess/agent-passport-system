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
  computeCompoundDigest, captureRoutingContext, detectRoutingDivergence,
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


// ═══════════════════════════════════════
// Finding Layer Tags (per xsa520 March 19 discussion on issue #3)
// ═══════════════════════════════════════

describe('PolicyDecision Finding Layer Tags', () => {
  it('structural findings always present on permit', () => {
    const agent = generateKeyPair()
    const evaluator = generateKeyPair()

    const intent = createActionIntent({
      agentId: 'layer-tag-agent',
      agentPublicKey: agent.publicKey,
      delegationId: 'del-layer-test',
      action: { type: 'analysis', target: 'doc', scopeRequired: 'analysis:run' },
      privateKey: agent.privateKey,
    })

    const validator = new FloorValidatorV1()
    const ctx: ValidationContext = {
      floorVersion: '1.0',
      floorPrinciples: [],
      delegation: {
        scope: ['analysis:run'],
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
        revoked: false,
        currentDepth: 1,
        maxDepth: 3,
      },
      agentRegistered: true,
      agentAttestationValid: true,
    }

    const decision = evaluateIntent({
      intent, validator, validationContext: ctx,
      evaluatorId: 'eval-layer',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey,
    })

    assert.equal(decision.verdict, 'permit')

    // All structural findings must be present
    const structural = decision.principlesEvaluated.filter(e => e.layer === 'structural')
    assert.ok(structural.length >= 5, `Expected ≥5 structural findings, got ${structural.length}`)

    // F-001 through F-005 must all be structural
    for (const id of ['F-001', 'F-002', 'F-003', 'F-004', 'F-005']) {
      const finding = decision.principlesEvaluated.find(e => e.principleId === id)
      assert.ok(finding, `Missing finding ${id}`)
      assert.equal(finding!.layer, 'structural', `${id} should be structural`)
    }
  })

  it('trust findings present for F-006 and F-007', () => {
    const agent = generateKeyPair()
    const evaluator = generateKeyPair()

    const intent = createActionIntent({
      agentId: 'layer-tag-agent-2',
      agentPublicKey: agent.publicKey,
      delegationId: 'del-layer-2',
      action: { type: 'analysis', target: 'doc', scopeRequired: 'analysis:run' },
      privateKey: agent.privateKey,
    })

    const validator = new FloorValidatorV1()
    const ctx: ValidationContext = {
      floorVersion: '1.0',
      floorPrinciples: [],
      delegation: {
        scope: ['analysis:run'],
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
        revoked: false,
        currentDepth: 1,
        maxDepth: 3,
      },
      agentRegistered: true,
      agentAttestationValid: true,
    }

    const decision = evaluateIntent({
      intent, validator, validationContext: ctx,
      evaluatorId: 'eval-layer-2',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey,
    })

    // F-006 and F-007 must be trust-layer
    for (const id of ['F-006', 'F-007']) {
      const finding = decision.principlesEvaluated.find(e => e.principleId === id)
      assert.ok(finding, `Missing finding ${id}`)
      assert.equal(finding!.layer, 'trust', `${id} should be trust-layer`)
    }
  })

  it('structural findings are deterministic (same input → same tags)', () => {
    const agent = generateKeyPair()
    const evaluator = generateKeyPair()
    const validator = new FloorValidatorV1()
    const ctx: ValidationContext = {
      floorVersion: '1.0',
      floorPrinciples: [],
      delegation: {
        scope: ['code:run'],
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
        revoked: false, currentDepth: 1, maxDepth: 3,
      },
      agentRegistered: true,
      agentAttestationValid: true,
    }

    // Run twice with same input
    const makeIntent = () => createActionIntent({
      agentId: 'det-agent',
      agentPublicKey: agent.publicKey,
      delegationId: 'del-det',
      action: { type: 'code', target: 'script', scopeRequired: 'code:run' },
      privateKey: agent.privateKey,
    })

    const d1 = evaluateIntent({
      intent: makeIntent(), validator, validationContext: ctx,
      evaluatorId: 'e', evaluatorPublicKey: evaluator.publicKey, evaluatorPrivateKey: evaluator.privateKey,
    })
    const d2 = evaluateIntent({
      intent: makeIntent(), validator, validationContext: ctx,
      evaluatorId: 'e', evaluatorPublicKey: evaluator.publicKey, evaluatorPrivateKey: evaluator.privateKey,
    })

    const s1 = d1.principlesEvaluated.filter(e => e.layer === 'structural')
    const s2 = d2.principlesEvaluated.filter(e => e.layer === 'structural')
    assert.equal(s1.length, s2.length)
    for (let i = 0; i < s1.length; i++) {
      assert.equal(s1[i].principleId, s2[i].principleId)
      assert.equal(s1[i].status, s2[i].status)
      assert.equal(s1[i].layer, s2[i].layer)
    }
  })

  it('structural findings present on deny too', () => {
    const agent = generateKeyPair()
    const evaluator = generateKeyPair()

    const intent = createActionIntent({
      agentId: 'deny-agent',
      agentPublicKey: agent.publicKey,
      delegationId: 'del-deny',
      action: { type: 'code', target: 'script', scopeRequired: 'admin:delete' },
      privateKey: agent.privateKey,
    })

    const validator = new FloorValidatorV1()
    const ctx: ValidationContext = {
      floorVersion: '1.0',
      floorPrinciples: [],
      delegation: {
        scope: ['code:run'],  // does NOT include admin:delete
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
        revoked: false, currentDepth: 1, maxDepth: 3,
      },
      agentRegistered: true,
      agentAttestationValid: true,
    }

    const decision = evaluateIntent({
      intent, validator, validationContext: ctx,
      evaluatorId: 'e', evaluatorPublicKey: evaluator.publicKey, evaluatorPrivateKey: evaluator.privateKey,
    })

    assert.equal(decision.verdict, 'deny')
    // Structural findings still present even on deny
    const structural = decision.principlesEvaluated.filter(e => e.layer === 'structural')
    assert.ok(structural.length >= 5)
    // The scope check specifically must be structural and failed
    const scopeCheck = decision.principlesEvaluated.find(e => e.principleId === 'F-003')
    assert.equal(scopeCheck!.layer, 'structural')
    assert.equal(scopeCheck!.status, 'fail')
  })
})


// ════════════════════════════════════════════════════════════
// computeCompoundDigest tests (desiorac A2A#1672)
// ════════════════════════════════════════════════════════════

describe('computeCompoundDigest', () => {
  it('produces a 64-char hex hash', () => {
    const mockIntent = { intentId: 'i1', signature: 'sig1' } as any
    const mockReceipt = { policyReceiptId: 'pr1', signature: 'sig2' } as any
    const digest = computeCompoundDigest({
      intent: mockIntent, receipt: mockReceipt,
      executionFrameId: 'frame-001', timestamp: '2026-04-01T00:00:00Z',
    })
    assert.equal(digest.length, 64)
  })

  it('same inputs produce same digest (deterministic)', () => {
    const mockIntent = { intentId: 'i1', agentId: 'a1', signature: 'sig1' } as any
    const mockReceipt = { policyReceiptId: 'pr1', intentId: 'i1', signature: 'sig2' } as any
    const d1 = computeCompoundDigest({ intent: mockIntent, receipt: mockReceipt, executionFrameId: 'f1', timestamp: 't1' })
    const d2 = computeCompoundDigest({ intent: mockIntent, receipt: mockReceipt, executionFrameId: 'f1', timestamp: 't1' })
    assert.equal(d1, d2)
  })

  it('different executionFrameId produces different digest', () => {
    const mockIntent = { intentId: 'i1', signature: 'sig1' } as any
    const mockReceipt = { policyReceiptId: 'pr1', signature: 'sig2' } as any
    const d1 = computeCompoundDigest({ intent: mockIntent, receipt: mockReceipt, executionFrameId: 'frame-A', timestamp: 't1' })
    const d2 = computeCompoundDigest({ intent: mockIntent, receipt: mockReceipt, executionFrameId: 'frame-B', timestamp: 't1' })
    assert.notEqual(d1, d2)
  })
})


// ════════════════════════════════════════════════════════════
// captureRoutingContext + detectRoutingDivergence (desiorac OATR#2)
// ════════════════════════════════════════════════════════════

describe('captureRoutingContext', () => {
  it('hashes DID document and endpoint', () => {
    const ctx = captureRoutingContext({
      did: 'did:web:example.com',
      didDocument: { id: 'did:web:example.com', verificationMethod: [] },
      endpoint: 'https://api.example.com/agent',
    })
    assert.equal(ctx.did, 'did:web:example.com')
    assert.ok(ctx.didDocumentHash)
    assert.equal(ctx.didDocumentHash!.length, 64)
    assert.ok(ctx.endpointHash)
    assert.equal(ctx.endpointHash!.length, 64)
  })

  it('handles string DID document', () => {
    const ctx = captureRoutingContext({ did: 'did:key:z6Mk', didDocument: '{"id":"did:key:z6Mk"}' })
    assert.ok(ctx.didDocumentHash)
  })
})

describe('detectRoutingDivergence', () => {
  const baseCtx = captureRoutingContext({
    did: 'did:web:a.com', didDocument: { id: 'a', key: 'k1' }, endpoint: 'https://a.com/agent',
  })

  it('detects no divergence when contexts match', () => {
    const result = detectRoutingDivergence({ intent: baseCtx, execution: baseCtx })
    assert.equal(result.pattern, 'none')
    assert.equal(result.riskLevel, 'none')
  })

  it('detects endpoint_migration (DID stable, doc stable, endpoint changed)', () => {
    const exec = captureRoutingContext({
      did: 'did:web:a.com', didDocument: { id: 'a', key: 'k1' }, endpoint: 'https://b.com/agent',
    })
    const result = detectRoutingDivergence({ intent: baseCtx, execution: exec })
    assert.equal(result.pattern, 'endpoint_migration')
    assert.equal(result.riskLevel, 'low')
    assert.equal(result.endpointChanged, true)
    assert.equal(result.didChanged, false)
    assert.equal(result.documentChanged, false)
  })

  it('detects key_rotation (DID stable, endpoint stable, doc changed)', () => {
    const exec = captureRoutingContext({
      did: 'did:web:a.com', didDocument: { id: 'a', key: 'k2-rotated' }, endpoint: 'https://a.com/agent',
    })
    const result = detectRoutingDivergence({ intent: baseCtx, execution: exec })
    assert.equal(result.pattern, 'key_rotation')
    assert.equal(result.riskLevel, 'medium')
    assert.equal(result.documentChanged, true)
    assert.equal(result.endpointChanged, false)
  })

  it('detects full_migration (DID stable, doc changed, endpoint changed)', () => {
    const exec = captureRoutingContext({
      did: 'did:web:a.com', didDocument: { id: 'a', key: 'k2-new' }, endpoint: 'https://b.com/agent',
    })
    const result = detectRoutingDivergence({ intent: baseCtx, execution: exec })
    assert.equal(result.pattern, 'full_migration')
    assert.equal(result.riskLevel, 'medium')
    assert.equal(result.documentChanged, true)
    assert.equal(result.endpointChanged, true)
  })

  it('detects entity_change (DID changed — always high risk)', () => {
    const exec = captureRoutingContext({
      did: 'did:web:evil.com', didDocument: { id: 'evil' }, endpoint: 'https://evil.com/agent',
    })
    const result = detectRoutingDivergence({ intent: baseCtx, execution: exec })
    assert.equal(result.pattern, 'entity_change')
    assert.equal(result.riskLevel, 'high')
    assert.equal(result.didChanged, true)
  })

  it('returns none when no routing context provided', () => {
    const result = detectRoutingDivergence({ intent: {}, execution: {} })
    assert.equal(result.pattern, 'none')
    assert.equal(result.riskLevel, 'none')
  })

  it('includes resolutionDeltaMs when provided', () => {
    const exec = captureRoutingContext({
      did: 'did:web:a.com', didDocument: { id: 'a', key: 'k1' }, endpoint: 'https://b.com/agent',
    })
    const result = detectRoutingDivergence({ intent: baseCtx, execution: exec, resolutionDeltaMs: 1500 })
    assert.equal(result.resolutionDeltaMs, 1500)
    assert.equal(result.pattern, 'endpoint_migration')
  })
})
