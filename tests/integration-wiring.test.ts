// ══════════════════════════════════════════════════════════════════
// Integration Wiring Tests — Layers working together
// ══════════════════════════════════════════════════════════════════
// P1: Verify that isolated layers are properly connected.

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, clearStores,
  createPassport,
  createDelegation,
  loadFloor,
  FloorValidatorV1,
  createCommerceDelegation,
  createFeed, createRegistry, registerAgent,
  createTaskBrief, reviewEvidence, submitEvidence,
  completeTask, createTaskUnit, assignTask, acceptTask,
  submitDeliverable, handoffEvidence,
  // Integration bridges
  commerceWithIntent,
  commerceReceiptToActionReceipt,
  validateCommerceDelegation,
  coordinationToAgora,
  postTaskCreated,
  postReviewCompleted,
  postTaskCompleted,
  // Attribution (to verify commerce receipts flow in)
  computeAttribution, traceBeneficiary,
} from '../src/index.js'
import type { ValidationContext, CommerceActionReceipt } from '../src/index.js'

// ── Setup ──

const human = generateKeyPair()
const evaluator = generateKeyPair()
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
      weight: p.weight,
    })),
    delegation: {
      scope: ['commerce:checkout', 'commerce:browse'],
      spendLimit: 500,
      spentAmount: 0,
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      revoked: false,
      currentDepth: 0,
      maxDepth: 2,
    },
    agentRegistered: true,
    agentAttestationValid: true,
    ...overrides,
  }
}

/** Helper: create a proper passport with its own keypair */
function makeAgent(agentId: string) {
  const { signedPassport, keyPair } = createPassport({
    agentId,
    agentName: agentId,
    ownerAlias: 'test-owner',
    mission: 'Integration testing',
    capabilities: ['commerce:checkout', 'web_search'],
    runtime: { platform: 'node', version: '22.0' },
  })
  return { signedPassport, keyPair }
}

// ══════════════════════════════════════
// COMMERCE → INTENT/POLICY
// ══════════════════════════════════════

describe('Commerce → Intent/Policy', () => {
  beforeEach(() => clearStores())

  it('permits commerce when policy and preflight both pass', () => {
    const { signedPassport, keyPair } = makeAgent('agent-shopper')

    const delegation = createDelegation({
      delegatedTo: keyPair.publicKey,
      delegatedBy: human.publicKey,
      scope: ['commerce:checkout', 'commerce:browse'],
      spendLimit: 500,
      privateKey: human.privateKey,
    })

    const commerceDel = createCommerceDelegation({
      agentId: 'agent-shopper',
      delegationId: delegation.delegationId,
      spendLimit: 500,
      approvedMerchants: ['Amazon'],
    })

    const result = commerceWithIntent({
      signedPassport,
      agentPrivateKey: keyPair.privateKey,
      delegation,
      commerceDelegation: commerceDel,
      merchantName: 'Amazon',
      estimatedTotal: { amount: 50, currency: 'usd' },
      actionDescription: 'Buy office supplies',
      validator,
      validationContext: makeContext(),
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey,
    })

    assert.ok(result.permitted, `Should be permitted but got: ${result.reason}`)
    assert.ok(result.intent.intentId.startsWith('intent_'))
    assert.equal(result.decision.verdict, 'permit')
    assert.ok(result.preflight.permitted)
    assert.equal(result.blockedAt, undefined)
  })

  it('blocks at policy when delegation scope is wrong', () => {
    const { signedPassport, keyPair } = makeAgent('agent-wrong-scope')

    const delegation = createDelegation({
      delegatedTo: keyPair.publicKey,
      delegatedBy: human.publicKey,
      scope: ['web_search'],  // no commerce scope
      spendLimit: 500,
      privateKey: human.privateKey,
    })

    const commerceDel = createCommerceDelegation({
      agentId: 'agent-wrong-scope',
      delegationId: delegation.delegationId,
      spendLimit: 500,
    })

    const result = commerceWithIntent({
      signedPassport,
      agentPrivateKey: keyPair.privateKey,
      delegation,
      commerceDelegation: commerceDel,
      merchantName: 'Amazon',
      estimatedTotal: { amount: 50, currency: 'usd' },
      actionDescription: 'Buy stuff',
      validator,
      validationContext: makeContext({
        delegation: {
          scope: ['web_search'],
          spendLimit: 500, spentAmount: 0,
          expiresAt: new Date(Date.now() + 86400000).toISOString(),
          revoked: false, currentDepth: 0, maxDepth: 2,
        },
      }),
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey,
    })

    assert.equal(result.permitted, false)
    assert.equal(result.blockedAt, 'policy')
    assert.ok(result.reason, 'Should have a reason')
  })

  it('blocks at preflight when merchant not approved', () => {
    const { signedPassport, keyPair } = makeAgent('agent-bad-merchant')

    const delegation = createDelegation({
      delegatedTo: keyPair.publicKey,
      delegatedBy: human.publicKey,
      scope: ['commerce:checkout', 'commerce:browse'],
      spendLimit: 500,
      privateKey: human.privateKey,
    })

    const commerceDel = createCommerceDelegation({
      agentId: 'agent-bad-merchant',
      delegationId: delegation.delegationId,
      spendLimit: 500,
      approvedMerchants: ['Amazon'],
    })

    const result = commerceWithIntent({
      signedPassport,
      agentPrivateKey: keyPair.privateKey,
      delegation,
      commerceDelegation: commerceDel,
      merchantName: 'ShadyStore',
      estimatedTotal: { amount: 50, currency: 'usd' },
      actionDescription: 'Buy from unapproved merchant',
      validator,
      validationContext: makeContext(),
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey,
    })

    // Policy passes (agent has scope), but preflight blocks (bad merchant)
    assert.equal(result.permitted, false)
    assert.equal(result.blockedAt, 'preflight')
    assert.equal(result.decision.verdict, 'permit')
  })
})

// ══════════════════════════════════════
// COMMERCE → ATTRIBUTION
// ══════════════════════════════════════

describe('Commerce → Attribution', () => {
  it('converts commerce receipt to action receipt for attribution', () => {
    const commerceReceipt: CommerceActionReceipt = {
      receiptId: 'rcpt-commerce-test123',
      version: '1.0',
      timestamp: new Date().toISOString(),
      agentId: 'agent-shopper',
      delegationId: 'del-123',
      action: {
        type: 'commerce:complete_checkout',
        target: 'https://merchant.com/checkout',
        method: 'POST',
        scopeUsed: 'commerce:checkout',
        spend: { amount: 99, currency: 'usd' },
      },
      checkout: {
        sessionId: 'sess-abc',
        merchantName: 'TechStore',
        items: [{ skuId: 'sku-1', name: 'Keyboard', quantity: 1, unitPrice: 99 }],
        totalAmount: 99,
        totalCurrency: 'usd',
        status: 'completed',
      },
      delegationChain: [human.publicKey, evaluator.publicKey],
      beneficiary: 'tymofii-pidlisnyi',
      signature: 'test-sig',
    }

    const actionReceipt = commerceReceiptToActionReceipt(commerceReceipt)

    assert.equal(actionReceipt.receiptId, 'rcpt-commerce-test123')
    assert.equal(actionReceipt.agentId, 'agent-shopper')
    assert.equal(actionReceipt.action.scopeUsed, 'commerce:checkout')
    assert.equal(actionReceipt.action.spend?.amount, 99)
    assert.equal(actionReceipt.result.status, 'success')
    assert.ok(actionReceipt.result.summary.includes('TechStore'))
  })

  it('converted receipt works with computeAttribution', () => {
    const { keyPair } = makeAgent('agent-buyer')

    const commerceReceipt: CommerceActionReceipt = {
      receiptId: 'rcpt-commerce-attr',
      version: '1.0',
      timestamp: new Date().toISOString(),
      agentId: 'agent-buyer',
      delegationId: 'del-456',
      action: {
        type: 'commerce:complete_checkout',
        target: 'https://shop.com/checkout',
        method: 'POST',
        scopeUsed: 'commerce:checkout',
        spend: { amount: 200, currency: 'usd' },
      },
      checkout: {
        sessionId: 'sess-def',
        merchantName: 'CloudShop',
        items: [{ skuId: 'sku-2', name: 'Server', quantity: 1, unitPrice: 200 }],
        totalAmount: 200,
        totalCurrency: 'usd',
        status: 'completed',
      },
      delegationChain: [human.publicKey, keyPair.publicKey],
      beneficiary: 'tymofii-pidlisnyi',
      signature: 'test-sig-2',
    }

    const actionReceipt = commerceReceiptToActionReceipt(commerceReceipt)
    const report = computeAttribution(
      [actionReceipt],
      'agent-buyer',
      'tymofii-pidlisnyi',
      keyPair.privateKey,
      { scopeWeights: { 'commerce:checkout': 0.8 } },
    )

    assert.equal(report.agentId, 'agent-buyer')
    assert.equal(report.entries.length, 1)
    assert.ok(report.totalWeight > 0, 'Should have positive weight')
    assert.equal(report.entries[0].scopeUsed, 'commerce:checkout')
  })

  it('converted receipt works with traceBeneficiary', () => {
    const { keyPair } = makeAgent('agent-tracer')

    const commerceReceipt: CommerceActionReceipt = {
      receiptId: 'rcpt-commerce-trace',
      version: '1.0',
      timestamp: new Date().toISOString(),
      agentId: 'agent-tracer',
      delegationId: 'del-789',
      action: {
        type: 'commerce:complete_checkout',
        target: 'https://store.com/checkout',
        method: 'POST',
        scopeUsed: 'commerce:checkout',
        spend: { amount: 50, currency: 'usd' },
      },
      checkout: {
        sessionId: 'sess-ghi',
        merchantName: 'TestShop',
        items: [{ skuId: 'sku-3', name: 'Widget', quantity: 2, unitPrice: 25 }],
        totalAmount: 50,
        totalCurrency: 'usd',
        status: 'completed',
      },
      delegationChain: [human.publicKey, keyPair.publicKey],
      beneficiary: 'tymofii-pidlisnyi',
      signature: 'test-sig-3',
    }

    const actionReceipt = commerceReceiptToActionReceipt(commerceReceipt)

    const delegation = createDelegation({
      delegatedTo: keyPair.publicKey,
      delegatedBy: human.publicKey,
      scope: ['commerce:checkout'],
      spendLimit: 1000,
      privateKey: human.privateKey,
    })

    const beneficiaryMap = new Map([
      [human.publicKey, { principalId: 'tymofii-pidlisnyi', name: 'Tymofii' }],
    ])

    const trace = traceBeneficiary(actionReceipt, [delegation], beneficiaryMap)

    assert.equal(trace.beneficiary, 'tymofii-pidlisnyi')
    assert.equal(trace.executorAgent, 'agent-tracer')
    assert.ok(trace.verified, 'Trace should be verified')
  })
})

// ══════════════════════════════════════
// COMMERCE → DELEGATION
// ══════════════════════════════════════

describe('Commerce → Delegation', () => {
  beforeEach(() => clearStores())

  it('validates commerce delegation against protocol delegation', () => {
    const { keyPair } = makeAgent('agent-valid')
    const delegation = createDelegation({
      delegatedTo: keyPair.publicKey,
      delegatedBy: human.publicKey,
      scope: ['commerce:checkout', 'commerce:browse', 'web_search'],
      spendLimit: 1000,
      privateKey: human.privateKey,
    })
    const commerceDel = createCommerceDelegation({
      agentId: 'agent-valid',
      delegationId: delegation.delegationId,
      spendLimit: 500,
    })
    const result = validateCommerceDelegation(commerceDel, delegation)
    assert.ok(result.valid, `Should be valid but got: ${result.errors.join(', ')}`)
    assert.ok(result.scopeMatch)
    assert.ok(result.withinSpendLimit)
    assert.ok(result.notRevoked)
  })

  it('rejects when commerce spend limit exceeds protocol limit', () => {
    const { keyPair } = makeAgent('agent-overspend')
    const delegation = createDelegation({
      delegatedTo: keyPair.publicKey,
      delegatedBy: human.publicKey,
      scope: ['commerce:checkout'],
      spendLimit: 100,
      privateKey: human.privateKey,
    })
    const commerceDel = createCommerceDelegation({
      agentId: 'agent-overspend',
      delegationId: delegation.delegationId,
      spendLimit: 500,
    })
    const result = validateCommerceDelegation(commerceDel, delegation)
    assert.equal(result.valid, false)
    assert.equal(result.withinSpendLimit, false)
    assert.ok(result.errors.some(e => e.includes('spend limit')))
  })

  it('rejects when commerce scopes not in protocol delegation', () => {
    const { keyPair } = makeAgent('agent-noscope')
    const delegation = createDelegation({
      delegatedTo: keyPair.publicKey,
      delegatedBy: human.publicKey,
      scope: ['web_search'],
      spendLimit: 1000,
      privateKey: human.privateKey,
    })
    const commerceDel = createCommerceDelegation({
      agentId: 'agent-noscope',
      delegationId: delegation.delegationId,
      spendLimit: 500,
    })
    const result = validateCommerceDelegation(commerceDel, delegation)
    assert.equal(result.valid, false)
    assert.equal(result.scopeMatch, false)
  })

  it('rejects when delegation IDs dont match', () => {
    const { keyPair } = makeAgent('agent-mismatch')
    const delegation = createDelegation({
      delegatedTo: keyPair.publicKey,
      delegatedBy: human.publicKey,
      scope: ['commerce:checkout'],
      spendLimit: 1000,
      privateKey: human.privateKey,
    })
    const commerceDel = createCommerceDelegation({
      agentId: 'agent-mismatch',
      delegationId: 'wrong-id',
      spendLimit: 500,
    })
    const result = validateCommerceDelegation(commerceDel, delegation)
    assert.equal(result.valid, false)
    assert.ok(result.errors.some(e => e.includes('mismatch')))
  })
})

// ══════════════════════════════════════
// COORDINATION → AGORA
// ══════════════════════════════════════

describe('Coordination → Agora', () => {
  beforeEach(() => clearStores())

  it('posts task creation event to agora feed', () => {
    const operator = generateKeyPair()
    const brief = createTaskBrief({
      title: 'Research AI Safety',
      description: 'Comprehensive analysis of alignment techniques',
      operatorPublicKey: operator.publicKey,
      operatorPrivateKey: operator.privateKey,
      roles: [{ role: 'researcher', description: 'Find evidence', allowedScopes: ['web_search'], forbiddenScopes: [] }],
      deliverables: [{ name: 'Report', description: 'Research report', format: 'markdown', producedBy: 'researcher' }],
      acceptanceCriteria: ['3+ sources cited'],
    })

    const feed = createFeed()
    const registry = createRegistry()
    registerAgent(registry, { agentId: 'operator-1', agentName: 'Operator', publicKey: operator.publicKey })

    const result = postTaskCreated({
      brief,
      agentId: 'operator-1',
      agentName: 'Operator',
      publicKey: operator.publicKey,
      privateKey: operator.privateKey,
      feed,
      registry,
    })

    assert.ok(result.message.id.startsWith('msg-'))
    assert.equal(result.message.topic, `coordination:${brief.taskId}`)
    assert.ok(result.message.content.includes('Research AI Safety'))
    assert.equal(result.feed.messages.length, 1)
  })

  it('posts review decision to agora feed', () => {
    const operator = generateKeyPair()
    const researcher = generateKeyPair()

    const brief = createTaskBrief({
      title: 'Test Task',
      description: 'Testing',
      operatorPublicKey: operator.publicKey,
      operatorPrivateKey: operator.privateKey,
      roles: [{ role: 'researcher', description: 'Research', allowedScopes: ['web_search'], forbiddenScopes: [] }],
      deliverables: [{ name: 'Report', description: 'Report', format: 'md', producedBy: 'researcher' }],
      acceptanceCriteria: ['Done'],
    })

    const evidence = submitEvidence({
      taskId: brief.taskId,
      submitterPublicKey: researcher.publicKey,
      submitterPrivateKey: researcher.privateKey,
      role: 'researcher',
      claims: [{ dimension: 'safety', subject: 'RLHF', claim: 'Effective alignment technique', quote: 'RLHF has shown promising results in alignment', sourceUrl: 'https://example.com', confidence: 'high' }],
      methodology: 'Literature review',
    })

    const review = reviewEvidence({
      taskId: brief.taskId,
      packet: evidence,
      reviewerPublicKey: operator.publicKey,
      reviewerPrivateKey: operator.privateKey,
      verdict: 'approve',
      score: 85,
      threshold: 70,
      rationale: 'Solid evidence with good sourcing',
    })

    const feed = createFeed()
    const registry = createRegistry()

    const result = postReviewCompleted({
      review,
      agentId: 'operator-1',
      agentName: 'Operator',
      publicKey: operator.publicKey,
      privateKey: operator.privateKey,
      feed,
      registry,
    })

    assert.ok(result.message.content.includes('approve'))
    assert.ok(result.message.content.includes('85'))
    assert.equal(result.feed.messages.length, 1)
  })

  it('posts task completion with metrics to agora', () => {
    const operator = generateKeyPair()
    const researcherKeys = generateKeyPair()

    const brief = createTaskBrief({
      title: 'Integration Test',
      description: 'Testing agora integration',
      operatorPublicKey: operator.publicKey,
      operatorPrivateKey: operator.privateKey,
      roles: [{ role: 'researcher', description: 'Research', allowedScopes: ['web_search'], forbiddenScopes: [] }],
      deliverables: [{ name: 'Report', description: 'Report', format: 'md', producedBy: 'researcher' }],
      acceptanceCriteria: ['Done'],
    })

    const del = createDelegation({
      delegatedTo: researcherKeys.publicKey,
      delegatedBy: operator.publicKey,
      scope: ['web_search'],
      spendLimit: 100,
      privateKey: operator.privateKey,
    })

    const { assignment, updatedBrief } = assignTask({
      brief,
      role: 'researcher',
      agentId: 'researcher-1',
      agentPublicKey: researcherKeys.publicKey,
      delegationId: del.delegationId,
      operatorPrivateKey: operator.privateKey,
    })

    const accepted = acceptTask(assignment, researcherKeys.privateKey)

    const evidence = submitEvidence({
      taskId: updatedBrief.taskId,
      submitterPublicKey: researcherKeys.publicKey,
      submitterPrivateKey: researcherKeys.privateKey,
      role: 'researcher',
      claims: [{ dimension: 'test', subject: 'test', claim: 'test claim', quote: 'test supporting quote here', sourceUrl: 'https://test.com', confidence: 'high' }],
      methodology: 'Testing',
    })

    const review = reviewEvidence({
      taskId: updatedBrief.taskId,
      packet: evidence,
      reviewerPublicKey: operator.publicKey,
      reviewerPrivateKey: operator.privateKey,
      verdict: 'approve',
      score: 90,
      threshold: 70,
      rationale: 'Good work',
    })

    const handoff = handoffEvidence({
      taskId: updatedBrief.taskId,
      packet: evidence,
      review,
      fromRole: 'researcher',
      toRole: 'researcher',
      toAgentPublicKey: researcherKeys.publicKey,
      operatorPrivateKey: operator.privateKey,
    })

    const deliverable = submitDeliverable({
      taskId: updatedBrief.taskId,
      specId: updatedBrief.deliverables[0].deliverableId,
      submitterPublicKey: researcherKeys.publicKey,
      submitterPrivateKey: researcherKeys.privateKey,
      role: 'researcher',
      content: 'Final report content',
      evidencePacketIds: [evidence.packetId],
      citationCount: 1,
      gapsFlagged: 0,
    })

    const unit = createTaskUnit(updatedBrief)
    unit.assignments.push(accepted)
    unit.evidencePackets.push(evidence)
    unit.reviews.push(review)
    unit.handoffs.push(handoff)
    unit.deliverables.push(deliverable)

    const completion = completeTask({
      brief: updatedBrief,
      unit,
      operatorPublicKey: operator.publicKey,
      operatorPrivateKey: operator.privateKey,
      status: 'completed',
      retrospective: 'Integration test passed — layers connected.',
    })

    const feed = createFeed()
    const registry = createRegistry()

    const result = postTaskCompleted({
      completion,
      agentId: 'operator-1',
      agentName: 'Operator',
      publicKey: operator.publicKey,
      privateKey: operator.privateKey,
      feed,
      registry,
    })

    assert.ok(result.message.content.includes('completed'))
    assert.ok(result.message.content.includes('Agents: 1'))
    assert.ok(result.message.content.includes('Integration test passed'))
    assert.equal(result.feed.messages.length, 1)
  })

  it('builds full coordination thread in agora', () => {
    const operator = generateKeyPair()
    const feed = createFeed()
    const registry = createRegistry()
    registerAgent(registry, { agentId: 'op', agentName: 'Operator', publicKey: operator.publicKey })

    const events: Array<{ event: Parameters<typeof coordinationToAgora>[0]['event'], detail: string }> = [
      { event: 'task_created', detail: 'New research task' },
      { event: 'task_assigned', detail: 'Assigned to researcher' },
      { event: 'evidence_submitted', detail: '3 claims found' },
      { event: 'review_completed', detail: 'Approved 85/70' },
      { event: 'deliverable_submitted', detail: 'Report ready' },
      { event: 'task_completed', detail: 'All done' },
    ]

    let currentFeed = feed
    for (const e of events) {
      const result = coordinationToAgora({
        event: e.event,
        taskId: 'task-thread-test',
        agentId: 'op',
        agentName: 'Operator',
        publicKey: operator.publicKey,
        privateKey: operator.privateKey,
        feed: currentFeed,
        registry,
        detail: e.detail,
      })
      currentFeed = result.feed
    }

    assert.equal(currentFeed.messages.length, 6)
    const topics = new Set(currentFeed.messages.map(m => m.topic))
    assert.equal(topics.size, 1)
    assert.ok(topics.has('coordination:task-thread-test'))
  })
})
