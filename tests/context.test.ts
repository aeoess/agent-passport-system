// ══════════════════════════════════════════════════════════════════
// Agent Context Tests — Automatic Compliance Enforcement
// ══════════════════════════════════════════════════════════════════

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import {
  joinSocialContract, delegate,
  createAgentContext, AgentContext,
  loadFloor,
} from '../src/index.js'
import type {
  SocialContractAgent,
  ValuesFloor,
  Delegation,
} from '../src/index.js'

// ── Test Helpers ──

const floorYaml = readFileSync('values/floor.yaml', 'utf-8')

function createTestAgent(name = 'test-agent'): { agent: SocialContractAgent; floor: ValuesFloor } {
  const floor = loadFloor(floorYaml)
  const agent = joinSocialContract({
    name,
    mission: 'Test agent for context enforcement',
    owner: 'test-human',
    capabilities: ['code', 'search', 'communicate'],
    platform: 'test',
    models: ['test-model'],
    floor
  })
  return { agent, floor }
}

function createTestDelegation(agent: SocialContractAgent, scope: string[]): Delegation {
  const principal = joinSocialContract({
    name: 'principal',
    mission: 'Principal',
    owner: 'human',
    capabilities: ['admin'],
    platform: 'test',
    models: ['test'],
    floor: loadFloor(floorYaml)
  })
  return delegate({
    from: principal,
    toPublicKey: agent.publicKey,
    scope,
    spendLimit: 1000,
    maxDepth: 3,
    expiresInHours: 24
  })
}

// ══════════════════════════════════════
// CONTEXT CREATION
// ══════════════════════════════════════

describe('AgentContext — Creation', () => {
  it('creates a context with default settings', () => {
    const { agent, floor } = createTestAgent()
    const ctx = createAgentContext(agent, floor)
    assert.ok(ctx instanceof AgentContext)
    assert.equal(ctx.enforcement, 'auto')
  })

  it('creates with custom enforcement level', () => {
    const { agent, floor } = createTestAgent()
    const ctx = createAgentContext(agent, floor, { enforcement: 'strict' })
    assert.equal(ctx.enforcement, 'strict')
  })

  it('creates with manual mode', () => {
    const { agent, floor } = createTestAgent()
    const ctx = createAgentContext(agent, floor, { enforcement: 'manual' })
    assert.equal(ctx.enforcement, 'manual')
  })

  it('rejects agent without attestation', () => {
    const { floor } = createTestAgent()
    const agentNoAttest = joinSocialContract({
      name: 'no-attest', mission: 'No attestation', owner: 'human',
      capabilities: ['test'], platform: 'test', models: ['test']
    })
    assert.throws(() => createAgentContext(agentNoAttest, floor), /floor attestation/)
  })
})

// ══════════════════════════════════════
// DELEGATION MANAGEMENT
// ══════════════════════════════════════

describe('AgentContext — Delegations', () => {
  it('adds and finds delegation by scope', () => {
    const { agent, floor } = createTestAgent()
    const ctx = createAgentContext(agent, floor)
    const del = createTestDelegation(agent, ['data:read', 'data:write'])
    ctx.addDelegation(del)
    const found = ctx.findDelegation('data:read')
    assert.ok(found)
    assert.equal(found!.delegationId, del.delegationId)
  })

  it('returns null when no delegation matches scope', () => {
    const { agent, floor } = createTestAgent()
    const ctx = createAgentContext(agent, floor)
    ctx.addDelegation(createTestDelegation(agent, ['data:read']))
    assert.equal(ctx.findDelegation('admin:delete'), null)
  })

  it('removes delegation', () => {
    const { agent, floor } = createTestAgent()
    const ctx = createAgentContext(agent, floor)
    const del = createTestDelegation(agent, ['data:read'])
    ctx.addDelegation(del)
    assert.equal(ctx.removeDelegation(del.delegationId), true)
    assert.equal(ctx.findDelegation('data:read'), null)
  })
})

// ══════════════════════════════════════
// AUTO ENFORCEMENT — THE CORE FEATURE
// ══════════════════════════════════════

describe('AgentContext — Auto Enforcement', () => {
  let agent: SocialContractAgent
  let floor: ValuesFloor
  let ctx: AgentContext
  let del: Delegation

  beforeEach(() => {
    const setup = createTestAgent()
    agent = setup.agent
    floor = setup.floor
    ctx = createAgentContext(agent, floor, { enforcement: 'auto' })
    del = createTestDelegation(agent, ['data:read', 'data:write', 'api:fetch'])
    ctx.addDelegation(del)
  })

  it('permits action within scope — full 3-sig chain', () => {
    const result = ctx.execute({
      type: 'api:fetch',
      target: 'https://api.example.com/data',
      scope: 'data:read'
    })
    assert.equal(result.permitted, true)
    assert.equal(result.verdict, 'permit')
    assert.ok(result.intent)
    assert.ok(result.intent.signature)
    assert.ok(result.decision)
    assert.ok(result.decision.signature)
    assert.match(result.reason, /passed/)
  })

  it('denies action outside delegation scope', () => {
    const result = ctx.execute({
      type: 'admin:delete', target: 'database', scope: 'admin:delete'
    })
    assert.equal(result.permitted, false)
    assert.equal(result.verdict, 'deny')
    assert.match(result.reason, /No valid delegation/)
  })

  it('produces signed intent (signature 1)', () => {
    const result = ctx.execute({ type: 'api:fetch', target: 't', scope: 'data:read' })
    assert.match(result.intent.intentId, /^intent_/)
    assert.equal(result.intent.agentId, agent.agentId)
    assert.ok(result.intent.signature)
    assert.equal(result.intent.action.scopeRequired, 'data:read')
  })

  it('produces signed policy decision (signature 2)', () => {
    const result = ctx.execute({ type: 'api:fetch', target: 't', scope: 'data:read' })
    assert.match(result.decision.decisionId, /^pdec_/)
    assert.equal(result.decision.intentId, result.intent.intentId)
    assert.ok(result.decision.signature)
    assert.equal(result.decision.verdict, 'permit')
  })

  it('complete() produces receipt + policy receipt (signature 3)', () => {
    const result = ctx.execute({ type: 'api:fetch', target: 't', scope: 'data:read' })
    const completed = ctx.complete(result, { status: 'success', summary: 'Fetched data' })

    assert.ok(completed.receipt.receiptId)
    assert.ok(completed.receipt.signature)
    assert.match(completed.policyReceipt.policyReceiptId, /^prec_/)
    assert.equal(completed.policyReceipt.chain.intentSignature, result.intent.signature)
    assert.equal(completed.policyReceipt.chain.decisionSignature, result.decision.signature)
    assert.equal(completed.policyReceipt.chain.receiptSignature, completed.receipt.signature)
  })

  it('throws when completing a denied action', () => {
    const result = ctx.execute({ type: 'nuke', target: 'all', scope: 'admin:nuke' })
    assert.equal(result.permitted, false)
    assert.throws(
      () => ctx.complete(result, { status: 'success', summary: 'nope' }),
      /Cannot complete a denied action/
    )
  })

  it('tracks stats correctly', () => {
    ctx.execute({ type: 'fetch', target: 'a', scope: 'data:read' })
    ctx.execute({ type: 'fetch', target: 'b', scope: 'data:write' })
    ctx.execute({ type: 'nope', target: 'c', scope: 'admin:delete' })

    const stats = ctx.stats
    assert.equal(stats.permitted, 2)
    assert.equal(stats.denied, 1)
    assert.equal(stats.total, 3)
  })
})

// ══════════════════════════════════════
// MANUAL MODE
// ══════════════════════════════════════

describe('AgentContext — Manual Mode', () => {
  it('permits everything in manual mode', () => {
    const { agent, floor } = createTestAgent()
    const ctx = createAgentContext(agent, floor, { enforcement: 'manual' })
    ctx.addDelegation(createTestDelegation(agent, ['data:read']))
    const result = ctx.execute({ type: 'fetch', target: 't', scope: 'data:read' })
    assert.equal(result.permitted, true)
    assert.match(result.reason, /Manual mode/)
  })

  it('still denies when no delegation exists even in manual mode', () => {
    const { agent, floor } = createTestAgent()
    const ctx = createAgentContext(agent, floor, { enforcement: 'manual' })
    const result = ctx.execute({ type: 'fetch', target: 't', scope: 'data:read' })
    assert.equal(result.permitted, false)
    assert.match(result.reason, /No valid delegation/)
  })
})

// ══════════════════════════════════════
// CALLBACKS
// ══════════════════════════════════════

describe('AgentContext — Callbacks', () => {
  it('fires onPolicyDecision callback', () => {
    let called = false
    let capturedVerdict = ''
    const { agent, floor } = createTestAgent()
    const ctx = createAgentContext(agent, floor, {
      onPolicyDecision: (decision) => { called = true; capturedVerdict = decision.verdict }
    })
    ctx.addDelegation(createTestDelegation(agent, ['data:read']))
    ctx.execute({ type: 'fetch', target: 't', scope: 'data:read' })
    assert.equal(called, true)
    assert.equal(capturedVerdict, 'permit')
  })

  it('fires onDenied callback on denial', () => {
    let deniedCalled = false
    const { agent, floor } = createTestAgent()
    const ctx = createAgentContext(agent, floor, {
      onDenied: () => { deniedCalled = true }
    })
    ctx.execute({ type: 'nope', target: 't', scope: 'admin:nuke' })
    assert.equal(deniedCalled, true)
  })
})

// ══════════════════════════════════════
// AUDIT LOG
// ══════════════════════════════════════

describe('AgentContext — Audit Log', () => {
  it('records every action attempt', () => {
    const { agent, floor } = createTestAgent()
    const ctx = createAgentContext(agent, floor)
    ctx.addDelegation(createTestDelegation(agent, ['data:read']))

    ctx.execute({ type: 'fetch', target: 'a', scope: 'data:read' })
    ctx.execute({ type: 'nope', target: 'b', scope: 'admin:delete' })
    ctx.execute({ type: 'fetch', target: 'c', scope: 'data:read' })

    const log = ctx.auditLog
    assert.equal(log.length, 3)
    assert.equal(log[0].verdict, 'permit')
    assert.equal(log[1].verdict, 'deny')
    assert.equal(log[2].verdict, 'permit')
  })

  it('audit entries contain enforcement details', () => {
    const { agent, floor } = createTestAgent()
    const ctx = createAgentContext(agent, floor)
    ctx.addDelegation(createTestDelegation(agent, ['data:read']))
    ctx.execute({ type: 'fetch', target: 'a', scope: 'data:read' })

    const entry = ctx.auditLog[0]
    assert.ok(entry.enforcement)
    assert.equal(entry.enforcement.inlinePassed, true)
    assert.match(entry.intentId, /^intent_/)
  })

  it('updates audit entry with receipt after complete()', () => {
    const { agent, floor } = createTestAgent()
    const ctx = createAgentContext(agent, floor)
    ctx.addDelegation(createTestDelegation(agent, ['data:read']))

    const result = ctx.execute({ type: 'fetch', target: 'a', scope: 'data:read' })
    ctx.complete(result, { status: 'success', summary: 'done' })

    assert.ok(ctx.auditLog[0].receiptId)
  })
})

// ══════════════════════════════════════
// SPEND ENFORCEMENT
// ══════════════════════════════════════

describe('AgentContext — Spend Limits', () => {
  it('permits spend within delegation limit', () => {
    const { agent, floor } = createTestAgent()
    const ctx = createAgentContext(agent, floor)
    ctx.addDelegation(createTestDelegation(agent, ['commerce:purchase']))

    const result = ctx.execute({
      type: 'commerce:purchase', target: 'merchant',
      scope: 'commerce:purchase',
      spend: { amount: 50, currency: 'USD' }
    })
    assert.equal(result.permitted, true)
  })

  it('narrows spend that exceeds remaining budget', () => {
    const { agent, floor } = createTestAgent()
    const ctx = createAgentContext(agent, floor)

    const principal = joinSocialContract({
      name: 'principal', mission: 'P', owner: 'h',
      capabilities: ['admin'], platform: 'test', models: ['test'],
      floor: loadFloor(floorYaml)
    })
    const del = delegate({
      from: principal, toPublicKey: agent.publicKey,
      scope: ['commerce:purchase'], spendLimit: 100,
      maxDepth: 2, expiresInHours: 24
    })
    ctx.addDelegation(del)

    const result = ctx.execute({
      type: 'commerce:purchase', target: 'merchant',
      scope: 'commerce:purchase',
      spend: { amount: 150, currency: 'USD' }
    })
    assert.equal(result.verdict, 'narrow')
    assert.equal(result.permitted, true)
    assert.ok(result.constraints)
  })
})

// ══════════════════════════════════════
// FULL LIFECYCLE
// ══════════════════════════════════════

describe('AgentContext — Full Lifecycle', () => {
  it('execute → complete → verify full 3-signature chain', () => {
    const { agent, floor } = createTestAgent()
    const ctx = createAgentContext(agent, floor)
    ctx.addDelegation(createTestDelegation(agent, ['data:read', 'api:fetch']))

    const result = ctx.execute({
      type: 'api:fetch', target: 'https://api.example.com',
      scope: 'api:fetch', context: 'Fetching user data'
    })
    assert.equal(result.permitted, true)

    const completed = ctx.complete(result, {
      status: 'success', summary: 'Retrieved 42 records'
    })

    // All 3 signatures present and linked
    assert.ok(completed.policyReceipt.chain.intentSignature)
    assert.ok(completed.policyReceipt.chain.decisionSignature)
    assert.ok(completed.policyReceipt.chain.receiptSignature)

    // State tracked
    assert.equal(ctx.allReceipts.length, 1)
    assert.equal(ctx.allDecisions.length, 1)
    assert.equal(ctx.auditLog.length, 1)
    assert.equal(ctx.stats.permitted, 1)
    assert.equal(ctx.stats.denied, 0)
  })

  it('multiple actions build a complete audit trail', () => {
    const { agent, floor } = createTestAgent()
    const ctx = createAgentContext(agent, floor)
    ctx.addDelegation(createTestDelegation(agent, ['data:read', 'data:write', 'api:fetch']))

    const r1 = ctx.execute({ type: 'fetch', target: 'a', scope: 'data:read' })
    ctx.complete(r1, { status: 'success', summary: 'read' })

    const r2 = ctx.execute({ type: 'write', target: 'b', scope: 'data:write' })
    ctx.complete(r2, { status: 'success', summary: 'wrote' })

    ctx.execute({ type: 'nope', target: 'c', scope: 'admin:nuke' })

    assert.equal(ctx.allReceipts.length, 2)
    assert.equal(ctx.allDecisions.length, 3)
    assert.deepEqual(ctx.stats, { permitted: 2, denied: 1, narrowed: 0, total: 3 })
  })
})

// ══════════════════════════════════════
// CUSTOM EVALUATOR
// ══════════════════════════════════════

describe('AgentContext — Custom Evaluator', () => {
  it('uses separate evaluator identity when provided', () => {
    const { agent, floor } = createTestAgent()
    const evaluator = joinSocialContract({
      name: 'evaluator', mission: 'Policy evaluation', owner: 'human',
      capabilities: ['evaluate'], platform: 'test', models: ['test'], floor
    })

    const ctx = createAgentContext(agent, floor, {
      evaluator: {
        id: evaluator.agentId,
        publicKey: evaluator.publicKey,
        privateKey: evaluator.keyPair.privateKey
      }
    })
    ctx.addDelegation(createTestDelegation(agent, ['data:read']))

    const result = ctx.execute({ type: 'fetch', target: 'a', scope: 'data:read' })
    assert.equal(result.permitted, true)
    assert.equal(result.decision.evaluatorId, evaluator.agentId)
    assert.equal(result.decision.evaluatorPublicKey, evaluator.publicKey)
  })
})
