// Bounded Escalation Tests (Module 27 — Fourth Attenuation Invariant)
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, sign as signRaw } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import {
  createEscalationGrant, verifyEscalationGrant,
  requestEscalation, activateEscalation,
  checkEscalatedAction, revokeEscalation, isEscalationActive,
} from '../src/core/escalation.js'

const future = (ms: number) => new Date(Date.now() + ms).toISOString()

describe('Escalation Grant — Creation & Verification', () => {
  it('creates a signed escalation grant', () => {
    const human = generateKeyPair()
    const agent = generateKeyPair()
    const grant = createEscalationGrant({
      delegationId: 'del-001', grantedTo: agent.publicKey, grantedBy: human.publicKey,
      granterPrivateKey: human.privateKey,
      ceiling: { scope: ['data:read', 'data:write'], maxSpend: 100, maxDurationMs: 300000 },
      expiresAt: future(86400000),
    })
    assert.ok(grant.grantId.startsWith('esc_'))
    assert.deepEqual(grant.allowedTriggers, ['human_authorized'])
    assert.deepEqual(grant.allowedActionClasses, ['tentative'])
    assert.ok(grant.signature)
  })

  it('verifies grant — ceiling within granter scope', () => {
    const human = generateKeyPair()
    const agent = generateKeyPair()
    const grant = createEscalationGrant({
      delegationId: 'del-002', grantedTo: agent.publicKey, grantedBy: human.publicKey,
      granterPrivateKey: human.privateKey,
      ceiling: { scope: ['data:read'], maxSpend: 50, maxDurationMs: 60000 },
      expiresAt: future(86400000),
    })
    const result = verifyEscalationGrant(grant, ['data:read', 'data:write', 'search'])
    assert.equal(result.valid, true)
    assert.equal(result.grantValid, true)
    assert.equal(result.ceilingWithinScope, true)
  })

  it('rejects grant — ceiling exceeds granter scope (monotonic narrowing violation)', () => {
    const human = generateKeyPair()
    const agent = generateKeyPair()
    const grant = createEscalationGrant({
      delegationId: 'del-003', grantedTo: agent.publicKey, grantedBy: human.publicKey,
      granterPrivateKey: human.privateKey,
      ceiling: { scope: ['admin:delete'], maxSpend: 1000, maxDurationMs: 60000 },
      expiresAt: future(86400000),
    })
    const result = verifyEscalationGrant(grant, ['data:read', 'data:write'])
    assert.equal(result.valid, false)
    assert.equal(result.ceilingWithinScope, false)
    assert.ok(result.errors.some(e => e.includes('exceeds')))
  })

  it('rejects tampered grant signature', () => {
    const human = generateKeyPair()
    const agent = generateKeyPair()
    const grant = createEscalationGrant({
      delegationId: 'del-004', grantedTo: agent.publicKey, grantedBy: human.publicKey,
      granterPrivateKey: human.privateKey,
      ceiling: { scope: ['data:read'], maxSpend: 50, maxDurationMs: 60000 },
      expiresAt: future(86400000),
    })
    const tampered = { ...grant, signature: 'deadbeef'.repeat(16) }
    const result = verifyEscalationGrant(tampered, ['data:read'])
    assert.equal(result.grantValid, false)
  })
})

describe('Escalation Request & Activation', () => {
  it('requests and activates escalation with human_authorized trigger', () => {
    const human = generateKeyPair()
    const agent = generateKeyPair()
    const gateway = generateKeyPair()

    const grant = createEscalationGrant({
      delegationId: 'del-005', grantedTo: agent.publicKey, grantedBy: human.publicKey,
      granterPrivateKey: human.privateKey,
      ceiling: { scope: ['data:read', 'data:write'], maxSpend: 200, maxDurationMs: 300000 },
      expiresAt: future(86400000),
    })

    const approvalSig = signRaw(canonicalize({ approve: grant.grantId, grantedTo: grant.grantedTo }), human.privateKey)

    const request = requestEscalation({
      grant, agentPrivateKey: agent.privateKey, agentPublicKey: agent.publicKey,
      trigger: { type: 'human_authorized', evidence: 'Service outage', humanApprovalSignature: approvalSig },
    })

    assert.ok(request.requestId.startsWith('escreq_'))
    assert.equal(request.trigger.type, 'human_authorized')

    const active = activateEscalation({ grant, request, gatewayPrivateKey: gateway.privateKey })
    assert.ok(active.escalationId.startsWith('active_esc_'))
    assert.equal(active.status, 'active')
    assert.deepEqual(active.effectiveScope, ['data:read', 'data:write'])
    assert.equal(active.effectiveSpendLimit, 200)
  })

  it('rejects request with disallowed trigger type', () => {
    const human = generateKeyPair()
    const agent = generateKeyPair()
    const grant = createEscalationGrant({
      delegationId: 'del-006', grantedTo: agent.publicKey, grantedBy: human.publicKey,
      granterPrivateKey: human.privateKey,
      ceiling: { scope: ['data:read'], maxSpend: 50, maxDurationMs: 60000 },
      allowedTriggers: ['human_authorized'],
      expiresAt: future(86400000),
    })
    assert.throws(() => {
      requestEscalation({
        grant, agentPrivateKey: agent.privateKey, agentPublicKey: agent.publicKey,
        trigger: { type: 'multi_witness', evidence: 'fabricated' },
      })
    }, /not allowed/)
  })

  it('rejects request without human approval signature', () => {
    const human = generateKeyPair()
    const agent = generateKeyPair()
    const gateway = generateKeyPair()
    const grant = createEscalationGrant({
      delegationId: 'del-007', grantedTo: agent.publicKey, grantedBy: human.publicKey,
      granterPrivateKey: human.privateKey,
      ceiling: { scope: ['data:read'], maxSpend: 50, maxDurationMs: 60000 },
      expiresAt: future(86400000),
    })
    const request = requestEscalation({
      grant, agentPrivateKey: agent.privateKey, agentPublicKey: agent.publicKey,
      trigger: { type: 'human_authorized', evidence: 'emergency' },
    })
    assert.throws(() => {
      activateEscalation({ grant, request, gatewayPrivateKey: gateway.privateKey })
    }, /humanApprovalSignature/)
  })
})

describe('Escalated Action Checks', () => {
  function makeActiveEscalation() {
    const human = generateKeyPair()
    const agent = generateKeyPair()
    const gateway = generateKeyPair()
    const grant = createEscalationGrant({
      delegationId: 'del-008', grantedTo: agent.publicKey, grantedBy: human.publicKey,
      granterPrivateKey: human.privateKey,
      ceiling: { scope: ['data:read', 'data:write'], maxSpend: 100, maxDurationMs: 300000 },
      allowedActionClasses: ['tentative'],
      expiresAt: future(86400000),
    })
    const approvalSig = signRaw(canonicalize({ approve: grant.grantId, grantedTo: grant.grantedTo }), human.privateKey)
    const request = requestEscalation({
      grant, agentPrivateKey: agent.privateKey, agentPublicKey: agent.publicKey,
      trigger: { type: 'human_authorized', evidence: 'test', humanApprovalSignature: approvalSig },
    })
    const active = activateEscalation({ grant, request, gatewayPrivateKey: gateway.privateKey })
    return { grant, active }
  }

  it('permits tentative action within escalation scope', () => {
    const { grant, active } = makeActiveEscalation()
    const result = checkEscalatedAction({ escalation: active, grant, action: 'data:read', actionClass: 'tentative' })
    assert.equal(result.permitted, true)
    assert.equal(result.effectClass, 'tentative')
  })

  it('blocks action outside escalation scope', () => {
    const { grant, active } = makeActiveEscalation()
    const result = checkEscalatedAction({ escalation: active, grant, action: 'admin:delete', actionClass: 'tentative' })
    assert.equal(result.permitted, false)
    assert.ok(result.errors.some(e => e.includes('not within escalation scope')))
  })

  it('blocks irreversible action when only tentative permitted', () => {
    const { grant, active } = makeActiveEscalation()
    const result = checkEscalatedAction({ escalation: active, grant, action: 'data:write', actionClass: 'irreversible' })
    assert.equal(result.permitted, false)
    assert.ok(result.errors.some(e => e.includes('not permitted by grant')))
  })

  it('blocks action exceeding escalation spend limit', () => {
    const { grant, active } = makeActiveEscalation()
    active.spentDuringEscalation = 90
    const result = checkEscalatedAction({ escalation: active, grant, action: 'data:write', actionClass: 'tentative', spend: 20 })
    assert.equal(result.permitted, false)
    assert.ok(result.errors.some(e => e.includes('exceeds remaining')))
  })

  it('permits action within remaining spend budget', () => {
    const { grant, active } = makeActiveEscalation()
    active.spentDuringEscalation = 50
    const result = checkEscalatedAction({ escalation: active, grant, action: 'data:read', actionClass: 'tentative', spend: 30 })
    assert.equal(result.permitted, true)
  })
})

describe('Escalation Lifecycle', () => {
  it('revoking escalation blocks further actions', () => {
    const human = generateKeyPair()
    const agent = generateKeyPair()
    const gateway = generateKeyPair()
    const grant = createEscalationGrant({
      delegationId: 'del-009', grantedTo: agent.publicKey, grantedBy: human.publicKey,
      granterPrivateKey: human.privateKey,
      ceiling: { scope: ['data:read'], maxSpend: 50, maxDurationMs: 60000 },
      expiresAt: future(86400000),
    })
    const approvalSig = signRaw(canonicalize({ approve: grant.grantId, grantedTo: grant.grantedTo }), human.privateKey)
    const request = requestEscalation({
      grant, agentPrivateKey: agent.privateKey, agentPublicKey: agent.publicKey,
      trigger: { type: 'human_authorized', evidence: 'test', humanApprovalSignature: approvalSig },
    })
    let active = activateEscalation({ grant, request, gatewayPrivateKey: gateway.privateKey })
    assert.equal(isEscalationActive(active), true)

    active = revokeEscalation(active)
    assert.equal(active.status, 'revoked')
    assert.equal(isEscalationActive(active), false)

    const result = checkEscalatedAction({ escalation: active, grant, action: 'data:read', actionClass: 'tentative' })
    assert.equal(result.permitted, false)
    assert.ok(result.errors.some(e => e.includes('revoked')))
  })

  it('expired escalation blocks actions', () => {
    const human = generateKeyPair()
    const agent = generateKeyPair()
    const gateway = generateKeyPair()
    const grant = createEscalationGrant({
      delegationId: 'del-010', grantedTo: agent.publicKey, grantedBy: human.publicKey,
      granterPrivateKey: human.privateKey,
      ceiling: { scope: ['data:read'], maxSpend: 50, maxDurationMs: 1 }, // 1ms TTL
      expiresAt: future(86400000),
    })
    const approvalSig = signRaw(canonicalize({ approve: grant.grantId, grantedTo: grant.grantedTo }), human.privateKey)
    const request = requestEscalation({
      grant, agentPrivateKey: agent.privateKey, agentPublicKey: agent.publicKey,
      trigger: { type: 'human_authorized', evidence: 'test', humanApprovalSignature: approvalSig },
    })
    const active = activateEscalation({ grant, request, gatewayPrivateKey: gateway.privateKey })
    // Wait for TTL to expire (1ms)
    const start = Date.now(); while (Date.now() - start < 5) {} // busy wait 5ms
    const result = checkEscalatedAction({ escalation: active, grant, action: 'data:read', actionClass: 'tentative' })
    assert.equal(result.permitted, false)
    assert.ok(result.errors.some(e => e.includes('expired')))
  })
})
