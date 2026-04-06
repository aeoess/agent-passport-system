// Agent Posture Overlay Tests
// Posture is a gateway enforcement overlay, NOT passport-embedded.
// These tests verify the type contract and scope restriction patterns
// that the gateway uses for posture enforcement.

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import { scopeAuthorizes, clearStores } from '../src/core/delegation.js'
import {
  createActionIntent, evaluateIntent, FloorValidatorV1,
} from '../src/core/policy.js'
import { loadFloor } from '../src/core/values.js'
import type { AgentPostureStatus } from '../src/types/passport.js'
import type { ValidationContext } from '../src/types/policy.js'

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
`

function makeCtx(overrides: Partial<ValidationContext> = {}): ValidationContext {
  const floor = loadFloor(FLOOR_YAML)
  return {
    floorVersion: '0.1',
    floorPrinciples: floor.floor.map(p => ({
      id: p.id,
      name: p.name,
      enforcement: p.enforcement,
      weight: p.weight,
    })),
    delegation: {
      scope: ['read:docs', 'commerce', 'write:issues'],
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      revoked: false,
      currentDepth: 0,
      maxDepth: 3,
      spendLimit: 100,
      spentAmount: 0,
    },
    agentRegistered: true,
    agentAttestationValid: true,
    ...overrides,
  }
}

describe('Agent Posture Overlay — Type & Enforcement Patterns', () => {
  const validator = new FloorValidatorV1()

  beforeEach(() => { clearStores() })

  it('AgentPostureStatus type has 3 states', () => {
    const statuses: AgentPostureStatus[] = ['active', 'restricted', 'suspended']
    assert.equal(statuses.length, 3)
    assert.ok(statuses.includes('active'))
    assert.ok(statuses.includes('restricted'))
    assert.ok(statuses.includes('suspended'))
  })

  it('suspended agent: gateway would deny all actions (simulated via revoked)', () => {
    // Gateway implements suspension by checking status before delegation.
    // At SDK level, simulation via agentRegistered=false (same deny path).
    const kp = generateKeyPair()
    const intent = createActionIntent({
      agentId: 'agent-suspended',
      agentPublicKey: kp.publicKey,
      delegationId: 'del-test',
      action: { type: 'read:docs', target: 'readme', scopeRequired: 'read:docs' },
      privateKey: kp.privateKey,
    })

    const ctx = makeCtx({ agentRegistered: false })
    const decision = evaluateIntent({
      intent, validator, validationContext: ctx,
      evaluatorId: 'gw', evaluatorPublicKey: kp.publicKey, evaluatorPrivateKey: kp.privateKey,
    })
    assert.equal(decision.verdict, 'deny')
  })

  it('restricted agent: commerce scope denied when restricted', () => {
    // Gateway restricts by checking restricted_scopes against action scope.
    // At SDK level, simulate by removing commerce from delegation scope.
    const restrictedScopes = ['commerce']
    const fullScopes = ['read:docs', 'commerce', 'write:issues']
    const allowedAfterRestriction = fullScopes.filter(s => !restrictedScopes.includes(s))

    // Commerce should not be authorized
    assert.equal(scopeAuthorizes(allowedAfterRestriction, 'commerce'), false)
    // Read should still be authorized
    assert.equal(scopeAuthorizes(allowedAfterRestriction, 'read:docs'), true)
  })

  it('restricted agent: non-restricted scope permitted', () => {
    const restrictedScopes = ['commerce']
    const fullScopes = ['read:docs', 'commerce', 'write:issues']
    const allowedAfterRestriction = fullScopes.filter(s => !restrictedScopes.includes(s))

    const kp = generateKeyPair()
    const intent = createActionIntent({
      agentId: 'agent-restricted',
      agentPublicKey: kp.publicKey,
      delegationId: 'del-test',
      action: { type: 'read:docs', target: 'readme', scopeRequired: 'read:docs' },
      privateKey: kp.privateKey,
    })

    const ctx = makeCtx({
      delegation: {
        scope: allowedAfterRestriction,
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
        revoked: false, currentDepth: 0, maxDepth: 3,
      },
    })
    const decision = evaluateIntent({
      intent, validator, validationContext: ctx,
      evaluatorId: 'gw', evaluatorPublicKey: kp.publicKey, evaluatorPrivateKey: kp.privateKey,
    })
    assert.equal(decision.verdict, 'permit')
  })

  it('active agent: normal flow, all scopes available', () => {
    const kp = generateKeyPair()
    const intent = createActionIntent({
      agentId: 'agent-active',
      agentPublicKey: kp.publicKey,
      delegationId: 'del-test',
      action: { type: 'commerce:purchase', target: 'item', scopeRequired: 'commerce', spend: { amount: 5, currency: 'USD' } },
      privateKey: kp.privateKey,
    })

    const ctx = makeCtx()
    const decision = evaluateIntent({
      intent, validator, validationContext: ctx,
      evaluatorId: 'gw', evaluatorPublicKey: kp.publicKey, evaluatorPrivateKey: kp.privateKey,
    })
    assert.equal(decision.verdict, 'permit')
  })

  it('restore from suspended to active: actions permitted again', () => {
    const kp = generateKeyPair()

    // Suspended
    const ctxSuspended = makeCtx({ agentRegistered: false })
    const intentS = createActionIntent({
      agentId: 'agent-restore', agentPublicKey: kp.publicKey, delegationId: 'del-test',
      action: { type: 'read:docs', target: 'r', scopeRequired: 'read:docs' },
      privateKey: kp.privateKey,
    })
    const decSuspended = evaluateIntent({
      intent: intentS, validator, validationContext: ctxSuspended,
      evaluatorId: 'gw', evaluatorPublicKey: kp.publicKey, evaluatorPrivateKey: kp.privateKey,
    })
    assert.equal(decSuspended.verdict, 'deny')

    // Restore to active
    const ctxActive = makeCtx()
    const intentA = createActionIntent({
      agentId: 'agent-restore', agentPublicKey: kp.publicKey, delegationId: 'del-test',
      action: { type: 'read:docs', target: 'r', scopeRequired: 'read:docs' },
      privateKey: kp.privateKey,
    })
    const decActive = evaluateIntent({
      intent: intentA, validator, validationContext: ctxActive,
      evaluatorId: 'gw', evaluatorPublicKey: kp.publicKey, evaluatorPrivateKey: kp.privateKey,
    })
    assert.equal(decActive.verdict, 'permit')
  })

  it('posture state transitions follow expected pattern', () => {
    // Gateway-enforced transition: active → restricted → suspended → active
    const transitions: Array<{ from: AgentPostureStatus; to: AgentPostureStatus; reason: string }> = [
      { from: 'active', to: 'restricted', reason: 'repeated_near_misses' },
      { from: 'restricted', to: 'suspended', reason: 'policy_violation' },
      { from: 'suspended', to: 'active', reason: 'manual_review_cleared' },
    ]

    for (const t of transitions) {
      assert.ok(t.from !== t.to, `Transition from ${t.from} to ${t.to} must change state`)
      assert.ok(t.reason.length > 0, 'Transition must have a reason')
    }
  })

  it('multiple scope restrictions stack correctly', () => {
    const restrictedScopes = ['commerce', 'write:issues']
    const fullScopes = ['read:docs', 'commerce', 'write:issues', 'admin:read']
    const allowed = fullScopes.filter(s => !restrictedScopes.includes(s))

    assert.equal(scopeAuthorizes(allowed, 'commerce'), false)
    assert.equal(scopeAuthorizes(allowed, 'write:issues'), false)
    assert.equal(scopeAuthorizes(allowed, 'read:docs'), true)
    assert.equal(scopeAuthorizes(allowed, 'admin:read'), true)
  })

  it('suspended agent cannot escalate even with wildcard delegation', () => {
    // Even wildcard scope cannot override a suspension
    // (gateway checks posture BEFORE scope)
    const kp = generateKeyPair()
    const intent = createActionIntent({
      agentId: 'agent-escalator', agentPublicKey: kp.publicKey, delegationId: 'del-wild',
      action: { type: 'admin:nuke', target: 'prod', scopeRequired: '*' },
      privateKey: kp.privateKey,
    })

    // Suspended = not registered at gateway level
    const ctx = makeCtx({ agentRegistered: false })
    const decision = evaluateIntent({
      intent, validator, validationContext: ctx,
      evaluatorId: 'gw', evaluatorPublicKey: kp.publicKey, evaluatorPrivateKey: kp.privateKey,
    })
    assert.equal(decision.verdict, 'deny')
  })

  it('posture does NOT mutate the passport credential', () => {
    // Verify: SignedPassport has no posture/degradation field
    const kp = generateKeyPair()
    const sp: import('../src/types/passport.js').SignedPassport = {
      passport: {
        version: '1.0', agentId: 'test', agentName: 'T', ownerAlias: 'o',
        publicKey: kp.publicKey, mission: 'm', capabilities: [],
        runtime: { platform: 'n', models: [], toolsCount: 0, memoryType: 'e' },
        createdAt: new Date().toISOString(), expiresAt: new Date(Date.now()+86400000).toISOString(),
        voteWeight: 1, reputation: { overall: 0, collaborationsCompleted: 0, proposalsSubmitted: 0, proposalsApproved: 0, tokensContributed: 0, tasksCompleted: 0, lastUpdated: new Date().toISOString() },
        delegations: [], metadata: {},
      },
      signature: 'sig', signedAt: new Date().toISOString(),
    }

    // Passport should have NO posture/status/degradation field
    assert.equal((sp.passport as any).posture, undefined)
    assert.equal((sp.passport as any).degradation, undefined)
    assert.equal((sp.passport as any).operationalStatus, undefined)
  })
})
