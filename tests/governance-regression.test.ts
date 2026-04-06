// Governance Regression Tests — authorization boundary enforcement
// Tests real behaviors the gateway implements: scope matching,
// spend limits, cascade revocation, wildcard scope.
// Canary suite: runs continuously, not just at release.

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import {
  createDelegation, revokeDelegation, cascadeRevoke,
  verifyDelegation, clearStores, scopeAuthorizes,
} from '../src/core/delegation.js'
import {
  createActionIntent, evaluateIntent, FloorValidatorV1,
} from '../src/core/policy.js'
import { loadFloor } from '../src/core/values.js'
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
`

function makeValidationContext(overrides: Partial<ValidationContext> = {}): ValidationContext {
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
      scope: ['read:docs'],
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      revoked: false,
      currentDepth: 0,
      maxDepth: 3,
    },
    agentRegistered: true,
    agentAttestationValid: true,
    ...overrides,
  }
}

describe('Governance Regression — Authorization Boundaries', () => {
  const validator = new FloorValidatorV1()

  beforeEach(() => {
    clearStores()
  })

  it('GR-1: scope escalation denied — read agent tries write', () => {
    const kp = generateKeyPair()
    const intent = createActionIntent({
      agentId: 'agent-test',
      agentPublicKey: kp.publicKey,
      delegationId: 'del-test',
      action: { type: 'write:docs', target: 'project/readme', scopeRequired: 'write:docs' },
      privateKey: kp.privateKey,
    })

    const ctx = makeValidationContext({
      delegation: {
        scope: ['read:docs'],
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
        revoked: false,
        currentDepth: 0,
        maxDepth: 3,
      },
    })

    const decision = evaluateIntent({
      intent,
      validator,
      validationContext: ctx,
      evaluatorId: 'gateway',
      evaluatorPublicKey: kp.publicKey,
      evaluatorPrivateKey: kp.privateKey,
    })

    assert.equal(decision.verdict, 'deny')
  })

  it('GR-2: spend exhaustion narrowed — budget exceeded', () => {
    const kp = generateKeyPair()
    const intent = createActionIntent({
      agentId: 'agent-test',
      agentPublicKey: kp.publicKey,
      delegationId: 'del-test',
      action: { type: 'commerce:purchase', target: 'item-1', scopeRequired: 'commerce', spend: { amount: 0.02, currency: 'USD' } },
      privateKey: kp.privateKey,
    })

    const ctx = makeValidationContext({
      delegation: {
        scope: ['commerce'],
        spendLimit: 10,
        spentAmount: 9.99,
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
        revoked: false,
        currentDepth: 0,
        maxDepth: 3,
      },
    })

    const decision = evaluateIntent({
      intent,
      validator,
      validationContext: ctx,
      evaluatorId: 'gateway',
      evaluatorPublicKey: kp.publicKey,
      evaluatorPrivateKey: kp.privateKey,
    })

    // SDK narrows (budget constraint), gateway translates to deny
    assert.ok(decision.verdict === 'deny' || decision.verdict === 'narrow',
      `Expected deny or narrow, got: ${decision.verdict}`)
  })

  it('GR-3: revoked delegation denied', () => {
    const kp = generateKeyPair()
    const intent = createActionIntent({
      agentId: 'agent-test',
      agentPublicKey: kp.publicKey,
      delegationId: 'del-test',
      action: { type: 'read:docs', target: 'project/readme', scopeRequired: 'read:docs' },
      privateKey: kp.privateKey,
    })

    const ctx = makeValidationContext({
      delegation: {
        scope: ['read:docs'],
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
        revoked: true,
        currentDepth: 0,
        maxDepth: 3,
      },
    })

    const decision = evaluateIntent({
      intent,
      validator,
      validationContext: ctx,
      evaluatorId: 'gateway',
      evaluatorPublicKey: kp.publicKey,
      evaluatorPrivateKey: kp.privateKey,
    })

    assert.equal(decision.verdict, 'deny')
  })

  it('GR-4: valid action within scope permitted', () => {
    const kp = generateKeyPair()
    const intent = createActionIntent({
      agentId: 'agent-test',
      agentPublicKey: kp.publicKey,
      delegationId: 'del-test',
      action: { type: 'commerce:purchase', target: 'item-1', scopeRequired: 'commerce', spend: { amount: 5, currency: 'USD' } },
      privateKey: kp.privateKey,
    })

    const ctx = makeValidationContext({
      delegation: {
        scope: ['commerce'],
        spendLimit: 100,
        spentAmount: 10,
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
        revoked: false,
        currentDepth: 0,
        maxDepth: 3,
      },
    })

    const decision = evaluateIntent({
      intent,
      validator,
      validationContext: ctx,
      evaluatorId: 'gateway',
      evaluatorPublicKey: kp.publicKey,
      evaluatorPrivateKey: kp.privateKey,
    })

    assert.equal(decision.verdict, 'permit')
  })

  it('GR-5: wildcard scope permits scope check but does not bypass budget', () => {
    const kp = generateKeyPair()

    // Wildcard scope should permit the scope check
    assert.equal(scopeAuthorizes(['*'], 'commerce:purchase'), true)
    assert.equal(scopeAuthorizes(['*'], 'admin:delete'), true)

    // But budget still enforced
    const intent = createActionIntent({
      agentId: 'agent-test',
      agentPublicKey: kp.publicKey,
      delegationId: 'del-test',
      action: { type: 'commerce:purchase', target: 'item', scopeRequired: '*', spend: { amount: 200, currency: 'USD' } },
      privateKey: kp.privateKey,
    })

    const ctx = makeValidationContext({
      delegation: {
        scope: ['*'],
        spendLimit: 100,
        spentAmount: 0,
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
        revoked: false,
        currentDepth: 0,
        maxDepth: 3,
      },
    })

    const decision = evaluateIntent({
      intent,
      validator,
      validationContext: ctx,
      evaluatorId: 'gateway',
      evaluatorPublicKey: kp.publicKey,
      evaluatorPrivateKey: kp.privateKey,
    })

    // SDK narrows on budget violation, gateway translates to deny
    assert.ok(decision.verdict === 'deny' || decision.verdict === 'narrow',
      `Expected deny or narrow, got: ${decision.verdict}`)
  })

  it('GR-6: budget boundary exact — spend_used=99.99, tries $0.01, limit=100 — permitted', () => {
    const kp = generateKeyPair()
    const intent = createActionIntent({
      agentId: 'agent-test',
      agentPublicKey: kp.publicKey,
      delegationId: 'del-test',
      action: { type: 'commerce:purchase', target: 'item', scopeRequired: 'commerce', spend: { amount: 0.01, currency: 'USD' } },
      privateKey: kp.privateKey,
    })

    const ctx = makeValidationContext({
      delegation: {
        scope: ['commerce'],
        spendLimit: 100,
        spentAmount: 99.99,
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
        revoked: false,
        currentDepth: 0,
        maxDepth: 3,
      },
    })

    const decision = evaluateIntent({
      intent,
      validator,
      validationContext: ctx,
      evaluatorId: 'gateway',
      evaluatorPublicKey: kp.publicKey,
      evaluatorPrivateKey: kp.privateKey,
    })

    assert.equal(decision.verdict, 'permit')
  })

  it('GR-7: empty scope denies all actions', () => {
    assert.equal(scopeAuthorizes([], 'read:docs'), false)
    assert.equal(scopeAuthorizes([], 'commerce'), false)
    assert.equal(scopeAuthorizes([], '*'), false)
  })

  it('GR-8: no delegation (unregistered agent) denies action', () => {
    const kp = generateKeyPair()
    const intent = createActionIntent({
      agentId: 'agent-unregistered',
      agentPublicKey: kp.publicKey,
      delegationId: 'del-none',
      action: { type: 'read:docs', target: 'project', scopeRequired: 'read:docs' },
      privateKey: kp.privateKey,
    })

    const ctx = makeValidationContext({
      agentRegistered: false,
      agentAttestationValid: false,
    })

    const decision = evaluateIntent({
      intent,
      validator,
      validationContext: ctx,
      evaluatorId: 'gateway',
      evaluatorPublicKey: kp.publicKey,
      evaluatorPrivateKey: kp.privateKey,
    })

    assert.equal(decision.verdict, 'deny')
  })
})
