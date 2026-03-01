// Graduated Enforcement Tests
// Tests the inline/audit/warn enforcement modes on Values Floor principles
// Part of the Agent Passport System v1.8.0

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair,
  loadFloor,
  resolveEnforcementMode, effectiveEnforcementMode,
  createActionIntent,
  evaluateIntent,
  FloorValidatorV1,
  ENFORCEMENT_ESCALATION_ORDER,
} from '../src/index.js'
import type { EnforcementMode, FloorPrinciple } from '../src/index.js'
import type { ValidationContext } from '../src/types/policy.js'

// ── Fixtures ──

const FLOOR_YAML = `
version: "0.2"
schema: "agent-social-contract/values-floor"
last_updated: "2026-03-01"
governance_uri: "https://aeoess.com/protocol.html"

floor:
  - id: "F-001"
    name: "Traceability"
    principle: "Every action traceable"
    enforcement:
      mode: inline
      technical: true
      mechanism: "Delegation chains"
    weight: "mandatory"
  - id: "F-002"
    name: "Honest Identity"
    principle: "No impersonation"
    enforcement:
      mode: inline
      technical: true
      mechanism: "Passport verification"
    weight: "mandatory"
  - id: "F-003"
    name: "Scoped Authority"
    principle: "Stay within scope"
    enforcement:
      mode: inline
      technical: true
      mechanism: "Delegation scopes"
    weight: "mandatory"
  - id: "F-004"
    name: "Revocability"
    principle: "Humans can revoke"
    enforcement:
      mode: inline
      technical: true
      mechanism: "Revocation registry"
    weight: "mandatory"
  - id: "F-005"
    name: "Auditability"
    principle: "All actions auditable"
    enforcement:
      mode: inline
      technical: true
      mechanism: "Action receipts"
    weight: "mandatory"
  - id: "F-006"
    name: "Non-Deception"
    principle: "No manipulation"
    enforcement:
      mode: audit
      technical: false
      mechanism: "Reputation"
    weight: "strong_consideration"
  - id: "F-007"
    name: "Proportionality"
    principle: "Autonomy proportional to trust"
    enforcement:
      mode: warn
      technical: false
      mechanism: "Reputation"
    weight: "strong_consideration"
`

// Floor with F-003 set to 'audit' instead of 'inline' (weaker enforcement)
const RELAXED_FLOOR_YAML = `
version: "0.2"
schema: "agent-social-contract/values-floor"
last_updated: "2026-03-01"
governance_uri: "https://aeoess.com/protocol.html"

floor:
  - id: "F-001"
    name: "Traceability"
    principle: "Every action traceable"
    enforcement:
      mode: inline
      technical: true
      mechanism: "Delegation chains"
    weight: "mandatory"
  - id: "F-002"
    name: "Honest Identity"
    principle: "No impersonation"
    enforcement:
      mode: inline
      technical: true
      mechanism: "Passport verification"
    weight: "mandatory"
  - id: "F-003"
    name: "Scoped Authority"
    principle: "Stay within scope"
    enforcement:
      mode: audit
      technical: true
      mechanism: "Delegation scopes"
    weight: "mandatory"
  - id: "F-004"
    name: "Revocability"
    principle: "Humans can revoke"
    enforcement:
      mode: inline
      technical: true
      mechanism: "Revocation registry"
    weight: "mandatory"
  - id: "F-005"
    name: "Auditability"
    principle: "All actions auditable"
    enforcement:
      mode: inline
      technical: true
      mechanism: "Action receipts"
    weight: "mandatory"
  - id: "F-006"
    name: "Non-Deception"
    principle: "No manipulation"
    enforcement:
      mode: audit
      technical: false
      mechanism: "Reputation"
    weight: "strong_consideration"
  - id: "F-007"
    name: "Proportionality"
    principle: "Autonomy proportional to trust"
    enforcement:
      mode: warn
      technical: false
      mechanism: "Reputation"
    weight: "strong_consideration"
`

const agent = generateKeyPair()
const evaluator = generateKeyPair()

function makeCtx(overrides?: Partial<ValidationContext>): ValidationContext {
  const floor = loadFloor(FLOOR_YAML)
  return {
    floorVersion: '0.2',
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

function makeIntent(scopeRequired = 'code_execution') {
  return createActionIntent({
    agentId: 'test-agent',
    agentPublicKey: agent.publicKey,
    delegationId: 'del_test',
    action: { type: 'execute', target: 'task', scopeRequired },
    context: 'Graduated enforcement test',
    privateKey: agent.privateKey
  })
}

// ══════════════════════════════════════
// FLOOR LOADING — Enforcement Modes
// ══════════════════════════════════════

describe('Floor Loading — Enforcement Modes', () => {
  it('parses mode field from YAML', () => {
    const floor = loadFloor(FLOOR_YAML)
    const f001 = floor.floor.find(p => p.id === 'F-001')!
    const f006 = floor.floor.find(p => p.id === 'F-006')!
    const f007 = floor.floor.find(p => p.id === 'F-007')!
    assert.equal(f001.enforcement.mode, 'inline')
    assert.equal(f006.enforcement.mode, 'audit')
    assert.equal(f007.enforcement.mode, 'warn')
  })

  it('resolves mode from technical flag when mode absent (backward compat)', () => {
    const oldYaml = `
version: "0.1"
schema: "test"
last_updated: "2026-01-01"
governance_uri: "test"
floor:
  - id: "F-001"
    name: "Test"
    principle: "Test principle"
    enforcement:
      technical: true
      mechanism: "test"
    weight: "mandatory"
  - id: "F-006"
    name: "Soft"
    principle: "Soft principle"
    enforcement:
      technical: false
      mechanism: "reputation"
    weight: "strong_consideration"
`
    const floor = loadFloor(oldYaml)
    const f001 = floor.floor.find(p => p.id === 'F-001')!
    const f006 = floor.floor.find(p => p.id === 'F-006')!
    // Post-processing resolves mode from technical flag
    assert.equal(f001.enforcement.mode, 'inline')
    assert.equal(f006.enforcement.mode, 'audit')
  })

  it('all 7 principles have enforcement mode set after loading', () => {
    const floor = loadFloor(FLOOR_YAML)
    for (const p of floor.floor) {
      assert.ok(p.enforcement.mode, `${p.id} missing enforcement mode`)
      assert.ok(
        ['inline', 'audit', 'warn'].includes(p.enforcement.mode),
        `${p.id} has invalid mode: ${p.enforcement.mode}`
      )
    }
  })
})

// ══════════════════════════════════════
// resolveEnforcementMode
// ══════════════════════════════════════

describe('resolveEnforcementMode', () => {
  it('returns mode when explicitly set', () => {
    assert.equal(resolveEnforcementMode({ mode: 'warn', technical: true, mechanism: '' }), 'warn')
    assert.equal(resolveEnforcementMode({ mode: 'audit', technical: true, mechanism: '' }), 'audit')
    assert.equal(resolveEnforcementMode({ mode: 'inline', technical: false, mechanism: '' }), 'inline')
  })

  it('falls back to technical flag when mode absent', () => {
    assert.equal(resolveEnforcementMode({ technical: true, mechanism: '' } as any), 'inline')
    assert.equal(resolveEnforcementMode({ technical: false, mechanism: '' } as any), 'audit')
  })

  it('defaults to audit when nothing set', () => {
    assert.equal(resolveEnforcementMode({ mechanism: '' } as any), 'audit')
  })
})

// ══════════════════════════════════════
// effectiveEnforcementMode (narrowing)
// ══════════════════════════════════════

describe('effectiveEnforcementMode — Extension Narrowing', () => {
  it('escalation order: warn < audit < inline', () => {
    assert.ok(ENFORCEMENT_ESCALATION_ORDER['warn'] < ENFORCEMENT_ESCALATION_ORDER['audit'])
    assert.ok(ENFORCEMENT_ESCALATION_ORDER['audit'] < ENFORCEMENT_ESCALATION_ORDER['inline'])
  })

  it('returns floor mode when no extensions', () => {
    assert.equal(effectiveEnforcementMode('audit'), 'audit')
    assert.equal(effectiveEnforcementMode('inline'), 'inline')
  })

  it('extension can escalate audit → inline', () => {
    assert.equal(effectiveEnforcementMode('audit', 'inline'), 'inline')
  })

  it('extension can escalate warn → audit', () => {
    assert.equal(effectiveEnforcementMode('warn', 'audit'), 'audit')
  })

  it('extension cannot de-escalate inline → audit', () => {
    assert.equal(effectiveEnforcementMode('inline', 'audit'), 'inline')
  })

  it('strictest wins across multiple extensions', () => {
    assert.equal(effectiveEnforcementMode('audit', 'warn', 'audit', 'inline'), 'inline')
  })
})

// ══════════════════════════════════════
// FloorValidatorV1 — Graduated Enforcement
// ══════════════════════════════════════

describe('FloorValidatorV1 — Graduated Enforcement', () => {
  const validator = new FloorValidatorV1()

  it('inline failure → deny (scope violation blocks action)', () => {
    const intent = makeIntent('email_management') // not in scope
    const ctx = makeCtx()
    const result = validator.evaluate(
      { ...intent, signature: undefined } as any,
      ctx
    )
    assert.equal(result.verdict, 'deny')
    assert.ok(result.enforcement?.inlinePassed === false)
  })

  it('audit failure → permit with audit findings', () => {
    // Use relaxed floor where F-003 (scope) is audit instead of inline
    const floor = loadFloor(RELAXED_FLOOR_YAML)
    const ctx = makeCtx({
      floorPrinciples: floor.floor.map(p => ({
        id: p.id, name: p.name,
        enforcement: p.enforcement,
        weight: p.weight
      }))
    })
    const intent = makeIntent('email_management') // out of scope
    const result = validator.evaluate(
      { ...intent, signature: undefined } as any,
      ctx
    )
    // F-003 is audit mode — should permit but log
    assert.equal(result.verdict, 'permit')
    assert.ok(result.auditFindings, 'Expected audit findings')
    assert.ok(result.auditFindings!.length > 0, 'Expected at least one audit finding')
    assert.equal(result.auditFindings![0].principleId, 'F-003')
    assert.equal(result.enforcement?.auditIssueCount, 1)
  })

  it('all principles get enforcementMode in evaluation', () => {
    const intent = makeIntent()
    const ctx = makeCtx()
    const result = validator.evaluate(
      { ...intent, signature: undefined } as any,
      ctx
    )
    for (const pe of result.principlesEvaluated) {
      assert.ok(pe.enforcementMode, `${pe.principleId} missing enforcementMode`)
    }
  })

  it('enforcement summary reflects actual state', () => {
    const intent = makeIntent()
    const ctx = makeCtx()
    const result = validator.evaluate(
      { ...intent, signature: undefined } as any,
      ctx
    )
    assert.ok(result.enforcement)
    assert.equal(result.enforcement!.inlinePassed, true)
    assert.equal(result.enforcement!.auditIssueCount, 0)
    assert.equal(result.enforcement!.warningCount, 0)
  })

  it('inline + audit failures: deny overrides audit findings', () => {
    // Unregistered agent (F-001 inline fail) + relaxed scope check (F-003 audit fail)
    const floor = loadFloor(RELAXED_FLOOR_YAML)
    const ctx = makeCtx({
      floorPrinciples: floor.floor.map(p => ({
        id: p.id, name: p.name,
        enforcement: p.enforcement,
        weight: p.weight
      })),
      agentRegistered: false // F-001 inline failure
    })
    const intent = makeIntent('email_management') // F-003 audit failure
    const result = validator.evaluate(
      { ...intent, signature: undefined } as any,
      ctx
    )
    // Inline failure takes precedence — deny
    assert.equal(result.verdict, 'deny')
    // But audit findings still captured
    assert.ok(result.auditFindings, 'Audit findings should still be captured')
    assert.equal(result.enforcement?.inlinePassed, false)
  })

  it('full 3-sig chain works with graduated enforcement', () => {
    const intent = makeIntent()
    const ctx = makeCtx()
    const decision = evaluateIntent({
      intent,
      validator,
      validationContext: ctx,
      evaluatorId: 'eval-001',
      evaluatorPublicKey: evaluator.publicKey,
      evaluatorPrivateKey: evaluator.privateKey
    })
    assert.equal(decision.verdict, 'permit')
    assert.ok(decision.decisionId.startsWith('pdec_'))
  })
})
