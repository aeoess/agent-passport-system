// Values Floor — Loading, Attestation, Compliance, Common Ground
// Adversarial scenarios marked with [ADVERSARIAL]

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createPassport, clearStores,
  loadFloor, attestFloor, verifyAttestation,
  evaluateCompliance, negotiateCommonGround,
  createDelegation, createReceipt
} from '../src/index.js'
import type { ActionReceipt } from '../src/index.js'

const human = generateKeyPair()
const agentA = generateKeyPair()
const agentB = generateKeyPair()
const verifier = generateKeyPair()

const FLOOR_YAML = `
version: "0.1"
schema: "agent-social-contract/values-floor"
last_updated: "2026-02-20"
governance_uri: "https://aeoess.com/protocol.html"
floor:
  - id: "F-001"
    name: "Traceability"
    principle: "Every action traceable to a human"
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

const FLOOR_JSON = JSON.stringify({
  version: '0.1',
  schema: 'agent-social-contract/values-floor',
  lastUpdated: '2026-02-20',
  governanceUri: 'https://aeoess.com/protocol.html',
  floor: [
    { id: 'F-001', name: 'Traceability', principle: 'Every action traceable', enforcement: { technical: true, mechanism: 'Chains' }, weight: 'mandatory' },
    { id: 'F-002', name: 'Honest Identity', principle: 'No misrepresentation', enforcement: { technical: true, mechanism: 'Passport' }, weight: 'mandatory' }
  ]
})

describe('Floor Loading', () => {
  it('loads floor from YAML', () => {
    const floor = loadFloor(FLOOR_YAML)
    assert.equal(floor.version, '0.1')
    assert.equal(floor.floor.length, 7)
    assert.equal(floor.floor[0].id, 'F-001')
  })

  it('loads floor from JSON', () => {
    const floor = loadFloor(FLOOR_JSON)
    assert.equal(floor.version, '0.1')
    assert.equal(floor.floor.length, 2)
  })

  it('parses enforcement flags correctly', () => {
    const floor = loadFloor(FLOOR_YAML)
    const f001 = floor.floor.find(p => p.id === 'F-001')
    assert.ok(f001!.enforcement.technical)
    const f006 = floor.floor.find(p => p.id === 'F-006')
    assert.ok(!f006!.enforcement.technical)
  })
})

describe('Floor Attestation', () => {
  it('creates and verifies valid attestation', () => {
    const att = attestFloor(
      'agent-a', agentA.publicKey, '0.1', [], agentA.privateKey
    )
    assert.ok(att.attestationId.startsWith('att_'))
    const v = verifyAttestation(att)
    assert.ok(v.valid)
  })

  it('attestation includes extensions', () => {
    const att = attestFloor(
      'agent-a', agentA.publicKey, '0.1',
      ['creative-work', 'medical-context'],
      agentA.privateKey
    )
    assert.ok(att.commitment.includes('creative-work'))
  })

  it('[ADVERSARIAL] rejects tampered attestation', () => {
    const att = attestFloor(
      'agent-a', agentA.publicKey, '0.1', [], agentA.privateKey
    )
    att.floorVersion = '9.9'  // tamper
    const v = verifyAttestation(att)
    assert.ok(!v.valid)
    assert.ok(v.errors.some(e => e.includes('Invalid attestation signature')))
  })

  it('[ADVERSARIAL] detects expired attestation', () => {
    const att = attestFloor(
      'agent-a', agentA.publicKey, '0.1', [], agentA.privateKey, -1
    )
    const v = verifyAttestation(att)
    assert.ok(!v.valid)
    assert.ok(v.errors.some(e => e.includes('expired')))
  })
})

describe('Compliance Evaluation', () => {
  beforeEach(() => clearStores())

  it('fully compliant agent scores high', () => {
    const floor = loadFloor(FLOOR_YAML)
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      privateKey: human.privateKey
    })
    const receipt = createReceipt({
      agentId: 'agent-a',
      delegationId: d.delegationId,
      delegation: d,
      action: { type: 'execute', target: 'task', scopeUsed: 'code_execution' },
      result: { status: 'success', summary: 'done' },
      delegationChain: [human.publicKey, agentA.publicKey],
      privateKey: agentA.privateKey
    })
    const delegationContext = new Map([[d.delegationId, { scope: d.scope, revoked: false }]])
    const report = evaluateCompliance(
      'agent-a', [receipt], floor, delegationContext, verifier.privateKey
    )
    assert.ok(report.overallCompliance > 0.8)
    const enforced = report.checks.filter(c => c.status === 'enforced')
    assert.ok(enforced.length >= 4)
  })

  it('[ADVERSARIAL] detects violation: action under revoked delegation', () => {
    const floor = loadFloor(FLOOR_YAML)
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      privateKey: human.privateKey
    })
    const receipt = createReceipt({
      agentId: 'agent-a',
      delegationId: d.delegationId,
      delegation: d,
      action: { type: 'execute', target: 'task', scopeUsed: 'code_execution' },
      result: { status: 'success', summary: 'done' },
      delegationChain: [human.publicKey, agentA.publicKey],
      privateKey: agentA.privateKey
    })
    // Mark delegation as revoked in context
    const delegationContext = new Map([[d.delegationId, { scope: d.scope, revoked: true }]])
    const report = evaluateCompliance(
      'agent-a', [receipt], floor, delegationContext, verifier.privateKey
    )
    const f004 = report.checks.find(c => c.principleId === 'F-004')
    assert.equal(f004!.status, 'violation')
  })

  it('[ADVERSARIAL] detects violation: action outside scope', () => {
    const floor = loadFloor(FLOOR_YAML)
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['web_search'],
      privateKey: human.privateKey
    })
    const receipt = createReceipt({
      agentId: 'agent-a',
      delegationId: d.delegationId,
      delegation: d,
      action: { type: 'search', target: 'query', scopeUsed: 'web_search' },
      result: { status: 'success', summary: 'done' },
      delegationChain: [human.publicKey, agentA.publicKey],
      privateKey: agentA.privateKey
    })
    // Context says delegation only allows code_execution — mismatch with receipt
    const delegationContext = new Map([[d.delegationId, { scope: ['code_execution'], revoked: false }]])
    const report = evaluateCompliance(
      'agent-a', [receipt], floor, delegationContext, verifier.privateKey
    )
    const f003 = report.checks.find(c => c.principleId === 'F-003')
    assert.equal(f003!.status, 'violation')
  })
})

describe('Common Ground Negotiation', () => {
  it('compatible agents find common ground', () => {
    const pA = createPassport({
      agentId: 'a', agentName: 'A', ownerAlias: 'o', mission: 'm',
      capabilities: ['code_execution'],
      runtime: { platform: 't', models: ['m'], toolsCount: 1, memoryType: 'm' }
    })
    const pB = createPassport({
      agentId: 'b', agentName: 'B', ownerAlias: 'o', mission: 'm',
      capabilities: ['web_search'],
      runtime: { platform: 't', models: ['m'], toolsCount: 1, memoryType: 'm' }
    })
    const attA = attestFloor('a', pA.keyPair.publicKey, '0.1', ['creative-work'], pA.keyPair.privateKey)
    const attB = attestFloor('b', pB.keyPair.publicKey, '0.1', ['creative-work', 'medical'], pB.keyPair.privateKey)

    const ground = negotiateCommonGround(
      pA.signedPassport.passport, attA,
      pB.signedPassport.passport, attB
    )
    assert.ok(ground.compatible)
    assert.equal(ground.floorVersion, '0.1')
    assert.deepEqual(ground.sharedExtensions, ['creative-work'])
  })

  it('[ADVERSARIAL] incompatible floor versions rejected', () => {
    const pA = createPassport({
      agentId: 'a', agentName: 'A', ownerAlias: 'o', mission: 'm',
      capabilities: ['code_execution'],
      runtime: { platform: 't', models: ['m'], toolsCount: 1, memoryType: 'm' }
    })
    const pB = createPassport({
      agentId: 'b', agentName: 'B', ownerAlias: 'o', mission: 'm',
      capabilities: ['web_search'],
      runtime: { platform: 't', models: ['m'], toolsCount: 1, memoryType: 'm' }
    })
    const attA = attestFloor('a', pA.keyPair.publicKey, '0.1', [], pA.keyPair.privateKey)
    const attB = attestFloor('b', pB.keyPair.publicKey, '2.0', [], pB.keyPair.privateKey)

    const ground = negotiateCommonGround(
      pA.signedPassport.passport, attA,
      pB.signedPassport.passport, attB
    )
    assert.ok(!ground.compatible)
    assert.ok(ground.incompatibilityReasons.some(r => r.includes('Incompatible')))
  })
})
