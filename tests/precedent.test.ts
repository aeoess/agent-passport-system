// Precedent Control Tests (Module 25)
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import {
  createPrecedentLibrary, markAsNormative, verifyNormativePrecedent,
  addToLibrary, checkAlignment, supersedePrecedent, analyzeDrift,
} from '../src/core/precedent.js'
import type { Precedent } from '../src/types/intent.js'

function makePrecedent(id: string, subject: string, decision: string, context: string): Precedent {
  return {
    precedentId: id, deliberationId: `d-${id}`, subject, context, decision,
    agentScores: { 'agent-a': 80 }, createdAt: new Date().toISOString(), citedCount: 0,
  }
}

describe('Precedent Library — Creation & Normative Marking', () => {
  it('creates empty library', () => {
    const lib = createPrecedentLibrary()
    assert.equal(lib.precedents.length, 0)
    assert.equal(lib.categories.length, 0)
  })

  it('marks precedent as normative with signature', () => {
    const kp = generateKeyPair()
    const p = makePrecedent('p1', 'deploy to production', 'approve', 'all tests passing')
    const np = markAsNormative({ precedent: p, approverPrivateKey: kp.privateKey, approverPublicKey: kp.publicKey, category: 'deployment' })
    assert.equal(np.status, 'normative')
    assert.equal(np.category, 'deployment')
    assert.equal(np.approvedBy, kp.publicKey)
    assert.ok(np.approvalSignature)
  })

  it('verifies normative precedent signature', () => {
    const kp = generateKeyPair()
    const p = makePrecedent('p2', 'budget increase', 'deny', 'over threshold')
    const np = markAsNormative({ precedent: p, approverPrivateKey: kp.privateKey, approverPublicKey: kp.publicKey, category: 'budget' })
    assert.equal(verifyNormativePrecedent(np), true)
  })

  it('rejects tampered normative precedent', () => {
    const kp = generateKeyPair()
    const p = makePrecedent('p3', 'access request', 'approve', 'within scope')
    const np = markAsNormative({ precedent: p, approverPrivateKey: kp.privateKey, approverPublicKey: kp.publicKey, category: 'access' })
    const tampered = { ...np, decision: 'deny' }
    assert.equal(verifyNormativePrecedent(tampered), false)
  })
})

describe('Precedent Library — Alignment Checks', () => {
  it('aligns when outcome matches similar precedent', () => {
    const kp = generateKeyPair()
    let lib = createPrecedentLibrary()
    const p = makePrecedent('p1', 'deploy to production with passing tests', 'approve deployment', 'tests passing, no blockers')
    const np = markAsNormative({ precedent: p, approverPrivateKey: kp.privateKey, approverPublicKey: kp.publicKey, category: 'deployment' })
    lib = addToLibrary(lib, np)
    const result = checkAlignment(lib, { subject: 'deploy to production with all tests green', context: 'tests passing', outcome: 'approve deployment' })
    assert.equal(result.aligned, true)
    assert.equal(result.requiresDistinguishing, false)
  })

  it('requires distinguishing when outcome differs from similar precedent', () => {
    const kp = generateKeyPair()
    let lib = createPrecedentLibrary()
    const p = makePrecedent('p1', 'deploy to production with passing tests', 'approve deployment', 'tests passing, no blockers')
    const np = markAsNormative({ precedent: p, approverPrivateKey: kp.privateKey, approverPublicKey: kp.publicKey, category: 'deployment' })
    lib = addToLibrary(lib, np)
    const result = checkAlignment(lib, { subject: 'deploy to production with passing tests', context: 'tests passing but load is high', outcome: 'deny deployment' })
    assert.equal(result.aligned, false)
    assert.equal(result.requiresDistinguishing, true)
    assert.ok(result.reason.includes('Diverges'))
  })

  it('no precedent means aligned by default', () => {
    const lib = createPrecedentLibrary()
    const result = checkAlignment(lib, { subject: 'something new', context: 'never seen before', outcome: 'approve' })
    assert.equal(result.aligned, true)
    assert.equal(result.closestPrecedent, null)
  })
})

describe('Precedent Library — Supersede', () => {
  it('supersedes old precedent and marks it', () => {
    const kp = generateKeyPair()
    let lib = createPrecedentLibrary()
    const old = makePrecedent('p-old', 'deploy on Friday', 'approve', 'was ok in small team')
    const npOld = markAsNormative({ precedent: old, approverPrivateKey: kp.privateKey, approverPublicKey: kp.publicKey, category: 'deployment' })
    lib = addToLibrary(lib, npOld)
    const newer = makePrecedent('p-new', 'deploy on Friday', 'deny', 'too risky at scale')
    const npNew = markAsNormative({ precedent: newer, approverPrivateKey: kp.privateKey, approverPublicKey: kp.publicKey, category: 'deployment' })
    lib = supersedePrecedent({ library: lib, oldPrecedentId: 'p-old', newPrecedent: npNew, distinguishingNote: 'team grew, risk profile changed' })
    const oldInLib = lib.precedents.find(p => p.precedentId === 'p-old')!
    assert.equal(oldInLib.status, 'superseded')
    assert.equal(oldInLib.supersededBy, 'p-new')
    assert.equal(lib.precedents.length, 2)
  })
})

describe('Precedent Library — Drift Analysis', () => {
  it('detects drift when >20% decisions diverge from precedent', () => {
    const kp = generateKeyPair()
    let lib = createPrecedentLibrary()
    const p = makePrecedent('p1', 'deploy with passing tests', 'approve deployment', 'tests green')
    const np = markAsNormative({ precedent: p, approverPrivateKey: kp.privateKey, approverPublicKey: kp.publicKey, category: 'deployment' })
    lib = addToLibrary(lib, np)
    const decisions = [
      { id: 'd1', subject: 'deploy with passing tests', context: 'tests green', outcome: 'approve deployment' },
      { id: 'd2', subject: 'deploy with passing tests', context: 'tests green', outcome: 'approve deployment' },
      { id: 'd3', subject: 'deploy with passing tests', context: 'tests green', outcome: 'deny deployment' },
      { id: 'd4', subject: 'deploy with passing tests', context: 'tests green', outcome: 'deny deployment' },
      { id: 'd5', subject: 'deploy with passing tests', context: 'tests green', outcome: 'deny deployment' },
    ]
    const drift = analyzeDrift(lib, decisions)
    assert.equal(drift.driftDetected, true)
    assert.equal(drift.divergentCount, 3)
    assert.equal(drift.alignedCount, 2)
    assert.ok(drift.driftScore > 0.5)
  })

  it('reports no drift when decisions align', () => {
    const kp = generateKeyPair()
    let lib = createPrecedentLibrary()
    const p = makePrecedent('p1', 'deploy with passing tests', 'approve deployment', 'tests green')
    const np = markAsNormative({ precedent: p, approverPrivateKey: kp.privateKey, approverPublicKey: kp.publicKey, category: 'deploy' })
    lib = addToLibrary(lib, np)
    const decisions = [
      { id: 'd1', subject: 'deploy with passing tests', context: 'tests green', outcome: 'approve deployment' },
      { id: 'd2', subject: 'deploy with passing tests', context: 'tests green', outcome: 'approve deployment' },
    ]
    const drift = analyzeDrift(lib, decisions)
    assert.equal(drift.driftDetected, false)
    assert.equal(drift.driftScore, 0)
  })

  it('empty library means no drift', () => {
    const lib = createPrecedentLibrary()
    const decisions = [{ id: 'd1', subject: 'anything', context: 'ctx', outcome: 'approve' }]
    const drift = analyzeDrift(lib, decisions)
    assert.equal(drift.driftDetected, false)
    assert.equal(drift.evaluationCount, 1)
  })
})
