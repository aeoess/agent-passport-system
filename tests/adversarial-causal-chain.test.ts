import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createTaintLabel, mergeTaints, createSAO, verifySAO,
  createExecutionFrame, recordAccess, closeFrame,
  verifyFrameChain, computeStepHash, checkDataFlow,
  createCrossChainPermit, countersignPermit
} from '../src/index.js'
import { generateKeyPair } from '../src/crypto/keys.js'

describe('ADVERSARIAL AUDIT — Causal Chain + Cross-Chain Enforcement', () => {

  // ═══ ATTACK 1: Timestamp manipulation ═══
  // Can an attacker create taint labels with future/past timestamps
  // to manipulate the chain ordering?
  it('ATK-1: Timestamp manipulation does not affect chain hash', () => {
    const t1 = createTaintLabel('alice', 'c1', 'd1')
    const t2 = { ...createTaintLabel('bob', 'c2', 'd2'), taintedAt: '2020-01-01T00:00:00Z' }
    
    let frame = createExecutionFrame('agent-1')
    frame = recordAccess(frame, t1)
    frame = recordAccess(frame, t2)
    
    // Chain should still verify because timestamps are in the taint
    // which is canonicalized into the hash
    const result = verifyFrameChain(frame)
    assert.equal(result.valid, true)
    
    // But if attacker changes timestamp AFTER recording, chain breaks
    const tampered = {
      ...frame,
      accessedContexts: [
        frame.accessedContexts[0],
        { ...frame.accessedContexts[1], taintedAt: '2099-01-01T00:00:00Z' }
      ]
    }
    const tamperedResult = verifyFrameChain(tampered)
    assert.equal(tamperedResult.valid, false, 'Timestamp tampering should break chain')
  })

  // ═══ ATTACK 2: Principal ID spoofing in taint label ═══
  // Can an attacker create a taint label claiming to be from a
  // different principal and inject it into the frame?
  it('ATK-2: Spoofed principal in taint label — gateway must be sole writer', () => {
    // The taint label itself is NOT signed. Anyone can create one.
    // Security depends on the gateway being the only entity that
    // calls recordAccess(). If agent can call it directly, they
    // can inject fake taint.
    const fakeTaint = createTaintLabel('alice', 'c1', 'd1')
    // This succeeds — the label is just a struct, not signed
    assert.equal(fakeTaint.principalId, 'alice')
    // FINDING: Taint labels are unsigned. Security property:
    // gateway is sole writer of execution frames.
  })

  // ═══ ATTACK 3: Frame reset attack ═══
  // Can an agent reset its execution frame to clear taint?
  it('ATK-3: Frame reset — creating new frame clears taint', () => {
    let frame = createExecutionFrame('agent-1')
    frame = recordAccess(frame, createTaintLabel('alice', 'c1', 'd1'))
    assert.equal(frame.frameTaint.labels.length, 1)
    
    // Attacker creates a fresh frame
    const freshFrame = createExecutionFrame('agent-1')
    assert.equal(freshFrame.frameTaint.labels.length, 0)
    // FINDING: Nothing prevents frame replacement at the module level.
    // Security depends on the gateway maintaining frame state and
    // not allowing agent to reset it.
  })

  // ═══ ATTACK 4: Chain fork attack ═══
  // Can an attacker create two divergent chains from the same frame?
  it('ATK-4: Chain fork — two branches from same state', () => {
    let frame = createExecutionFrame('agent-1')
    frame = recordAccess(frame, createTaintLabel('alice', 'c1', 'd1'))
    const checkpoint = { ...frame }
    
    // Branch A: record bob access
    const branchA = recordAccess(checkpoint, createTaintLabel('bob', 'c2', 'd2'))
    // Branch B: record charlie access
    const branchB = recordAccess(checkpoint, createTaintLabel('charlie', 'c3', 'd3'))
    
    // Both branches verify independently
    assert.equal(verifyFrameChain(branchA).valid, true)
    assert.equal(verifyFrameChain(branchB).valid, true)
    
    // But they have different chain heads — fork is detectable
    assert.notEqual(branchA.chainHead, branchB.chainHead)
    // FINDING: Fork is possible at the module level but detectable.
    // Gateway must maintain single authoritative frame per agent.
  })

  // ═══ ATTACK 5: Permit scope bypass ═══
  // Can an attacker use a permit for scope X to authorize scope Y?
  it('ATK-5: Permit scope bypass — wrong scope should be blocked', () => {
    const keys = generateKeyPair()
    const keysB = generateKeyPair()
    
    const halfPermit = createCrossChainPermit({
      sourcePrincipalId: keys.publicKey,
      sourcePrincipalPublicKey: keys.publicKey,
      sourceDataClasses: ['data:read'],
      destPrincipalId: keysB.publicKey,
      destPrincipalPublicKey: keysB.publicKey,
      destAllowedScopes: ['data:write'],  // Only write allowed
      purpose: 'test',
      sourcePrivateKey: keys.privateKey
    })
    const permit = countersignPermit(halfPermit, keysB.privateKey)
    
    let frame = createExecutionFrame('agent-1')
    frame = recordAccess(frame, createTaintLabel(keys.publicKey, 'c1', 'd1'))
    
    // Try to use permit for commerce:purchase (not covered by data:write)
    const result = checkDataFlow({
      inputTaint: frame.frameTaint,
      actionPrincipalId: keysB.publicKey,
      actionScope: 'commerce:purchase',
      permits: [permit],
      frame
    })
    assert.equal(result.verdict, 'blocked', 'Wrong scope should be blocked')
  })

  // ═══ ATTACK 6: SAO data tampering ═══
  // Can an attacker modify SAO data after creation?
  it('ATK-6: SAO data tampering detected by hash', () => {
    const keys = generateKeyPair()
    const sao = createSAO(
      { secret: 'classified' },
      createTaintLabel('alice', 'c1', 'd1'),
      keys.privateKey,
      keys.publicKey
    )
    
    assert.equal(verifySAO(sao), true)
    
    // Tamper with data
    const tampered = { ...sao, data: { secret: 'declassified' } }
    assert.equal(verifySAO(tampered), false, 'Tampered SAO should fail verification')
  })

  // ═══ ATTACK 7: Taint laundering via summarization ═══
  // Agent reads Alice's data, summarizes it, and tries to claim
  // the summary is "new" data without Alice's taint
  it('ATK-7: Taint laundering — frame taint survives summarization', () => {
    let frame = createExecutionFrame('agent-1')
    frame = recordAccess(frame, createTaintLabel('alice', 'c1', 'd1'))
    
    // Agent "summarizes" (internally, we don't track this)
    // But the frame still has alice's taint
    
    // Agent tries to send "summary" under bob's delegation
    const result = checkDataFlow({
      inputTaint: frame.frameTaint,
      actionPrincipalId: 'bob',
      actionScope: 'data:write',
      permits: [],
      frame
    })
    assert.equal(result.verdict, 'blocked', 'Laundered data should still be blocked')
  })

  // ═══ ATTACK 8: Expired permit reuse ═══
  it('ATK-8: Expired permit should not authorize flow', () => {
    const keys = generateKeyPair()
    const keysB = generateKeyPair()
    
    const halfPermit = createCrossChainPermit({
      sourcePrincipalId: keys.publicKey,
      sourcePrincipalPublicKey: keys.publicKey,
      sourceDataClasses: ['*'],
      destPrincipalId: keysB.publicKey,
      destPrincipalPublicKey: keysB.publicKey,
      destAllowedScopes: ['*'],
      purpose: 'test',
      expiresInHours: -1, // Already expired
      sourcePrivateKey: keys.privateKey
    })
    const permit = countersignPermit(halfPermit, keysB.privateKey)
    
    let frame = createExecutionFrame('agent-1')
    frame = recordAccess(frame, createTaintLabel(keys.publicKey, 'c1', 'd1'))
    
    const result = checkDataFlow({
      inputTaint: frame.frameTaint,
      actionPrincipalId: keysB.publicKey,
      actionScope: 'data:write',
      permits: [permit],
      frame
    })
    assert.equal(result.verdict, 'blocked', 'Expired permit should not work')
  })

  // ═══ ATTACK 9: Read-only data exfiltration ═══
  it('ATK-9: Read-only data blocks even same-principal outbound', () => {
    let frame = createExecutionFrame('agent-1')
    frame = recordAccess(frame, createTaintLabel('alice', 'c1', 'd1', 'read-only'))
    
    // Same principal, but data is read-only
    const result = checkDataFlow({
      inputTaint: frame.frameTaint,
      actionPrincipalId: 'alice',
      actionScope: 'data:write',
      permits: [],
      frame
    })
    assert.equal(result.verdict, 'blocked', 'Read-only data should block even same principal')
  })

  // ═══ ATTACK 10: Three-principal confused deputy ═══
  it('ATK-10: Three principals — all pairs need permits', () => {
    const keysA = generateKeyPair()
    const keysB = generateKeyPair()
    const keysC = generateKeyPair()
    
    // Permit A→B exists
    const halfAB = createCrossChainPermit({
      sourcePrincipalId: keysA.publicKey,
      sourcePrincipalPublicKey: keysA.publicKey,
      sourceDataClasses: ['*'],
      destPrincipalId: keysB.publicKey,
      destPrincipalPublicKey: keysB.publicKey,
      destAllowedScopes: ['*'],
      purpose: 'test',
      sourcePrivateKey: keysA.privateKey
    })
    const permitAB = countersignPermit(halfAB, keysB.privateKey)
    
    let frame = createExecutionFrame('agent-1')
    frame = recordAccess(frame, createTaintLabel(keysA.publicKey, 'c1', 'd1'))
    frame = recordAccess(frame, createTaintLabel(keysC.publicKey, 'c3', 'd3'))
    
    // Try action under B — has permit from A but NOT from C
    const result = checkDataFlow({
      inputTaint: frame.frameTaint,
      actionPrincipalId: keysB.publicKey,
      actionScope: 'data:write',
      permits: [permitAB],
      frame
    })
    assert.equal(result.verdict, 'blocked', 'Missing C→B permit should block')
  })

  // ═══ ATTACK 11: Chain head without matching steps ═══
  it('ATK-11: Fabricated chain head with empty steps', () => {
    const frame = createExecutionFrame('agent-1')
    const fabricated = { ...frame, chainHead: 'fabricated_hash_value', stepCount: 1 }
    const result = verifyFrameChain(fabricated)
    assert.equal(result.valid, false, 'Fabricated chain head should fail')
  })

  // ═══ ATTACK 12: Step insertion in middle of chain ═══
  it('ATK-12: Inserting a step in the middle breaks chain', () => {
    let frame = createExecutionFrame('agent-1')
    frame = recordAccess(frame, createTaintLabel('alice', 'c1', 'd1'))
    frame = recordAccess(frame, createTaintLabel('bob', 'c2', 'd2'))
    
    // Insert a fake step between steps 0 and 1
    const inserted = {
      ...frame,
      accessedContexts: [
        frame.accessedContexts[0],
        createTaintLabel('charlie', 'c3', 'd3'), // inserted
        frame.accessedContexts[1]
      ],
      stepCount: 3
    }
    const result = verifyFrameChain(inserted)
    assert.equal(result.valid, false, 'Inserted step should break chain')
  })
})
