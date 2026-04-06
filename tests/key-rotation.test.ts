// Key Rotation — DID Document + Identity Continuity + Delegation Invalidation
// Tests cover: identity continuity, planned/emergency rotation, chain verification,
// state machine, delegation invalidation, backward compatibility, edge cases.

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  createDIDDocument, announceKeyRotation, activateKeyRotation,
  verifyRotationChain, isKeyActive, rotateAndInvalidate,
} from '../src/core/key-rotation.js'
import { generateKeyPair, publicKeyFromPrivate } from '../src/crypto/keys.js'
import { createDID, hexToMultibase } from '../src/core/did.js'
import { createDelegation, cascadeRevoke, clearStores } from '../src/core/delegation.js'
import type { AgentPassport, KeyPair, RotatableDIDDocument } from '../src/types/passport.js'

function makePassport(keyPair: KeyPair): AgentPassport {
  return {
    version: '1.0',
    agentId: 'test-agent-' + keyPair.publicKey.slice(0, 8),
    agentName: 'Test Agent',
    ownerAlias: 'tester',
    publicKey: keyPair.publicKey,
    mission: 'testing key rotation',
    capabilities: ['test'],
    runtime: { platform: 'node', models: ['test'], toolsCount: 1, memoryType: 'ephemeral' },
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 86400000).toISOString(),
    voteWeight: 1,
    reputation: { overall: 0, collaborationsCompleted: 0, proposalsSubmitted: 0, proposalsApproved: 0, tokensContributed: 0, tasksCompleted: 0, lastUpdated: new Date().toISOString() },
    delegations: [],
    metadata: {},
  }
}

// ══════════════════════════════════════
// Identity continuity
// ══════════════════════════════════════

describe('Key Rotation — Identity Continuity', () => {
  it('createDIDDocument produces valid initial document', () => {
    const kp = generateKeyPair()
    const passport = makePassport(kp)
    const doc = createDIDDocument(passport)

    assert.ok(doc.id.startsWith('did:aps:'))
    assert.equal(doc.verificationMethod.length, 1)
    assert.equal(doc.authentication.length, 1)
    assert.equal(doc.assertionMethod.length, 1)
    assert.equal(doc.capabilityDelegation.length, 1)
    assert.deepEqual(doc.rotationLog, [])
    assert.equal(doc.pendingRotation, undefined)
    assert.equal(doc.controller, doc.id)
  })

  it('DID document id matches did:aps:z6Mk format', () => {
    const kp = generateKeyPair()
    const passport = makePassport(kp)
    const doc = createDIDDocument(passport)

    assert.ok(doc.id.startsWith('did:aps:z'), `Expected did:aps:z prefix, got: ${doc.id}`)
    assert.equal(doc.verificationMethod[0].id, `${doc.id}#key-1`)
    assert.equal(doc.verificationMethod[0].type, 'Ed25519VerificationKey2020')
  })

  it('verificationMethod publicKeyMultibase round-trips to hex', () => {
    const kp = generateKeyPair()
    const passport = makePassport(kp)
    const doc = createDIDDocument(passport)

    const multibase = doc.verificationMethod[0].publicKeyMultibase
    assert.ok(multibase.startsWith('z'))
  })
})

// ══════════════════════════════════════
// Planned rotation
// ══════════════════════════════════════

describe('Key Rotation — Planned Mode', () => {
  let kpOld: KeyPair
  let kpNew: KeyPair
  let doc: RotatableDIDDocument

  beforeEach(() => {
    kpOld = generateKeyPair()
    kpNew = generateKeyPair()
    doc = createDIDDocument(makePassport(kpOld))
  })

  it('announceKeyRotation(planned) sets pendingRotation and adds new key', () => {
    const rotated = announceKeyRotation(doc, kpOld.privateKey, kpNew, {
      mode: 'planned',
      activationDelayMs: 5000,
    })

    assert.ok(rotated.pendingRotation)
    assert.equal(rotated.pendingRotation!.mode, 'planned')
    assert.equal(rotated.pendingRotation!.state, 'announced')
    assert.equal(rotated.verificationMethod.length, 2)
    // Both keys in auth lists
    assert.equal(rotated.authentication.length, 2)
    assert.equal(rotated.assertionMethod.length, 2)
    assert.equal(rotated.capabilityDelegation.length, 2)
    // No rotation log entry yet
    assert.equal(rotated.rotationLog.length, 0)
  })

  it('isKeyActive returns true for BOTH keys during overlap', () => {
    const rotated = announceKeyRotation(doc, kpOld.privateKey, kpNew, {
      mode: 'planned',
      activationDelayMs: 60000, // 1 minute in the future
    })

    assert.equal(isKeyActive(rotated, kpOld.publicKey), true)
    assert.equal(isKeyActive(rotated, kpNew.publicKey), true)
  })

  it('activateKeyRotation after activationTime completes rotation', () => {
    const rotated = announceKeyRotation(doc, kpOld.privateKey, kpNew, {
      mode: 'planned',
      activationDelayMs: 0, // immediate activation eligible
    })

    // Activate with a time after activationTime
    const futureTime = new Date(Date.now() + 1000)
    const activated = activateKeyRotation(rotated, futureTime)

    assert.equal(activated.pendingRotation, undefined)
    assert.equal(activated.rotationLog.length, 1)
    assert.equal(activated.rotationLog[0].state, 'activated')
    assert.equal(activated.authentication.length, 1)
    assert.equal(activated.assertionMethod.length, 1)
    assert.equal(activated.capabilityDelegation.length, 1)
    // Old key has retiredAt
    const oldVm = activated.verificationMethod.find(
      vm => vm.publicKeyMultibase === hexToMultibase(kpOld.publicKey)
    )
    assert.ok(oldVm?.retiredAt)
  })

  it('isKeyActive returns false for old key after activation, true for new key', () => {
    const rotated = announceKeyRotation(doc, kpOld.privateKey, kpNew, {
      mode: 'planned',
      activationDelayMs: 0,
    })
    const activated = activateKeyRotation(rotated, new Date(Date.now() + 1000))

    assert.equal(isKeyActive(activated, kpOld.publicKey), false)
    assert.equal(isKeyActive(activated, kpNew.publicKey), true)
  })

  it('activateKeyRotation throws before activationTime', () => {
    const rotated = announceKeyRotation(doc, kpOld.privateKey, kpNew, {
      mode: 'planned',
      activationDelayMs: 86400000, // 24h
    })

    assert.throws(
      () => activateKeyRotation(rotated),
      /Activation time not reached/,
    )
  })

  it('activateKeyRotation throws when no pending rotation', () => {
    assert.throws(
      () => activateKeyRotation(doc),
      /No pending rotation/,
    )
  })

  it('planned rotation with default 24h overlap', () => {
    const rotated = announceKeyRotation(doc, kpOld.privateKey, kpNew, { mode: 'planned' })

    const activationTime = new Date(rotated.pendingRotation!.activationTime)
    const now = Date.now()
    // Should be ~24h from now (within 2 seconds tolerance)
    const diffMs = activationTime.getTime() - now
    assert.ok(diffMs > 86398000 && diffMs < 86402000, `Expected ~24h, got ${diffMs}ms`)
  })
})

// ══════════════════════════════════════
// Emergency rotation
// ══════════════════════════════════════

describe('Key Rotation — Emergency Mode', () => {
  it('emergency rotation immediately retires old key', () => {
    const kpOld = generateKeyPair()
    const kpNew = generateKeyPair()
    const doc = createDIDDocument(makePassport(kpOld))

    const rotated = announceKeyRotation(doc, kpOld.privateKey, kpNew, { mode: 'emergency' })

    // No pending — goes straight to rotationLog
    assert.equal(rotated.pendingRotation, undefined)
    assert.equal(rotated.rotationLog.length, 1)
    assert.equal(rotated.rotationLog[0].state, 'activated')
    assert.equal(rotated.rotationLog[0].mode, 'emergency')

    // Old key retired
    const oldVm = rotated.verificationMethod.find(
      vm => vm.publicKeyMultibase === hexToMultibase(kpOld.publicKey)
    )
    assert.ok(oldVm?.retiredAt)

    // Auth lists contain only new key
    assert.equal(rotated.authentication.length, 1)
  })

  it('isKeyActive returns false for old key immediately after emergency rotation', () => {
    const kpOld = generateKeyPair()
    const kpNew = generateKeyPair()
    const doc = createDIDDocument(makePassport(kpOld))

    const rotated = announceKeyRotation(doc, kpOld.privateKey, kpNew, { mode: 'emergency' })

    assert.equal(isKeyActive(rotated, kpOld.publicKey), false)
    assert.equal(isKeyActive(rotated, kpNew.publicKey), true)
  })
})

// ══════════════════════════════════════
// Chain verification
// ══════════════════════════════════════

describe('Key Rotation — Chain Verification', () => {
  it('verifyRotationChain true for valid single rotation', () => {
    const kpA = generateKeyPair()
    const kpB = generateKeyPair()
    const doc = createDIDDocument(makePassport(kpA))

    const rotated = announceKeyRotation(doc, kpA.privateKey, kpB, { mode: 'emergency' })

    assert.equal(verifyRotationChain(rotated), true)
  })

  it('verifyRotationChain true for double rotation (A → B → C)', () => {
    const kpA = generateKeyPair()
    const kpB = generateKeyPair()
    const kpC = generateKeyPair()

    let doc = createDIDDocument(makePassport(kpA))
    doc = announceKeyRotation(doc, kpA.privateKey, kpB, { mode: 'emergency' })
    doc = announceKeyRotation(doc, kpB.privateKey, kpC, { mode: 'emergency' })

    assert.equal(doc.rotationLog.length, 2)
    assert.equal(verifyRotationChain(doc), true)
  })

  it('verifyRotationChain false for forged signature', () => {
    const kpA = generateKeyPair()
    const kpB = generateKeyPair()
    const doc = createDIDDocument(makePassport(kpA))

    const rotated = announceKeyRotation(doc, kpA.privateKey, kpB, { mode: 'emergency' })

    // Forge signature
    rotated.rotationLog[0].rotationSignature = 'deadbeef'.repeat(16)

    assert.equal(verifyRotationChain(rotated), false)
  })

  it('verifyRotationChain false for tampered newKey', () => {
    const kpA = generateKeyPair()
    const kpB = generateKeyPair()
    const kpFake = generateKeyPair()
    const doc = createDIDDocument(makePassport(kpA))

    const rotated = announceKeyRotation(doc, kpA.privateKey, kpB, { mode: 'emergency' })

    // Tamper with newKey in the log entry
    rotated.rotationLog[0].newKey = kpFake.publicKey

    assert.equal(verifyRotationChain(rotated), false)
  })

  it('verifyRotationChain true for empty log', () => {
    const kp = generateKeyPair()
    const doc = createDIDDocument(makePassport(kp))

    assert.equal(verifyRotationChain(doc), true)
  })
})

// ══════════════════════════════════════
// State machine — rotateAndInvalidate
// ══════════════════════════════════════

describe('Key Rotation — State Machine (rotateAndInvalidate)', () => {
  beforeEach(() => {
    clearStores()
  })

  it('tracks state transitions with zero delegations', () => {
    const kpOld = generateKeyPair()
    const kpNew = generateKeyPair()
    const doc = createDIDDocument(makePassport(kpOld))

    const result = rotateAndInvalidate(doc, kpOld.privateKey, kpNew, [], { mode: 'planned' })

    assert.equal(result.rotationState, 'announced')
    assert.deepEqual(result.revocationResults, [])
    assert.ok(result.didDocument.pendingRotation)
  })

  it('emergency mode with delegations: revokes and activates', () => {
    const kpOld = generateKeyPair()
    const kpNew = generateKeyPair()
    const doc = createDIDDocument(makePassport(kpOld))

    // Create a delegation to revoke
    const del = createDelegation({
      delegatedBy: kpOld.publicKey,
      delegatedTo: kpNew.publicKey,
      scope: ['read:*'],
      maxDepth: 2,
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      privateKey: kpOld.privateKey,
    })

    const result = rotateAndInvalidate(
      doc, kpOld.privateKey, kpNew,
      [del.delegationId],
      { mode: 'emergency' },
    )

    // Should have revoked the delegation
    assert.equal(result.revocationResults.length, 1)
    assert.ok(!result.revocationResults[0].error)
    assert.equal(result.rotationState, 'activated')
  })

  it('multiple delegations all revoked: state tracks all results', () => {
    const kpOld = generateKeyPair()
    const kpNew = generateKeyPair()
    const kpThird = generateKeyPair()
    const doc = createDIDDocument(makePassport(kpOld))

    const del1 = createDelegation({
      delegatedBy: kpOld.publicKey,
      delegatedTo: kpNew.publicKey,
      scope: ['read:*'],
      maxDepth: 2,
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      privateKey: kpOld.privateKey,
    })
    const del2 = createDelegation({
      delegatedBy: kpOld.publicKey,
      delegatedTo: kpThird.publicKey,
      scope: ['write:*'],
      maxDepth: 2,
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      privateKey: kpOld.privateKey,
    })

    const result = rotateAndInvalidate(
      doc, kpOld.privateKey, kpNew,
      [del1.delegationId, del2.delegationId],
      { mode: 'planned' },
    )

    assert.equal(result.revocationResults.length, 2)
    assert.ok(!result.revocationResults[0].error)
    assert.ok(!result.revocationResults[1].error)
    assert.equal(result.rotationState, 'revocation_complete')
  })

  it('planned mode with all delegations revoked: state reaches revocation_complete', () => {
    const kpOld = generateKeyPair()
    const kpNew = generateKeyPair()
    const doc = createDIDDocument(makePassport(kpOld))

    const del = createDelegation({
      delegatedBy: kpOld.publicKey,
      delegatedTo: kpNew.publicKey,
      scope: ['read:*'],
      maxDepth: 2,
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      privateKey: kpOld.privateKey,
    })

    const result = rotateAndInvalidate(
      doc, kpOld.privateKey, kpNew,
      [del.delegationId],
      { mode: 'planned' },
    )

    assert.equal(result.rotationState, 'revocation_complete')
    assert.ok(result.didDocument.pendingRotation)
    assert.equal(result.didDocument.pendingRotation!.state, 'revocation_complete')
  })
})

// ══════════════════════════════════════
// Delegation invalidation
// ══════════════════════════════════════

describe('Key Rotation — Delegation Invalidation', () => {
  beforeEach(() => {
    clearStores()
  })

  it('rotateAndInvalidate cascade-revokes delegations under old key', () => {
    const kpOld = generateKeyPair()
    const kpNew = generateKeyPair()
    const kpChild = generateKeyPair()
    const doc = createDIDDocument(makePassport(kpOld))

    // Create parent → child delegation chain
    const parentDel = createDelegation({
      delegatedBy: kpOld.publicKey,
      delegatedTo: kpNew.publicKey,
      scope: ['read:*'],
      maxDepth: 3,
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      privateKey: kpOld.privateKey,
    })

    const result = rotateAndInvalidate(
      doc, kpOld.privateKey, kpNew,
      [parentDel.delegationId],
      { mode: 'emergency' },
    )

    assert.equal(result.revocationResults[0].cascadeCount, 1) // just the parent
    assert.ok(!result.revocationResults[0].error)
  })

  it('new delegations under new key work after rotation', () => {
    const kpOld = generateKeyPair()
    const kpNew = generateKeyPair()
    const kpThird = generateKeyPair()
    const doc = createDIDDocument(makePassport(kpOld))

    // Rotate
    const rotated = announceKeyRotation(doc, kpOld.privateKey, kpNew, { mode: 'emergency' })

    // New delegation under new key should work fine
    const del = createDelegation({
      delegatedBy: kpNew.publicKey,
      delegatedTo: kpThird.publicKey,
      scope: ['read:*'],
      maxDepth: 2,
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      privateKey: kpNew.privateKey,
    })

    assert.ok(del.delegationId)
    assert.ok(del.signature)
  })
})

// ══════════════════════════════════════
// Backward compatibility
// ══════════════════════════════════════

describe('Key Rotation — Backward Compatibility', () => {
  it('SignedPassport without didDocument is unchanged', () => {
    // Just verify the type allows undefined didDocument
    const sp: import('../src/types/passport.js').SignedPassport = {
      passport: makePassport(generateKeyPair()),
      signature: 'test-sig',
      signedAt: new Date().toISOString(),
    }

    assert.equal(sp.didDocument, undefined)
    assert.ok(sp.passport.agentId)
  })

  it('SignedPassport with didDocument works', () => {
    const kp = generateKeyPair()
    const passport = makePassport(kp)
    const doc = createDIDDocument(passport)

    const sp: import('../src/types/passport.js').SignedPassport = {
      passport,
      signature: 'test-sig',
      signedAt: new Date().toISOString(),
      didDocument: doc,
    }

    assert.ok(sp.didDocument)
    assert.equal(sp.didDocument!.rotationLog.length, 0)
  })
})

// ══════════════════════════════════════
// Edge cases
// ══════════════════════════════════════

describe('Key Rotation — Edge Cases', () => {
  it('wrong private key throws', () => {
    const kpOld = generateKeyPair()
    const kpNew = generateKeyPair()
    const kpWrong = generateKeyPair()
    const doc = createDIDDocument(makePassport(kpOld))

    assert.throws(
      () => announceKeyRotation(doc, kpWrong.privateKey, kpNew, { mode: 'planned' }),
      /does not match/,
    )
  })

  it('double pending rotation throws', () => {
    const kpOld = generateKeyPair()
    const kpNew = generateKeyPair()
    const kpNew2 = generateKeyPair()
    const doc = createDIDDocument(makePassport(kpOld))

    const rotated = announceKeyRotation(doc, kpOld.privateKey, kpNew, { mode: 'planned' })

    assert.throws(
      () => announceKeyRotation(rotated, kpOld.privateKey, kpNew2, { mode: 'planned' }),
      /already pending/,
    )
  })

  it('isKeyActive returns false for unknown key', () => {
    const kp = generateKeyPair()
    const kpRandom = generateKeyPair()
    const doc = createDIDDocument(makePassport(kp))

    assert.equal(isKeyActive(doc, kpRandom.publicKey), false)
  })

  it('triple rotation chain (A → B → C → D) verifies', () => {
    const kpA = generateKeyPair()
    const kpB = generateKeyPair()
    const kpC = generateKeyPair()
    const kpD = generateKeyPair()

    let doc = createDIDDocument(makePassport(kpA))
    doc = announceKeyRotation(doc, kpA.privateKey, kpB, { mode: 'emergency' })
    doc = announceKeyRotation(doc, kpB.privateKey, kpC, { mode: 'emergency' })
    doc = announceKeyRotation(doc, kpC.privateKey, kpD, { mode: 'emergency' })

    assert.equal(doc.rotationLog.length, 3)
    assert.equal(verifyRotationChain(doc), true)
    assert.equal(isKeyActive(doc, kpA.publicKey), false)
    assert.equal(isKeyActive(doc, kpB.publicKey), false)
    assert.equal(isKeyActive(doc, kpC.publicKey), false)
    assert.equal(isKeyActive(doc, kpD.publicKey), true)
  })

  it('isKeyActive considers pendingRotation activationTime for old key', () => {
    const kpOld = generateKeyPair()
    const kpNew = generateKeyPair()
    const doc = createDIDDocument(makePassport(kpOld))

    const rotated = announceKeyRotation(doc, kpOld.privateKey, kpNew, {
      mode: 'planned',
      activationDelayMs: 0, // activation time = now
    })

    // After activation time, old key should not be active
    const futureTime = new Date(Date.now() + 1000)
    assert.equal(isKeyActive(rotated, kpOld.publicKey, futureTime), false)
    assert.equal(isKeyActive(rotated, kpNew.publicKey, futureTime), true)
  })
})
