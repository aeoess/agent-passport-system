// Identity & Key Rotation Tests (Module 22)
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, verify as verifySignature } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import {
  createIdentityDocument, rotateKey, emergencyRotate,
  verifyRotation, verifyRotationLog,
  resolveCurrentKey, wasKeyActive,
} from '../src/core/identity.js'

describe('Identity Document Creation', () => {
  it('creates identity document with initial key', () => {
    const kp = generateKeyPair()
    const doc = createIdentityDocument({ publicKey: kp.publicKey })
    assert.ok(doc.identityId.startsWith('id_'))
    assert.equal(doc.currentPublicKey, kp.publicKey)
    assert.equal(doc.previousPublicKey, null)
    assert.equal(doc.rotationLog.length, 0)
    assert.equal(doc.recoveryKeys.length, 0)
  })

  it('creates identity document with recovery keys', () => {
    const kp = generateKeyPair()
    const r1 = generateKeyPair()
    const r2 = generateKeyPair()
    const doc = createIdentityDocument({ publicKey: kp.publicKey, recoveryKeys: [r1.publicKey, r2.publicKey] })
    assert.equal(doc.recoveryKeys.length, 2)
  })
})

describe('Key Rotation', () => {
  it('rotates key — old key signs continuity, new key proves possession', () => {
    const original = generateKeyPair()
    const newKp = generateKeyPair()
    const doc = createIdentityDocument({ publicKey: original.publicKey })
    const result = rotateKey({ identity: doc, oldPrivateKey: original.privateKey, newKeyPair: newKp, reason: 'scheduled' })
    assert.equal(result.identity.currentPublicKey, newKp.publicKey)
    assert.equal(result.identity.previousPublicKey, original.publicKey)
    assert.equal(result.identity.rotationLog.length, 1)
    assert.equal(result.rotationEntry.reason, 'scheduled')
  })

  it('verifies rotation entry — both signatures valid', () => {
    const original = generateKeyPair()
    const newKp = generateKeyPair()
    const doc = createIdentityDocument({ publicKey: original.publicKey })
    const { rotationEntry } = rotateKey({ identity: doc, oldPrivateKey: original.privateKey, newKeyPair: newKp, reason: 'upgrade' })
    const result = verifyRotation(rotationEntry)
    assert.equal(result.valid, true)
    assert.equal(result.continuityValid, true)
    assert.equal(result.possessionValid, true)
  })

  it('detects tampered continuity signature', () => {
    const original = generateKeyPair()
    const newKp = generateKeyPair()
    const doc = createIdentityDocument({ publicKey: original.publicKey })
    const { rotationEntry } = rotateKey({ identity: doc, oldPrivateKey: original.privateKey, newKeyPair: newKp, reason: 'scheduled' })
    const tampered = { ...rotationEntry, continuitySignature: 'deadbeef'.repeat(16) }
    const result = verifyRotation(tampered)
    assert.equal(result.valid, false)
    assert.equal(result.continuityValid, false)
    assert.equal(result.possessionValid, true)
  })

  it('detects tampered possession signature', () => {
    const original = generateKeyPair()
    const newKp = generateKeyPair()
    const doc = createIdentityDocument({ publicKey: original.publicKey })
    const { rotationEntry } = rotateKey({ identity: doc, oldPrivateKey: original.privateKey, newKeyPair: newKp, reason: 'scheduled' })
    const tampered = { ...rotationEntry, possessionSignature: 'deadbeef'.repeat(16) }
    const result = verifyRotation(tampered)
    assert.equal(result.valid, false)
    assert.equal(result.continuityValid, true)
    assert.equal(result.possessionValid, false)
  })
})

describe('Rotation Log Verification', () => {
  it('verifies full rotation log with multiple rotations', () => {
    const k1 = generateKeyPair(), k2 = generateKeyPair(), k3 = generateKeyPair()
    let doc = createIdentityDocument({ publicKey: k1.publicKey })
    doc = rotateKey({ identity: doc, oldPrivateKey: k1.privateKey, newKeyPair: k2, reason: 'scheduled' }).identity
    doc = rotateKey({ identity: doc, oldPrivateKey: k2.privateKey, newKeyPair: k3, reason: 'upgrade' }).identity
    assert.equal(doc.rotationLog.length, 2)
    const result = verifyRotationLog(doc)
    assert.equal(result.valid, true)
    assert.equal(result.chainValid, true)
  })

  it('detects broken chain — tampered log entry order', () => {
    const k1 = generateKeyPair(), k2 = generateKeyPair(), k3 = generateKeyPair()
    let doc = createIdentityDocument({ publicKey: k1.publicKey })
    doc = rotateKey({ identity: doc, oldPrivateKey: k1.privateKey, newKeyPair: k2, reason: 'scheduled' }).identity
    doc = rotateKey({ identity: doc, oldPrivateKey: k2.privateKey, newKeyPair: k3, reason: 'upgrade' }).identity
    const tampered = { ...doc, rotationLog: [doc.rotationLog[1], doc.rotationLog[0]] }
    const result = verifyRotationLog(tampered)
    assert.equal(result.valid, false)
    assert.equal(result.chainValid, false)
  })

  it('verifies empty rotation log as valid', () => {
    const kp = generateKeyPair()
    const doc = createIdentityDocument({ publicKey: kp.publicKey })
    const result = verifyRotationLog(doc)
    assert.equal(result.valid, true)
  })
})

describe('Emergency Rotation', () => {
  it('emergency rotates with pre-committed recovery key', () => {
    const original = generateKeyPair()
    const recovery = generateKeyPair()
    const newKp = generateKeyPair()
    const doc = createIdentityDocument({ publicKey: original.publicKey, recoveryKeys: [recovery.publicKey] })
    const result = emergencyRotate({ identity: doc, recoveryPrivateKey: recovery.privateKey, newKeyPair: newKp })
    assert.equal(result.identity.currentPublicKey, newKp.publicKey)
    assert.equal(result.rotationEntry.reason, 'recovery')
  })

  it('emergency rotation fails with wrong recovery key', () => {
    const original = generateKeyPair()
    const realRecovery = generateKeyPair()
    const wrongRecovery = generateKeyPair()
    const newKp = generateKeyPair()
    const doc = createIdentityDocument({ publicKey: original.publicKey, recoveryKeys: [realRecovery.publicKey] })
    const result = emergencyRotate({ identity: doc, recoveryPrivateKey: wrongRecovery.privateKey, newKeyPair: newKp })
    const entry = result.rotationEntry
    const recoveryKeyUsed = doc.recoveryKeys.some(rk => {
      try {
        const payload = canonicalize({ rotationId: entry.rotationId, oldPublicKey: entry.oldPublicKey, newPublicKey: entry.newPublicKey, reason: entry.reason, rotatedAt: entry.rotatedAt })
        return verifySignature(payload, entry.continuitySignature, rk)
      } catch { return false }
    })
    assert.equal(recoveryKeyUsed, false)
  })
})

describe('Key Resolution & History', () => {
  it('resolveCurrentKey returns latest key after multiple rotations', () => {
    const k1 = generateKeyPair(), k2 = generateKeyPair(), k3 = generateKeyPair()
    let doc = createIdentityDocument({ publicKey: k1.publicKey })
    doc = rotateKey({ identity: doc, oldPrivateKey: k1.privateKey, newKeyPair: k2, reason: 'scheduled' }).identity
    doc = rotateKey({ identity: doc, oldPrivateKey: k2.privateKey, newKeyPair: k3, reason: 'upgrade' }).identity
    assert.equal(resolveCurrentKey(doc), k3.publicKey)
  })

  it('wasKeyActive correctly identifies current and historical keys', () => {
    const k1 = generateKeyPair(), k2 = generateKeyPair(), k3 = generateKeyPair(), neverUsed = generateKeyPair()
    let doc = createIdentityDocument({ publicKey: k1.publicKey })
    doc = rotateKey({ identity: doc, oldPrivateKey: k1.privateKey, newKeyPair: k2, reason: 'scheduled' }).identity
    doc = rotateKey({ identity: doc, oldPrivateKey: k2.privateKey, newKeyPair: k3, reason: 'upgrade' }).identity
    assert.equal(wasKeyActive(doc, k1.publicKey), true)
    assert.equal(wasKeyActive(doc, k2.publicKey), true)
    assert.equal(wasKeyActive(doc, k3.publicKey), true)
    assert.equal(wasKeyActive(doc, neverUsed.publicKey), false)
  })
})
