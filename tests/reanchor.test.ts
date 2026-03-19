// Delegation Re-anchoring Tests (Module 26)
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { createIdentityDocument, rotateKey } from '../src/core/identity.js'
import {
  createDelegationRef, resolvePublicKey, reanchorDelegation,
  verifyReanchoredDelegation, verifyWithRef, didCoversKey,
} from '../src/core/reanchor.js'

describe('DelegationRef — Creation & Resolution', () => {
  it('creates raw key ref and resolves', () => {
    const kp = generateKeyPair()
    const ref = createDelegationRef({ publicKey: kp.publicKey })
    assert.equal(ref.type, 'raw_key')
    assert.equal(resolvePublicKey(ref), kp.publicKey)
  })

  it('creates DID ref with identity document and resolves', () => {
    const kp = generateKeyPair()
    const doc = createIdentityDocument({ publicKey: kp.publicKey })
    const ref = createDelegationRef({ did: 'did:aps:abc123', identityDocument: doc })
    assert.equal(ref.type, 'did')
    assert.equal(resolvePublicKey(ref), kp.publicKey)
  })

  it('DID ref without identity document returns null', () => {
    const ref = createDelegationRef({ did: 'did:aps:unknown' })
    assert.equal(ref.type, 'did')
    assert.equal(resolvePublicKey(ref), null)
  })
})

describe('Re-anchor Delegation', () => {
  it('re-anchors a raw-key delegation to DID references', () => {
    const delegator = generateKeyPair()
    const delegate = generateKeyPair()
    const delegatorDoc = createIdentityDocument({ publicKey: delegator.publicKey })
    const delegateDoc = createIdentityDocument({ publicKey: delegate.publicKey })

    const ra = reanchorDelegation({
      delegationId: 'del-001',
      delegatorKey: delegator.publicKey,
      delegateKey: delegate.publicKey,
      scope: ['data:read', 'search'],
      spendLimit: 500,
      delegatorDid: 'did:aps:delegator',
      delegateDid: 'did:aps:delegate',
      delegatorIdentity: delegatorDoc,
      delegateIdentity: delegateDoc,
    })

    assert.equal(ra.delegationId, 'del-001')
    assert.equal(ra.delegatorRef.type, 'did')
    assert.equal(ra.delegateRef.type, 'did')
    assert.equal(ra.originalDelegatorKey, delegator.publicKey)
    assert.equal(ra.originalDelegateKey, delegate.publicKey)
    assert.deepEqual(ra.scope, ['data:read', 'search'])
    assert.equal(ra.spendLimit, 500)
    assert.ok(ra.reanchoredAt)
  })
})

describe('Verify Re-anchored Delegation', () => {
  it('verifies when DID keys match original keys', () => {
    const delegator = generateKeyPair()
    const delegate = generateKeyPair()
    const delegatorDoc = createIdentityDocument({ publicKey: delegator.publicKey })
    const delegateDoc = createIdentityDocument({ publicKey: delegate.publicKey })

    const ra = reanchorDelegation({
      delegationId: 'del-002', delegatorKey: delegator.publicKey, delegateKey: delegate.publicKey,
      scope: ['data:read'], delegatorDid: 'did:aps:a', delegateDid: 'did:aps:b',
      delegatorIdentity: delegatorDoc, delegateIdentity: delegateDoc,
    })
    const result = verifyReanchoredDelegation(ra)
    assert.equal(result.valid, true)
    assert.equal(result.errors.length, 0)
  })

  it('fails when delegator DID resolves to different key', () => {
    const delegator = generateKeyPair()
    const delegate = generateKeyPair()
    const wrongKey = generateKeyPair()
    const wrongDoc = createIdentityDocument({ publicKey: wrongKey.publicKey })
    const delegateDoc = createIdentityDocument({ publicKey: delegate.publicKey })

    const ra = reanchorDelegation({
      delegationId: 'del-003', delegatorKey: delegator.publicKey, delegateKey: delegate.publicKey,
      scope: ['data:read'], delegatorDid: 'did:aps:wrong', delegateDid: 'did:aps:b',
      delegatorIdentity: wrongDoc, delegateIdentity: delegateDoc,
    })
    const result = verifyReanchoredDelegation(ra)
    assert.equal(result.valid, false)
    assert.ok(result.errors.some(e => e.includes('different key')))
  })
})

describe('Verify With Ref — Compatibility Bridge', () => {
  it('verifies signature against raw key ref', () => {
    const kp = generateKeyPair()
    const msg = canonicalize({ action: 'data:read', agent: 'test' })
    const sig = sign(msg, kp.privateKey)
    const ref = createDelegationRef({ publicKey: kp.publicKey })
    const result = verifyWithRef(msg, sig, ref)
    assert.equal(result.verified, true)
    assert.equal(result.resolvedKey, kp.publicKey)
  })

  it('verifies signature against DID ref', () => {
    const kp = generateKeyPair()
    const doc = createIdentityDocument({ publicKey: kp.publicKey })
    const msg = canonicalize({ action: 'search', scope: 'all' })
    const sig = sign(msg, kp.privateKey)
    const ref = createDelegationRef({ did: 'did:aps:test', identityDocument: doc })
    const result = verifyWithRef(msg, sig, ref)
    assert.equal(result.verified, true)
  })

  it('fails for DID ref without identity document', () => {
    const kp = generateKeyPair()
    const msg = canonicalize({ test: true })
    const sig = sign(msg, kp.privateKey)
    const ref = createDelegationRef({ did: 'did:aps:unresolved' })
    const result = verifyWithRef(msg, sig, ref)
    assert.equal(result.verified, false)
    assert.equal(result.resolvedKey, null)
  })
})

describe('DID Covers Key — Rotated Key History', () => {
  it('covers current key', () => {
    const kp = generateKeyPair()
    const doc = createIdentityDocument({ publicKey: kp.publicKey })
    const ref = createDelegationRef({ did: 'did:aps:test', identityDocument: doc })
    assert.equal(didCoversKey(ref, kp.publicKey), true)
  })

  it('covers historical key after rotation', () => {
    const k1 = generateKeyPair()
    const k2 = generateKeyPair()
    let doc = createIdentityDocument({ publicKey: k1.publicKey })
    doc = rotateKey({ identity: doc, oldPrivateKey: k1.privateKey, newKeyPair: k2, reason: 'scheduled' }).identity
    const ref = createDelegationRef({ did: 'did:aps:rotated', identityDocument: doc })
    assert.equal(didCoversKey(ref, k1.publicKey), true) // old key
    assert.equal(didCoversKey(ref, k2.publicKey), true) // new key
  })

  it('does not cover unknown key', () => {
    const kp = generateKeyPair()
    const unknown = generateKeyPair()
    const doc = createIdentityDocument({ publicKey: kp.publicKey })
    const ref = createDelegationRef({ did: 'did:aps:test', identityDocument: doc })
    assert.equal(didCoversKey(ref, unknown.publicKey), false)
  })
})
