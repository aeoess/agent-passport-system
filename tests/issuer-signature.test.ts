// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Tests for passport issuer countersignature (CA model)

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createPassport, countersignPassport, verifyIssuerSignature,
  isIssuerVerified, generateKeyPair, signPassport
} from '../src/index.js'

describe('Issuer Countersignature', () => {
  const issuerKeys = generateKeyPair()
  const agentKeys = generateKeyPair()

  function makePassport() {
    const { signedPassport } = createPassport({
      agentId: `test-${Date.now()}`,
      agentName: 'Test Agent',
      ownerAlias: 'test-owner',
      mission: 'Testing',
      capabilities: ['test'],
      runtime: { platform: 'test', models: ['test'], toolsCount: 1, memoryType: 'volatile' as any },
    })
    return signedPassport
  }

  it('countersign and verify round-trip', () => {
    const passport = makePassport()
    const countersigned = countersignPassport(passport, issuerKeys.privateKey, 'aeoess')
    assert.ok(countersigned.issuerSignature)
    assert.equal(countersigned.issuerSignature!.issuerId, 'aeoess')
    assert.equal(countersigned.issuerSignature!.issuerPublicKey, issuerKeys.publicKey)
    assert.ok(verifyIssuerSignature(countersigned, issuerKeys.publicKey))
  })

  it('rejects verification with wrong issuer key', () => {
    const passport = makePassport()
    const countersigned = countersignPassport(passport, issuerKeys.privateKey)
    const wrongKeys = generateKeyPair()
    assert.equal(verifyIssuerSignature(countersigned, wrongKeys.publicKey), false)
  })

  it('rejects passport without issuer signature', () => {
    const passport = makePassport()
    assert.equal(verifyIssuerSignature(passport, issuerKeys.publicKey), false)
  })

  it('rejects tampered passport content', () => {
    const passport = makePassport()
    const countersigned = countersignPassport(passport, issuerKeys.privateKey)
    const tampered = {
      ...countersigned,
      passport: { ...countersigned.passport, agentName: 'Tampered' },
    }
    assert.equal(verifyIssuerSignature(tampered, issuerKeys.publicKey), false)
  })

  it('rejects tampered agent signature', () => {
    const passport = makePassport()
    const countersigned = countersignPassport(passport, issuerKeys.privateKey)
    const tampered = { ...countersigned, signature: 'a'.repeat(128) }
    assert.equal(verifyIssuerSignature(tampered, issuerKeys.publicKey), false)
  })

  it('preserves original agent signature after countersign', () => {
    const passport = makePassport()
    const originalSig = passport.signature
    const countersigned = countersignPassport(passport, issuerKeys.privateKey)
    assert.equal(countersigned.signature, originalSig)
    assert.equal(countersigned.passport.publicKey, passport.passport.publicKey)
  })

  it('isIssuerVerified returns true for countersigned', () => {
    const passport = makePassport()
    const countersigned = countersignPassport(passport, issuerKeys.privateKey)
    assert.ok(isIssuerVerified(countersigned))
  })

  it('isIssuerVerified returns false for unsigned', () => {
    const passport = makePassport()
    assert.equal(isIssuerVerified(passport), false)
  })

  it('different issuers produce different signatures', () => {
    const passport = makePassport()
    const issuer2 = generateKeyPair()
    const cs1 = countersignPassport(passport, issuerKeys.privateKey, 'aeoess')
    const cs2 = countersignPassport(passport, issuer2.privateKey, 'other-issuer')
    assert.notEqual(cs1.issuerSignature!.signature, cs2.issuerSignature!.signature)
    assert.ok(verifyIssuerSignature(cs1, issuerKeys.publicKey))
    assert.ok(verifyIssuerSignature(cs2, issuer2.publicKey))
    assert.equal(verifyIssuerSignature(cs1, issuer2.publicKey), false)
    assert.equal(verifyIssuerSignature(cs2, issuerKeys.publicKey), false)
  })
})
