// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// A signature over a passport says who signed it, not who vouches for it.
// ══════════════════════════════════════════════════════════════════
// The verifying key is carried by the passport, so a good signature is
// available to anyone who can generate a key pair. `verifyPassport(passport)`
// with no options returned `valid: true` for a passport minted seconds
// earlier claiming any agentId and any owner, and two in-repo callers gated on
// that: `checkPassportGate`, whose own banner calls it a gate predicate, and
// `assignRole`, which issues a role to the agentId the passport claims.
//
// The contract: integrity and authority are separate questions and the second
// is the caller's. `valid` is true only when a trusted issuer countersigned
// the passport, or when the caller explicitly said it would accept a
// self-signed one. This matches what the Python SDK now does at ad76e38.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createPassport } from '../src/core/passport.js'
import { verifyPassport } from '../src/verification/verify.js'
import { checkPassportGate } from '../src/core/commerce.js'
import { assignRole } from '../src/core/intent.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import type { SignedPassport } from '../src/types/passport.js'

function minted(agentId = 'ag_attacker_claims_treasury'): SignedPassport {
  const r = createPassport({
    agentId, agentName: 'Treasury Bot', ownerAlias: 'acme-finance',
    mission: 'move money', capabilities: ['commerce:checkout'],
    runtime: { platform: 'node', models: [], toolsCount: 0, memoryType: 'session' },
  } as never)
  return ((r as { signedPassport?: SignedPassport }).signedPassport ?? r) as SignedPassport
}

/** The countersignature the SDK already verifies: over
 *  canonicalize({passport, signature, signedAt}). No new preimage. */
function countersign(signed: SignedPassport, issuerPriv: string, issuerPub: string): SignedPassport {
  const payload = canonicalize({
    passport: signed.passport,
    signature: signed.signature,
    signedAt: (signed as { signedAt?: string }).signedAt,
  })
  return {
    ...signed,
    issuerSignature: {
      issuerId: 'aeoess',
      issuerPublicKey: issuerPub,
      signature: sign(payload, issuerPriv),
      signedAt: (signed as { signedAt?: string }).signedAt,
    },
  } as SignedPassport
}

describe('verifyPassport separates integrity from authority', () => {
  it('a bare call does not establish authority', () => {
    const result = verifyPassport(minted())
    assert.equal(result.valid, false)
    assert.equal(result.issuerTrustChecked, false)
    assert.equal(result.selfSignedAccepted, false)
  })

  it('a trusted issuer countersignature makes it valid', () => {
    const issuer = generateKeyPair()
    const result = verifyPassport(countersign(minted(), issuer.privateKey, issuer.publicKey),
      { trustedIssuers: [issuer.publicKey] })
    assert.equal(result.valid, true, result.errors.join('; '))
    assert.equal(result.issuerTrustChecked, true)
    assert.equal(result.selfSignedAccepted, false)
  })

  it('allowSelfSigned is an explicit opt-in', () => {
    const result = verifyPassport(minted(), { allowSelfSigned: true })
    assert.equal(result.valid, true, result.errors.join('; '))
    assert.equal(result.selfSignedAccepted, true)
    assert.equal(result.issuerTrustChecked, false)
  })

  it('trustedIssuers supplied but no countersignature is refused', () => {
    const issuer = generateKeyPair()
    const result = verifyPassport(minted(), { trustedIssuers: [issuer.publicKey] })
    assert.equal(result.valid, false)
    assert.equal(result.issuerTrustChecked, true)
  })

  it('a countersignature by a key not in trustedIssuers is refused', () => {
    const issuer = generateKeyPair(), stranger = generateKeyPair()
    const result = verifyPassport(countersign(minted(), issuer.privateKey, issuer.publicKey),
      { trustedIssuers: [stranger.publicKey] })
    assert.equal(result.valid, false)
  })

  it('a countersignature naming a trusted key but made by another is refused', () => {
    const issuer = generateKeyPair(), forger = generateKeyPair()
    const result = verifyPassport(countersign(minted(), forger.privateKey, issuer.publicKey),
      { trustedIssuers: [issuer.publicKey] })
    assert.equal(result.valid, false)
    assert.ok(result.errors.some(e => /countersignature/i.test(e)), result.errors.join('; '))
  })

  it('a countersigned passport whose body was altered is refused', () => {
    const issuer = generateKeyPair()
    const signed = countersign(minted(), issuer.privateKey, issuer.publicKey)
    const tampered = { ...signed, passport: { ...signed.passport, agentId: 'ag_promoted' } }
    assert.equal(verifyPassport(tampered as SignedPassport, { trustedIssuers: [issuer.publicKey] }).valid, false)
  })

  it('an expired passport under a trusted issuer is still refused', () => {
    const issuer = generateKeyPair()
    const r = createPassport({
      agentId: 'ag_expired', agentName: 'X', ownerAlias: 'o', mission: 'm',
      capabilities: ['a'], expiresInDays: -1,
      runtime: { platform: 'node', models: [], toolsCount: 0, memoryType: 'session' },
    } as never)
    const signed = ((r as { signedPassport?: SignedPassport }).signedPassport ?? r) as SignedPassport
    const result = verifyPassport(countersign(signed, issuer.privateKey, issuer.publicKey),
      { trustedIssuers: [issuer.publicKey] })
    assert.equal(result.valid, false)
    assert.ok(result.errors.some(e => /expired/i.test(e)), result.errors.join('; '))
  })

  it('opting in to self-signed still requires a good signature', () => {
    const signed = minted()
    const tampered = { ...signed, passport: { ...signed.passport, agentId: 'ag_other' } }
    assert.equal(verifyPassport(tampered as SignedPassport, { allowSelfSigned: true }).valid, false)
  })

  it('a non-boolean allowSelfSigned does not admit', () => {
    // Re-attack, not in the brief, and the shape this repo has been bitten by
    // before: trust-anchors.ts records that a security option read with a
    // loose test let `{}`, `NaN` and a Set through every gate. An unparsed
    // config value arrives as the STRING "true" or "false", and neither is a
    // caller saying yes.
    for (const value of ['true', 'false', 1, {}, [], 'yes', new Set([true])]) {
      const result = verifyPassport(minted(), { allowSelfSigned: value as never })
      assert.equal(result.valid, false, `allowSelfSigned: ${String(value)} admitted`)
      assert.equal(result.selfSignedAccepted, false)
    }
  })

  it('allowSelfSigned does not rescue a failed issuer check', () => {
    // Re-attack, not in the brief. A caller that names issuers has asked for
    // that check; the opt-in must not be a way to ignore the answer.
    const issuer = generateKeyPair(), stranger = generateKeyPair()
    const signed = countersign(minted(), issuer.privateKey, issuer.publicKey)
    const result = verifyPassport(signed, { trustedIssuers: [stranger.publicKey], allowSelfSigned: true })
    assert.equal(result.valid, false)
  })
})

describe('the two gates fail closed without a trust input', () => {
  it('checkPassportGate does not pass a passport nobody vouched for', () => {
    const gate = checkPassportGate(minted())
    assert.equal(gate.passed, false)
  })

  it('checkPassportGate passes under a trusted issuer', () => {
    const issuer = generateKeyPair()
    const gate = checkPassportGate(countersign(minted(), issuer.privateKey, issuer.publicKey),
      { trustedIssuers: [issuer.publicKey] })
    assert.equal(gate.passed, true, gate.detail)
  })

  it('assignRole refuses a passport nobody vouched for', () => {
    const assigner = generateKeyPair()
    assert.throws(() => assignRole({
      signedPassport: minted(), role: 'treasurer', autonomyLevel: 'high',
      scope: ['commerce:checkout'],
      assignerPrivateKey: assigner.privateKey, assignerPublicKey: assigner.publicKey,
    } as never), /passport verification failed/)
  })

  it('assignRole accepts one countersigned by a trusted issuer', () => {
    const assigner = generateKeyPair(), issuer = generateKeyPair()
    const a = assignRole({
      signedPassport: countersign(minted(), issuer.privateKey, issuer.publicKey),
      role: 'treasurer', autonomyLevel: 'high', scope: ['commerce:checkout'],
      assignerPrivateKey: assigner.privateKey, assignerPublicKey: assigner.publicKey,
      trustedIssuers: [issuer.publicKey],
    } as never)
    assert.equal(a.role, 'treasurer')
  })
})
