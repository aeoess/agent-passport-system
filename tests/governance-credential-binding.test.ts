// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// A governance credential's proof must be the claimed issuer's, and its
// proof configuration must be inside the signed bytes.
// ══════════════════════════════════════════════════════════════════
// Same two contracts the credential surfaces in vc.ts and vc-wrapper.ts were
// brought to, applied to the one surface in this repo that carried the same
// construction and was out of that finding's scope.
//
// The binding half arrives here inverted. vc.ts took its verification key OUT
// of the proof; verifyGovernanceCredential takes it from the caller, which is
// the right way round, and then never relates it to `credential.issuer`. So a
// credential can verify under a key the relying party trusts while naming
// somebody else as its issuer, and the party who can mint one is any other
// holder of a trusted key. verifyGovernanceBlock, in the same module, already
// does the check that closes this: it compares `source_did` to
// `createDID(publicKey)`. The credential path just never adopted it.
//
// The preimage half is the same as vc.ts: the proof was attached after the
// body was signed, so `created` and `verificationMethod` were rewritable
// without invalidating `proofValue`.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import { createDID } from '../src/core/did.js'
import {
  generateGovernanceBlock, verifyGovernanceBlock,
  createVerifiedGovernanceCredential, verifyGovernanceCredential,
} from '../src/core/governance-block.js'
import type { GovernanceBlock, VerifiedGovernanceCredential } from '../src/core/governance-block.js'

const publisher = generateKeyPair()
const attacker = generateKeyPair()

const CONTENT = 'the governed content'

const TERMS = {
  version: '1.0',
  training: 'prohibited' as const,
  inference: 'permitted' as const,
  attribution_required: true,
}

function block(): GovernanceBlock {
  return generateGovernanceBlock({
    content: CONTENT,
    publicKey: publisher.publicKey,
    privateKey: publisher.privateKey,
    terms: TERMS,
  })
}

describe('governance block: the identity binding that already existed', () => {
  it('a block claiming a publisher it was not signed by is refused', () => {
    // verifyGovernanceBlock compares source_did against createDID(publicKey).
    // This is the convention the credential path is brought to below; it is
    // asserted here so the two cannot drift apart.
    const forged = { ...block(), source_did: createDID(attacker.publicKey) }
    const result = verifyGovernanceBlock(forged, CONTENT, publisher.publicKey)
    assert.equal(result.didConsistent, false)
    assert.equal(result.valid, false)
  })
})

describe('governance credential: the proof must be the claimed issuer\'s', () => {
  it('accepts a credential whose issuer is the key that signed it', () => {
    const b = block()
    const credential = createVerifiedGovernanceCredential({
      block: b, privateKey: publisher.privateKey, publisherDid: createDID(publisher.publicKey),
    })
    const result = verifyGovernanceCredential(credential, b, publisher.publicKey)
    assert.equal(result.valid, true, result.errors.join('; '))
  })

  it('refuses a credential naming an issuer the signing key does not commit to', () => {
    // The attacker holds a key the relying party trusts for its own purposes,
    // and mints a governance credential naming the publisher as issuer. The
    // proof verifies under the attacker's key, which is the key supplied, and
    // the credential says the publisher issued it.
    const b = block()
    const forged = createVerifiedGovernanceCredential({
      block: b,
      privateKey: attacker.privateKey,
      publisherDid: createDID(publisher.publicKey),
    })
    assert.equal(forged.issuer, createDID(publisher.publicKey))
    const result = verifyGovernanceCredential(forged, b, attacker.publicKey)
    assert.equal(result.valid, false, 'a credential must not name an issuer its signer is not')
    assert.equal(result.keyAuthority, 'rejected')
  })

  it('refuses a verificationMethod naming a DID other than the issuer', () => {
    const b = block()
    const credential = createVerifiedGovernanceCredential({
      block: b, privateKey: publisher.privateKey, publisherDid: createDID(publisher.publicKey),
    })
    const rewritten = JSON.parse(JSON.stringify(credential)) as VerifiedGovernanceCredential
    rewritten.proof.verificationMethod = `${createDID(attacker.publicKey)}#key-1`
    const result = verifyGovernanceCredential(rewritten, b, publisher.publicKey)
    assert.equal(result.valid, false)
  })

  it('refuses an issuer DID that does not commit to any key', () => {
    const b = block()
    const credential = createVerifiedGovernanceCredential({
      block: b, privateKey: publisher.privateKey, publisherDid: 'did:web:example.com',
    })
    const result = verifyGovernanceCredential(credential, b, publisher.publicKey)
    assert.equal(result.valid, false)
    // Not 'rejected': the method is not self-certifying, so nothing was
    // disproved. This surface resolves no DID documents, same as the others.
    assert.equal(result.keyAuthority, 'unresolved')
  })
})

describe('governance credential: the proof configuration is signed', () => {
  const rewrites: Array<[string, (c: VerifiedGovernanceCredential) => void]> = [
    ['created', c => { c.proof.created = '2020-01-01T00:00:00.000Z' }],
    ['verificationMethod fragment', c => {
      c.proof.verificationMethod = `${createDID(publisher.publicKey)}#some-other-key`
    }],
    ['proof type', c => { (c.proof as { type: string }).type = 'JsonWebSignature2020' }],
    ['proof purpose', c => {
      (c.proof as { proofPurpose: string }).proofPurpose = 'authentication'
    }],
  ]

  for (const [field, mutate] of rewrites) {
    it(`refuses a ${field} rewritten after signing`, () => {
      const b = block()
      const credential = createVerifiedGovernanceCredential({
        block: b, privateKey: publisher.privateKey, publisherDid: createDID(publisher.publicKey),
      })
      assert.equal(verifyGovernanceCredential(credential, b, publisher.publicKey).valid, true)

      const rewritten = JSON.parse(JSON.stringify(credential)) as VerifiedGovernanceCredential
      mutate(rewritten)
      const result = verifyGovernanceCredential(rewritten, b, publisher.publicKey)
      assert.equal(result.valid, false, `${field} was rewritable without invalidating the proof`)
    })
  }
})

describe('governance credential: what the result reports', () => {
  it('separates possession of the key from authority over the identity', () => {
    const b = block()
    const credential = createVerifiedGovernanceCredential({
      block: b, privateKey: publisher.privateKey, publisherDid: createDID(publisher.publicKey),
    })
    const ok = verifyGovernanceCredential(credential, b, publisher.publicKey)
    assert.equal(ok.proofOfPossession, true)
    assert.equal(ok.keyAuthority, 'verified')

    // A credential whose bytes do not verify at all: possession is false too.
    const tampered = JSON.parse(JSON.stringify(credential)) as VerifiedGovernanceCredential
    tampered.credentialSubject.termsVersion = 'rewritten'
    const bad = verifyGovernanceCredential(tampered, b, publisher.publicKey)
    assert.equal(bad.proofOfPossession, false)
    assert.equal(bad.valid, false)
  })

  it('still catches a block modified after issuance', () => {
    const b = block()
    const credential = createVerifiedGovernanceCredential({
      block: b, privateKey: publisher.privateKey, publisherDid: createDID(publisher.publicKey),
    })
    const modified = { ...b, terms: { ...b.terms, training: 'permitted' as const } }
    const result = verifyGovernanceCredential(credential, modified, publisher.publicKey)
    assert.equal(result.valid, false)
    assert.ok(result.errors.some(e => e.includes('hash mismatch')))
  })
})
