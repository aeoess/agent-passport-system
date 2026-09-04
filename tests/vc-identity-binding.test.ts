// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// A credential's proof must be the claimed issuer's, and its replay
// context must be inside the signed bytes.
// ══════════════════════════════════════════════════════════════════
// Two contracts, one for each half of F-02.
//
// BINDING. `proof.verificationMethod` is part of the document the presenter
// wrote. Deriving the verification key from it and verifying under that key
// establishes only that whoever assembled the document held one private key,
// which is true of every document anyone can make. So a credential could name
// a trusted issuer, carry a proof over an attacker's key, verify, and return
// the trusted issuer's DID to the caller. The key must instead be shown to
// belong to the DID the document claims to speak for.
//
// REPLAY. `challenge` and `domain` were attached to the proof after the body
// was signed, so a presentation minted for one verifier could be readdressed
// to another without invalidating it, and the one function that compared a
// challenge compared a field the presenter could rewrite. Both are now inside
// the signed bytes, and a verifier that states an expectation refuses a proof
// that carries none.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalizeForWrite } from '../src/core/canonical.js'
import { createDID, createDIDHex } from '../src/core/did.js'
import { toDIDKey } from '../src/core/did-interop.js'
import { verifyVC, verifyPresentation, createPresentation } from '../src/core/vc.js'
import {
  passportToVerifiableCredential, verifyVerifiableCredential,
  createVerifiablePresentation, verifyVerifiablePresentation,
} from '../src/core/vc-wrapper.js'
import {
  createCredentialRequest, fulfillCredentialRequest, verifyCredentialResponse,
} from '../src/core/credential-request.js'
import { bindVerificationMethod } from '../src/core/vc-proof.js'

const attacker = generateKeyPair()
const trusted = generateKeyPair()
const holder = generateKeyPair()

const proofValue = (body: Record<string, unknown>, privateKey: string): string =>
  Buffer.from(sign(canonicalizeForWrite(body), privateKey), 'hex').toString('base64url')

/** A credential whose proof configuration is NOT in the signed bytes, i.e. the
 *  shape the shipped signer produced before this repair. Used to show that the
 *  verifier no longer accepts it. */
function unboundCredential(opts: {
  issuer: string
  verificationMethod: string
  signingKey: string
  proofPurpose?: string
}): Record<string, unknown> {
  const body = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:aps:credential:binding-fixture',
    type: ['VerifiableCredential'],
    issuer: opts.issuer,
    issuanceDate: '2026-01-01T00:00:00.000Z',
    credentialSubject: { id: 'did:example:subject', role: 'admin' },
  }
  return {
    ...body,
    proof: {
      type: 'Ed25519Signature2020',
      created: '2026-01-01T00:00:00.000Z',
      verificationMethod: opts.verificationMethod,
      proofPurpose: opts.proofPurpose ?? 'assertionMethod',
      proofValue: proofValue(body, opts.signingKey),
    },
  }
}

describe('F-02 binding: the proof key must belong to the claimed identity', () => {
  it('vc.ts refuses a credential naming a trusted issuer with an attacker proof', async () => {
    const result = await verifyVC(unboundCredential({
      issuer: createDID(trusted.publicKey),
      verificationMethod: `${createDID(attacker.publicKey)}#key-1`,
      signingKey: attacker.privateKey,
    }) as never)
    assert.equal(result.valid, false)
    assert.equal(result.keyAuthority, 'rejected')
    // And it no longer hands back the issuer the forgery named. Returning a
    // trusted DID from a rejected verification is how a caller allowlists an
    // attacker.
    assert.equal(result.issuerDID, '')
  })

  it('vc.ts refuses a presentation naming a trusted holder with an attacker proof', async () => {
    const body = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:aps:presentation:binding-fixture',
      type: ['VerifiablePresentation'],
      holder: createDID(trusted.publicKey),
      verifiableCredential: [],
    }
    const vp = {
      ...body,
      proof: {
        type: 'Ed25519Signature2020',
        created: '2026-01-01T00:00:00.000Z',
        verificationMethod: `${createDID(attacker.publicKey)}#key-1`,
        proofPurpose: 'authentication',
        proofValue: proofValue(body, attacker.privateKey),
      },
    }
    const result = await verifyPresentation(vp as never, { expectedChallenge: 'nonce-binding' })
    assert.equal(result.valid, false)
    assert.equal(result.keyAuthority, 'rejected')
  })

  it('vc-wrapper refuses a did:key issuer whose proof is over an attacker did:key', async () => {
    const vc = await passportToVerifiableCredential(
      { agentId: 'agent-binding', publicKey: holder.publicKey }, trusted.privateKey)
    const forged = JSON.parse(JSON.stringify(vc))
    forged.proof.verificationMethod = `${toDIDKey(attacker.publicKey)}#key-1`
    forged.proof.proofValue = proofValue(
      Object.fromEntries(Object.entries(forged).filter(([k]) => k !== 'proof')) as Record<string, unknown>,
      attacker.privateKey)
    const result = await verifyVerifiableCredential(forged)
    assert.equal(result.valid, false)
    assert.equal(result.keyAuthority, 'rejected')
    assert.equal(result.issuerDID, '')
  })

  it('vc-wrapper no longer reads a non-did:key identifier as raw key material', () => {
    // The old fallback took the last colon-separated segment of the
    // verificationMethod and used it as a public key, so a did:aps identifier
    // in hex form supplied its own verification key with nothing tying it to
    // the claimed did:key issuer.
    const binding = bindVerificationMethod(
      toDIDKey(trusted.publicKey),
      `did:aps:${attacker.publicKey}#key-1`)
    assert.equal(binding.keyAuthority, 'rejected')
  })

  it('a DID method that is not self-certifying is unresolved, not accepted', async () => {
    const result = await verifyVC(unboundCredential({
      issuer: 'did:web:example.com',
      verificationMethod: 'did:web:example.com#key-1',
      signingKey: attacker.privateKey,
    }) as never)
    assert.equal(result.valid, false)
    // Not 'rejected': nothing was disproved. The verifier resolves no DID
    // documents, so it cannot establish the binding either way, and an
    // unestablished binding is not an acceptance.
    assert.equal(result.keyAuthority, 'unresolved')
  })

  it('a non-canonical self-certifying identifier is rejected', () => {
    // Same key, different multibase spelling: two DID strings must not map to
    // one key, or the equality check that binds them means nothing.
    assert.equal(bindVerificationMethod('did:key:zZZZZ', 'did:key:zZZZZ#k').keyAuthority, 'rejected')
    assert.equal(
      bindVerificationMethod(createDIDHex(trusted.publicKey), `${createDIDHex(trusted.publicKey)}#key-1`).keyAuthority,
      'rejected')
  })

  it('a proof made for a different purpose is refused', async () => {
    const result = await verifyVC(unboundCredential({
      issuer: createDID(trusted.publicKey),
      verificationMethod: `${createDID(trusted.publicKey)}#key-1`,
      signingKey: trusted.privateKey,
      proofPurpose: 'authentication',
    }) as never)
    assert.equal(result.valid, false)
    assert.match(String(result.error), /not a credential purpose/)
  })

  it('a proof of a different type is refused', async () => {
    const credential = unboundCredential({
      issuer: createDID(trusted.publicKey),
      verificationMethod: `${createDID(trusted.publicKey)}#key-1`,
      signingKey: trusted.privateKey,
    }) as Record<string, unknown>
    ;(credential.proof as Record<string, unknown>).type = 'JsonWebSignature2020'
    const result = await verifyVC(credential as never)
    assert.equal(result.valid, false)
    assert.match(String(result.error), /Unsupported proof type/)
  })

  it('an expected issuer that does not match is refused', async () => {
    const vc = unboundCredential({
      issuer: createDID(trusted.publicKey),
      verificationMethod: `${createDID(trusted.publicKey)}#key-1`,
      signingKey: trusted.privateKey,
    })
    assert.equal((await verifyVC(vc as never)).valid, false, 'unbound proof shape must not verify')
    const result = await verifyVC(vc as never, { expectedIssuer: createDID(attacker.publicKey) })
    assert.equal(result.valid, false)
  })
})

describe('the presentation creators refuse options a verifier could never accept', () => {
  // The types require `challenge`. A JavaScript caller is not typed, and a
  // presentation minted without one is permanently unverifiable, because both
  // presentation verifiers require an expected challenge and refuse a proof
  // carrying none. That is the creator-verifier disagreement the attestation
  // path already refuses to ship.
  const creators: Array<[string, (options: unknown) => Promise<unknown>]> = [
    ['createPresentation',
      (options) => createPresentation([], holder.privateKey, holder.publicKey, options as never)],
    ['createVerifiablePresentation',
      (options) => createVerifiablePresentation([], holder.privateKey, options as never)],
  ]

  const badChallenge: Array<[string, unknown]> = [
    ['an empty options object', {}],
    ['an empty challenge', { challenge: '' }],
    ['a null challenge', { challenge: null }],
    ['an undefined challenge', { challenge: undefined }],
    ['a numeric challenge', { challenge: 12345 }],
    ['an object challenge', { challenge: { nonce: 'a' } }],
    ['absent options entirely', undefined],
  ]

  const badDomain: Array<[string, unknown]> = [
    ['an empty domain', { challenge: 'nonce-a', domain: '' }],
    ['a null domain', { challenge: 'nonce-a', domain: null }],
    ['a numeric domain', { challenge: 'nonce-a', domain: 443 }],
  ]

  for (const [name, create] of creators) {
    for (const [label, options] of badChallenge) {
      it(`${name} refuses ${label}`, async () => {
        await assert.rejects(() => create(options) as Promise<unknown>,
          (err: unknown) => err instanceof TypeError && /challenge is required/.test(err.message))
      })
    }

    for (const [label, options] of badDomain) {
      it(`${name} refuses ${label}`, async () => {
        await assert.rejects(() => create(options) as Promise<unknown>,
          (err: unknown) => err instanceof TypeError && /domain is optional/.test(err.message))
      })
    }

    it(`${name} still accepts a challenge alone, and a challenge with a domain`, async () => {
      await assert.doesNotReject(() => create({ challenge: 'nonce-a' }) as Promise<unknown>)
      await assert.doesNotReject(
        () => create({ challenge: 'nonce-a', domain: 'verifier-a.example' }) as Promise<unknown>)
    })

    it(`${name} refuses before signing, so no unverifiable presentation exists`, async () => {
      let returned: unknown = 'nothing was returned'
      try {
        returned = await create({})
      } catch {
        // expected
      }
      assert.equal(returned, 'nothing was returned')
    })
  }
})

describe('F-02 replay: challenge and domain are inside the signed bytes', () => {
  it('legacy createPresentation honours the options it declares', async () => {
    const vp = await createPresentation([], holder.privateKey, holder.publicKey, {
      challenge: 'nonce-a', domain: 'verifier-a.example',
    })
    // It used to accept these and silently discard them, so a caller that
    // asked for replay protection got a presentation with none.
    assert.equal(vp.proof.challenge, 'nonce-a')
    assert.equal(vp.proof.domain, 'verifier-a.example')
  })

  for (const surface of ['vc.ts', 'vc-wrapper.ts'] as const) {
    describe(surface, () => {
      const mint = async (options: { challenge: string; domain?: string }) =>
        surface === 'vc.ts'
          ? await createPresentation([], holder.privateKey, holder.publicKey, options)
          : await createVerifiablePresentation([], holder.privateKey, options)
      const check = async (vp: unknown, opts?: Record<string, string>) =>
        surface === 'vc.ts'
          ? await verifyPresentation(vp as never, opts as never)
          : await verifyVerifiablePresentation(vp as never, opts as never)

      it('accepts the presentation it was minted for', async () => {
        const vp = await mint({ challenge: 'nonce-a', domain: 'verifier-a.example' })
        const result = await check(vp, { expectedChallenge: 'nonce-a', expectedDomain: 'verifier-a.example' })
        assert.equal(result.valid, true)
        // The verified values are returned so the relying party can consume
        // the nonce; one-time use is its state, not this verifier's.
        assert.equal(result.challenge, 'nonce-a')
        assert.equal(result.domain, 'verifier-a.example')
      })

      it('refuses a challenge rewritten after signing', async () => {
        const vp = JSON.parse(JSON.stringify(await mint({ challenge: 'nonce-a', domain: 'verifier-a.example' })))
        vp.proof.challenge = 'nonce-b'
        const result = await check(vp, { expectedChallenge: 'nonce-b', expectedDomain: 'verifier-a.example' })
        assert.equal(result.valid, false)
      })

      it('refuses a domain rewritten after signing', async () => {
        const vp = JSON.parse(JSON.stringify(await mint({ challenge: 'nonce-a', domain: 'verifier-a.example' })))
        vp.proof.domain = 'verifier-b.example'
        const result = await check(vp, { expectedChallenge: 'nonce-a', expectedDomain: 'verifier-b.example' })
        assert.equal(result.valid, false)
      })

      it('refuses a challenge that does not match the expectation', async () => {
        const vp = await mint({ challenge: 'nonce-a' })
        assert.equal((await check(vp, { expectedChallenge: 'nonce-b' })).valid, false)
      })

      it('refuses a domain that does not match the expectation', async () => {
        const vp = await mint({ challenge: 'nonce-a', domain: 'verifier-a.example' })
        assert.equal((await check(vp, {
          expectedChallenge: 'nonce-a', expectedDomain: 'verifier-b.example',
        })).valid, false)
      })

      it('refuses a proof carrying no challenge when one is expected', async () => {
        // The creator requires a challenge, so a proof without one has to be
        // built by hand. That is exactly what an attacker presenting an
        // unbound presentation would do.
        const vp = JSON.parse(JSON.stringify(await mint({ challenge: 'nonce-a' })))
        delete vp.proof.challenge
        assert.equal((await check(vp, { expectedChallenge: 'nonce-a' })).valid, false)
      })

      it('refuses a proof carrying no domain when one is expected', async () => {
        const vp = await mint({ challenge: 'nonce-a' })
        assert.equal((await check(vp, {
          expectedChallenge: 'nonce-a', expectedDomain: 'verifier-a.example',
        })).valid, false)
      })

      it('refuses a verifier that states no challenge at all', async () => {
        // Required in the types; an untyped caller reaching here is making no
        // replay check, not a weaker one.
        const vp = await mint({ challenge: 'nonce-a' })
        assert.equal((await check(vp, {} as never)).valid, false)
      })

      it('refuses a created timestamp rewritten after signing', async () => {
        // `created` is proof configuration too. It was outside the signature
        // along with everything else in the proof block.
        const vp = JSON.parse(JSON.stringify(await mint({ challenge: 'nonce-a' })))
        vp.proof.created = '2020-01-01T00:00:00.000Z'
        assert.equal((await check(vp, { expectedChallenge: 'nonce-a' })).valid, false)
      })

      it('refuses a proofPurpose rewritten after signing', async () => {
        const vp = JSON.parse(JSON.stringify(await mint({ challenge: 'nonce-a' })))
        vp.proof.proofPurpose = 'assertionMethod'
        assert.equal((await check(vp, { expectedChallenge: 'nonce-a' })).valid, false)
      })
    })
  }

  it('verifyCredentialResponse compares a challenge that is actually signed', async () => {
    const agent = generateKeyPair()
    const request = createCredentialRequest(['grade'], 'did:key:z6MkVerifier', 'real-challenge')
    const vp = await fulfillCredentialRequest(request, {
      agentId: 'agent-replay', publicKey: agent.publicKey, grade: 1,
      expiresAt: '2027-01-01T00:00:00.000Z',
    }, agent.privateKey)

    assert.equal((await verifyCredentialResponse(vp, 'real-challenge')).valid, true)
    assert.equal((await verifyCredentialResponse(vp, 'wrong-challenge')).valid, false)

    // The rewrite that used to defeat the check this function advertises.
    const rewritten = JSON.parse(JSON.stringify(vp))
    rewritten.proof.challenge = 'wrong-challenge'
    assert.equal((await verifyCredentialResponse(rewritten, 'wrong-challenge')).valid, false)
  })

  it('verifyCredentialResponse cannot be called without a challenge to compare', async () => {
    const agent = generateKeyPair()
    const request = createCredentialRequest(['grade'], 'did:key:z6MkVerifier', 'some-challenge')
    const vp = await fulfillCredentialRequest(request, {
      agentId: 'agent-noreplay', publicKey: agent.publicKey, grade: 1,
      expiresAt: '2027-01-01T00:00:00.000Z',
    }, agent.privateKey)
    // The challenge is required in the types. It used to be optional, and a
    // call that omitted it verified the response while comparing no nonce,
    // reporting the skip in `checks` — a response to nothing in particular,
    // replayable by anyone who had seen it. An untyped caller reaching here
    // now gets a rejection instead of a pass with a note.
    const omitted = await verifyCredentialResponse(vp, undefined as never)
    assert.equal(omitted.valid, false)

    const supplied = await verifyCredentialResponse(vp, 'some-challenge')
    assert.equal(supplied.valid, true)
  })
})
