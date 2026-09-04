// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// The old body-only proof preimage is not accepted, and must not become
// accepted again.
// ══════════════════════════════════════════════════════════════════
// Before this branch, a credential's proof was made over the document body
// alone and the proof block was attached afterwards, so `created`,
// `proofPurpose`, `verificationMethod`, `challenge` and `domain` were
// rewritable without invalidating `proofValue`. The preimage now covers the
// proof configuration, and credentials issued under the old rule do not
// verify. Reissuance is the migration; this is a ratified break.
//
// The tempting repair is to accept both preimages for a while. It cannot be
// done safely: a verifier that still accepts an old-format proof cannot
// authenticate that proof's challenge or domain, because they were never
// signed, so the replay hole stays open for anything presented in the old
// format — and a presenter chooses the format. Dual verification would keep
// the finding open under the appearance of having closed it.
//
// Every credential below is signed by the LEGITIMATE issuer over the exact
// bytes the shipped code signed. Nothing here is forged. They are refused for
// covering too little, which is the whole point: if any of these ever passes
// again, dual verification has been reintroduced.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalizeForWrite } from '../src/core/canonical.js'
import { createDID } from '../src/core/did.js'
import { toDIDKey } from '../src/core/did-interop.js'
import { verifyVC, verifyPresentation } from '../src/core/vc.js'
import { verifyVerifiableCredential, verifyVerifiablePresentation } from '../src/core/vc-wrapper.js'
import { verifyGovernanceCredential, generateGovernanceBlock } from '../src/core/governance-block.js'
import type { GovernanceBlock, VerifiedGovernanceCredential } from '../src/core/governance-block.js'

const issuer = generateKeyPair()

/** The pre-branch signature: over the document body, with the proof block
 *  excluded entirely. Reproduced here rather than imported, because the code
 *  that produced it no longer exists. */
const bodyOnlyProofValue = (body: Record<string, unknown>): string =>
  Buffer.from(sign(canonicalizeForWrite(body), issuer.privateKey), 'hex').toString('base64url')

function oldFormatCredential(did: string): Record<string, unknown> {
  const body = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:aps:credential:old-format',
    type: ['VerifiableCredential'],
    issuer: did,
    issuanceDate: '2026-01-01T00:00:00.000Z',
    credentialSubject: { id: did, role: 'reader' },
  }
  return {
    ...body,
    proof: {
      type: 'Ed25519Signature2020',
      created: '2026-01-01T00:00:00.000Z',
      verificationMethod: `${did}#key-1`,
      proofPurpose: 'assertionMethod',
      proofValue: bodyOnlyProofValue(body),
    },
  }
}

function oldFormatPresentation(did: string, challenge: string): Record<string, unknown> {
  const body = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:aps:presentation:old-format',
    type: ['VerifiablePresentation'],
    holder: did,
    verifiableCredential: [],
  }
  return {
    ...body,
    proof: {
      type: 'Ed25519Signature2020',
      created: '2026-01-01T00:00:00.000Z',
      verificationMethod: `${did}#key-1`,
      proofPurpose: 'authentication',
      // Signed over the body only, then challenge and domain grafted on. This
      // is exactly the artifact whose replay fields could be rewritten.
      proofValue: bodyOnlyProofValue(body),
      challenge,
      domain: 'verifier-a.example',
    },
  }
}

describe('a credential signed under the old body-only preimage is refused', () => {
  it('vc.ts refuses one, though the issuer really signed it', async () => {
    const did = createDID(issuer.publicKey)
    const credential = oldFormatCredential(did)
    const result = await verifyVC(credential as never)
    assert.equal(result.valid, false,
      'accepting the old preimage reopens F-02: the proof configuration is unauthenticated')
    // The issuer binding holds — this is not a forgery, and the failure is
    // about what the signature covers, not about who made it.
    assert.equal(result.keyAuthority, 'verified')
    assert.equal(result.proofOfPossession, false)
  })

  it('vc-wrapper refuses one', async () => {
    const did = toDIDKey(issuer.publicKey)
    const result = await verifyVerifiableCredential(oldFormatCredential(did) as never)
    assert.equal(result.valid, false)
    assert.equal(result.keyAuthority, 'verified')
    assert.equal(result.proofOfPossession, false)
  })

  it('a presentation in the old format is refused even when the challenge matches', async () => {
    const did = createDID(issuer.publicKey)
    const vp = oldFormatPresentation(did, 'nonce-a')
    const result = await verifyPresentation(vp as never, { expectedChallenge: 'nonce-a' })
    assert.equal(result.valid, false,
      'the challenge on an old-format proof was never signed, so matching it establishes nothing')
  })

  it('the wrapper refuses the same presentation', async () => {
    const did = toDIDKey(issuer.publicKey)
    const vp = oldFormatPresentation(did, 'nonce-a')
    const result = await verifyVerifiablePresentation(vp as never, { expectedChallenge: 'nonce-a' })
    assert.equal(result.valid, false)
  })

  it('a governance credential in the old format is refused', () => {
    const block: GovernanceBlock = generateGovernanceBlock({
      content: 'governed content',
      publicKey: issuer.publicKey,
      privateKey: issuer.privateKey,
      terms: { version: '1.0', training: 'prohibited', inference: 'permitted', attribution_required: true },
    })
    const { signature: _sig, ...blockWithoutSig } = block
    void blockWithoutSig
    const did = createDID(issuer.publicKey)
    const body = {
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://aeoess.com/governance/v1'],
      type: ['VerifiableCredential', 'GovernanceCredential'],
      issuer: did,
      issuanceDate: '2026-01-01T00:00:00.000Z',
      credentialSubject: {
        governanceBlockHash: 'sha256:whatever',
        contentHash: block.content_hash,
        publisherDid: block.source_did,
        termsVersion: block.terms.version,
      },
    }
    const credential = {
      ...body,
      proof: {
        type: 'Ed25519Signature2020',
        created: '2026-01-01T00:00:00.000Z',
        verificationMethod: `${did}#key-1`,
        proofPurpose: 'assertionMethod',
        proofValue: bodyOnlyProofValue(body),
      },
    } as unknown as VerifiedGovernanceCredential
    const result = verifyGovernanceCredential(credential, block, issuer.publicKey)
    assert.equal(result.valid, false)
    assert.equal(result.proofOfPossession, false)
  })
})

describe('what makes the break necessary rather than merely chosen', () => {
  it('an old-format proof carries a challenge nothing signed', async () => {
    // The presenter, not the issuer, decides what the challenge says. Two
    // presentations differing only in their challenge carry the SAME
    // proofValue, because the signature never covered it. A verifier that
    // accepted this format could compare the field and learn nothing.
    const did = createDID(issuer.publicKey)
    const forA = oldFormatPresentation(did, 'nonce-a')
    const forB = oldFormatPresentation(did, 'nonce-b')
    const proofA = (forA as { proof: { proofValue: string } }).proof
    const proofB = (forB as { proof: { proofValue: string } }).proof
    assert.equal(proofA.proofValue, proofB.proofValue,
      'one signature, two challenges: this is why the old format cannot be dual-verified')

    // And both are refused, so neither readdressing succeeds.
    assert.equal((await verifyPresentation(forA as never, { expectedChallenge: 'nonce-a' })).valid, false)
    assert.equal((await verifyPresentation(forB as never, { expectedChallenge: 'nonce-b' })).valid, false)
  })
})
