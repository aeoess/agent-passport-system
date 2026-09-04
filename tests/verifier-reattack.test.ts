// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Second pass at the repaired verifiers, from angles the audit did not use.
// ══════════════════════════════════════════════════════════════════
// The first pass fixed what was reported. This one tries to get a
// security-shaped `true` back out of the same four surfaces by other routes:
// identifiers that look equal without being equal, canonicalization the
// verifier and the attacker might read differently, a signature that covers
// less than the verifier assumes, and one signature doing duty for two
// artifacts.
//
// Every case here is kept whatever it found. A case that passes today is a
// regression guard; the two that describe a limit rather than a defence say so
// in place, because a limit nobody wrote down is a limit nobody checks.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize, canonicalizeForWrite } from '../src/core/canonical.js'
import { createDID } from '../src/core/did.js'
import { toDIDKey } from '../src/core/did-interop.js'
import { bindVerificationMethod, proofSigningInput } from '../src/core/vc-proof.js'
import { verifyVC } from '../src/core/vc.js'
import { createVerifiablePresentation, verifyVerifiablePresentation } from '../src/core/vc-wrapper.js'
import { parseRfc3339 } from '../src/core/rfc3339.js'
import {
  createContentAddressableIntent, createDecisionArtifact, verifyDecisionArtifact,
} from '../src/core/decision-semantics.js'
import { createMinimalEnvelope, verifyExecutionEnvelope } from '../src/core/execution-envelope.js'
import type { PolicyDecision } from '../src/types/policy.js'

const agent = generateKeyPair()
const evaluator = generateKeyPair()
const artifactSigner = generateKeyPair()

const b64 = (hex: string) => Buffer.from(hex, 'hex').toString('base64url')

describe('re-attack: identifiers that look equal without being equal', () => {
  it('a DID differing only by Unicode normalization is not the claimed DID', () => {
    // NFC and NFD spellings compare unequal as JS strings, and the binding is
    // string equality. The attack would be the reverse — two spellings the
    // verifier treats as equal while a human reads them as different — so what
    // matters is that no normalization happens on either side.
    const did = createDID(agent.publicKey)
    const decomposed = did.normalize('NFD')
    const composed = did.normalize('NFC')
    assert.equal(composed, did)
    const binding = bindVerificationMethod(composed, `${decomposed}#key-1`)
    // For a base58 DID these are the same string, so this asserts the
    // identifier alphabet has no combining characters to exploit in the first
    // place. If a future DID method admitted them, this would start failing
    // and the binding would need an explicit normalization decision.
    assert.equal(binding.keyAuthority, 'verified')
  })

  it('a homoglyph in the DID is a different DID', () => {
    // Cyrillic small letter a (U+0430) for Latin a, in the method name.
    const did = createDID(agent.publicKey)
    const inMethod = did.replace('did:aps:', 'did:аps:')
    assert.notEqual(inMethod, did)
    // Claimed DID and verificationMethod disagree: a rejection.
    assert.equal(bindVerificationMethod(did, `${inMethod}#key-1`).keyAuthority, 'rejected')
    // They agree with each other, and name a method that does not exist. That
    // is 'unresolved' rather than 'rejected' — nothing was disproved — and the
    // property that matters is that it is not an acceptance.
    assert.equal(bindVerificationMethod(inMethod, `${inMethod}#key-1`).keyAuthority, 'unresolved')

    // And in the identifier, where it would have to decode to a key.
    const inIdentifier = did.slice(0, -1) + 'а'
    assert.notEqual(inIdentifier, did)
    assert.notEqual(bindVerificationMethod(inIdentifier, `${inIdentifier}#key-1`).keyAuthority, 'verified')
    assert.equal(bindVerificationMethod(did, `${inIdentifier}#key-1`).keyAuthority, 'rejected')
  })

  it('a zero-width character inside a DID does not bind', () => {
    const did = createDID(agent.publicKey)
    const padded = did + '​'
    assert.equal(bindVerificationMethod(padded, `${padded}#key-1`).keyAuthority, 'rejected')
    assert.equal(bindVerificationMethod(did, `${padded}#key-1`).keyAuthority, 'rejected')
  })

  it('a scope that differs only by Unicode is outside an allowed set', async () => {
    // Scope matching is set membership on exact strings. A homoglyph scope is
    // a different scope, which is the safe direction: it fails the allow-list
    // rather than passing it.
    const signer = generateKeyPair()
    const envelope = createMinimalEnvelope({
      agentDid: 'did:aps:agent', runId: 'run', actionId: 'action',
      scope: ['commerce:purchаse'], revocationStatus: 'active',
      decisionHash: 'sha256:x', policyRef: 'p', evaluationMethod: 'deterministic',
      verdict: 'permit', evaluatedAt: new Date().toISOString(),
      evaluatorDid: 'did:aps:e', evaluatorSignature: 'f'.repeat(128),
      receiptHash: 'sha256:x',
      signerPrivateKey: signer.privateKey, signerPublicKey: signer.publicKey,
    })
    const result = verifyExecutionEnvelope(envelope, {
      trustedSignerPublicKeys: [signer.publicKey],
      expected: { allowedScope: ['commerce:purchase'] },
    })
    assert.equal(result.contextValid, false)
    assert.equal(result.valid, false)
  })
})

describe('re-attack: canonicalization', () => {
  it('a duplicate JSON key cannot make the verifier read a different document', () => {
    // JSON.parse keeps the LAST occurrence of a duplicated key, and the
    // canonicalizer walks the parsed object, so both the verifier and any
    // recomputation see the same value. There is no split view to exploit.
    const raw = '{"verdict":"deny","verdict":"permit","id":"x"}'
    const parsed = JSON.parse(raw) as Record<string, unknown>
    assert.equal(parsed.verdict, 'permit')
    assert.equal(canonicalize(parsed), canonicalize({ id: 'x', verdict: 'permit' }))
  })

  it('a null-valued member is indistinguishable from an absent one, as documented', () => {
    // Stated so the property is checked rather than assumed: the canonical
    // form strips null and undefined, which is why no security-critical field
    // may use null as a meaningful value. A verifier that relied on presence
    // to mean something would be exploitable here.
    assert.equal(canonicalize({ a: 1, b: null }), canonicalize({ a: 1 }))
    assert.equal(canonicalize({ a: 1, b: undefined }), canonicalize({ a: 1 }))
  })

  it('reordering members does not change what was signed', () => {
    const a = { z: 1, a: 2, m: { y: 3, b: 4 } }
    const b = { a: 2, m: { b: 4, y: 3 }, z: 1 }
    assert.equal(canonicalize(a), canonicalize(b))
  })
})

describe('re-attack: a signature that covers less than the verifier assumes', () => {
  it('a credential proof made over a prefix of the document does not verify', async () => {
    // Sign the body without credentialSubject, then present the full
    // credential. Before the proof configuration entered the signed bytes this
    // class of attack had a larger surface; it is checked here because a
    // partial preimage is the first thing to try against a new signing input.
    const did = createDID(agent.publicKey)
    const full = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:aps:credential:prefix',
      type: ['VerifiableCredential'],
      issuer: did,
      issuanceDate: '2026-01-01T00:00:00.000Z',
      credentialSubject: { id: did, role: 'admin' },
    }
    const { credentialSubject: _dropped, ...prefix } = full
    const proofConfig = {
      type: 'Ed25519Signature2020', created: '2026-01-01T00:00:00.000Z',
      verificationMethod: `${did}#key-1`, proofPurpose: 'assertionMethod',
    }
    const overPrefix = sign(proofSigningInput(prefix, proofConfig, canonicalizeForWrite), agent.privateKey)
    const forged = { ...full, proof: { ...proofConfig, proofValue: b64(overPrefix) } }
    const result = await verifyVC(forged as never)
    assert.equal(result.valid, false)
    assert.equal(result.keyAuthority, 'rejected')
  })

  it('a presentation proof made before a credential was added does not verify', async () => {
    const holder = generateKeyPair()
    const issuerDid = toDIDKey(agent.publicKey)
    const body = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:aps:credential:smuggled',
      type: ['VerifiableCredential'],
      issuer: issuerDid,
      issuanceDate: '2026-01-01T00:00:00.000Z',
      credentialSubject: { id: issuerDid, role: 'admin' },
    }
    const proofConfig = {
      type: 'Ed25519Signature2020', created: '2026-01-01T00:00:00.000Z',
      verificationMethod: `${issuerDid}#key-1`, proofPurpose: 'assertionMethod',
    }
    const credential = {
      ...body,
      proof: {
        ...proofConfig,
        proofValue: b64(sign(proofSigningInput(body, proofConfig, canonicalizeForWrite), agent.privateKey)),
      },
    }
    // An empty presentation, signed, then a real credential smuggled in after.
    const empty = await createVerifiablePresentation([], holder.privateKey, { challenge: 'n' })
    const smuggled = JSON.parse(JSON.stringify(empty))
    smuggled.verifiableCredential = [credential]
    const result = await verifyVerifiablePresentation(smuggled, { expectedChallenge: 'n' })
    assert.equal(result.valid, false)
  })
})

describe('re-attack: one signature doing duty for two artifacts', () => {
  it('a decision signature lifted onto a second artifact does not transfer', async () => {
    const intent = await createContentAddressableIntent({
      agentId: 'agent-reattack', agentPublicKey: agent.publicKey,
      delegationId: 'del', action: { type: 'admin', target: 'system', scopeRequired: 'admin:*' },
      privateKey: agent.privateKey,
    })
    const body = {
      decisionId: 'pdec_reattack', intentId: intent.intentId,
      evaluatorId: 'evaluator-reattack', evaluatorPublicKey: evaluator.publicKey,
      verdict: 'permit', evaluationMethod: 'deterministic', principlesEvaluated: [],
      reason: 'permitted', floorVersion: 'floor',
      evaluatedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
    }
    const decision = { ...body, signature: sign(canonicalizeForWrite(body), evaluator.privateKey) } as unknown as PolicyDecision
    const artifact = await createDecisionArtifact({
      intent, decision, engine: 'aps', signerPrivateKey: artifactSigner.privateKey,
    })

    // A second artifact about the same intent and decision, carrying the same
    // proof block, but describing a different engine and a different verdict.
    const twin = JSON.parse(JSON.stringify(artifact))
    twin.artifactId = 'dart_twin'
    twin.engine = 'other-engine'
    twin.evaluation.verdict = 'deny'
    const { proof, ...twinBody } = twin
    twin.proof.artifactSignature = sign(
      canonicalizeForWrite({
        ...twinBody,
        proof: { intentSignature: proof.intentSignature, decisionSignature: proof.decisionSignature },
      }),
      artifactSigner.privateKey)

    const keys = {
      intentSignerPublicKey: agent.publicKey,
      decisionSignerPublicKey: evaluator.publicKey,
      artifactSignerPublicKey: artifactSigner.publicKey,
    }
    assert.equal((await verifyDecisionArtifact(artifact, keys, intent, decision)).valid, true)
    // The twin carries a real decision signature and a real artifact
    // signature; what it cannot have is a verdict the decision did not reach.
    const twinResult = await verifyDecisionArtifact(twin, keys, intent, decision)
    assert.equal(twinResult.valid, false)
    assert.equal(twinResult.projectionValid, false)
  })

  it('an evaluator signature lifted onto a second envelope does not transfer', () => {
    const signer = generateKeyPair()
    const body = {
      decisionId: 'pdec_env_reattack', intentId: 'intent_a',
      evaluatorId: 'evaluator-reattack', evaluatorPublicKey: evaluator.publicKey,
      verdict: 'permit', evaluationMethod: 'deterministic', principlesEvaluated: [],
      reason: 'permitted', floorVersion: 'floor',
      evaluatedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
    }
    const decision = { ...body, signature: sign(canonicalizeForWrite(body), evaluator.privateKey) } as unknown as PolicyDecision

    // A second envelope, correctly signed by a trusted gateway, carrying the
    // real evaluator signature but describing a different action.
    const envelope = createMinimalEnvelope({
      agentDid: 'did:aps:agent', runId: 'run', actionId: 'intent_b',
      scope: ['admin:*'], revocationStatus: 'active',
      decisionHash: 'sha256:whatever', policyRef: 'floor',
      evaluationMethod: 'deterministic', verdict: 'permit',
      evaluatedAt: decision.evaluatedAt,
      evaluatorDid: 'did:aps:evaluator-reattack',
      evaluatorSignature: decision.signature,
      receiptHash: 'sha256:whatever',
      signerPrivateKey: signer.privateKey, signerPublicKey: signer.publicKey,
    })
    const result = verifyExecutionEnvelope(envelope, {
      trustedSignerPublicKeys: [signer.publicKey],
      originalDecision: decision,
      evaluatorPublicKey: evaluator.publicKey,
      expected: { actionId: 'intent_b' },
    })
    // The signature verifies over the decision; the envelope projects a
    // different action_id and a decision_hash that is not that decision's.
    assert.equal(result.valid, false)
    assert.equal(result.evaluatorAuthority, 'rejected')
  })
})

describe('re-attack: stated limits, not defences', () => {
  it('LIMIT: a verificationMethod fragment the controller does not list still binds', () => {
    // A self-certifying DID commits to exactly one key, so the fragment
    // selects nothing and cannot substitute key material. Checking that the
    // controller lists this fragment would need the DID document this SDK does
    // not resolve. Recorded so the limit is visible rather than assumed.
    const did = createDID(agent.publicKey)
    for (const fragment of ['key-1', 'key-99', 'not-a-key', '']) {
      const binding = bindVerificationMethod(did, `${did}#${fragment}`)
      assert.equal(binding.keyAuthority, 'verified',
        `fragment ${fragment} changed the binding, which would mean it carries authority`)
      assert.equal(binding.keyAuthority === 'verified' && binding.publicKey, agent.publicKey)
    }
  })

  it('LIMIT: a leap second is refused rather than interpreted', () => {
    // RFC 3339 admits :60. The instant it names has no millisecond
    // representation, and folding it either way would move a boundary, so it
    // is refused with its own reason. A caller carrying leap seconds has to
    // decide what one means before a verifier can.
    const result = parseRfc3339('2016-12-31T23:59:60Z')
    assert.equal(result.ok, false)
    assert.equal(result.ok === false && result.reason, 'leap_second')
  })

  it('LIMIT: revocation_status is what the emitter wrote, not a live check', () => {
    // An envelope emitted while the delegation was active still says active
    // after it is revoked. Nothing in the envelope can know otherwise; the
    // relying party has to consult its own revocation view.
    const signer = generateKeyPair()
    const envelope = createMinimalEnvelope({
      agentDid: 'did:aps:agent', runId: 'run', actionId: 'action',
      scope: ['read:*'], revocationStatus: 'active',
      decisionHash: 'sha256:x', policyRef: 'p', evaluationMethod: 'deterministic',
      verdict: 'permit', evaluatedAt: new Date().toISOString(),
      evaluatorDid: 'did:aps:e', evaluatorSignature: 'f'.repeat(128),
      receiptHash: 'sha256:x',
      signerPrivateKey: signer.privateKey, signerPublicKey: signer.publicKey,
    })
    const result = verifyExecutionEnvelope(envelope, { trustedSignerPublicKeys: [signer.publicKey] })
    assert.equal(result.capabilityActive, true)
    // and the envelope is still not valid, because nothing else was supplied.
    assert.equal(result.valid, false)
  })

  it('LIMIT: a presentation does not bind its credentials to the holder', () => {
    // A holder may legitimately present a credential about someone else, so a
    // valid presentation of a valid credential says nothing about whether the
    // presenter is its subject. The relying party compares them itself.
    assert.ok(true, 'stated in the scope of claim on both presentation verifiers')
  })
})

describe('re-attack: attacker-supplied key material', () => {
  it('a small-order public key does not verify anything', () => {
    // The Edwards identity as a public key makes the RFC 8032 equation
    // degenerate. crypto/keys.ts refuses inadmissible key material, and the
    // binding path cannot reach verify() with one anyway, but the property is
    // worth pinning where a verifier depends on it.
    const identity = '01' + '00'.repeat(31)
    assert.equal(bindVerificationMethod(`did:aps:${identity}`, `did:aps:${identity}#key-1`).keyAuthority, 'rejected')
  })

  it('an over-long public key in a DID is refused rather than truncated', () => {
    const overlong = agent.publicKey + 'ff'
    assert.equal(bindVerificationMethod(`did:key:${overlong}`, `did:key:${overlong}#key-1`).keyAuthority, 'rejected')
  })
})
