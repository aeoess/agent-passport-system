// Verification-source tests: happy path per method, fail-closed validation,
// canonicalization stability, and the additive byte-identity hard gate (a
// receipt whose commitments omit the field signs byte-for-byte as before).

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  buildVerificationSource,
  validateVerificationSource,
  type VerificationSource,
} from '../../src/v2/verification-source/index.js'
import {
  createBilateralReceipt,
  createEvidenceCommitment,
  verifyBilateralReceipt,
} from '../../src/core/bilateral-receipt.js'
import { canonicalize } from '../../src/core/canonical.js'
import { canonicalizeJCS } from '../../src/core/canonical-jcs.js'
import { buildEvidenceDescriptor } from '../../src/v2/assurance/descriptor.js'
import { generateKeyPair } from '../../src/crypto/keys.js'
import type { InteractionOutcome } from '../../src/types/bilateral-receipt.js'

const T0 = Date.parse('2026-06-01T00:00:00.000Z')

// ── happy path per method ──

describe('verification-source: happy path per method', () => {
  it('inline: method + verified_at_ms only', () => {
    const s = buildVerificationSource({ method: 'inline', verified_at_ms: T0 })
    assert.deepEqual(s, { method: 'inline', verified_at_ms: T0 })
    assert.equal(validateVerificationSource(s).valid, true)
  })

  it('resolver: carries the allowlisted https origin used', () => {
    const s = buildVerificationSource({
      method: 'resolver', verified_at_ms: T0, resolver_origin: 'https://resolver.example',
    })
    assert.equal(s.resolver_origin, 'https://resolver.example')
    assert.equal(validateVerificationSource(s).valid, true)
  })

  it('pinned: carries when and through which method the pin was populated', () => {
    const s = buildVerificationSource({
      method: 'pinned', verified_at_ms: T0,
      pin_populated_at_ms: T0 - 86_400_000, pin_populated_via: 'resolver',
    })
    assert.equal(s.pin_populated_via, 'resolver')
    assert.equal(validateVerificationSource(s).valid, true)
  })
})

// ── fail closed ──

describe('verification-source: fail-closed validation', () => {
  it('INVALID: pinned without population provenance', () => {
    const v = validateVerificationSource({ method: 'pinned', verified_at_ms: T0 } as VerificationSource)
    assert.equal(v.valid, false)
    assert.ok(v.reasons.some((r) => r.includes('pin_populated_at_ms')))
    assert.ok(v.reasons.some((r) => r.includes('pin_populated_via')))
  })

  it('INVALID: pinned with timestamp but no via', () => {
    const v = validateVerificationSource({
      method: 'pinned', verified_at_ms: T0, pin_populated_at_ms: T0 - 1,
    } as VerificationSource)
    assert.equal(v.valid, false)
  })

  it('INVALID: pin populated after the check it backs', () => {
    const v = validateVerificationSource({
      method: 'pinned', verified_at_ms: T0,
      pin_populated_at_ms: T0 + 1, pin_populated_via: 'inline',
    })
    assert.equal(v.valid, false)
    assert.ok(v.reasons.some((r) => r.includes('not be later')))
  })

  it('INVALID: resolver without resolver_origin', () => {
    const v = validateVerificationSource({ method: 'resolver', verified_at_ms: T0 } as VerificationSource)
    assert.equal(v.valid, false)
    assert.ok(v.reasons.some((r) => r.includes('resolver_origin')))
  })

  it('INVALID: resolver with a non-https origin', () => {
    const v = validateVerificationSource({
      method: 'resolver', verified_at_ms: T0, resolver_origin: 'http://resolver.example',
    })
    assert.equal(v.valid, false)
  })

  it('INVALID: inline carrying method-mismatched fields', () => {
    const v = validateVerificationSource({
      method: 'inline', verified_at_ms: T0, resolver_origin: 'https://resolver.example',
    })
    assert.equal(v.valid, false)
    const v2 = validateVerificationSource({
      method: 'inline', verified_at_ms: T0, pin_populated_via: 'inline',
    } as VerificationSource)
    assert.equal(v2.valid, false)
  })

  it('INVALID: non-finite or non-positive verified_at_ms', () => {
    for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      const v = validateVerificationSource({ method: 'inline', verified_at_ms: bad })
      assert.equal(v.valid, false, `verified_at_ms ${bad} must be invalid`)
    }
  })

  it('builder throws on the same invalid combinations', () => {
    assert.throws(() => buildVerificationSource({ method: 'pinned', verified_at_ms: T0 }), /pin_populated/)
    assert.throws(() => buildVerificationSource({ method: 'resolver', verified_at_ms: T0 }), /resolver_origin/)
  })
})

// ── canonicalization stability ──

describe('verification-source: canonicalization stability', () => {
  it('identical records canonicalize to identical bytes under both schemes', () => {
    const a = buildVerificationSource({
      method: 'pinned', verified_at_ms: T0,
      pin_populated_at_ms: T0 - 5_000, pin_populated_via: 'inline',
    })
    const b = buildVerificationSource({
      pin_populated_via: 'inline', pin_populated_at_ms: T0 - 5_000,
      verified_at_ms: T0, method: 'pinned',
    })
    assert.equal(canonicalize(a), canonicalize(b))
    assert.equal(canonicalizeJCS(a as unknown as Record<string, unknown>), canonicalizeJCS(b as unknown as Record<string, unknown>))
  })

  it('the builder never emits explicitly-undefined keys', () => {
    const s = buildVerificationSource({ method: 'inline', verified_at_ms: T0 })
    assert.deepEqual(Object.keys(s).sort(), ['method', 'verified_at_ms'])
  })
})

// ── the additive byte-identity hard gate ──

describe('verification-source: omission keeps receipt bytes and signatures unchanged', () => {
  const outcome: InteractionOutcome = {
    toolName: 'records.read',
    requestHash: 'a'.repeat(64),
    responseHash: 'b'.repeat(64),
    status: 'success',
    summary: 'one read',
  }

  it('a commitment built without the field has the exact pre-change key set', () => {
    const c = createEvidenceCommitment({ type: 'compliance_check', credential: 'jwt-bytes', pass: true })
    assert.equal(Object.prototype.hasOwnProperty.call(c, 'verificationSource'), false)
    assert.deepEqual(
      Object.keys(c).sort(),
      ['committedAt', 'credentialHash', 'issuerKid', 'jwks', 'pass', 'type'],
    )
  })

  it('receipt body bytes with the field omitted equal the hand-built pre-change body', () => {
    const reqKp = generateKeyPair()
    const srvKp = generateKeyPair()
    const commitment = createEvidenceCommitment({ type: 'compliance_check', credential: 'jwt-bytes', pass: true })
    const receipt = createBilateralReceipt({
      requestingAgentId: 'agent-req', servingAgentId: 'agent-srv',
      outcome, requestedAt: '2026-06-01T00:00:00.000Z', completedAt: '2026-06-01T00:00:01.000Z',
      requestingAgentPrivateKey: reqKp.privateKey, servingAgentPrivateKey: srvKp.privateKey,
      evidenceCommitments: [commitment],
    })
    // Reconstruct the signed body exactly as verifyBilateralReceipt does,
    // and a pre-change body shape (no verificationSource key anywhere).
    const body = {
      receiptId: receipt.receiptId, version: receipt.version,
      requestingAgentId: receipt.requestingAgentId, servingAgentId: receipt.servingAgentId,
      delegationId: receipt.delegationId, outcome: receipt.outcome,
      requestedAt: receipt.requestedAt, completedAt: receipt.completedAt,
      agreedAt: receipt.agreedAt, evidenceCommitments: receipt.evidenceCommitments,
      aud: receipt.aud, fieldDisclosureProfile: receipt.fieldDisclosureProfile,
    }
    const preChangeBody = {
      ...body,
      evidenceCommitments: [{
        type: commitment.type, credentialHash: commitment.credentialHash,
        issuerKid: undefined, jwks: undefined, pass: commitment.pass,
        committedAt: commitment.committedAt,
      }],
    }
    assert.equal(canonicalize(body), canonicalize(preChangeBody))
    // And the signatures over those bytes validate.
    const v = verifyBilateralReceipt(receipt, reqKp.publicKey, srvKp.publicKey)
    assert.equal(v.requestingAgentSignatureValid, true)
    assert.equal(v.servingAgentSignatureValid, true)
  })

  it('a commitment carrying the field changes the signed bytes (it is inside the signature)', () => {
    const source = buildVerificationSource({ method: 'inline', verified_at_ms: T0 })
    const withField = createEvidenceCommitment({
      type: 'compliance_check', credential: 'jwt-bytes', pass: true, verificationSource: source,
    })
    const withoutField = createEvidenceCommitment({ type: 'compliance_check', credential: 'jwt-bytes', pass: true })
    assert.notEqual(
      canonicalize({ evidenceCommitments: [withField] }),
      canonicalize({ evidenceCommitments: [withoutField] }),
    )
  })
})

// ── descriptor carry-through ──

describe('verification-source: descriptor signer facts', () => {
  it('echoes the source onto the SignerClaim when recorded, absent otherwise', () => {
    const source = buildVerificationSource({
      method: 'resolver', verified_at_ms: T0, resolver_origin: 'https://resolver.example',
    })
    const d = buildEvidenceDescriptor({
      receiptId: 'r-1',
      signatures: [
        { signerId: 'signer-a', claim: 'outcome', valid: true, verificationSource: source },
        { signerId: 'signer-b', claim: 'outcome', valid: true },
      ],
    })
    assert.deepEqual(d.signerClaims[0].verificationSource, source)
    assert.equal(Object.prototype.hasOwnProperty.call(d.signerClaims[1], 'verificationSource'), false)
  })

  it('does not alter independence or corroboration facts', () => {
    const source = buildVerificationSource({ method: 'inline', verified_at_ms: T0 })
    const base = {
      receiptId: 'r-2',
      signatures: [
        { signerId: 'signer-a', claim: 'outcome', valid: true as const, chainsTo: ['root-1'] },
        { signerId: 'signer-b', claim: 'outcome', valid: true as const, chainsTo: ['root-2'] },
      ],
    }
    const withSources = {
      ...base,
      signatures: base.signatures.map((s) => ({ ...s, verificationSource: source })),
    }
    const d1 = buildEvidenceDescriptor(base)
    const d2 = buildEvidenceDescriptor(withSources)
    assert.equal(d1.corroborationStatus, d2.corroborationStatus)
    assert.equal(d1.independentSignerCount, d2.independentSignerCount)
    assert.deepEqual(d1.independenceRelations, d2.independenceRelations)
  })
})
