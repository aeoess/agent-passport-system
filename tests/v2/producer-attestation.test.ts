// Producer-attestation tests: commitment round-trip, hash binding (mutated
// attestation bytes fail), omission byte-identity on both carriers, and the
// CPA slot presence/absence behavior including fail-closed shape checks.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import {
  createProducerAttestationCommitment,
  verifyProducerAttestationCommitment,
  validateProducerAttestationCommitment,
  buildCpaProducerAttestationRef,
  validateCpaProducerAttestationRef,
  type ProducerAttestationCommitment,
} from '../../src/v2/producer-attestation/index.js'
import { buildCPA, verifyCPA } from '../../src/v2/context-provenance/index.js'
import type { ContextItem } from '../../src/v2/context-provenance/index.js'
import { canonicalizeJCS } from '../../src/core/canonical-jcs.js'
import { publicKeyFromPrivate } from '../../src/crypto/keys.js'
import { hexToMultibase } from '../../src/core/did.js'
import type { RotatableDIDDocument } from '../../src/types/passport.js'

const ATTESTATION = 'eyJhbGciOiJFUzI1NiJ9.fake-eat-token-bytes.signature'
const sha256Hex = (s: string) => createHash('sha256').update(s, 'utf-8').digest('hex')

// ── minimal CPA harness (mirrors the context-provenance roundtrip tests) ──

const PRIV = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
const PUB = publicKeyFromPrivate(PRIV)
const PRODUCER_DID = `did:aps:${hexToMultibase(PUB)}`
const ATTESTED_AT = '2026-06-09T12:00:00Z'
const ACTION_REF = sha256Hex('producer-attestation.action.001')

function makeDIDDoc(pubHex: string, did: string): RotatableDIDDocument {
  const keyId = `${did}#key-1`
  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
    ],
    id: did,
    controller: did,
    verificationMethod: [
      { id: keyId, type: 'Ed25519VerificationKey2020', controller: did, publicKeyMultibase: hexToMultibase(pubHex) },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
    capabilityDelegation: [keyId],
    rotationLog: [],
    created: '2026-01-01T00:00:00Z',
    updated: '2026-01-01T00:00:00Z',
  }
}
const DID_DOC = makeDIDDoc(PUB, PRODUCER_DID)

const ITEMS: ContextItem[] = [
  { channel: 'user_instruction', ctx_id: 'ctx-1', content: 'summarize the labs' },
]

// ── receipt-side commitment ──

describe('producer-attestation: commitment round-trip and hash binding', () => {
  it('round-trip: create then check against the same bytes', () => {
    const c = createProducerAttestationCommitment({
      attestation: ATTESTATION,
      format: 'eat+jwt',
      locatorUri: 'https://attestations.example/eat/123',
      bindingNote: 'covers producer identity and code measurement',
    })
    assert.equal(c.type, 'producer_attestation')
    assert.equal(c.attestationFormat, 'eat+jwt')
    assert.equal(c.credentialHash, sha256Hex(ATTESTATION))
    assert.equal(verifyProducerAttestationCommitment(c, ATTESTATION).valid, true)
  })

  it('NEGATIVE: mutated attestation bytes fail the hash binding', () => {
    const c = createProducerAttestationCommitment({ attestation: ATTESTATION, format: 'tee-quote' })
    const v = verifyProducerAttestationCommitment(c, ATTESTATION + 'x')
    assert.equal(v.valid, false)
    assert.ok(v.reasons.some((r) => r.includes('do not match')))
  })

  it('NEGATIVE: structural validation fails closed', () => {
    assert.throws(() => createProducerAttestationCommitment({ attestation: ATTESTATION, format: '  ' }), /format/)
    assert.throws(() => createProducerAttestationCommitment({ attestation: '', format: 'eat+jwt' }), /attestation bytes/)
    const bad = { type: 'producer_attestation', attestationFormat: 'eat+jwt', credentialHash: 'nothex', committedAt: ATTESTED_AT } as unknown as ProducerAttestationCommitment
    assert.equal(validateProducerAttestationCommitment(bad).valid, false)
  })

  it('omitted options introduce no keys (no explicitly-undefined keys)', () => {
    const c = createProducerAttestationCommitment({ attestation: ATTESTATION, format: 'eat+jwt' })
    assert.equal(Object.prototype.hasOwnProperty.call(c, 'locatorUri'), false)
    assert.equal(Object.prototype.hasOwnProperty.call(c, 'bindingNote'), false)
    assert.equal(Object.prototype.hasOwnProperty.call(c, 'verificationSource'), false)
  })
})

// ── CPA-side ref ──

describe('producer-attestation: CPA ref builder', () => {
  it('builds from bytes or from a precomputed hash, but not both or neither', () => {
    const fromBytes = buildCpaProducerAttestationRef({ attestation: ATTESTATION, format: 'eat+jwt' })
    const fromHash = buildCpaProducerAttestationRef({ content_hash: sha256Hex(ATTESTATION), format: 'eat+jwt' })
    assert.deepEqual(fromBytes, fromHash)
    assert.throws(() => buildCpaProducerAttestationRef({ format: 'eat+jwt' }), /exactly one/)
    assert.throws(
      () => buildCpaProducerAttestationRef({ attestation: ATTESTATION, content_hash: sha256Hex(ATTESTATION), format: 'eat+jwt' }),
      /exactly one/,
    )
  })

  it('NEGATIVE: rejects a malformed hash and an empty format', () => {
    assert.throws(() => buildCpaProducerAttestationRef({ content_hash: 'NOTHEX', format: 'eat+jwt' }), /content_hash/)
    assert.throws(() => buildCpaProducerAttestationRef({ attestation: ATTESTATION, format: '' }), /format/)
    assert.equal(validateCpaProducerAttestationRef({ format: 'x', content_hash: 'short' }).valid, false)
  })
})

// ── CPA slot presence / absence ──

describe('producer-attestation: CPA slot', () => {
  it('omission byte-identity: a slot-free CPA has the exact pre-slot canonical bytes', () => {
    const cpa = buildCPA({
      privateKey: PRIV, action_ref: ACTION_REF, producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT, mode: 'full-set', items: ITEMS,
    })
    assert.equal(Object.prototype.hasOwnProperty.call(cpa, 'producer_attestation'), false)
    // Hand-build the pre-slot unsigned shape from the CPA's own fields and
    // compare canonical bytes: byte-identical means the signature is over
    // the same bytes as before the slot existed.
    const preSlotUnsigned = {
      version: cpa.version, action_ref: cpa.action_ref, producer_did: cpa.producer_did,
      producer_pubkey: cpa.producer_pubkey, attested_at: cpa.attested_at, mode: cpa.mode,
      partitions: cpa.partitions, root: cpa.root, signature: '',
    }
    assert.equal(
      canonicalizeJCS({ ...cpa, signature: '' } as unknown as Record<string, unknown>),
      canonicalizeJCS(preSlotUnsigned as unknown as Record<string, unknown>),
    )
    assert.equal(verifyCPA(cpa, DID_DOC).valid, true)
  })

  it('presence: the slot is inside the signed bytes and the CPA still validates', () => {
    const ref = buildCpaProducerAttestationRef({
      attestation: ATTESTATION, format: 'eat+jwt',
      locator_uri: 'https://attestations.example/eat/123',
      binding_note: 'covers environment',
    })
    const cpa = buildCPA({
      privateKey: PRIV, action_ref: ACTION_REF, producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT, mode: 'full-set', items: ITEMS,
      producer_attestation: ref,
    })
    assert.deepEqual(cpa.producer_attestation, ref)
    assert.equal(verifyCPA(cpa, DID_DOC).valid, true)
  })

  it('NEGATIVE: tampering with the slot after signing fails the signature check', () => {
    const ref = buildCpaProducerAttestationRef({ attestation: ATTESTATION, format: 'eat+jwt' })
    const cpa = buildCPA({
      privateKey: PRIV, action_ref: ACTION_REF, producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT, mode: 'full-set', items: ITEMS,
      producer_attestation: ref,
    })
    const tampered = {
      ...cpa,
      producer_attestation: { ...ref, content_hash: sha256Hex('different-bytes') },
    }
    const v = verifyCPA(tampered, DID_DOC)
    assert.equal(v.valid, false)
    assert.ok(v.reasons.includes('SIGNATURE_INVALID'))
  })

  it('NEGATIVE: a present-but-malformed slot is SHAPE_INVALID (fail closed)', () => {
    const cpa = buildCPA({
      privateKey: PRIV, action_ref: ACTION_REF, producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT, mode: 'full-set', items: ITEMS,
    })
    const malformed = { ...cpa, producer_attestation: { format: '', content_hash: 'nothex' } }
    const v = verifyCPA(malformed, DID_DOC)
    assert.equal(v.valid, false)
    assert.ok(v.reasons.includes('SHAPE_INVALID'))
  })
})
