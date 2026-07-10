// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// cross_issuer_attestation signal_type (v0.1): tests
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

import { generateKeyPair } from '../../../crypto/keys.js'

import {
  signCrossIssuerAttestation,
  verifyCrossIssuerAttestation,
  canonicalizeForSignature,
} from '../index.js'

import type {
  ConstituentReference,
  CrossIssuerAttestationEnvelope,
  UnsignedCrossIssuerAttestationEnvelope,
} from '../types.js'

function sha256Hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

const FIXED_COMPOSED_AT = '2026-05-26T16:00:00Z'
const FIXED_ISSUED_AT_A = '2026-05-26T15:30:00Z'
const FIXED_ISSUED_AT_B = '2026-05-26T15:45:00.500Z'
const FIXED_ISSUED_AT_C = '2026-05-26T15:55:00+02:00'

function makeConstituent(
  seed: string,
  signal_type: string,
  issued_at: string,
): ConstituentReference {
  const kp = generateKeyPair()
  return {
    envelope_hash: sha256Hex(`constituent:${seed}`),
    issuer_id: kp.publicKey,
    signal_type,
    issued_at,
  }
}

function makeUnsigned(
  composer_id: string,
  constituents: readonly ConstituentReference[],
  composition_purpose = 'C-II-4 test bundle',
  composed_at: string = FIXED_COMPOSED_AT,
): UnsignedCrossIssuerAttestationEnvelope {
  return {
    signal_type: 'cross_issuer_attestation',
    composer_id,
    composed_at,
    constituents,
    composition_purpose,
  }
}

// ── Round-trip ─────────────────────────────────────────────────

describe('cross_issuer_attestation: round-trip with 1 constituent', () => {
  it('signs and verifies a single-constituent bundle', () => {
    const kp = generateKeyPair()
    const constituent = makeConstituent('only', 'cognitive_attestation', FIXED_ISSUED_AT_A)
    const signed = signCrossIssuerAttestation(
      kp.privateKey,
      makeUnsigned(kp.publicKey, [constituent]),
    )
    assert.equal(signed.signal_type, 'cross_issuer_attestation')
    assert.equal(signed.composer_id, kp.publicKey)
    assert.equal(signed.signature.length, 128)
    assert.equal(signed.constituents.length, 1)
    const result = verifyCrossIssuerAttestation(signed)
    assert.equal(result.valid, true, `expected valid, got reason=${result.reason}`)
  })
})

describe('cross_issuer_attestation: round-trip with 3 constituents from different issuers', () => {
  it('signs and verifies a 3-constituent bundle spanning different signal_types', () => {
    const kp = generateKeyPair()
    const constituents = [
      makeConstituent('a', 'cognitive_attestation', FIXED_ISSUED_AT_A),
      makeConstituent('b', 'memory_provenance', FIXED_ISSUED_AT_B),
      makeConstituent('c', 'governance_attestation', FIXED_ISSUED_AT_C),
    ]
    const signed = signCrossIssuerAttestation(
      kp.privateKey,
      makeUnsigned(kp.publicKey, constituents),
    )
    assert.equal(signed.constituents.length, 3)
    const issuerIds = new Set(signed.constituents.map(c => c.issuer_id))
    assert.equal(issuerIds.size, 3, 'each constituent must have a distinct issuer')
    const signalTypes = new Set(signed.constituents.map(c => c.signal_type))
    assert.deepEqual(
      [...signalTypes].sort(),
      ['cognitive_attestation', 'governance_attestation', 'memory_provenance'],
    )
    const result = verifyCrossIssuerAttestation(signed)
    assert.equal(result.valid, true, `expected valid, got reason=${result.reason}`)
  })
})

// ── Validation rules ────────────────────────────────────────────

describe('cross_issuer_attestation: empty constituents', () => {
  it('returns CONSTITUENTS_EMPTY when constituents array is empty', () => {
    const kp = generateKeyPair()
    const signed = signCrossIssuerAttestation(
      kp.privateKey,
      makeUnsigned(kp.publicKey, []),
    )
    const result = verifyCrossIssuerAttestation(signed)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'CONSTITUENTS_EMPTY')
  })
})

describe('cross_issuer_attestation: duplicate envelope_hash', () => {
  it('returns CONSTITUENT_HASH_DUPLICATE when two constituents share an envelope_hash', () => {
    const kp = generateKeyPair()
    const a = makeConstituent('shared', 'cognitive_attestation', FIXED_ISSUED_AT_A)
    const b: ConstituentReference = {
      ...makeConstituent('other', 'memory_provenance', FIXED_ISSUED_AT_B),
      envelope_hash: a.envelope_hash,
    }
    const signed = signCrossIssuerAttestation(
      kp.privateKey,
      makeUnsigned(kp.publicKey, [a, b]),
    )
    const result = verifyCrossIssuerAttestation(signed)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'CONSTITUENT_HASH_DUPLICATE')
  })
})

// ── Tamper detection ────────────────────────────────────────────

describe('cross_issuer_attestation: tamper detection (hash byte)', () => {
  it('mutating one byte of a constituent envelope_hash invalidates the signature', () => {
    const kp = generateKeyPair()
    const constituents = [
      makeConstituent('a', 'cognitive_attestation', FIXED_ISSUED_AT_A),
      makeConstituent('b', 'memory_provenance', FIXED_ISSUED_AT_B),
    ]
    const signed = signCrossIssuerAttestation(
      kp.privateKey,
      makeUnsigned(kp.publicKey, constituents),
    )
    const original = signed.constituents[0].envelope_hash
    const lastChar = original.slice(-1)
    const flipped = lastChar === '0' ? '1' : '0'
    const mutated: ConstituentReference = {
      ...signed.constituents[0],
      envelope_hash: original.slice(0, -1) + flipped,
    }
    const tampered: CrossIssuerAttestationEnvelope = {
      ...signed,
      constituents: [mutated, signed.constituents[1]],
    }
    const result = verifyCrossIssuerAttestation(tampered)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'SIGNATURE_INVALID')
  })
})

describe('cross_issuer_attestation: tamper detection (reorder)', () => {
  it('reordering constituents invalidates the signature', () => {
    const kp = generateKeyPair()
    const constituents = [
      makeConstituent('a', 'cognitive_attestation', FIXED_ISSUED_AT_A),
      makeConstituent('b', 'memory_provenance', FIXED_ISSUED_AT_B),
      makeConstituent('c', 'governance_attestation', FIXED_ISSUED_AT_C),
    ]
    const signed = signCrossIssuerAttestation(
      kp.privateKey,
      makeUnsigned(kp.publicKey, constituents),
    )
    const reordered: CrossIssuerAttestationEnvelope = {
      ...signed,
      constituents: [signed.constituents[2], signed.constituents[1], signed.constituents[0]],
    }
    const result = verifyCrossIssuerAttestation(reordered)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'SIGNATURE_INVALID')
  })
})

// ── Wrong-key detection ─────────────────────────────────────────

describe('cross_issuer_attestation: wrong-key detection', () => {
  it('envelope signed by key A but claiming composer_id of key B fails', () => {
    const keyA = generateKeyPair()
    const keyB = generateKeyPair()
    const constituent = makeConstituent('only', 'cognitive_attestation', FIXED_ISSUED_AT_A)
    const signedByA = signCrossIssuerAttestation(
      keyA.privateKey,
      makeUnsigned(keyA.publicKey, [constituent]),
    )
    const lying: CrossIssuerAttestationEnvelope = { ...signedByA, composer_id: keyB.publicKey }
    const result = verifyCrossIssuerAttestation(lying)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'SIGNATURE_INVALID')
  })
})

// ── Canonicalization stability ──────────────────────────────────

describe('cross_issuer_attestation: canonicalization stability', () => {
  it('two envelopes with identical content but different field order produce the same signature', () => {
    const kp = generateKeyPair()
    const constituents = [
      makeConstituent('a', 'cognitive_attestation', FIXED_ISSUED_AT_A),
      makeConstituent('b', 'memory_provenance', FIXED_ISSUED_AT_B),
    ]
    const ordering1: UnsignedCrossIssuerAttestationEnvelope = {
      signal_type: 'cross_issuer_attestation',
      composer_id: kp.publicKey,
      composed_at: FIXED_COMPOSED_AT,
      constituents,
      composition_purpose: 'canon-test',
    }
    const ordering2 = {
      composition_purpose: 'canon-test',
      constituents,
      composed_at: FIXED_COMPOSED_AT,
      composer_id: kp.publicKey,
      signal_type: 'cross_issuer_attestation' as const,
    }
    const signed1 = signCrossIssuerAttestation(kp.privateKey, ordering1)
    const signed2 = signCrossIssuerAttestation(
      kp.privateKey,
      ordering2 as UnsignedCrossIssuerAttestationEnvelope,
    )
    assert.equal(signed1.signature, signed2.signature)
    const canon1 = canonicalizeForSignature(ordering1)
    const canon2 = canonicalizeForSignature(ordering2 as UnsignedCrossIssuerAttestationEnvelope)
    assert.equal(canon1, canon2)
  })
})

// ── Shape failures ──────────────────────────────────────────────

describe('cross_issuer_attestation: shape failures', () => {
  it('returns SHAPE_INVALID or COMPOSER_ID_INVALID_FORMAT when composer_id is missing', () => {
    const kp = generateKeyPair()
    const constituent = makeConstituent('only', 'cognitive_attestation', FIXED_ISSUED_AT_A)
    const signed = signCrossIssuerAttestation(
      kp.privateKey,
      makeUnsigned(kp.publicKey, [constituent]),
    )
    const { composer_id: _omit, ...withoutId } = signed
    const result = verifyCrossIssuerAttestation(withoutId)
    assert.equal(result.valid, false)
    assert.ok(
      result.reason === 'SHAPE_INVALID' || result.reason === 'COMPOSER_ID_INVALID_FORMAT',
      `expected SHAPE_INVALID or COMPOSER_ID_INVALID_FORMAT, got ${result.reason}`,
    )
  })

  it('returns COMPOSITION_PURPOSE_TOO_LONG when composition_purpose exceeds 280 chars', () => {
    const kp = generateKeyPair()
    const constituent = makeConstituent('only', 'cognitive_attestation', FIXED_ISSUED_AT_A)
    const tooLong = 'x'.repeat(281)
    const signed = signCrossIssuerAttestation(
      kp.privateKey,
      makeUnsigned(kp.publicKey, [constituent], tooLong),
    )
    const result = verifyCrossIssuerAttestation(signed)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'COMPOSITION_PURPOSE_TOO_LONG')
  })
})
