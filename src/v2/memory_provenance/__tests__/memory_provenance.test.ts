// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// memory_provenance signal_type (v0.1): tests
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

import { generateKeyPair, publicKeyFromPrivate } from '../../../crypto/keys.js'

import {
  signMemoryProvenance,
  verifyMemoryProvenance,
  isMemoryProvenance,
  canonicalizeForSignature,
} from '../index.js'

import type {
  MemoryProvenanceEnvelope,
  MemoryProvenanceSource,
  UnsignedMemoryProvenanceEnvelope,
} from '../types.js'

function sha256Hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

const FIXED_INGESTED_AT = '2026-05-26T16:00:00Z'
const FIXED_ISSUED_AT = '2026-05-25T09:30:00Z'

function makeSource(overrides: Partial<MemoryProvenanceSource> = {}): MemoryProvenanceSource {
  const issuerKey = generateKeyPair().publicKey
  return {
    issuer_id: overrides.issuer_id ?? issuerKey,
    issued_at: overrides.issued_at ?? FIXED_ISSUED_AT,
    source_ref: overrides.source_ref ?? sha256Hex('source.original.content.001'),
    reduction_map_ref: overrides.reduction_map_ref ?? 'urn:aps:reduction:summarize-v1',
  }
}

function makeUnsigned(ingesterPub: string): UnsignedMemoryProvenanceEnvelope {
  return {
    signal_type: 'memory_provenance' as const,
    memory_ref: sha256Hex('memory.entry.after.transform.001'),
    source: makeSource(),
    ingester_id: ingesterPub,
    ingested_at: FIXED_INGESTED_AT,
  }
}

// ── Round-trip ───────────────────────────────────────────────────

describe('memory_provenance: round-trip', () => {
  it('sign + verify returns valid:true on a well-formed envelope', () => {
    const kp = generateKeyPair()
    const signed = signMemoryProvenance(kp.privateKey, makeUnsigned(kp.publicKey))
    assert.equal(signed.signal_type, 'memory_provenance')
    assert.equal(signed.ingester_id, kp.publicKey)
    assert.equal(signed.signature.length, 128)
    const result = verifyMemoryProvenance(signed)
    assert.equal(result.valid, true, `expected valid, got reason=${result.reason}`)
    assert.equal(isMemoryProvenance(signed), true)
  })
})

// ── Tamper detection ────────────────────────────────────────────

describe('memory_provenance: tamper detection', () => {
  it('mutating one byte of memory_ref causes verification to fail', () => {
    const kp = generateKeyPair()
    const signed = signMemoryProvenance(kp.privateKey, makeUnsigned(kp.publicKey))
    const lastChar = signed.memory_ref.slice(-1)
    const flipped = lastChar === '0' ? '1' : '0'
    const tampered = {
      ...signed,
      memory_ref: signed.memory_ref.slice(0, -1) + flipped,
    } as MemoryProvenanceEnvelope
    const result = verifyMemoryProvenance(tampered)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'SIGNATURE_INVALID')
  })

  it('mutating one byte of source.source_ref causes verification to fail', () => {
    const kp = generateKeyPair()
    const signed = signMemoryProvenance(kp.privateKey, makeUnsigned(kp.publicKey))
    const original = signed.source.source_ref
    const lastChar = original.slice(-1)
    const flipped = lastChar === '0' ? '1' : '0'
    const tampered = {
      ...signed,
      source: { ...signed.source, source_ref: original.slice(0, -1) + flipped },
    } as MemoryProvenanceEnvelope
    const result = verifyMemoryProvenance(tampered)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'SIGNATURE_INVALID')
  })
})

// ── Wrong-key detection ────────────────────────────────────────

describe('memory_provenance: wrong-key detection', () => {
  it('envelope signed with key A but claiming ingester_id of key B fails', () => {
    const keyA = generateKeyPair()
    const keyB = generateKeyPair()
    const signedByA = signMemoryProvenance(keyA.privateKey, makeUnsigned(keyA.publicKey))
    const lyingEnvelope = { ...signedByA, ingester_id: keyB.publicKey } as MemoryProvenanceEnvelope
    const result = verifyMemoryProvenance(lyingEnvelope)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'SIGNATURE_INVALID')
  })

  it('signMemoryProvenance always overwrites ingester_id to match the signing key', () => {
    const keyA = generateKeyPair()
    const keyB = generateKeyPair()
    const unsigned = makeUnsigned(keyB.publicKey)
    const signed = signMemoryProvenance(keyA.privateKey, unsigned)
    assert.equal(signed.ingester_id, publicKeyFromPrivate(keyA.privateKey))
    const result = verifyMemoryProvenance(signed)
    assert.equal(result.valid, true)
  })
})

// ── Canonicalization stability ─────────────────────────────────

describe('memory_provenance: canonicalization stability', () => {
  it('two envelopes with the same logical content but different field order produce the same signature', () => {
    const kp = generateKeyPair()
    const sourceFields: MemoryProvenanceSource = makeSource()
    const memory_ref = sha256Hex('memory.canon.001')

    const ordering1: UnsignedMemoryProvenanceEnvelope = {
      signal_type: 'memory_provenance' as const,
      memory_ref,
      source: sourceFields,
      ingester_id: kp.publicKey,
      ingested_at: FIXED_INGESTED_AT,
    }
    const ordering2 = {
      ingested_at: FIXED_INGESTED_AT,
      source: {
        reduction_map_ref: sourceFields.reduction_map_ref,
        source_ref: sourceFields.source_ref,
        issued_at: sourceFields.issued_at,
        issuer_id: sourceFields.issuer_id,
      },
      ingester_id: kp.publicKey,
      memory_ref,
      signal_type: 'memory_provenance' as const,
    } as UnsignedMemoryProvenanceEnvelope

    const signed1 = signMemoryProvenance(kp.privateKey, ordering1)
    const signed2 = signMemoryProvenance(kp.privateKey, ordering2)
    assert.equal(signed1.signature, signed2.signature)

    const canon1 = canonicalizeForSignature(ordering1)
    const canon2 = canonicalizeForSignature(ordering2)
    assert.equal(canon1, canon2)
  })
})

// ── Shape failures ─────────────────────────────────────────────

describe('memory_provenance: shape failures', () => {
  it('returns SHAPE_INVALID for non-object input', () => {
    assert.deepEqual(verifyMemoryProvenance(null), { valid: false, reason: 'SHAPE_INVALID' })
    assert.deepEqual(verifyMemoryProvenance('string'), { valid: false, reason: 'SHAPE_INVALID' })
    assert.deepEqual(verifyMemoryProvenance(42), { valid: false, reason: 'SHAPE_INVALID' })
  })

  it('returns SHAPE_INVALID when signal_type is wrong', () => {
    const kp = generateKeyPair()
    const signed = signMemoryProvenance(kp.privateKey, makeUnsigned(kp.publicKey))
    const result = verifyMemoryProvenance({ ...signed, signal_type: 'something_else' })
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'SHAPE_INVALID')
  })

  it('returns MISSING_SOURCE_FIELDS when source field is absent', () => {
    const kp = generateKeyPair()
    const signed = signMemoryProvenance(kp.privateKey, makeUnsigned(kp.publicKey))
    const stripped = { ...signed } as Record<string, unknown>
    delete stripped.source
    const result = verifyMemoryProvenance(stripped)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'MISSING_SOURCE_FIELDS')
  })

  it('returns MISSING_SOURCE_FIELDS when source is present but reduction_map_ref is empty', () => {
    const kp = generateKeyPair()
    const signed = signMemoryProvenance(kp.privateKey, makeUnsigned(kp.publicKey))
    const result = verifyMemoryProvenance({
      ...signed,
      source: { ...signed.source, reduction_map_ref: '' },
    })
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'MISSING_SOURCE_FIELDS')
  })

  it('returns INGESTER_ID_INVALID_FORMAT for non-hex ingester_id', () => {
    const kp = generateKeyPair()
    const signed = signMemoryProvenance(kp.privateKey, makeUnsigned(kp.publicKey))
    const result = verifyMemoryProvenance({ ...signed, ingester_id: 'not-hex' })
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'INGESTER_ID_INVALID_FORMAT')
  })

  it('returns INGESTER_ID_INVALID_FORMAT for wrong-length hex ingester_id', () => {
    const kp = generateKeyPair()
    const signed = signMemoryProvenance(kp.privateKey, makeUnsigned(kp.publicKey))
    const result = verifyMemoryProvenance({ ...signed, ingester_id: 'abcd' })
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'INGESTER_ID_INVALID_FORMAT')
  })

  it('returns TIMESTAMP_FORMAT_INVALID for malformed ingested_at', () => {
    const kp = generateKeyPair()
    const signed = signMemoryProvenance(kp.privateKey, makeUnsigned(kp.publicKey))
    const result = verifyMemoryProvenance({ ...signed, ingested_at: 'yesterday' })
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'TIMESTAMP_FORMAT_INVALID')
  })

  it('returns TIMESTAMP_FORMAT_INVALID for malformed source.issued_at', () => {
    const kp = generateKeyPair()
    const signed = signMemoryProvenance(kp.privateKey, makeUnsigned(kp.publicKey))
    const result = verifyMemoryProvenance({
      ...signed,
      source: { ...signed.source, issued_at: '2026/05/25' },
    })
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'TIMESTAMP_FORMAT_INVALID')
  })

  it('returns SOURCE_HASH_INVALID_FORMAT when source.source_ref is not 64 hex chars', () => {
    const kp = generateKeyPair()
    const signed = signMemoryProvenance(kp.privateKey, makeUnsigned(kp.publicKey))
    const result = verifyMemoryProvenance({
      ...signed,
      source: { ...signed.source, source_ref: 'short' },
    })
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'SOURCE_HASH_INVALID_FORMAT')
  })

  it('returns SHAPE_INVALID when memory_ref is malformed', () => {
    const kp = generateKeyPair()
    const signed = signMemoryProvenance(kp.privateKey, makeUnsigned(kp.publicKey))
    const result = verifyMemoryProvenance({ ...signed, memory_ref: 'XYZ' })
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'SHAPE_INVALID')
  })
})

// ── Type guard ─────────────────────────────────────────────────

describe('memory_provenance: type guard', () => {
  it('isMemoryProvenance accepts a valid signed envelope', () => {
    const kp = generateKeyPair()
    const signed = signMemoryProvenance(kp.privateKey, makeUnsigned(kp.publicKey))
    assert.equal(isMemoryProvenance(signed), true)
  })

  it('isMemoryProvenance rejects non-object inputs', () => {
    assert.equal(isMemoryProvenance(null), false)
    assert.equal(isMemoryProvenance('string'), false)
    assert.equal(isMemoryProvenance(42), false)
    assert.equal(isMemoryProvenance([]), false)
  })

  it('isMemoryProvenance rejects envelope with wrong signal_type', () => {
    const kp = generateKeyPair()
    const signed = signMemoryProvenance(kp.privateKey, makeUnsigned(kp.publicKey))
    assert.equal(isMemoryProvenance({ ...signed, signal_type: 'reasoning_integrity' }), false)
  })

  it('isMemoryProvenance rejects envelope with malformed signature', () => {
    const kp = generateKeyPair()
    const signed = signMemoryProvenance(kp.privateKey, makeUnsigned(kp.publicKey))
    assert.equal(isMemoryProvenance({ ...signed, signature: 'short' }), false)
  })
})
