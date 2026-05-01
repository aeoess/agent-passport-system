// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// APSBundle — construct + verify tests.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { createAPSBundle, computeMerkleRoot } from '../construct/bundle.js'
import { verifyAPSBundle } from '../verify/bundle.js'
import type { APSBundle, BundledReceiptRef } from '../types/bundle.js'
import type { CreateAPSBundleInput } from '../construct/bundle.js'

const PRIVATE_KEY = '55'.repeat(64)
const FIXED_TS = '2026-04-30T00:00:00.000Z'

const RID_A = 'a'.repeat(64)
const RID_B = 'b'.repeat(64)
const RID_C = 'c'.repeat(64)

function refOf(id: string, claim_type = 'aps:action:v1'): BundledReceiptRef {
  return { receipt_id: id, claim_type }
}

function input(receipts: BundledReceiptRef[], extras: Partial<CreateAPSBundleInput> = {}): CreateAPSBundleInput {
  return {
    timestamp: FIXED_TS,
    scope_of_claim: {
      asserts: 'Bundler asserts the listed receipt_ids were observed in the declared period.',
      does_not_assert: [
        'That every receipt referenced is itself valid.',
        'That no other receipts existed outside this bundle.',
      ],
      capture_mode: 'gateway_observed',
      completeness: 'complete',
      self_attested: false,
    },
    bundler_did: 'did:aps:test-bundler-001',
    period_start: '2026-04-30T00:00:00.000Z',
    period_end: '2026-05-01T00:00:00.000Z',
    receipts,
    profile_conformance: ['aps:profile/mva-v1'],
    ...extras,
  }
}

describe('createAPSBundle', () => {
  it('round-trips empty bundle (receipt_count = 0)', () => {
    const bundle = createAPSBundle(input([]), PRIVATE_KEY)
    assert.equal(bundle.receipt_count, 0)
    // Empty merkle_root sentinel = sha256('') = e3b0c44298...
    assert.equal(bundle.merkle_root, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    const v = verifyAPSBundle(bundle)
    assert.equal(v.valid, true)
  })

  it('round-trips single-receipt bundle', () => {
    const bundle = createAPSBundle(input([refOf(RID_A)]), PRIVATE_KEY)
    assert.equal(bundle.receipt_count, 1)
    assert.equal(bundle.merkle_root, computeMerkleRoot([RID_A]))
    const v = verifyAPSBundle(bundle)
    assert.equal(v.valid, true)
  })

  it('round-trips two-receipt bundle and merkle_root is deterministic', () => {
    const bundle1 = createAPSBundle(input([refOf(RID_A), refOf(RID_B)]), PRIVATE_KEY)
    const bundle2 = createAPSBundle(input([refOf(RID_A), refOf(RID_B)]), PRIVATE_KEY)
    assert.equal(bundle1.merkle_root, bundle2.merkle_root)
    assert.equal(bundle1.receipt_id, bundle2.receipt_id)
    assert.equal(verifyAPSBundle(bundle1).valid, true)
  })

  it('round-trips three-receipt bundle (exercises odd-layer duplicate path)', () => {
    const bundle = createAPSBundle(input([refOf(RID_A), refOf(RID_B), refOf(RID_C)]), PRIVATE_KEY)
    assert.equal(bundle.receipt_count, 3)
    assert.equal(verifyAPSBundle(bundle).valid, true)
  })

  it('produces same merkle_root regardless of input receipt order (sort discipline)', () => {
    const ordered = createAPSBundle(input([refOf(RID_A), refOf(RID_B), refOf(RID_C)]), PRIVATE_KEY)
    const reordered = createAPSBundle(input([refOf(RID_C), refOf(RID_A), refOf(RID_B)]), PRIVATE_KEY)
    assert.equal(ordered.merkle_root, reordered.merkle_root)
    // receipt_id matches too because all other fields and order-of-keys are equal.
    assert.equal(ordered.receipt_id, reordered.receipt_id)
  })

  it('round-trips profile_conformance values verbatim', () => {
    const bundle = createAPSBundle(
      input([refOf(RID_A)], { profile_conformance: ['aps:profile/mva-v1', 'aps:profile/extra'] }),
      PRIVATE_KEY,
    )
    assert.deepEqual(bundle.profile_conformance, ['aps:profile/mva-v1', 'aps:profile/extra'])
    assert.equal(verifyAPSBundle(bundle).valid, true)
  })
})

describe('verifyAPSBundle', () => {
  it('detects mutated receipt_count via RECEIPT_ID_MISMATCH', () => {
    const bundle = createAPSBundle(input([refOf(RID_A), refOf(RID_B)]), PRIVATE_KEY)
    const tampered: APSBundle = { ...bundle, receipt_count: 99 }
    const v = verifyAPSBundle(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'RECEIPT_ID_MISMATCH')
  })

  it('detects mutated merkle_root via RECEIPT_ID_MISMATCH', () => {
    const bundle = createAPSBundle(input([refOf(RID_A), refOf(RID_B)]), PRIVATE_KEY)
    const tampered: APSBundle = { ...bundle, merkle_root: '0'.repeat(64) }
    const v = verifyAPSBundle(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'RECEIPT_ID_MISMATCH')
  })

  it('detects mutated signature bytes alone via SIGNATURE_INVALID', () => {
    const bundle = createAPSBundle(input([refOf(RID_A), refOf(RID_B)]), PRIVATE_KEY)
    const flipped =
      bundle.signature.slice(0, -1) + (bundle.signature.endsWith('0') ? '1' : '0')
    const tampered: APSBundle = { ...bundle, signature: flipped }
    const v = verifyAPSBundle(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'SIGNATURE_INVALID')
  })

  it('rejects wrong claim_type with INVALID_CLAIM_TYPE', () => {
    const bundle = createAPSBundle(input([refOf(RID_A)]), PRIVATE_KEY)
    const wrong = { ...bundle, claim_type: 'aps:action:v1' as unknown as 'aps:bundle:v1' }
    const v = verifyAPSBundle(wrong)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'INVALID_CLAIM_TYPE')
  })

  it('rejects malformed merkle_root with INVALID_MERKLE_ROOT', () => {
    const bundle = createAPSBundle(input([refOf(RID_A)]), PRIVATE_KEY)
    const bad: APSBundle = { ...bundle, merkle_root: 'too-short' }
    const v = verifyAPSBundle(bad)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'INVALID_MERKLE_ROOT')
  })

  it('rejects malformed receipt_count with INVALID_RECEIPT_COUNT', () => {
    const bundle = createAPSBundle(input([refOf(RID_A)]), PRIVATE_KEY)
    const bad: APSBundle = { ...bundle, receipt_count: -1 }
    const v = verifyAPSBundle(bad)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'INVALID_RECEIPT_COUNT')
  })
})
