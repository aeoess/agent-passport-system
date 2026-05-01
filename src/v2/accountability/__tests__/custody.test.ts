// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// CustodyReceipt — construct + verify conformance.
//
// Note: this file uses node:test rather than vitest because the repo
// has no vitest install; node:test is the v2 convention (see
// tests/v2/instruction-provenance/conformance.test.ts and siblings).
// The describe/it/assert API is interchangeable for these tests.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createCustodyReceipt } from '../construct/custody.js'
import { verifyCustodyReceipt } from '../verify/custody.js'
import type {
  CustodyEventType,
  CustodyPurpose,
  CustodyReceipt,
} from '../types/custody.js'
import type { ScopeOfClaim } from '../types/base.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

const PRIV = '22'.repeat(64)
const TS = '2026-04-30T00:00:00.000Z'
const MERKLE_ROOT_1 = '0000000000000000000000000000000000000000000000000000000000000001'

const SCOPE: ScopeOfClaim = {
  asserts: 'Custodian sealed the named receipt batch at the named time for the named purpose.',
  does_not_assert: [
    'that the underlying receipts are factually accurate',
    'that downstream custody handoffs were honored',
  ],
  capture_mode: 'self_attested',
  completeness: 'complete',
  self_attested: true,
}

function makeBaseInput(overrides: Partial<CustodyReceipt> = {}) {
  return {
    timestamp: TS,
    scope_of_claim: SCOPE,
    custodian_did: 'did:aps:test-custodian-001',
    event_type: 'sealed' as CustodyEventType,
    subject_receipt_batch: { merkle_root: MERKLE_ROOT_1, count: 1 },
    purpose: 'internal_audit' as CustodyPurpose,
    ...overrides,
  }
}

describe('CustodyReceipt — construct + verify', () => {
  it('happy path: construct + verify round-trips green', () => {
    const r = createCustodyReceipt(makeBaseInput(), PRIV)
    const v = verifyCustodyReceipt(r)
    assert.equal(v.valid, true, `expected valid; got reason=${v.reason}`)
    assert.equal(r.claim_type, 'aps:custody:v1')
    assert.equal(r.signer_did.length, 64)
    assert.equal(r.signature.length, 128)
    assert.equal(r.receipt_id.length, 64)
  })

  it('receipt_id is stable across reruns with identical inputs', () => {
    const a = createCustodyReceipt(makeBaseInput(), PRIV)
    const b = createCustodyReceipt(makeBaseInput(), PRIV)
    assert.equal(a.receipt_id, b.receipt_id)
    assert.equal(a.signature, b.signature)
  })

  it('all 8 event types are accepted by construct + verify', () => {
    const events: CustodyEventType[] = [
      'created',
      'sealed',
      'transferred',
      'disclosed',
      'redacted',
      'erased',
      'expired',
      'verified',
    ]
    for (const event_type of events) {
      const input = makeBaseInput({ event_type })
      // 'transferred' requires next_custodian_did per the type contract;
      // handled in a dedicated test. Other events accept the base input.
      if (event_type === 'transferred') continue
      const r = createCustodyReceipt(input, PRIV)
      const v = verifyCustodyReceipt(r)
      assert.equal(v.valid, true, `event_type=${event_type} did not verify: ${v.reason}`)
    }
  })

  it('all 7 purposes are accepted by construct + verify', () => {
    const purposes: CustodyPurpose[] = [
      'internal_audit',
      'regulator_disclosure',
      'subject_access',
      'litigation_discovery',
      'vendor_handoff',
      'archival',
      'incident_response',
    ]
    for (const purpose of purposes) {
      const r = createCustodyReceipt(makeBaseInput({ purpose }), PRIV)
      const v = verifyCustodyReceipt(r)
      assert.equal(v.valid, true, `purpose=${purpose} did not verify: ${v.reason}`)
    }
  })

  it('transferred event carries next_custodian_did and round-trips', () => {
    const r = createCustodyReceipt(
      makeBaseInput({
        event_type: 'transferred',
        next_custodian_did: 'did:aps:test-custodian-002',
      }),
      PRIV,
    )
    assert.equal(r.event_type, 'transferred')
    assert.equal(r.next_custodian_did, 'did:aps:test-custodian-002')
    const v = verifyCustodyReceipt(r)
    assert.equal(v.valid, true, `verify failed: ${v.reason}`)
  })

  it('erased event preserves merkle_root + count (cryptographic-erasure pattern)', () => {
    const r = createCustodyReceipt(
      makeBaseInput({
        event_type: 'erased',
        purpose: 'subject_access',
        subject_receipt_batch: { merkle_root: MERKLE_ROOT_1, count: 42 },
      }),
      PRIV,
    )
    assert.equal(r.event_type, 'erased')
    // The chain remains verifiable across erasure: merkle_root and count
    // survive even though the underlying content is irrecoverable.
    assert.equal(r.subject_receipt_batch.merkle_root, MERKLE_ROOT_1)
    assert.equal(r.subject_receipt_batch.count, 42)
    const v = verifyCustodyReceipt(r)
    assert.equal(v.valid, true, `verify failed: ${v.reason}`)
  })

  it('tamper on event_type to a non-enum value yields INVALID_EVENT_TYPE', () => {
    const r = createCustodyReceipt(makeBaseInput(), PRIV)
    const tampered = { ...r, event_type: 'fabricated' as CustodyEventType }
    const v = verifyCustodyReceipt(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'INVALID_EVENT_TYPE')
  })

  it('tamper on event_type to a different valid enum yields RECEIPT_ID_MISMATCH', () => {
    const r = createCustodyReceipt(makeBaseInput({ event_type: 'sealed' }), PRIV)
    const tampered: CustodyReceipt = { ...r, event_type: 'erased' }
    const v = verifyCustodyReceipt(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'RECEIPT_ID_MISMATCH')
  })

  it('tamper on signature alone yields SIGNATURE_INVALID', () => {
    const r = createCustodyReceipt(makeBaseInput(), PRIV)
    const tampered: CustodyReceipt = { ...r, signature: '00'.repeat(64) }
    const v = verifyCustodyReceipt(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'SIGNATURE_INVALID')
  })

  it('rejects wrong claim_type', () => {
    const r = createCustodyReceipt(makeBaseInput(), PRIV)
    const tampered = { ...r, claim_type: 'aps:action:v1' as 'aps:custody:v1' }
    const v = verifyCustodyReceipt(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'INVALID_CLAIM_TYPE')
  })

  it('matches the on-disk fixture byte-for-byte', () => {
    const fixturePath = join(__dirname, '..', 'fixtures', 'custody.fixture.json')
    const fixture = JSON.parse(readFileSync(fixturePath, 'utf-8')) as CustodyReceipt
    const built = createCustodyReceipt(makeBaseInput(), PRIV)
    assert.deepEqual(built, fixture)
    const v = verifyCustodyReceipt(fixture)
    assert.equal(v.valid, true, `fixture failed verify: ${v.reason}`)
  })
})
