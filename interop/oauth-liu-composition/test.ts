// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// node --test suite for the Liu composition vectors: emit, verify, tie-back,
// and tamper cases. Tamper mutations run on in-memory copies of the committed
// records; nothing on disk is modified by this suite.

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { verifyReceiptV1 } from '../../src/v2/receipt-core/receipt.js'
import type { ReceiptV1 } from '../../src/v2/receipt-core/types.js'
import { verifyRevocationObservation } from '../../src/v2/revocation-enforcement/observation.js'
import type { SignedRevocationObservation } from '../../src/v2/revocation-enforcement/types.js'
import { emitAll } from './emit-vectors.js'
import { verifyAll, verifyReceiptVector, verifyObservationVector } from './verify-vectors.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const load = (...p: string[]): unknown => JSON.parse(readFileSync(join(HERE, ...p), 'utf8'))
const flipHexNibble = (hex: string, at: number): string =>
  hex.slice(0, at) + ((parseInt(hex[at], 16) ^ 0x1).toString(16)) + hex.slice(at + 1)

function receiptResolver(vector: string) {
  const keys = load('vectors', vector, 'keys.json') as { signer: string; key_id: string; public_key_hex: string }
  return (signer: string, keyId: string): string | undefined =>
    signer === keys.signer && keyId === keys.key_id ? keys.public_key_hex : undefined
}

describe('liu composition vectors: emit and verify', () => {
  before(async () => {
    // Re-emit so the suite always exercises the full emit path. Keys and
    // timestamps are pinned, so emitted bytes are stable across runs.
    await emitAll()
  })

  it('emitted vectors are byte-stable across re-runs', async () => {
    const files = [
      ['vectors', 'v1-permit', 'record.json'], ['vectors', 'v1-permit', 'keys.json'],
      ['vectors', 'v2-denial', 'record.json'], ['vectors', 'v2-denial', 'keys.json'],
      ['vectors', 'v3-observation', 'record.json']
    ]
    const first = files.map(p => readFileSync(join(HERE, ...p), 'utf8'))
    await emitAll()
    const second = files.map(p => readFileSync(join(HERE, ...p), 'utf8'))
    assert.deepEqual(second, first)
  })

  it('all three vectors verify through the SDK path', () => {
    const results = verifyAll()
    for (const r of results) assert.equal(r.valid, true, `${r.vector}: ${r.detail}`)
  })

  it('v1 permit records an allow tied to the evidence and chain state', () => {
    const receipt = load('vectors', 'v1-permit', 'record.json') as ReceiptV1
    assert.equal(receipt.receipt_type, 'policy-decision')
    assert.equal(receipt.result.decision, 'allow')
    assert.ok(receipt.decision_ref, 'decision_ref present')
    assert.equal(receipt.evidence_refs.length, 2)
    assert.equal(verifyReceiptVector('v1-permit').valid, true)
  })

  it('v2 denial records the subset violation', () => {
    const receipt = load('vectors', 'v2-denial', 'record.json') as ReceiptV1
    assert.equal(receipt.result.decision, 'deny')
    assert.equal(receipt.result.reason, 'requested_action_outside_narrowed_subset')
    assert.equal(receipt.result.requested_action, 'cart_add')
    assert.deepEqual(receipt.result.narrowed_subset, ['inventory_check'])
    assert.equal(verifyReceiptVector('v2-denial').valid, true)
  })

  it('v3 observation carries the SET reference and the deny that followed', () => {
    const record = load('vectors', 'v3-observation', 'record.json') as SignedRevocationObservation
    assert.equal(record.status_source.kind, 'set')
    assert.equal(record.decision.effect, 'deny')
    assert.equal(record.maximum_staleness_ms, 300000)
    assert.equal(record.affected_scope, 'inventory_check')
    assert.equal(verifyObservationVector().valid, true)
  })
})

describe('liu composition vectors: tamper cases', () => {
  it('flipping one signature nibble on the permit receipt fails loud', () => {
    const receipt = structuredClone(load('vectors', 'v1-permit', 'record.json')) as ReceiptV1
    receipt.signatures[0].value = flipHexNibble(receipt.signatures[0].value, 3)
    const res = verifyReceiptV1(receipt, receiptResolver('v1-permit'))
    assert.equal(res.valid, false)
    assert.ok(res.errors.includes('signature_invalid'), `errors: ${res.errors.join(',')}`)
  })

  it('mutating one evidence_refs digest fails loud', () => {
    const receipt = structuredClone(load('vectors', 'v1-permit', 'record.json')) as ReceiptV1
    receipt.evidence_refs[0].sha256 = flipHexNibble(receipt.evidence_refs[0].sha256, 0)
    const res = verifyReceiptV1(receipt, receiptResolver('v1-permit'))
    // The receipt_id commits to evidence_refs, so the mutation breaks both the
    // id and every signature.
    assert.equal(res.valid, false)
    assert.ok(res.errors.includes('receipt_id_mismatch'), `errors: ${res.errors.join(',')}`)
  })

  it('flipping one signature nibble on the observation fails loud', () => {
    const record = structuredClone(load('vectors', 'v3-observation', 'record.json')) as SignedRevocationObservation
    record.signature = flipHexNibble(record.signature, 5)
    const res = verifyRevocationObservation(record, { expectedObserverKey: record.observer_key })
    assert.equal(res.valid, false)
  })

  it('denial asserts the subset violation, not a generic deny', () => {
    const receipt = load('vectors', 'v2-denial', 'record.json') as ReceiptV1
    assert.equal(receipt.result.reason, 'requested_action_outside_narrowed_subset')
    assert.ok(!(receipt.result.narrowed_subset as string[]).includes(receipt.result.requested_action as string))
  })
})
