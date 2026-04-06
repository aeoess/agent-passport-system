// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Interop: Receipt chaining — linear chain integrity and tamper detection

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import {
  generateKeyPair,
  sign,
  verify,
  canonicalizeJCS,
} from '../../src/index.js'

function sha256Hex(data: string): string {
  return createHash('sha256').update(data).digest('hex')
}

function buildChainedReceipt(
  privateKey: string,
  agentId: string,
  action: string,
  previousHash: string | null,
  index: number,
) {
  const payload = {
    agentId,
    action,
    index,
    timestamp: new Date(Date.now() + index * 1000).toISOString(),
    result: { status: 'success', summary: `Action ${index}` },
  }
  const canonical = canonicalizeJCS(payload)
  const receiptId = `sha256:${sha256Hex(canonical)}`
  const sig = sign(canonical, privateKey)

  return {
    spec: 'aps-chained-receipt-v1',
    receipt_id: receiptId,
    previousReceiptHash: previousHash,
    payload,
    signature: { alg: 'EdDSA', sig },
  }
}

describe('Receipt Chaining', () => {
  const keys = generateKeyPair()

  describe('Linear chain (3 receipts)', () => {
    const r1 = buildChainedReceipt(keys.privateKey, 'agent-chain-001', 'read_file', null, 0)
    const r2 = buildChainedReceipt(keys.privateKey, 'agent-chain-001', 'write_file', r1.receipt_id, 1)
    const r3 = buildChainedReceipt(keys.privateKey, 'agent-chain-001', 'delete_file', r2.receipt_id, 2)

    it('chain links correctly via previousReceiptHash', () => {
      assert.equal(r1.previousReceiptHash, null)
      assert.equal(r2.previousReceiptHash, r1.receipt_id)
      assert.equal(r3.previousReceiptHash, r2.receipt_id)
    })

    it('each receipt_id is sha256 of JCS payload', () => {
      for (const r of [r1, r2, r3]) {
        const expected = `sha256:${sha256Hex(canonicalizeJCS(r.payload))}`
        assert.equal(r.receipt_id, expected)
      }
    })

    it('each signature verifies', () => {
      for (const r of [r1, r2, r3]) {
        const canonical = canonicalizeJCS(r.payload)
        assert.ok(verify(canonical, r.signature.sig, keys.publicKey))
      }
    })
  })

  describe('Tamper detection', () => {
    it('modifying middle receipt breaks chain', () => {
      const r1 = buildChainedReceipt(keys.privateKey, 'agent-tamper-001', 'read', null, 0)
      const r2 = buildChainedReceipt(keys.privateKey, 'agent-tamper-001', 'write', r1.receipt_id, 1)
      const r3 = buildChainedReceipt(keys.privateKey, 'agent-tamper-001', 'delete', r2.receipt_id, 2)

      // Tamper r2's payload
      const tampered = { ...r2, payload: { ...r2.payload, action: 'TAMPERED' } }
      const tamperedId = `sha256:${sha256Hex(canonicalizeJCS(tampered.payload))}`

      // r2's receipt_id no longer matches its content
      assert.notEqual(tamperedId, r2.receipt_id)
      // r3 still points to old r2 receipt_id, which no longer matches tampered r2
      assert.equal(r3.previousReceiptHash, r2.receipt_id)
      assert.notEqual(r3.previousReceiptHash, tamperedId)
    })

    it('signature fails on tampered payload', () => {
      const r = buildChainedReceipt(keys.privateKey, 'agent-tamper-002', 'read', null, 0)
      const tampered = { ...r.payload, action: 'TAMPERED' }
      const canonical = canonicalizeJCS(tampered)
      assert.ok(!verify(canonical, r.signature.sig, keys.publicKey))
    })
  })

  describe('Chain validation function', () => {
    it('validates a well-formed chain end-to-end', () => {
      const chain = []
      let prev: string | null = null
      for (let i = 0; i < 5; i++) {
        const r = buildChainedReceipt(keys.privateKey, 'agent-long-chain', `action_${i}`, prev, i)
        chain.push(r)
        prev = r.receipt_id
      }

      // Validate chain
      for (let i = 0; i < chain.length; i++) {
        const r = chain[i]
        // Content-addressed
        const expected = `sha256:${sha256Hex(canonicalizeJCS(r.payload))}`
        assert.equal(r.receipt_id, expected, `receipt ${i} content mismatch`)
        // Signature
        assert.ok(verify(canonicalizeJCS(r.payload), r.signature.sig, keys.publicKey), `receipt ${i} sig fail`)
        // Chain link
        if (i === 0) {
          assert.equal(r.previousReceiptHash, null)
        } else {
          assert.equal(r.previousReceiptHash, chain[i - 1].receipt_id, `receipt ${i} chain link broken`)
        }
      }
    })
  })
})
