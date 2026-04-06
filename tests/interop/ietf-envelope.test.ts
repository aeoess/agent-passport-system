// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Interop: IETF draft envelope receipt verification

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { canonicalizeJCS, verify } from '../../src/index.js'

const DIR = new URL('../../examples/interop/ietf-envelope/', import.meta.url).pathname

function loadReceipt(name: string) {
  return JSON.parse(readFileSync(`${DIR}${name}`, 'utf-8'))
}

const pubkey = readFileSync(`${DIR}gateway-pubkey.txt`, 'utf-8').trim()

describe('IETF Envelope Receipts', () => {
  const receipts = [
    { file: 'receipt-permit.json', finality: 'executed' },
    { file: 'receipt-deny.json', finality: 'denied' },
    { file: 'receipt-commerce.json', finality: 'executed' },
  ]

  for (const { file, finality } of receipts) {
    describe(file, () => {
      const r = loadReceipt(file)

      it('has required IETF fields', () => {
        assert.equal(r.spec, 'draft-farley-acta-signed-receipts-01')
        assert.ok(r.receipt_id, 'receipt_id present')
        assert.ok(r.issued_at, 'issued_at present')
        assert.ok(r.issuer_id, 'issuer_id present')
        assert.ok(r.payload, 'payload present')
        assert.ok(r.signature, 'signature present')
      })

      it('receipt_id is content-addressed (sha256 of JCS payload)', () => {
        const canonical = canonicalizeJCS(r.payload)
        const hash = createHash('sha256').update(canonical).digest('hex')
        assert.equal(r.receipt_id, `sha256:${hash}`)
      })

      it('Ed25519 signature verifies over JCS payload', () => {
        const canonical = canonicalizeJCS(r.payload)
        assert.ok(verify(canonical, r.signature.sig, pubkey))
      })

      it('issuer_id is a DID', () => {
        assert.ok(r.issuer_id.startsWith('did:'))
      })

      it('signature uses EdDSA', () => {
        assert.equal(r.signature.alg, 'EdDSA')
        assert.equal(r.signature.kid, r.issuer_id)
      })

      it('APS extensions present in payload', () => {
        assert.ok(r.payload.extensions?.aps, 'extensions.aps present')
        assert.ok(r.payload.extensions.aps.delegationChain, 'delegationChain present')
        assert.ok(r.payload.extensions.aps.scope, 'scope present')
        assert.equal(r.payload.extensions.aps.finality, finality)
      })
    })
  }

  describe('Chain integrity', () => {
    it('receipts are linked via previousReceiptHash', () => {
      const permit = loadReceipt('receipt-permit.json')
      const deny = loadReceipt('receipt-deny.json')
      const commerce = loadReceipt('receipt-commerce.json')

      assert.equal(permit.previousReceiptHash, null)
      assert.equal(deny.previousReceiptHash, permit.receipt_id)
      assert.equal(commerce.previousReceiptHash, deny.receipt_id)
    })
  })
})
