import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  namespaceProofId,
  parseNamespacedId,
  resolveProofUrl,
} from '../src/core/proof-namespace.ts'

describe('Proof ID Namespacing', () => {
  describe('namespaceProofId', () => {
    it('adds aps: prefix to bare ID', () => {
      assert.equal(namespaceProofId('drv_abc123'), 'aps:drv_abc123')
    })

    it('does not double-prefix', () => {
      assert.equal(namespaceProofId('aps:drv_abc123'), 'aps:drv_abc123')
    })

    it('handles various receipt ID formats', () => {
      assert.equal(namespaceProofId('acc_xyz'), 'aps:acc_xyz')
      assert.equal(namespaceProofId('stl_001'), 'aps:stl_001')
      assert.equal(namespaceProofId('pr-001'), 'aps:pr-001')
    })
  })

  describe('parseNamespacedId', () => {
    it('parses aps: namespace', () => {
      const result = parseNamespacedId('aps:drv_abc123')
      assert.equal(result.namespace, 'aps')
      assert.equal(result.id, 'drv_abc123')
    })

    it('parses DID-style namespace', () => {
      const result = parseNamespacedId('did:arkforge:prf_xyz')
      assert.equal(result.namespace, 'did:arkforge')
      assert.equal(result.id, 'prf_xyz')
    })

    it('returns null namespace for bare IDs', () => {
      const result = parseNamespacedId('bare_id_no_prefix')
      assert.equal(result.namespace, null)
      assert.equal(result.id, 'bare_id_no_prefix')
    })

    it('handles colons in ID portion', () => {
      const result = parseNamespacedId('did:aps:drv:sub:123')
      assert.equal(result.namespace, 'did:aps')
      assert.equal(result.id, 'drv:sub:123')
    })
  })

  describe('resolveProofUrl', () => {
    it('resolves aps: to gateway URL', () => {
      const url = resolveProofUrl('aps:drv_abc123')
      assert.equal(url, 'https://gateway.aeoess.com/.well-known/receipts/drv_abc123')
    })

    it('returns null for unknown namespace', () => {
      const url = resolveProofUrl('unknown:drv_abc123')
      assert.equal(url, null)
    })

    it('returns null for bare ID', () => {
      const url = resolveProofUrl('bare_id')
      assert.equal(url, null)
    })

    it('uses custom resolver registry', () => {
      const url = resolveProofUrl('arkforge:prf_xyz', {
        arkforge: 'https://arkforge.dev/.well-known/receipts/',
      })
      assert.equal(url, 'https://arkforge.dev/.well-known/receipts/prf_xyz')
    })

    it('custom registry overrides defaults', () => {
      const url = resolveProofUrl('aps:drv_abc', {
        aps: 'https://custom.gateway.com/receipts/',
      })
      assert.equal(url, 'https://custom.gateway.com/receipts/drv_abc')
    })
  })
})
