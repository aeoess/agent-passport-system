// ══════════════════════════════════════════════════════════════════
// B-10: Key Storage Backend — Tests
// ══════════════════════════════════════════════════════════════════

import { describe, it, after } from 'node:test'
import assert from 'node:assert/strict'
import { InMemoryKeyStorage, EncryptedFileKeyStorage } from '../src/crypto/key-storage.js'
import { generateKeyPair } from '../src/crypto/keys.js'
import { join } from 'path'
import { unlinkSync } from 'fs'

describe('Key Storage Backend (B-10)', () => {
  describe('InMemoryKeyStorage', () => {
    it('stores and retrieves keypairs', async () => {
      const store = new InMemoryKeyStorage()
      const keys = generateKeyPair()
      await store.store('agent-001', keys.privateKey, keys.publicKey)
      const retrieved = await store.retrieve('agent-001')
      assert.ok(retrieved)
      assert.equal(retrieved.privateKey, keys.privateKey)
      assert.equal(retrieved.publicKey, keys.publicKey)
    })

    it('returns null for unknown agent', async () => {
      const store = new InMemoryKeyStorage()
      const result = await store.retrieve('nonexistent')
      assert.equal(result, null)
    })

    it('deletes keypairs', async () => {
      const store = new InMemoryKeyStorage()
      const keys = generateKeyPair()
      await store.store('agent-002', keys.privateKey, keys.publicKey)
      const deleted = await store.delete('agent-002')
      assert.equal(deleted, true)
      const result = await store.retrieve('agent-002')
      assert.equal(result, null)
    })

    it('lists stored agents', async () => {
      const store = new InMemoryKeyStorage()
      await store.store('a1', 'pk1', 'pub1')
      await store.store('a2', 'pk2', 'pub2')
      const ids = await store.list()
      assert.deepEqual(ids.sort(), ['a1', 'a2'])
    })
  })

  describe('EncryptedFileKeyStorage', () => {
    const testFile = join('/tmp', `aps-key-test-${Date.now()}.json`)
    after(() => { try { unlinkSync(testFile) } catch {} })

    it('encrypts keys to file and reads them back', async () => {
      const store = new EncryptedFileKeyStorage(testFile, 'test-password-123')
      const keys = generateKeyPair()
      await store.store('agent-enc', keys.privateKey, keys.publicKey)
      // New instance with same file + password should read back
      const store2 = new EncryptedFileKeyStorage(testFile, 'test-password-123')
      const retrieved = await store2.retrieve('agent-enc')
      assert.ok(retrieved)
      assert.equal(retrieved.privateKey, keys.privateKey)
      assert.equal(retrieved.publicKey, keys.publicKey)
    })

    it('wrong password fails to decrypt or returns corrupted data', async () => {
      const file2 = join('/tmp', `aps-key-test2-${Date.now()}.json`)
      after(() => { try { unlinkSync(file2) } catch {} })
      const store = new EncryptedFileKeyStorage(file2, 'correct-password')
      const keys = generateKeyPair()
      await store.store('agent-sec', keys.privateKey, keys.publicKey)
      // Wrong password — should either throw or return corrupted/null data
      const store2 = new EncryptedFileKeyStorage(file2, 'wrong-password')
      let failed = false
      try {
        const result = await store2.retrieve('agent-sec')
        // If it doesn't throw, the data should be corrupted (not matching original)
        if (!result || result.privateKey !== keys.privateKey) failed = true
      } catch {
        failed = true  // threw an error — correct behavior
      }
      assert.ok(failed, 'Wrong password should fail to recover correct keys')
    })
  })
})
