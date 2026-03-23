// ══════════════════════════════════════════════════════════════════
// Ed25519 → X25519 Interop Test Vectors
// ══════════════════════════════════════════════════════════════════
// Verifies cross-project compatibility with corpollc/qntm.
// Vectors from: https://github.com/corpollc/qntm/blob/main/python-dist/tests/interop/VECTORS.md
// Math: u = (1 + y) / (1 - y) mod p  (RFC 7748 §4.1)
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { deriveEncryptionKeypair } from '../src/core/encrypted-messaging.js'
import sodium from 'libsodium-wrappers'

const VECTORS = [
  {
    name: 'Vector 1 (zero seed)',
    seed: '0000000000000000000000000000000000000000000000000000000000000000',
    ed25519_pk: '3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29',
    x25519_pk: '5bf55c73b82ebe22be80f3430667af570fae2556a6415e6b30d4065300aa947d',
  },
  {
    name: 'Vector 2 (incrementing bytes)',
    seed: '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
    ed25519_pk: '79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664',
    x25519_pk: '4a3807d064d077181cc070989e76891d20dca5559548dc2c77c1a50273882b38',
  },
  {
    name: 'Vector 3 (all 0xFF)',
    seed: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    ed25519_pk: '76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5',
    x25519_pk: 'd1fa3f01826bd8b78e057c086c7b22c7ad4358ca918099cd7b7e5d3acd7e285b',
  },
  {
    name: 'Vector 4 (RFC 8032 test vector 1 seed)',
    seed: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    ed25519_pk: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    x25519_pk: 'd85e07ec22b0ad881537c2f44d662d1a143cf830c57aca4305d85c7a90f6b62e',
  },
  {
    name: 'Vector 5 (random)',
    seed: 'a3c4e2f1b8d7954c6e0f3a2b1d4c5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d',
    ed25519_pk: 'ea21e5719500ca99648e2693eec7dd40ff1ace600f5a70a1071f797be6d23316',
    x25519_pk: '2eb1f20188c191df7f49958c80baebd923f9f88fe3e5bbf79cc1201a417f3b38',
  },
]

describe('Ed25519 → X25519 Interop Vectors (qntm compatibility)', () => {
  for (const v of VECTORS) {
    it(`${v.name}: key derivation matches`, async () => {
      const result = await deriveEncryptionKeypair(v.seed)
      // Verify Ed25519 intermediate
      assert.equal(result.ed25519PublicKeyHex, v.ed25519_pk)
      // Verify X25519 derivation (the interop test)
      await sodium.ready
      const x25519Hex = sodium.to_hex(sodium.from_base64(result.publicKey))
      assert.equal(x25519Hex, v.x25519_pk)
    })
  }

  it('deriveEncryptionKeypair is deterministic', async () => {
    const seed = '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'
    const r1 = await deriveEncryptionKeypair(seed)
    const r2 = await deriveEncryptionKeypair(seed)
    assert.equal(r1.publicKey, r2.publicKey)
    assert.equal(r1.privateKey, r2.privateKey)
    assert.equal(r1.ed25519PublicKeyHex, r2.ed25519PublicKeyHex)
  })

  it('different seeds produce different X25519 keys', async () => {
    const results = await Promise.all(VECTORS.map(v => deriveEncryptionKeypair(v.seed)))
    const keys = new Set(results.map(r => r.publicKey))
    assert.equal(keys.size, VECTORS.length)
  })

  it('derived keypair can perform X25519 key agreement', async () => {
    await sodium.ready
    const alice = await deriveEncryptionKeypair(VECTORS[0].seed)
    const bob = await deriveEncryptionKeypair(VECTORS[1].seed)
    const aliceShared = sodium.crypto_scalarmult(
      sodium.from_base64(alice.privateKey), sodium.from_base64(bob.publicKey)
    )
    const bobShared = sodium.crypto_scalarmult(
      sodium.from_base64(bob.privateKey), sodium.from_base64(alice.publicKey)
    )
    assert.equal(sodium.to_hex(aliceShared), sodium.to_hex(bobShared))
  })
})
