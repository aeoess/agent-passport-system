// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Optional package tests: each cloud adapter reduces to a core HandleSigner over
// an injected backend port, produces byte-identical signatures to the Ed25519
// default, and never receives the raw private key.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { generateKeyPair, sign, verify, verifyWithSigner } from 'agent-passport-system'
import {
  createAwsKmsSigner,
  createAzureKeyVaultSigner,
  createVaultTransitSigner,
  createPkcs11Signer,
  type AwsKmsPort,
  type AzureKeyVaultPort,
  type VaultTransitPort,
  type Pkcs11Port,
} from '../src/index.js'

// A backend stub that seals the private key in a closure. The adapter receives
// only the port object; the key never crosses into the adapter or the consumer.
function sealedBackend() {
  const { privateKey, publicKey } = generateKeyPair()
  const port = {
    signRaw: async (_ref: string, messageUtf8: string) => sign(messageUtf8, privateKey),
    getRawPublicKeyHex: async (_ref: string) => publicKey,
  }
  return { port, publicKey }
}

describe('aps-remote-signer cloud adapters', () => {
  it('AWS KMS adapter signs byte-identically and verifies under the default', async () => {
    const { port, publicKey } = sealedBackend()
    const signer = createAwsKmsSigner({ client: port as AwsKmsPort, keyId: 'arn:aws:kms:...:key/abc' })

    const message = 'aps:aws-kms:msg'
    const sig = await signer.sign(message)
    assert.equal(sig.length, 128)
    assert.ok(verify(message, sig, publicKey))
    assert.ok(await verifyWithSigner(message, sig, signer))
    assert.equal(signer.handle.kind, 'aws-kms')
    assert.equal(signer.handle.keyRef, 'arn:aws:kms:...:key/abc')
  })

  it('Azure Key Vault adapter signs byte-identically', async () => {
    const { port, publicKey } = sealedBackend()
    const signer = createAzureKeyVaultSigner({ client: port as AzureKeyVaultPort, keyName: 'kv-key-1' })
    const message = 'aps:azure:msg'
    const sig = await signer.sign(message)
    assert.ok(verify(message, sig, publicKey))
    assert.equal(signer.handle.kind, 'azure-kv')
  })

  it('Vault Transit adapter signs byte-identically', async () => {
    const { port, publicKey } = sealedBackend()
    const signer = createVaultTransitSigner({ client: port as VaultTransitPort, keyName: 'transit-1' })
    const message = 'aps:vault:msg'
    const sig = await signer.sign(message)
    assert.ok(verify(message, sig, publicKey))
    assert.equal(signer.handle.kind, 'vault-transit')
  })

  it('PKCS#11 adapter signs byte-identically', async () => {
    const { port, publicKey } = sealedBackend()
    const signer = createPkcs11Signer({ client: port as Pkcs11Port, objectLabel: 'hsm:ed25519' })
    const message = 'aps:pkcs11:msg'
    const sig = await signer.sign(message)
    assert.ok(verify(message, sig, publicKey))
    assert.equal(signer.handle.kind, 'pkcs11')
  })

  it('signerKeyId override is honored', async () => {
    const { port } = sealedBackend()
    const signer = createAwsKmsSigner({
      client: port as AwsKmsPort,
      keyId: 'arn:aws:kms:...:key/abc',
      signerKeyId: 'arn:aws:kms:...:key/abc',
    })
    assert.equal(await signer.keyId(), 'arn:aws:kms:...:key/abc')
  })

  it('no adapter surface exposes a raw private key', async () => {
    const { port } = sealedBackend()
    const signers = [
      createAwsKmsSigner({ client: port as AwsKmsPort, keyId: 'k' }),
      createAzureKeyVaultSigner({ client: port as AzureKeyVaultPort, keyName: 'k' }),
      createVaultTransitSigner({ client: port as VaultTransitPort, keyName: 'k' }),
      createPkcs11Signer({ client: port as Pkcs11Port, objectLabel: 'k' }),
    ]
    for (const s of signers) {
      for (const v of Object.values(s as unknown as Record<string, unknown>)) {
        assert.notEqual(
          typeof v === 'string' && v.length === 64 && /^[0-9a-f]+$/i.test(v),
          true,
        )
      }
    }
  })
})
