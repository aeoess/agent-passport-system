// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Cross-algorithm mismatch verification (A2A #1672)
// Tests that receipts with mismatched algorithm claims are correctly rejected.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { verify } from '../src/crypto/keys.js'

const fixture = JSON.parse(
  readFileSync(new URL('../interop/fixtures/cross-algo-mismatch.json', import.meta.url).pathname, 'utf-8')
)

const pubKey = fixture.public_key_hex

function verifyWithAlgCheck(
  canonical: string,
  signature: string,
  publicKeyHex: string,
  header: { alg: string; kid: string },
  didDoc: any,
): { valid: boolean; error?: string } {
  // Step 1: Verify algorithm claim matches DID document key type
  const keyMethod = didDoc.verificationMethod?.find((vm: any) => vm.id === header.kid)
  if (!keyMethod) return { valid: false, error: 'key_not_found' }

  const keyType = keyMethod.type
  const expectedAlg = keyType === 'Ed25519VerificationKey2020' ? 'EdDSA'
    : keyType === 'EcdsaSecp256k1VerificationKey2019' ? 'ES256K'
    : keyType === 'JsonWebKey2020' ? 'ES256'
    : null

  if (expectedAlg && header.alg !== expectedAlg) {
    return { valid: false, error: 'algorithm_mismatch' }
  }

  // Step 2: Verify Ed25519 signature
  const sigValid = verify(canonical, signature, publicKeyHex)
  if (!sigValid) return { valid: false, error: 'signature_invalid' }

  return { valid: true }
}

describe('Cross-Algorithm Mismatch Verification (A2A #1672)', () => {
  const didDoc = fixture.did_document

  for (const testCase of fixture.cases) {
    it(testCase.description, () => {
      const result = verifyWithAlgCheck(
        testCase.canonical,
        testCase.signature,
        pubKey,
        testCase.header,
        didDoc,
      )

      assert.equal(result.valid, testCase.expected.valid,
        `Expected valid=${testCase.expected.valid} but got ${result.valid} (error: ${result.error})`)

      if (testCase.expected.error) {
        assert.equal(result.error, testCase.expected.error,
          `Expected error="${testCase.expected.error}" but got "${result.error}"`)
      }
    })
  }

  it('DID document has Ed25519 verification method', () => {
    assert.ok(didDoc.verificationMethod)
    assert.equal(didDoc.verificationMethod.length, 1)
    assert.equal(didDoc.verificationMethod[0].type, 'Ed25519VerificationKey2020')
    assert.equal(didDoc.verificationMethod[0].publicKeyHex, pubKey)
  })

  it('fixture has exactly 3 test cases', () => {
    assert.equal(fixture.cases.length, 3)
  })
})
