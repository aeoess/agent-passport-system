// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * EXPERIMENTAL, ISOLATED test suite for BBS selective-disclosure scope
 * credentials. Includes explicit negative-path fixtures.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  deriveDisclosureProof,
  generateKeyPair,
  issueScopeCredential,
  verifyDisclosureProof,
  verifyScopeCredential,
} from '../src/index.js'

// Deterministic 32-byte key material for reproducible tests. NOT for production.
const KEY_MATERIAL = new Uint8Array(32).fill(7)

const SCOPES = [
  'read:repo',
  'write:repo',
  'settle:usd:<=100',
  'invoke:tool:search',
]

const PH = new TextEncoder().encode('verifier-challenge-0001')

async function freshCredential(ciphersuite: 'SHA-256' | 'SHAKE-256' = 'SHA-256') {
  const keyPair = await generateKeyPair(KEY_MATERIAL, ciphersuite)
  const credential = await issueScopeCredential(keyPair, SCOPES, ciphersuite)
  return { keyPair, credential }
}

test('issued credential carries fixed-size signature and honest scope', async () => {
  const { credential } = await freshCredential()
  // IRTF BBS: PK is a 96-byte compressed G2 point, signature is 80 bytes.
  assert.equal(credential.publicKey.length, 96)
  assert.equal(credential.signature.length, 80)
  assert.equal(credential.scopes.length, 4)
  assert.equal(credential.scopeOfClaim.self_attested, true)
  assert.ok(credential.scopeOfClaim.does_not_assert.length > 0)
})

test('credential signature validates over the full scope vector', async () => {
  const { credential } = await freshCredential()
  assert.equal(await verifyScopeCredential(credential), true)
})

test('derive a subset proof, verify it reveals only the subset', async () => {
  const { credential } = await freshCredential()
  const proof = await deriveDisclosureProof(
    credential,
    ['read:repo', 'invoke:tool:search'],
    PH
  )
  assert.deepEqual(proof.disclosedScopes, ['read:repo', 'invoke:tool:search'])
  assert.deepEqual(proof.disclosedIndexes, [0, 3])
  assert.equal(proof.totalScopes, 4)
  // The undisclosed scopes never appear in the presentation object.
  const serialized = JSON.stringify(proof.disclosedScopes)
  assert.ok(!serialized.includes('write:repo'))
  assert.ok(!serialized.includes('settle:usd'))
  assert.equal(await verifyDisclosureProof(proof), true)
})

test('NEGATIVE: a tampered derived proof fails verification', async () => {
  const { credential } = await freshCredential()
  const proof = await deriveDisclosureProof(credential, ['read:repo'], PH)
  assert.equal(await verifyDisclosureProof(proof), true)
  // Flip one byte in the middle of the proof.
  const tampered = { ...proof, proof: new Uint8Array(proof.proof) }
  const mid = Math.floor(tampered.proof.length / 2)
  tampered.proof[mid] = tampered.proof[mid] ^ 0xff
  assert.equal(await verifyDisclosureProof(tampered), false)
})

test('NEGATIVE: swapping the disclosed value fails verification', async () => {
  const { credential } = await freshCredential()
  const proof = await deriveDisclosureProof(credential, ['read:repo'], PH)
  // Keep the index but claim a different scope value than was proven.
  const lied = { ...proof, disclosedScopes: ['write:repo'] }
  assert.equal(await verifyDisclosureProof(lied), false)
})

test('NEGATIVE: a mismatched presentation header fails verification', async () => {
  const { credential } = await freshCredential()
  const proof = await deriveDisclosureProof(credential, ['read:repo'], PH)
  const replayed = {
    ...proof,
    presentationHeader: new TextEncoder().encode('different-challenge'),
  }
  assert.equal(await verifyDisclosureProof(replayed), false)
})

test('NEGATIVE: disclosing a scope not in the credential is rejected', async () => {
  const { credential } = await freshCredential()
  await assert.rejects(
    () => deriveDisclosureProof(credential, ['admin:everything'], PH),
    /not present in credential/
  )
})

test('EDGE: revealing zero attributes produces a verifiable proof', async () => {
  const { credential } = await freshCredential()
  const proof = await deriveDisclosureProof(credential, [], PH)
  assert.deepEqual(proof.disclosedScopes, [])
  assert.deepEqual(proof.disclosedIndexes, [])
  assert.equal(proof.totalScopes, 4)
  // A zero-disclosure proof still proves possession of a valid credential.
  assert.equal(await verifyDisclosureProof(proof), true)
})

test('EDGE: revealing all attributes produces a verifiable proof', async () => {
  const { credential } = await freshCredential()
  const proof = await deriveDisclosureProof(credential, [...SCOPES], PH)
  assert.deepEqual(proof.disclosedIndexes, [0, 1, 2, 3])
  assert.deepEqual(proof.disclosedScopes, SCOPES)
  assert.equal(await verifyDisclosureProof(proof), true)
  // Tampering an all-disclosed proof still fails.
  const tampered = { ...proof, proof: new Uint8Array(proof.proof) }
  tampered.proof[0] = tampered.proof[0] ^ 0x01
  assert.equal(await verifyDisclosureProof(tampered), false)
})

test('EDGE: zero-disclosure proof is shorter than full-disclosure proof', async () => {
  // Proof size grows with the number of HIDDEN messages: revealing nothing
  // hides all four scopes, revealing all hides none. The all-hidden proof
  // therefore carries more scalars and is strictly longer.
  const { credential } = await freshCredential()
  const none = await deriveDisclosureProof(credential, [], PH)
  const all = await deriveDisclosureProof(credential, [...SCOPES], PH)
  assert.ok(
    none.proof.length > all.proof.length,
    'hiding more messages should yield a longer proof'
  )
})

test('disclosure order is normalized to ascending index order', async () => {
  const { credential } = await freshCredential()
  // Ask out of order; indexes and disclosed values come back sorted.
  const proof = await deriveDisclosureProof(
    credential,
    ['settle:usd:<=100', 'read:repo'],
    PH
  )
  assert.deepEqual(proof.disclosedIndexes, [0, 2])
  assert.deepEqual(proof.disclosedScopes, ['read:repo', 'settle:usd:<=100'])
  assert.equal(await verifyDisclosureProof(proof), true)
})

test('SHAKE-256 ciphersuite round-trips sign, disclose, verify', async () => {
  const { credential } = await freshCredential('SHAKE-256')
  assert.equal(await verifyScopeCredential(credential), true)
  const proof = await deriveDisclosureProof(credential, ['write:repo'], PH)
  assert.equal(proof.ciphersuite, 'SHAKE-256')
  assert.equal(await verifyDisclosureProof(proof), true)
})
