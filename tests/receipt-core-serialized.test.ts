// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { publicKeyFromPrivate } from '../src/crypto/keys.js'
import { createReceiptV1, verifyReceiptV1, verifyReceiptV1Serialized } from '../src/v2/receipt-core/receipt.js'

const privateKey = '00'.repeat(32)
const publicKey = publicKeyFromPrivate(privateKey)
const resolveKey = () => publicKey
const hex = (c: string) => c.repeat(64)

const receipt = createReceiptV1({
  profile: 'aps-receipt-v1',
  receipt_type: 'aps:action:v1',
  issuer: 'did:example:issuer',
  subject_agent: 'did:example:agent',
  action_ref: hex('a'),
  delegation_ref: hex('b'),
  issued_at: '2026-04-08T12:00:00.000Z',
  evidence_refs: [],
  result: { status: 'ok' },
}, [{ signer: 'did:example:issuer', key_id: 'k1', private_key: privateKey }])

const clean = JSON.stringify(receipt)
// JSON.stringify cannot emit a duplicate member, so the duplicate is spliced in
// textually. That is the point: the fact exists only in the byte stream.
const withDuplicate = clean.replace(
  '"issuer":"did:example:issuer"',
  '"issuer":"did:example:issuer","issuer":"did:example:attacker"',
)
// The same member name reached through an escape alias, caught only if names are
// compared AFTER decoding rather than as raw source text.
const withEscapedDuplicate = clean.replace(
  '"issuer":"did:example:issuer"',
  '"issuer":"did:example:issuer","\\u0069ssuer":"did:example:attacker"',
)

test('serialized: fixture guard, the duplicate survives in raw bytes and a permissive parser loses it', () => {
  assert.notEqual(withDuplicate, clean)
  assert.notEqual(withEscapedDuplicate, clean)
  assert.equal(withDuplicate.match(/"issuer":/g)?.length, 2)
  // A permissive parse keeps the LAST occurrence, so the object-taking verifier
  // downstream of JSON.parse can never see that a duplicate was present.
  const permissive = JSON.parse(withDuplicate) as { issuer: string }
  assert.equal(permissive.issuer, 'did:example:attacker')
  assert.equal(Object.keys(permissive).filter(k => k === 'issuer').length, 1)
})

test('serialized: a plain duplicated member is rejected at the parse stage', () => {
  const result = verifyReceiptV1Serialized(withDuplicate, resolveKey)
  assert.equal(result.valid, false)
  assert.equal(result.errors[0], 'parse_error')
  assert.match(result.errors[1], /duplicate object member/)
})

test('serialized: an escape-aliased duplicate is rejected at the parse stage', () => {
  const result = verifyReceiptV1Serialized(withEscapedDuplicate, resolveKey)
  assert.equal(result.valid, false)
  assert.equal(result.errors[0], 'parse_error')
  assert.match(result.errors[1], /duplicate object member/)
})

test('serialized: positive case, the clean document round-trips through the path', () => {
  const result = verifyReceiptV1Serialized(clean, resolveKey)
  assert.equal(result.valid, true)
  assert.deepEqual(result.errors, [])
  assert.equal(result.receipt_id_valid, true)
  assert.equal(result.signature_results.length, 1)
  assert.equal(result.signature_results[0].valid, true)
  // Byte round trip: the serialized path agrees with the object-taking path on
  // the same artifact, so the parser is additive rather than a second semantics.
  assert.deepEqual(result, verifyReceiptV1(receipt, resolveKey))
})

test('serialized: parse failure is distinguishable from structural and from signature failure', () => {
  // Parse stage: code first, parser message second.
  const parseFail = verifyReceiptV1Serialized('{"a":1,"a":2}', resolveKey)
  assert.equal(parseFail.errors[0], 'parse_error')

  // Structural stage: the document parses but is not a receipt, so the validator
  // message surfaces and no parse_error code appears.
  const structuralFail = verifyReceiptV1Serialized('{"profile":"not-a-receipt"}', resolveKey)
  assert.equal(structuralFail.valid, false)
  assert.ok(!structuralFail.errors.includes('parse_error'))
  assert.ok(structuralFail.errors.some(e => e.includes('ReceiptV1')))

  // Signature stage: parses and validates, but the key does not verify it.
  const signatureFail = verifyReceiptV1Serialized(clean, () => publicKeyFromPrivate('11'.repeat(32)))
  assert.equal(signatureFail.valid, false)
  assert.ok(signatureFail.errors.includes('signature_invalid'))
  assert.ok(!signatureFail.errors.includes('parse_error'))

  // All three are distinct, which is the requirement.
  assert.notDeepEqual(parseFail.errors, structuralFail.errors)
  assert.notDeepEqual(structuralFail.errors, signatureFail.errors)
})

test('serialized: a non-string or oversize input is refused rather than parsed', () => {
  const tooBig = verifyReceiptV1Serialized('"' + 'x'.repeat(2_000_000) + '"', resolveKey)
  assert.equal(tooBig.valid, false)
  assert.equal(tooBig.errors[0], 'parse_error')
})
