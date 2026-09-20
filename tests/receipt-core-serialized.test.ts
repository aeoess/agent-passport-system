// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { publicKeyFromPrivate } from '../src/crypto/keys.js'
import { createReceiptV1, verifyReceiptV1, verifyReceiptV1Serialized } from '../src/v2/receipt-core/receipt.js'
import { IJsonResourceLimitError, parseStrictIJson } from '../src/v2/receipt-core/jcs.js'

const privateKey = '00'.repeat(32)
const publicKey = publicKeyFromPrivate(privateKey)
const resolveKey = () => publicKey
const hex = (c: string) => c.repeat(64)

// A real section 5.3 stage. The earlier fixture used receipt_type "aps:action:v1" with a
// free-form result, which names no stage, so once the verifier enforces the type-specific
// schema of line 1214 that document is unsupported rather than valid and the duplicate
// member cases below would have passed for the wrong reason.
const receipt = createReceiptV1({
  profile: 'aps-receipt-v1',
  receipt_type: 'aps:action-intent:v1',
  issuer: 'did:example:agent',
  subject_agent: 'did:example:agent',
  action_ref: hex('a'),
  delegation_ref: `sha256:${hex('b')}`,
  issued_at: '2026-04-08T12:00:00.000Z',
  evidence_refs: [],
  result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
}, [{ signer: 'did:example:agent', key_id: 'k1', private_key: privateKey }])

const clean = JSON.stringify(receipt)
// JSON.stringify cannot emit a duplicate member, so the duplicate is spliced in
// textually. That is the point: the fact exists only in the byte stream.
const withDuplicate = clean.replace(
  '"issuer":"did:example:agent"',
  '"issuer":"did:example:agent","issuer":"did:example:attacker"',
)
// The same member name reached through an escape alias, caught only if names are
// compared AFTER decoding rather than as raw source text.
const withEscapedDuplicate = clean.replace(
  '"issuer":"did:example:agent"',
  '"issuer":"did:example:agent","\\u0069ssuer":"did:example:attacker"',
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

  // Structural stage: the document parses and claims this envelope profile but is not a
  // receipt, so the validator message surfaces and no parse_error code appears.
  const structuralFail = verifyReceiptV1Serialized('{"profile":"aps-receipt-v1"}', resolveKey)
  assert.equal(structuralFail.valid, false)
  assert.equal(structuralFail.status, 'invalid')
  assert.ok(!structuralFail.errors.includes('parse_error'))
  assert.ok(structuralFail.errors.some(e => e.includes('ReceiptV1')))

  // Another envelope profile is a fourth outcome: unsupported, not invalid, and not judged
  // against a schema that is not its own (draft line 1226).
  const foreignProfile = verifyReceiptV1Serialized('{"profile":"not-a-receipt"}', resolveKey)
  assert.equal(foreignProfile.valid, false)
  assert.equal(foreignProfile.status, 'unsupported')
  assert.deepEqual(foreignProfile.errors, ['unsupported_profile'])

  // Signature stage: parses and validates, but the key does not verify it.
  const signatureFail = verifyReceiptV1Serialized(clean, () => publicKeyFromPrivate('11'.repeat(32)))
  assert.equal(signatureFail.valid, false)
  assert.ok(signatureFail.errors.includes('signature_invalid'))
  assert.ok(!signatureFail.errors.includes('parse_error'))

  // All three are distinct, which is the requirement.
  assert.notDeepEqual(parseFail.errors, structuralFail.errors)
  assert.notDeepEqual(structuralFail.errors, signatureFail.errors)
})

test('serialized: a stack ceiling reached under a raised depth limit is a resource limit, not a parse failure', () => {
  // A caller may configure maxDepth above what this runtime's call stack can walk. The
  // parser then stops on the stack rather than on the configured limit, which is the same
  // kind of event and must not surface as a bare RangeError or as a malformed document.
  // Not reachable through verifyReceiptV1Serialized, which parses at the default ceiling.
  const deep = '{"a":'.repeat(10_000) + '1' + '}'.repeat(10_000)
  assert.throws(
    () => parseStrictIJson(deep, 1_048_576 * 8, 1_000_000),
    (err: unknown) => err instanceof IJsonResourceLimitError && !(err instanceof RangeError),
  )
  // A document within both ceilings is unaffected. The parser returns null-prototype
  // objects, so this reads the member rather than comparing against a plain literal.
  assert.equal((parseStrictIJson('{"a":1}') as Record<string, unknown>).a, 1)
})

test('serialized: a resource ceiling is indeterminate under RESOURCE_LIMIT, not invalid', () => {
  // Both ceilings belong to this parser, not to the draft, so
  // hitting one says this verifier stopped, never that the receipt is bad. Previously both
  // returned invalid/parse_error, which made validity depend on verifier capacity: the same
  // bytes verify under a higher ceiling.
  const tooBig = verifyReceiptV1Serialized('"' + 'x'.repeat(2_000_000) + '"', resolveKey)
  assert.equal(tooBig.valid, false)
  assert.equal(tooBig.status, 'indeterminate')
  assert.equal(tooBig.errors[0], 'RESOURCE_LIMIT')
  assert.ok(!tooBig.errors.includes('parse_error'))

  const tooDeep = verifyReceiptV1Serialized('{"a":'.repeat(200) + '1' + '}'.repeat(200), resolveKey)
  assert.equal(tooDeep.valid, false)
  assert.equal(tooDeep.status, 'indeterminate')
  assert.equal(tooDeep.errors[0], 'RESOURCE_LIMIT')
  assert.ok(!tooDeep.errors.includes('parse_error'))

  // The distinction the ruling turns on: a document that is actually malformed, and one
  // that is well formed but not a receipt, are unchanged and stay invalid.
  const malformed = verifyReceiptV1Serialized('{"a": }', resolveKey)
  assert.equal(malformed.status, 'invalid')
  assert.equal(malformed.errors[0], 'parse_error')

  const duplicate = verifyReceiptV1Serialized('{"a":1,"a":2}', resolveKey)
  assert.equal(duplicate.status, 'invalid')
  assert.equal(duplicate.errors[0], 'parse_error')

  // A conforming receipt under both ceilings is untouched.
  const ok = verifyReceiptV1Serialized(clean, resolveKey)
  assert.equal(ok.valid, true)
  assert.equal(ok.status, 'valid')
})
