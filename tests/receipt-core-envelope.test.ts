// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

// Envelope rules of draft-pidlisnyi-aps-03 section 5.1 that the validator did not enforce:
// a member the draft types as a string is a string and is not coerced, delegation_ref
// carries the "sha256:" form of a delegation_id, issued_at admits a conforming leap second
// and no other second 60, and a receipt string carries no Unicode noncharacter.

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { publicKeyFromPrivate } from '../src/crypto/keys.js'
import { createReceiptV1, isExactUtcMilliseconds, validateReceiptV1 } from '../src/v2/receipt-core/receipt.js'
import type { ReceiptV1 } from '../src/v2/receipt-core/types.js'

const privateKey = '00'.repeat(32)
const publicKey = publicKeyFromPrivate(privateKey)
const hex = (c: string) => c.repeat(64)

const intent = (): ReceiptV1 => createReceiptV1({
  profile: 'aps-receipt-v1',
  receipt_type: 'aps:action-intent:v1',
  issuer: 'did:example:agent',
  subject_agent: 'did:example:agent',
  action_ref: hex('a'),
  delegation_ref: `sha256:${hex('b')}`,
  issued_at: '2026-07-18T12:00:00.000Z',
  evidence_refs: [],
  result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
}, [{ signer: 'did:example:agent', key_id: 'key-1', private_key: privateKey }])

/** Every mutation below is refused, and the untouched control is accepted, so a test that
 *  passes because the receipt was already broken is distinguishable from one that passes
 *  because the rule fired. */
function assertRejected(mutate: (receipt: Record<string, unknown>) => void, label: string): void {
  const control = intent()
  assert.doesNotThrow(() => validateReceiptV1(control), `${label}: control receipt must validate`)
  const mutated = structuredClone(control) as unknown as Record<string, unknown>
  mutate(mutated)
  assert.throws(() => validateReceiptV1(mutated as unknown as ReceiptV1), TypeError, label)
}

test('envelope: a non-string member is refused rather than coerced', () => {
  // A regular expression coerces its argument, so each of these passed before: the array
  // wrapping one hex string stringifies to that string, and a number or object passed a
  // truthiness test.
  assertRejected(r => { r.action_ref = [hex('a')] }, 'action_ref as a one-element array')
  assertRejected(r => { r.receipt_id = [hex('a')] }, 'receipt_id as a one-element array')
  assertRejected(r => { r.issuer = 1 }, 'issuer as a number')
  assertRejected(r => { r.subject_agent = { did: 'x' } }, 'subject_agent as an object')
  assertRejected(r => { r.receipt_type = 1 }, 'receipt_type as a number')
  assertRejected(r => { r.delegation_ref = [`sha256:${hex('b')}`] }, 'delegation_ref as a one-element array')
  assertRejected(r => { r.decision_ref = [hex('c')] }, 'decision_ref as a one-element array')
  assertRejected(r => { r.prev = [hex('c')] }, 'prev as a one-element array')
  assertRejected(r => { r.issued_at = ['2026-07-18T12:00:00.000Z'] }, 'issued_at as a one-element array')
  assertRejected(r => { (r.evidence_refs as unknown[]).push({ artifact_type: 'a', sha256: [hex('d')] }) }, 'evidence sha256 as a one-element array')
  assertRejected(r => { (r.evidence_refs as unknown[]).push({ artifact_type: 2, sha256: hex('d') }) }, 'evidence artifact_type as a number')
  assertRejected(r => { (r.signatures as Record<string, unknown>[])[0].signer = 1 }, 'signature signer as a number')
  assertRejected(r => { (r.signatures as Record<string, unknown>[])[0].key_id = ['k'] }, 'signature key_id as a one-element array')
  assertRejected(r => { (r.signatures as Record<string, unknown>[])[0].value = ['0'.repeat(128)] }, 'signature value as a one-element array')
})

test('envelope: delegation_ref carries the sha256 prefixed delegation_id form', () => {
  assertRejected(r => { r.delegation_ref = hex('b') }, 'bare 64 hex')
  assertRejected(r => { r.delegation_ref = `sha256:${'B'.repeat(64)}` }, 'uppercase hex')
  assertRejected(r => { r.delegation_ref = `sha256:${hex('b')}0` }, 'one hex digit too many')
  assertRejected(r => { r.delegation_ref = 'sha256:' }, 'prefix with no digest')
  assertRejected(r => { r.delegation_ref = 'did:example:authority-basis' }, 'an identifier that is not a digest')
  assert.doesNotThrow(() => validateReceiptV1(intent()))
})

test('envelope: second 60 is accepted only at 23:59 on the last day of a month', () => {
  // RFC 3339 section 5.7 and Appendix D. The same rule is applied on the section 4.1 and
  // section 3 surfaces; no leap-second table is consulted.
  assert.equal(isExactUtcMilliseconds('2026-06-30T23:59:60.000Z'), true)
  assert.equal(isExactUtcMilliseconds('2026-12-31T23:59:60.500Z'), true)
  assert.equal(isExactUtcMilliseconds('2024-02-29T23:59:60.000Z'), true, 'leap-year February')
  assert.equal(isExactUtcMilliseconds('2026-02-29T23:59:60.000Z'), false, 'February 29 outside a leap year')
  assert.equal(isExactUtcMilliseconds('2026-06-29T23:59:60.000Z'), false, 'not the last day of the month')
  assert.equal(isExactUtcMilliseconds('2026-06-30T22:59:60.000Z'), false, 'not 23:59')
  assert.equal(isExactUtcMilliseconds('2026-06-30T23:58:60.000Z'), false, 'not 23:59')
  assert.equal(isExactUtcMilliseconds('2026-13-31T23:59:60.000Z'), false, 'month 13')
  assert.equal(isExactUtcMilliseconds('2026-00-31T23:59:60.000Z'), false, 'month 0')
  // Nothing else changed: the ordinary timestamps the check accepted and rejected before
  // are accepted and rejected still.
  assert.equal(isExactUtcMilliseconds('2026-07-18T12:00:00.000Z'), true)
  assert.equal(isExactUtcMilliseconds('2026-02-30T12:00:00.000Z'), false)
  assert.equal(isExactUtcMilliseconds('2026-07-18T12:00:00Z'), false, 'no milliseconds')
  assert.equal(isExactUtcMilliseconds('2026-07-18T12:00:00.000+00:00'), false, 'offset rather than Z')
  const receipt = structuredClone(intent()) as unknown as Record<string, unknown>
  receipt.issued_at = '2026-06-30T23:59:60.000Z'
  assert.doesNotThrow(() => validateReceiptV1(receipt as unknown as ReceiptV1, false))
})

test('envelope: a Unicode noncharacter in any string is refused', () => {
  assertRejected(r => { r.issuer = 'did:example:a﷐' }, 'noncharacter in issuer')
  assertRejected(r => { r.receipt_type = 'aps:action-intent:v1￿' }, 'noncharacter in receipt_type')
  assertRejected(r => { (r.result as Record<string, unknown>).status = 'decl￾ared' }, 'noncharacter in a result value')
  assertRejected(r => { (r.result as Record<string, unknown>)['k﷯'] = 'v' }, 'noncharacter in a result key')
  assertRejected(r => { (r.result as Record<string, unknown>).status = 'x\u{1fffe}' }, 'supplementary-plane noncharacter')
  // An unpaired surrogate was already refused by the canonicalizer and still is.
  assertRejected(r => { r.issuer = 'did:example:a\ud800' }, 'unpaired high surrogate')
})

test('envelope: the control receipt verifies, so the rejections above are not vacuous', () => {
  const receipt = intent()
  assert.equal(validateReceiptV1(receipt), undefined)
  assert.equal(receipt.delegation_ref, `sha256:${hex('b')}`)
  assert.equal(typeof publicKey, 'string')
})
