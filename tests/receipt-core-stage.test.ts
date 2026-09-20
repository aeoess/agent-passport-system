// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

// Section 5.3 stage rules. Before this, a generic ReceiptV1 validated whatever its
// receipt_type claimed: an action intent issued by the gateway, carrying a decision_ref and
// a free-form result, passed every check the SDK had.

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { createReceiptV1, verifyReceiptV1 } from '../src/v2/receipt-core/receipt.js'
import { publicKeyFromPrivate } from '../src/crypto/keys.js'
import { validateReceiptStageV1 } from '../src/v2/receipt-core/stage.js'
import type { ReceiptV1 } from '../src/v2/receipt-core/types.js'

const privateKey = '00'.repeat(32)
const hex = (c: string) => c.repeat(64)
const AGENT = 'did:example:agent'
const BOUNDARY = 'did:example:gateway'
const ISSUED_AT = '2026-07-18T12:00:00.000Z'
const VALID_UNTIL = '2026-07-18T12:00:05.000Z'

/** An override of undefined removes the member, since ReceiptV1 has no null members:
 *  "A member that is not applicable is absent, not null" (draft line 988). The signer is
 *  always the record's own issuer, so every fixture satisfies line 999 before the stage
 *  rules are reached and no test passes for the wrong reason. */
const testPublicKey = publicKeyFromPrivate(privateKey)
const resolveTestKey = (): string => testPublicKey

const sign = (fields: Record<string, unknown>): ReceiptV1 => {
  const body = Object.fromEntries(Object.entries(fields).filter(([, v]) => v !== undefined))
  const signer = body.issuer as string
  return createReceiptV1(body as never, [{ signer, key_id: `${signer}#key-1`, private_key: privateKey }])
}

const intent = (overrides: Record<string, unknown> = {}): ReceiptV1 => sign({
  profile: 'aps-receipt-v1',
  receipt_type: 'aps:action-intent:v1',
  issuer: AGENT,
  subject_agent: AGENT,
  action_ref: hex('a'),
  delegation_ref: `sha256:${hex('b')}`,
  issued_at: ISSUED_AT,
  evidence_refs: [],
  result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
  ...overrides,
})

const decision = (overrides: Record<string, unknown> = {}, resultOverrides: Record<string, unknown> = {}): ReceiptV1 => sign({
  profile: 'aps-receipt-v1',
  receipt_type: 'aps:policy-decision:v1',
  issuer: BOUNDARY,
  subject_agent: AGENT,
  action_ref: hex('a'),
  delegation_ref: `sha256:${hex('b')}`,
  decision_ref: hex('c'),
  prev: hex('d'),
  issued_at: ISSUED_AT,
  evidence_refs: [],
  result: {
    profile: 'aps-core-decision-output-v1',
    verdict: 'permit',
    effective_authority_ref: hex('e'),
    constraints: [],
    valid_until: VALID_UNTIL,
    ...resultOverrides,
  },
  ...overrides,
})

const actionResult = (resultOverrides: Record<string, unknown> = {}, overrides: Record<string, unknown> = {}): ReceiptV1 => sign({
  profile: 'aps-receipt-v1',
  receipt_type: 'aps:action-result:v1',
  issuer: BOUNDARY,
  subject_agent: AGENT,
  action_ref: hex('a'),
  delegation_ref: `sha256:${hex('b')}`,
  decision_ref: hex('c'),
  prev: hex('d'),
  issued_at: ISSUED_AT,
  evidence_refs: [],
  result: { profile: 'aps-action-result-v1', status: 'succeeded', effect_ref: hex('f'), error_code: null, ...resultOverrides },
  ...overrides,
})

test('stage 5.3.1: a conforming action intent is valid and every named rule rejects', () => {
  const control = validateReceiptStageV1(intent())
  assert.equal(control.status, 'valid')
  assert.equal(control.stage, 'action-intent')
  assert.equal(control.boundary_identity, 'not_applicable')
  assert.deepEqual(control.failures, [])

  const gatewayIssued = validateReceiptStageV1(intent({ issuer: BOUNDARY }))
  assert.equal(gatewayIssued.status, 'invalid')
  assert.deepEqual(gatewayIssued.failures.map(f => f.code), ['INTENT_ISSUER_NOT_ACTING_AGENT'])

  assert.deepEqual(validateReceiptStageV1(intent({ prev: hex('d') })).failures.map(f => f.code), ['INTENT_PREV_PRESENT'])
  assert.deepEqual(validateReceiptStageV1(intent({ decision_ref: hex('c') })).failures.map(f => f.code), ['INTENT_DECISION_REF_PRESENT'])
  assert.deepEqual(
    validateReceiptStageV1(intent({ result: { profile: 'aps-action-intent-result-v1', status: 'succeeded' } })).failures.map(f => f.code),
    ['INTENT_RESULT_INVALID'],
  )
  assert.deepEqual(
    validateReceiptStageV1(intent({ result: { profile: 'aps-action-intent-result-v1', status: 'declared', extra: 1 } })).failures.map(f => f.code),
    ['INTENT_RESULT_INVALID'],
  )
  assert.deepEqual(
    validateReceiptStageV1(intent({ result: { status: 'ok' } })).failures.map(f => f.code),
    ['INTENT_RESULT_PROFILE'],
  )
  // The exact shape the #200 integration produced: a gateway-issued intent with a
  // decision_ref and a free-form result. Generic validation still passes it.
  const generic = intent({ issuer: BOUNDARY, decision_ref: hex('c'), result: { status: 'ok' } })
  const staged = validateReceiptStageV1(generic)
  assert.equal(staged.status, 'invalid')
  assert.deepEqual(staged.failures.map(f => f.code).sort(),
    ['INTENT_DECISION_REF_PRESENT', 'INTENT_ISSUER_NOT_ACTING_AGENT', 'INTENT_RESULT_PROFILE'])
})

test('stage 5.3.2: the policy-decision result is closed and its window is checked against its own issued_at', () => {
  const withBoundary = validateReceiptStageV1(decision(), { boundaryIdentity: BOUNDARY })
  assert.equal(withBoundary.status, 'valid')
  assert.equal(withBoundary.boundary_identity, 'verified')

  const deny = validateReceiptStageV1(
    decision({}, { verdict: 'deny', effective_authority_ref: null, valid_until: null }),
    { boundaryIdentity: BOUNDARY },
  )
  assert.equal(deny.status, 'valid', 'a deny decision carries no window and is still valid')

  const stale = validateReceiptStageV1(decision({}, { valid_until: ISSUED_AT }), { boundaryIdentity: BOUNDARY })
  assert.deepEqual(stale.failures.map(f => f.code), ['DECISION_VALID_UNTIL_NOT_AFTER_ISSUED_AT'])

  const noPrev = validateReceiptStageV1(decision({ prev: undefined }), { boundaryIdentity: BOUNDARY })
  assert.deepEqual(noPrev.failures.map(f => f.code), ['DECISION_PREV_MISSING'])
  const noRef = validateReceiptStageV1(decision({ decision_ref: undefined }), { boundaryIdentity: BOUNDARY })
  assert.deepEqual(noRef.failures.map(f => f.code), ['DECISION_REF_MISSING'])

  for (const bad of [
    { verdict: 'approve' },
    { effective_authority_ref: null },
    { valid_until: null },
    { constraints: ['b', 'a'] },
    { constraints: ['a', 'a'] },
    { constraints: ['e\u0301'] }, // decomposed, so not NFC
    { profile: 'aps-core-decision-output-v2' },
  ]) {
    const result = validateReceiptStageV1(decision({}, bad), { boundaryIdentity: BOUNDARY })
    assert.equal(result.status, 'invalid', JSON.stringify(bad))
    assert.deepEqual(result.failures.map(f => f.code), ['DECISION_RESULT_INVALID'], JSON.stringify(bad))
  }
  // The canonical form is accepted, so the rejections above are the rule and not the shape.
  assert.equal(validateReceiptStageV1(decision({}, { constraints: ['a', 'b'] }), { boundaryIdentity: BOUNDARY }).status, 'valid')
})

test('stage 5.3.3: the action-result status decides which members may be null', () => {
  assert.equal(validateReceiptStageV1(actionResult(), { boundaryIdentity: BOUNDARY }).status, 'valid')
  assert.equal(validateReceiptStageV1(actionResult({ status: 'failed', effect_ref: null, error_code: 'E_TIMEOUT' }), { boundaryIdentity: BOUNDARY }).status, 'valid')
  assert.equal(validateReceiptStageV1(actionResult({ status: 'failed', effect_ref: hex('f'), error_code: 'E_TIMEOUT' }), { boundaryIdentity: BOUNDARY }).status, 'valid')
  assert.equal(validateReceiptStageV1(actionResult({ status: 'unknown', effect_ref: null, error_code: null }), { boundaryIdentity: BOUNDARY }).status, 'valid')

  const cases: [Record<string, unknown>, string][] = [
    [{ status: 'succeeded', effect_ref: null }, 'RESULT_EFFECT_REF_REQUIRED'],
    [{ status: 'succeeded', error_code: 'E' }, 'RESULT_ERROR_CODE_PRESENT'],
    [{ status: 'failed', effect_ref: null, error_code: '' }, 'RESULT_ERROR_CODE_REQUIRED'],
    [{ status: 'failed', effect_ref: null, error_code: null }, 'RESULT_ERROR_CODE_REQUIRED'],
    [{ status: 'unknown', effect_ref: hex('f'), error_code: null }, 'RESULT_UNKNOWN_NOT_NULL'],
    [{ status: 'partial', effect_ref: null, error_code: null }, 'RESULT_STATUS'],
    [{ effect_ref: [hex('f')] }, 'RESULT_EFFECT_REF'],
    [{ profile: 'aps-action-result-v2' }, 'RESULT_PROFILE'],
  ]
  for (const [bad, code] of cases) {
    const result = validateReceiptStageV1(actionResult(bad), { boundaryIdentity: BOUNDARY })
    assert.equal(result.status, 'invalid', JSON.stringify(bad))
    assert.deepEqual(result.failures.map(f => f.code), [code], JSON.stringify(bad))
  }
  const missing = validateReceiptStageV1(actionResult({}, { prev: undefined, decision_ref: undefined }), { boundaryIdentity: BOUNDARY })
  assert.deepEqual(missing.failures.map(f => f.code), ['RESULT_PREV_MISSING', 'RESULT_DECISION_REF_MISSING'])
})

test('boundary identity is trust input: absent is indeterminate, wrong is invalid, never valid by default', () => {
  const unsupplied = validateReceiptStageV1(decision())
  assert.equal(unsupplied.status, 'indeterminate')
  assert.equal(unsupplied.boundary_identity, 'not_established')
  assert.deepEqual(unsupplied.failures, [])

  const mismatch = validateReceiptStageV1(decision(), { boundaryIdentity: 'did:example:other-gateway' })
  assert.equal(mismatch.status, 'invalid')
  assert.equal(mismatch.boundary_identity, 'mismatch')
  assert.deepEqual(mismatch.failures.map(f => f.code), ['BOUNDARY_IDENTITY_MISMATCH'])

  assert.equal(validateReceiptStageV1(actionResult()).status, 'indeterminate')
  // The draft states no issuer-equals-subject_agent rule for these two stages and no rule
  // that a result issuer equals the decision issuer. Neither is invented here.
  const selfIssued = decision({ issuer: AGENT, subject_agent: AGENT })
  assert.equal(validateReceiptStageV1(selfIssued, { boundaryIdentity: AGENT }).status, 'valid')
})

test('an unknown receipt_type or envelope profile is unsupported, never valid or invalid', () => {
  const unknownType = validateReceiptStageV1(intent({ receipt_type: 'aps:action:v1', result: { status: 'ok' } }))
  assert.equal(unknownType.status, 'unsupported')
  assert.equal(unknownType.stage, null)
  assert.deepEqual(unknownType.failures.map(f => f.code), ['UNSUPPORTED_RECEIPT_TYPE'])

  const unknownProfile = { ...intent(), profile: 'aps-receipt-v2' } as unknown as ReceiptV1
  const profileResult = validateReceiptStageV1(unknownProfile)
  assert.equal(profileResult.status, 'unsupported')
  assert.deepEqual(profileResult.failures.map(f => f.code), ['UNSUPPORTED_PROFILE'])

  // A malformed envelope is invalid, not unsupported, whatever its receipt_type says.
  const malformed = { ...intent(), issued_at: 'yesterday' } as unknown as ReceiptV1
  assert.equal(validateReceiptStageV1(malformed).status, 'invalid')
  assert.deepEqual(validateReceiptStageV1(malformed).failures.map(f => f.code), ['SCHEMA_INVALID'])
})

test('the caller never selects the stage: a mismatch with receipt_type is itself a failure', () => {
  const receipt = intent()
  assert.equal(validateReceiptStageV1(receipt, { expectedReceiptType: 'aps:action-intent:v1' }).status, 'valid')
  const mismatch = validateReceiptStageV1(receipt, { expectedReceiptType: 'aps:policy-decision:v1' })
  assert.equal(mismatch.status, 'invalid')
  assert.deepEqual(mismatch.failures.map(f => f.code), ['STAGE_MISMATCH'])
})

test('a conforming leap second in a decision window is compared, not silently rejected', () => {
  // isExactUtcMilliseconds accepts a leap second, and Date cannot represent one:
  // Date.parse("...T23:59:60.000Z") is NaN, so any comparison through it answers false
  // and refuses a record the draft allows. The comparison is lexicographic on the fixed
  // width form instead, which is chronological for these strings.
  const leapIssued = '2026-06-30T23:59:59.000Z'
  const leapUntil = '2026-06-30T23:59:60.000Z'
  const ok = validateReceiptStageV1(
    decision({ issued_at: leapIssued }, { valid_until: leapUntil }),
    { boundaryIdentity: BOUNDARY },
  )
  assert.equal(ok.status, 'valid', JSON.stringify(ok.failures))

  // And the ordering still holds in the other direction at the same boundary.
  const reversed = validateReceiptStageV1(
    decision({ issued_at: leapUntil }, { valid_until: leapIssued }),
    { boundaryIdentity: BOUNDARY },
  )
  assert.deepEqual(reversed.failures.map(f => f.code), ['DECISION_VALID_UNTIL_NOT_AFTER_ISSUED_AT'])
})

// --- Only the required signatures decide the state, as ruled ----------------------

test('a signature nobody required cannot move the aggregate state', () => {
  // Signatures sit outside receipt_id by construction (lines 1003-1009), so a third
  // party holding no key material can append a descriptor to a published receipt
  // without changing a digest. Letting that flip a conforming record to invalid put the
  // verification outcome in that party's hands.
  const control = intent()
  const baseline = verifyReceiptV1(control, resolveTestKey)
  assert.equal(baseline.status, 'valid')
  assert.equal(baseline.other_signatures, 'none')

  const appended = structuredClone(control) as unknown as Record<string, unknown>
  ;(appended.signatures as Record<string, unknown>[]).push({
    signer: AGENT, key_id: `${AGENT}#appended`, alg: 'Ed25519', value: '0'.repeat(128),
  })
  ;(appended.signatures as Record<string, unknown>[]).sort((a, b) =>
    String(a.key_id) < String(b.key_id) ? -1 : String(a.key_id) > String(b.key_id) ? 1 : 0)
  // The appended descriptor names the issuer, so it IS required and does decide.
  const sameSigner = verifyReceiptV1(appended as never, resolveTestKey)
  assert.equal(sameSigner.status, 'invalid', 'a second issuer signature is still required')

  // One from another signer is not required, so it is reported and decides nothing.
  const other = structuredClone(control) as unknown as Record<string, unknown>
  ;(other.signatures as Record<string, unknown>[]).push({
    signer: 'did:example:bystander', key_id: 'did:example:bystander#k', alg: 'Ed25519', value: '0'.repeat(128),
  })
  const outsider = verifyReceiptV1(other as never, resolveTestKey)
  assert.equal(outsider.status, 'valid')
  assert.equal(outsider.other_signatures, 'not_all_verified')
  assert.ok(!outsider.errors.includes('signature_invalid'))
  assert.equal(outsider.signature_results.find(r => r.signer === 'did:example:bystander')?.required, false)
  assert.equal(outsider.signature_results.find(r => r.signer === AGENT)?.required, true)
})

test('a verifier can require a signer beyond the issuer, and a missing one is invalid', () => {
  const control = intent()
  const missing = verifyReceiptV1(control, resolveTestKey, {}, { requiredSigners: ['did:example:cosigner'] })
  assert.equal(missing.status, 'invalid')
  assert.ok(missing.errors.includes('required_signature_missing'))
})

// --- Key resolution outcomes kept apart, as ruled, on the receipt surface ----------

test('each key resolution outcome is reported apart from the others', () => {
  const control = intent()
  const cases: [unknown, string, string][] = [
    [{ outcome: 'not_found' }, 'key_not_found', 'indeterminate'],
    [{ outcome: 'ambiguous' }, 'key_ambiguous', 'indeterminate'],
    [{ outcome: 'unreachable' }, 'key_unreachable', 'indeterminate'],
    [{ outcome: 'malformed' }, 'key_material_malformed', 'indeterminate'],
    [{ outcome: 'unsupported_scheme' }, 'key_scheme_unsupported', 'unsupported'],
    [undefined, 'key_unresolved', 'indeterminate'],
  ]
  for (const [answer, reason, status] of cases) {
    const result = verifyReceiptV1(control, (() => answer) as never)
    assert.equal(result.signature_results[0].reason, reason, String(reason))
    assert.equal(result.status, status, String(reason))
    assert.ok(!result.errors.includes('signature_invalid'), 'no signature check ran')
  }
})

test('malformed key material is not a failed signature', () => {
  const control = intent()
  for (const material of ['', 'not-hex', 'ab'.repeat(16), 'ab'.repeat(40)]) {
    const result = verifyReceiptV1(control, () => material)
    assert.equal(result.status, 'indeterminate', material)
    assert.equal(result.signature_results[0].reason, 'key_material_malformed', material)
    assert.ok(!result.errors.includes('signature_invalid'), material)
  }
  // A well-formed key that did not sign this receipt is still a signature failure.
  const wrong = verifyReceiptV1(control, () => 'b'.repeat(64))
  assert.equal(wrong.status, 'invalid')
  assert.ok(wrong.errors.includes('signature_invalid'))
})
