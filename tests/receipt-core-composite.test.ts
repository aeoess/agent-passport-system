// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { publicKeyFromPrivate } from '../src/crypto/keys.js'
import { buildDecisionRefV1 } from '../src/v2/receipt-core/decision-ref.js'
import { createReceiptV1 } from '../src/v2/receipt-core/receipt.js'
import { verifyReceiptWithDecisionV1 } from '../src/v2/receipt-core/composite.js'
import type { CoreDecisionOutputV1 } from '../src/v2/receipt-core/types.js'

const privateKey = '00'.repeat(32)
const publicKey = publicKeyFromPrivate(privateKey)
const resolveKey = () => publicKey
const hex = (c: string) => c.repeat(64)

const ISSUED_AT = '2026-04-08T12:00:00.000Z'

const decisionOutput = (valid_until: string | null, verdict: 'permit' | 'deny' = 'permit'): CoreDecisionOutputV1 => ({
  profile: 'aps-core-decision-output-v1',
  verdict,
  effective_authority_ref: verdict === 'deny' ? null : hex('b'),
  constraints: [],
  valid_until,
})

/** The decision a receipt will reference. Any component change alters decision_ref. */
const decisionEvidence = (valid_until: string | null, opts: { policyId?: string; verdict?: 'permit' | 'deny' } = {}) => ({
  authority_state: { scope: ['read'], revoked: false },
  policy_input: { id: opts.policyId ?? 'p1', version: '1' },
  decision_context: { tenant: 't1' },
  decision_output: decisionOutput(valid_until, opts.verdict ?? 'permit'),
})

/** A signed receipt carrying the decision_ref for the supplied decision. */
const receiptFor = (decision: ReturnType<typeof decisionEvidence>, withDecisionRef = true) => {
  const { decision_ref } = buildDecisionRefV1({ action_ref: hex('a'), ...decision })
  return createReceiptV1({
    profile: 'aps-receipt-v1',
    receipt_type: 'aps:action:v1',
    issuer: 'did:example:issuer',
    subject_agent: 'did:example:agent',
    action_ref: hex('a'),
    delegation_ref: hex('c'),
    ...(withDecisionRef ? { decision_ref } : {}),
    issued_at: ISSUED_AT,
    evidence_refs: [],
    result: { status: 'ok' },
  }, [{ signer: 'did:example:issuer', key_id: 'k1', private_key: privateKey }])
}

test('composite: positive case, bound decision with a later valid_until', () => {
  const decision = decisionEvidence('2026-04-08T12:00:05.000Z')
  const result = verifyReceiptWithDecisionV1(receiptFor(decision), decision, resolveKey)
  assert.equal(result.valid, true)
  assert.deepEqual(result.errors, [])
  assert.equal(result.receipt.valid, true)
  assert.equal(result.decision_ref_present, true)
  assert.equal(result.decision_ref_bound, true)
  assert.equal(result.temporal_relation_valid, true)
})

test('composite: temporal negative, valid_until EQUAL to issued_at rejects', () => {
  // Strictly later is required, so the boundary value must fail.
  const decision = decisionEvidence(ISSUED_AT)
  const result = verifyReceiptWithDecisionV1(receiptFor(decision), decision, resolveKey)
  assert.equal(result.valid, false)
  assert.ok(result.errors.includes('valid_until_not_after_issued_at'))
  // The pair was correctly bound, so the failure is unambiguously temporal.
  assert.equal(result.decision_ref_bound, true)
  assert.equal(result.temporal_relation_valid, false)
})

test('composite: temporal negative, valid_until EARLIER than issued_at rejects', () => {
  const decision = decisionEvidence('2026-04-08T11:59:59.999Z')
  const result = verifyReceiptWithDecisionV1(receiptFor(decision), decision, resolveKey)
  assert.equal(result.valid, false)
  assert.ok(result.errors.includes('valid_until_not_after_issued_at'))
  assert.equal(result.decision_ref_bound, true)
})

test('composite: SUBSTITUTION negative, a valid decision with a good temporal relation but the wrong digest rejects', () => {
  // The receipt commits to decision A. Decision B is fully valid on its own and
  // its valid_until is comfortably later than issued_at, so every check except
  // the binding would pass. This is the substitution hole: without binding, B
  // would be accepted as evidence about a receipt that never referenced it.
  const committed = decisionEvidence('2026-04-08T12:00:05.000Z', { policyId: 'p1' })
  const substituted = decisionEvidence('2026-04-08T23:00:00.000Z', { policyId: 'p2-attacker' })
  const receipt = receiptFor(committed)

  // Guard the fixture: the two decisions really do have different digests, and
  // the substituted one really would pass the temporal check on its own.
  const refA = buildDecisionRefV1({ action_ref: hex('a'), ...committed }).decision_ref
  const refB = buildDecisionRefV1({ action_ref: hex('a'), ...substituted }).decision_ref
  assert.notEqual(refA, refB)
  assert.equal(receipt.decision_ref, refA)
  assert.ok(Date.parse(substituted.decision_output.valid_until as string) > Date.parse(ISSUED_AT))

  const result = verifyReceiptWithDecisionV1(receipt, substituted, resolveKey)
  assert.equal(result.valid, false)
  assert.ok(result.errors.includes('decision_ref_mismatch'))
  // The temporal stage must not have run: an ordering result over an unbound
  // pair says nothing about this receipt.
  assert.equal(result.temporal_relation_valid, false)
  assert.ok(!result.errors.includes('valid_until_not_after_issued_at'))
})

test('composite: absent decision_ref rejects rather than passing', () => {
  const decision = decisionEvidence('2026-04-08T12:00:05.000Z')
  const receipt = receiptFor(decision, false)
  assert.equal(receipt.decision_ref, undefined)
  const result = verifyReceiptWithDecisionV1(receipt, decision, resolveKey)
  assert.equal(result.valid, false)
  assert.ok(result.errors.includes('decision_ref_absent'))
  assert.equal(result.decision_ref_present, false)
  assert.equal(result.decision_ref_bound, false)
})

test('composite: a deny decision carries no window, named distinctly from the ordering failure', () => {
  const decision = decisionEvidence(null, { verdict: 'deny' })
  const result = verifyReceiptWithDecisionV1(receiptFor(decision), decision, resolveKey)
  assert.equal(result.valid, false)
  assert.ok(result.errors.includes('valid_until_absent'))
  assert.ok(!result.errors.includes('valid_until_not_after_issued_at'))
  assert.equal(result.decision_ref_bound, true)
})

test('composite: an unverifiable receipt fails at stage one and later stages do not run', () => {
  const decision = decisionEvidence('2026-04-08T12:00:05.000Z')
  const receipt = receiptFor(decision)
  const tampered = { ...receipt, result: { status: 'tampered' } }
  const result = verifyReceiptWithDecisionV1(tampered, decision, resolveKey)
  assert.equal(result.valid, false)
  assert.ok(result.errors.includes('receipt_invalid'))
  assert.equal(result.decision_ref_present, false)
  assert.equal(result.decision_ref_bound, false)
  assert.equal(result.temporal_relation_valid, false)
})
