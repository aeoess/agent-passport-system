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

const BOUNDARY = 'did:example:issuer'

/** A signed policy-decision receipt carrying the decision_ref for the supplied decision,
 *  and, as section 5.4 lines 1183-1184 require, that decision's own output as its result.
 *  These fixtures used receipt_type "aps:action:v1" with a free-form result, which names no
 *  stage in section 5.3, so the composite verifier was exercised only on a shape the draft
 *  does not define. */
const receiptFor = (decision: ReturnType<typeof decisionEvidence>, withDecisionRef = true) => {
  const { decision_ref } = buildDecisionRefV1({ action_ref: hex('a'), ...decision })
  return createReceiptV1({
    profile: 'aps-receipt-v1',
    receipt_type: 'aps:policy-decision:v1',
    issuer: BOUNDARY,
    subject_agent: 'did:example:agent',
    action_ref: hex('a'),
    delegation_ref: `sha256:${hex('c')}`,
    ...(withDecisionRef ? { decision_ref } : {}),
    prev: hex('d'),
    issued_at: ISSUED_AT,
    evidence_refs: [],
    result: decision.decision_output,
  }, [{ signer: BOUNDARY, key_id: 'k1', private_key: privateKey }])
}

/** The boundary identity is verifier trust input, so every call that expects a decided
 *  answer supplies it; the axis has its own test below. */
const verify = (receipt: Parameters<typeof verifyReceiptWithDecisionV1>[0], decision: ReturnType<typeof decisionEvidence>) =>
  verifyReceiptWithDecisionV1(receipt, decision, resolveKey, { boundaryIdentity: BOUNDARY })

test('composite: positive case, bound decision with a later valid_until', () => {
  const decision = decisionEvidence('2026-04-08T12:00:05.000Z')
  const result = verify(receiptFor(decision), decision)
  assert.equal(result.valid, true)
  assert.deepEqual(result.errors, [])
  assert.equal(result.receipt.valid, true)
  assert.equal(result.decision_ref_present, true)
  assert.equal(result.decision_ref_bound, true)
  assert.equal(result.temporal_relation_valid, true)
})

test('composite: temporal negative, valid_until EQUAL to issued_at rejects', () => {
  // Strictly later is required, so the boundary value must fail. The window now lives in
  // the receipt's own result, so the record fails its section 5.3.2 stage rule and the
  // composite reports that rather than reaching the cross-document comparison. Either way
  // the pair is refused, and the stage failure names the record that carries the defect.
  const decision = decisionEvidence(ISSUED_AT)
  const result = verify(receiptFor(decision), decision)
  assert.equal(result.valid, false)
  assert.equal(result.status, 'invalid')
  assert.ok(result.errors.includes('stage_invalid'))
  assert.ok(result.errors.includes('DECISION_VALID_UNTIL_NOT_AFTER_ISSUED_AT'))
  assert.ok(!result.errors.includes('stage_indeterminate'))
  assert.equal(result.temporal_relation_valid, false)
})

test('composite: temporal negative, valid_until EARLIER than issued_at rejects', () => {
  const decision = decisionEvidence('2026-04-08T11:59:59.999Z')
  const result = verify(receiptFor(decision), decision)
  assert.equal(result.valid, false)
  assert.ok(result.errors.includes('DECISION_VALID_UNTIL_NOT_AFTER_ISSUED_AT'))
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

  const result = verify(receipt, substituted)
  assert.equal(result.valid, false)
  assert.ok(result.errors.includes('decision_ref_mismatch'))
  // The temporal stage must not have run: an ordering result over an unbound
  // pair says nothing about this receipt.
  assert.equal(result.temporal_relation_valid, false)
  assert.ok(!result.errors.includes('valid_until_not_after_issued_at'))
})

test('composite: absent decision_ref rejects rather than passing', () => {
  // A policy-decision record without decision_ref breaks its own stage rule (line 984), so
  // that is what the composite reports. It is refused either way; the code names the
  // record's defect rather than the missing relation.
  const decision = decisionEvidence('2026-04-08T12:00:05.000Z')
  const receipt = receiptFor(decision, false)
  assert.equal(receipt.decision_ref, undefined)
  const result = verify(receipt, decision)
  assert.equal(result.valid, false)
  assert.ok(result.errors.includes('DECISION_REF_MISSING'))
  assert.equal(result.decision_ref_present, false)
  assert.equal(result.decision_ref_bound, false)

  // For a stage where decision_ref is absent by rule, passing a decision is still an error
  // rather than a silent pass: the relation was never examined.
  const intent = createReceiptV1({
    profile: 'aps-receipt-v1', receipt_type: 'aps:action-intent:v1', issuer: 'did:example:agent',
    subject_agent: 'did:example:agent', action_ref: hex('a'), delegation_ref: `sha256:${hex('c')}`,
    issued_at: ISSUED_AT, evidence_refs: [],
    result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
  } as never, [{ signer: 'did:example:agent', key_id: 'k1', private_key: privateKey }])
  const intentResult = verify(intent, decision)
  assert.equal(intentResult.valid, false)
  assert.ok(intentResult.errors.includes('decision_ref_absent'))
})

test('composite: a correct deny decision verifies, it is not a temporal failure', () => {
  // Draft line 1090 requires valid_until to be null for deny. Treating that absence as a
  // failure made every conforming deny decision fail this verifier, which is the opposite
  // of what the rule says.
  const decision = decisionEvidence(null, { verdict: 'deny' })
  const result = verify(receiptFor(decision), decision)
  assert.equal(result.valid, true)
  assert.equal(result.status, 'valid')
  assert.deepEqual(result.errors, [])
  assert.equal(result.decision_ref_bound, true)
  assert.equal(result.decision_output_bound, true)
  assert.equal(result.temporal_relation_valid, true)
})

test('composite: the decision output must be the result the receipt carries and signs', () => {
  // The digest binding alone did not establish this. decision_ref commits to a digest of
  // the output; nothing compared that output with receipt.result, so a decision object
  // whose output differed from the signed result could still bind.
  const decision = decisionEvidence('2026-04-08T12:00:05.000Z')
  const receipt = receiptFor(decision)
  const swapped = { ...receipt, result: { ...decision.decision_output, verdict: 'narrow' as const } }
  const result = verify(swapped, decision)
  assert.equal(result.valid, false)
  // The swap changes the signed body, so integrity fails first; the point of the case is
  // that a caller cannot reach a valid composite with a result that is not the output.
  assert.ok(result.errors.includes('receipt_invalid') || result.errors.includes('decision_output_mismatch'))

  // And the same check with the signature kept intact, by re-signing the swapped body.
  const reSigned = createReceiptV1({
    profile: 'aps-receipt-v1', receipt_type: 'aps:policy-decision:v1', issuer: BOUNDARY,
    subject_agent: 'did:example:agent', action_ref: hex('a'), delegation_ref: `sha256:${hex('c')}`,
    decision_ref: receipt.decision_ref, prev: hex('d'), issued_at: ISSUED_AT, evidence_refs: [],
    result: { ...decision.decision_output, verdict: 'narrow' as const },
  } as never, [{ signer: BOUNDARY, key_id: 'k1', private_key: privateKey }])
  const reSignedResult = verify(reSigned, decision)
  assert.equal(reSignedResult.valid, false)
  assert.equal(reSignedResult.decision_ref_bound, true)
  assert.equal(reSignedResult.decision_output_bound, false)
  assert.ok(reSignedResult.errors.includes('decision_output_mismatch'))
})

test('composite: an unresolvable signing key is indeterminate, not a failed signature', () => {
  const decision = decisionEvidence('2026-04-08T12:00:05.000Z')
  const result = verifyReceiptWithDecisionV1(receiptFor(decision), decision, () => undefined, { boundaryIdentity: BOUNDARY })
  assert.equal(result.valid, false)
  assert.equal(result.status, 'indeterminate')
  assert.equal(result.receipt.signer_authority, 'not_established')
  assert.ok(result.errors.includes('signer_authority_indeterminate'))
  assert.ok(!result.errors.includes('signature_invalid'))
  // The sub-result code names the status it reports, so a caller reading the codes is
  // not told the receipt was invalid when an axis was merely unestablished.
  assert.ok(result.errors.includes('receipt_indeterminate'))
  assert.ok(!result.errors.includes('receipt_invalid'))
})

test('composite: with no boundary identity supplied the composite is indeterminate', () => {
  const decision = decisionEvidence('2026-04-08T12:00:05.000Z')
  const result = verifyReceiptWithDecisionV1(receiptFor(decision), decision, resolveKey)
  assert.equal(result.valid, false)
  assert.equal(result.status, 'indeterminate')
  assert.equal(result.stage.boundary_identity, 'not_established')
  assert.ok(result.errors.includes('stage_indeterminate'))
  assert.ok(!result.errors.includes('stage_invalid'))
  assert.deepEqual(result.stage.failures, [], 'indeterminate here is an unestablished axis, not a failed rule')
})

test('composite: an unverifiable receipt fails at stage one and later stages do not run', () => {
  const decision = decisionEvidence('2026-04-08T12:00:05.000Z')
  const receipt = receiptFor(decision)
  const tampered = { ...receipt, result: { status: 'tampered' } }
  const result = verify(tampered, decision)
  assert.equal(result.valid, false)
  assert.ok(result.errors.includes('receipt_invalid'))
  assert.equal(result.decision_ref_present, false)
  assert.equal(result.decision_ref_bound, false)
  assert.equal(result.temporal_relation_valid, false)
})
