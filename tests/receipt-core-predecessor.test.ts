// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { publicKeyFromPrivate } from '../src/crypto/keys.js'
import { buildDecisionRefV1 } from '../src/v2/receipt-core/decision-ref.js'
import { computeReceiptIdV1, createReceiptV1 } from '../src/v2/receipt-core/receipt.js'
import { verifyReceiptPredecessorV1 } from '../src/v2/receipt-core/predecessor.js'
import { verifyReceiptWithDecisionV1 } from '../src/v2/receipt-core/composite.js'
import type { CoreDecisionOutputV1, ReceiptV1 } from '../src/v2/receipt-core/types.js'

const privateKey = '00'.repeat(32)
const publicKey = publicKeyFromPrivate(privateKey)
const resolveKey = () => publicKey
const hex = (c: string) => c.repeat(64)

const BOUNDARY = 'did:example:issuer'
const AGENT = 'did:example:agent'
const ACTION_REF = hex('a')
const DELEGATION_REF = `sha256:${hex('c')}`
const INTENT_AT = '2026-04-08T11:59:00.000Z'
const DECISION_AT = '2026-04-08T12:00:00.000Z'
const RESULT_AT = '2026-04-08T12:00:01.000Z'

const decisionOutput = (valid_until: string | null, verdict: 'permit' | 'deny' = 'permit'): CoreDecisionOutputV1 => ({
  profile: 'aps-core-decision-output-v1',
  verdict,
  effective_authority_ref: verdict === 'deny' ? null : hex('b'),
  constraints: [],
  valid_until,
})

const decisionEvidence = (opts: { policyId?: string } = {}) => ({
  authority_state: { scope: ['read'], revoked: false },
  policy_input: { id: opts.policyId ?? 'p1', version: '1' },
  decision_context: { tenant: 't1' },
  decision_output: decisionOutput('2026-04-08T12:00:05.000Z'),
})

/** A REAL three-record chain, minted end to end by the SDK. Every digest below comes from
 *  createReceiptV1 and computeReceiptIdV1; none is written by hand, so a test that passes
 *  here passes against bytes the SDK itself produces. */
const mintChain = (opts: { policyId?: string } = {}) => {
  const decision = decisionEvidence(opts)
  const { decision_ref } = buildDecisionRefV1({ action_ref: ACTION_REF, ...decision })

  const intent = createReceiptV1({
    profile: 'aps-receipt-v1', receipt_type: 'aps:action-intent:v1', issuer: AGENT,
    subject_agent: AGENT, action_ref: ACTION_REF, delegation_ref: DELEGATION_REF,
    issued_at: INTENT_AT, evidence_refs: [],
    result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
  } as never, [{ signer: AGENT, key_id: 'k1', private_key: privateKey }])

  const policyDecision = createReceiptV1({
    profile: 'aps-receipt-v1', receipt_type: 'aps:policy-decision:v1', issuer: BOUNDARY,
    subject_agent: AGENT, action_ref: ACTION_REF, delegation_ref: DELEGATION_REF,
    decision_ref, prev: intent.receipt_id, issued_at: DECISION_AT, evidence_refs: [],
    result: decision.decision_output,
  } as never, [{ signer: BOUNDARY, key_id: 'k1', private_key: privateKey }])

  const actionResult = createReceiptV1({
    profile: 'aps-receipt-v1', receipt_type: 'aps:action-result:v1', issuer: BOUNDARY,
    subject_agent: AGENT, action_ref: ACTION_REF, delegation_ref: DELEGATION_REF,
    decision_ref, prev: policyDecision.receipt_id, issued_at: RESULT_AT, evidence_refs: [],
    result: { profile: 'aps-action-result-v1', status: 'succeeded', effect_ref: hex('f'), error_code: null },
  } as never, [{ signer: BOUNDARY, key_id: 'k1', private_key: privateKey }])

  return { decision, decision_ref, intent, policyDecision, actionResult }
}

test('predecessor: the correct policy-decision record binds', () => {
  const { policyDecision, actionResult } = mintChain()
  const result = verifyReceiptPredecessorV1(actionResult, policyDecision)
  assert.equal(result.status, 'valid')
  assert.equal(result.bound, true)
  assert.equal(result.failure, null)
  assert.equal(result.detail, null)
  // The identifier reported is the recomputed one, and for an untampered record it is also
  // the claimed one.
  assert.equal(result.recomputed_predecessor_receipt_id, policyDecision.receipt_id)
  assert.equal(result.recomputed_predecessor_receipt_id, actionResult.prev)
})

test('predecessor: a prev that names the action-intent record does not bind', () => {
  // The chain's own earlier record, so the digest is real and the link is genuinely wrong
  // rather than wrong because the value is nonsense.
  const { decision_ref, intent, policyDecision } = mintChain()
  const namesIntent = createReceiptV1({
    profile: 'aps-receipt-v1', receipt_type: 'aps:action-result:v1', issuer: BOUNDARY,
    subject_agent: AGENT, action_ref: ACTION_REF, delegation_ref: DELEGATION_REF,
    decision_ref, prev: intent.receipt_id, issued_at: RESULT_AT, evidence_refs: [],
    result: { profile: 'aps-action-result-v1', status: 'succeeded', effect_ref: hex('f'), error_code: null },
  } as never, [{ signer: BOUNDARY, key_id: 'k1', private_key: privateKey }])

  assert.notEqual(intent.receipt_id, policyDecision.receipt_id, 'fixture guard: the two records differ')
  const result = verifyReceiptPredecessorV1(namesIntent, policyDecision)
  assert.equal(result.status, 'invalid')
  assert.equal(result.bound, false)
  assert.equal(result.failure, 'predecessor_receipt_id_mismatch')
  assert.equal(result.recomputed_predecessor_receipt_id, policyDecision.receipt_id)
})

test('predecessor: the action-intent record in the predecessor slot is the wrong type', () => {
  // Section 5.3.3 line 1104 names the consumed POLICY DECISION. An action-intent record is
  // refused on its type before any digest is compared, so a chain cannot skip the decision.
  const { decision_ref, intent } = mintChain()
  const namesIntent = createReceiptV1({
    profile: 'aps-receipt-v1', receipt_type: 'aps:action-result:v1', issuer: BOUNDARY,
    subject_agent: AGENT, action_ref: ACTION_REF, delegation_ref: DELEGATION_REF,
    decision_ref, prev: intent.receipt_id, issued_at: RESULT_AT, evidence_refs: [],
    result: { profile: 'aps-action-result-v1', status: 'succeeded', effect_ref: hex('f'), error_code: null },
  } as never, [{ signer: BOUNDARY, key_id: 'k1', private_key: privateKey }])

  // The digest would match: prev really is this record's receipt_id. Only the type refuses
  // it, which is the point of the case.
  assert.equal(computeReceiptIdV1(intent), namesIntent.prev)
  const result = verifyReceiptPredecessorV1(namesIntent, intent)
  assert.equal(result.status, 'invalid')
  assert.equal(result.failure, 'predecessor_not_policy_decision')
  assert.equal(result.recomputed_predecessor_receipt_id, null, 'refused before the recomputation')
})

test('predecessor: a missing predecessor is indeterminate, never valid and never a refusal', () => {
  const { actionResult } = mintChain()
  for (const absent of [undefined, null] as const) {
    const result = verifyReceiptPredecessorV1(actionResult, absent)
    assert.equal(result.status, 'indeterminate')
    assert.equal(result.bound, false)
    assert.equal(result.failure, 'predecessor_not_supplied')
    assert.equal(result.recomputed_predecessor_receipt_id, null)
  }
  // Calling with the argument omitted entirely is the same state.
  assert.equal(verifyReceiptPredecessorV1(actionResult).status, 'indeterminate')
})

test('predecessor: a receipt_id edited to match prev does not bind, the body is recomputed', () => {
  // THE CASE THE RECOMPUTATION EXISTS FOR. receipt_id sits outside its own preimage (lines
  // 1003-1009), so anyone can rewrite the field to whatever prev names without touching a
  // signature or a digest. Reading the claimed field would accept this pair.
  const { intent, policyDecision } = mintChain()
  const { decision_ref } = buildDecisionRefV1({ action_ref: ACTION_REF, ...decisionEvidence() })
  const namesIntent = createReceiptV1({
    profile: 'aps-receipt-v1', receipt_type: 'aps:action-result:v1', issuer: BOUNDARY,
    subject_agent: AGENT, action_ref: ACTION_REF, delegation_ref: DELEGATION_REF,
    decision_ref, prev: intent.receipt_id, issued_at: RESULT_AT, evidence_refs: [],
    result: { profile: 'aps-action-result-v1', status: 'succeeded', effect_ref: hex('f'), error_code: null },
  } as never, [{ signer: BOUNDARY, key_id: 'k1', private_key: privateKey }])

  // Relabel the policy-decision record's identifier to the value prev names. Its body is
  // untouched, so it still recomputes to its real identifier.
  const relabelled: ReceiptV1 = { ...policyDecision, receipt_id: intent.receipt_id }
  assert.equal(relabelled.receipt_id, namesIntent.prev, 'fixture guard: the CLAIMED field matches prev')
  assert.notEqual(computeReceiptIdV1(relabelled), namesIntent.prev, 'fixture guard: the BODY does not')

  const result = verifyReceiptPredecessorV1(namesIntent, relabelled)
  assert.equal(result.status, 'invalid')
  assert.equal(result.failure, 'predecessor_receipt_id_mismatch')
  assert.equal(result.recomputed_predecessor_receipt_id, policyDecision.receipt_id,
    'the reported identifier is the recomputed one, not the claimed one')
})

test('predecessor: a decision_ref that differs from the predecessor does not bind', () => {
  // Section 5.3.3 line 1105: decision_ref MUST equal that decision's decision_ref. The
  // digest link can hold while the two records name different decisions, so the equality is
  // its own check. The second decision is a real one, built from different policy input.
  const { policyDecision } = mintChain()
  const other = buildDecisionRefV1({ action_ref: ACTION_REF, ...decisionEvidence({ policyId: 'p2-other' }) }).decision_ref
  assert.notEqual(other, policyDecision.decision_ref, 'fixture guard: the two decisions differ')

  const disagrees = createReceiptV1({
    profile: 'aps-receipt-v1', receipt_type: 'aps:action-result:v1', issuer: BOUNDARY,
    subject_agent: AGENT, action_ref: ACTION_REF, delegation_ref: DELEGATION_REF,
    decision_ref: other, prev: policyDecision.receipt_id, issued_at: RESULT_AT, evidence_refs: [],
    result: { profile: 'aps-action-result-v1', status: 'succeeded', effect_ref: hex('f'), error_code: null },
  } as never, [{ signer: BOUNDARY, key_id: 'k1', private_key: privateKey }])

  const result = verifyReceiptPredecessorV1(disagrees, policyDecision)
  assert.equal(result.status, 'invalid')
  assert.equal(result.failure, 'decision_ref_mismatch')
  // The prev link itself held, so the recomputation ran and is reported.
  assert.equal(result.recomputed_predecessor_receipt_id, policyDecision.receipt_id)
})

test('predecessor: a record that is not an action-result is not_applicable', () => {
  // Including the policy-decision to action-intent link of section 5.3.2 line 1072, which is
  // out of scope for this primitive. not_applicable is not a pass.
  const { intent, policyDecision, actionResult } = mintChain()
  for (const [subject, name] of [[intent, 'action-intent'], [policyDecision, 'policy-decision']] as const) {
    const result = verifyReceiptPredecessorV1(subject, intent)
    assert.equal(result.status, 'not_applicable', name)
    assert.equal(result.bound, false, `${name}: not_applicable is never a pass`)
    assert.equal(result.failure, null)
  }
  // The policy-decision record's own prev really does name the intent, and this primitive
  // still declines to judge it.
  assert.equal(policyDecision.prev, intent.receipt_id)
  assert.equal(verifyReceiptPredecessorV1(policyDecision, intent).bound, false)
  // A malformed predecessor is refused for an action-result subject, so the type dispatch
  // above is what produced not_applicable rather than a lenient structural check.
  assert.equal(verifyReceiptPredecessorV1(actionResult, { ...policyDecision, issued_at: 'nope' }).failure,
    'predecessor_malformed')
})

test('composite: without the predecessor option, every existing result is unchanged', () => {
  // The frozen table below was produced by running verifyReceiptWithDecisionV1 over the
  // inputs of tests/receipt-core-composite.test.ts on the commit BEFORE the predecessor
  // option existed. Each entry is that recorded answer. If adding the option moved any
  // existing caller's valid, status, errors or per-axis flags, one of these fails.
  const ISSUED_AT = '2026-04-08T12:00:00.000Z'
  const compositeOutput = (valid_until: string | null, verdict: 'permit' | 'deny' = 'permit'): CoreDecisionOutputV1 => ({
    profile: 'aps-core-decision-output-v1', verdict,
    effective_authority_ref: verdict === 'deny' ? null : hex('b'), constraints: [], valid_until,
  })
  const evidence = (valid_until: string | null, opts: { policyId?: string; verdict?: 'permit' | 'deny' } = {}) => ({
    authority_state: { scope: ['read'], revoked: false },
    policy_input: { id: opts.policyId ?? 'p1', version: '1' },
    decision_context: { tenant: 't1' },
    decision_output: compositeOutput(valid_until, opts.verdict ?? 'permit'),
  })
  const receiptFor = (d: ReturnType<typeof evidence>, withDecisionRef = true) => {
    const { decision_ref } = buildDecisionRefV1({ action_ref: ACTION_REF, ...d })
    return createReceiptV1({
      profile: 'aps-receipt-v1', receipt_type: 'aps:policy-decision:v1', issuer: BOUNDARY,
      subject_agent: AGENT, action_ref: ACTION_REF, delegation_ref: DELEGATION_REF,
      ...(withDecisionRef ? { decision_ref } : {}), prev: hex('d'), issued_at: ISSUED_AT,
      evidence_refs: [], result: d.decision_output,
    } as never, [{ signer: BOUNDARY, key_id: 'k1', private_key: privateKey }])
  }
  const actionResultFor = (d: ReturnType<typeof evidence>, issuedAt: string) => {
    const { decision_ref } = buildDecisionRefV1({ action_ref: ACTION_REF, ...d })
    return createReceiptV1({
      profile: 'aps-receipt-v1', receipt_type: 'aps:action-result:v1', issuer: BOUNDARY,
      subject_agent: AGENT, action_ref: ACTION_REF, delegation_ref: DELEGATION_REF,
      decision_ref, prev: hex('d'), issued_at: issuedAt, evidence_refs: [],
      result: { profile: 'aps-action-result-v1', status: 'succeeded', effect_ref: hex('f'), error_code: null },
    } as never, [{ signer: BOUNDARY, key_id: 'k1', private_key: privateKey }])
  }

  const OLD_KEYS = ['valid', 'status', 'receipt', 'stage', 'decision_ref_present',
    'decision_ref_bound', 'decision_output_bound', 'temporal_relation_valid', 'errors']

  type Frozen = {
    valid: boolean; status: string; decision_ref_present: boolean; decision_ref_bound: boolean
    decision_output_bound: boolean | 'not_applicable'
    temporal_relation_valid: boolean | 'not_applicable'
    errors: string[]; receipt_status: string; stage_status: string
  }
  const check = (name: string, actual: ReturnType<typeof verifyReceiptWithDecisionV1>, expected: Frozen) => {
    assert.deepEqual(Object.keys(actual), [...OLD_KEYS.slice(0, 8), 'predecessor_bound', 'errors'],
      `${name}: the key set grew by predecessor_bound and nothing else`)
    assert.equal(actual.predecessor_bound, 'not_checked', `${name}: unrequested axis is not_checked`)
    const { predecessor_bound, receipt, stage, ...rest } = actual
    assert.deepEqual({ ...rest, receipt_status: receipt.status, stage_status: stage.status }, expected, name)
  }

  const permit = evidence('2026-04-08T12:00:05.000Z')
  check('permit_bound', verifyReceiptWithDecisionV1(receiptFor(permit), permit, resolveKey, { boundaryIdentity: BOUNDARY }), {
    valid: true, status: 'valid', decision_ref_present: true, decision_ref_bound: true,
    decision_output_bound: true, temporal_relation_valid: true, errors: [],
    receipt_status: 'valid', stage_status: 'valid',
  })

  const equal = evidence(ISSUED_AT)
  check('valid_until_equal', verifyReceiptWithDecisionV1(receiptFor(equal), equal, resolveKey, { boundaryIdentity: BOUNDARY }), {
    valid: false, status: 'invalid', decision_ref_present: false, decision_ref_bound: false,
    decision_output_bound: 'not_applicable', temporal_relation_valid: false,
    errors: ['receipt_invalid', 'stage_invalid', 'DECISION_VALID_UNTIL_NOT_AFTER_ISSUED_AT'],
    receipt_status: 'invalid', stage_status: 'invalid',
  })

  const earlier = evidence('2026-04-08T11:59:59.999Z')
  check('valid_until_earlier', verifyReceiptWithDecisionV1(receiptFor(earlier), earlier, resolveKey, { boundaryIdentity: BOUNDARY }), {
    valid: false, status: 'invalid', decision_ref_present: false, decision_ref_bound: false,
    decision_output_bound: 'not_applicable', temporal_relation_valid: false,
    errors: ['receipt_invalid', 'stage_invalid', 'DECISION_VALID_UNTIL_NOT_AFTER_ISSUED_AT'],
    receipt_status: 'invalid', stage_status: 'invalid',
  })

  const committed = evidence('2026-04-08T12:00:05.000Z', { policyId: 'p1' })
  const substituted = evidence('2026-04-08T23:00:00.000Z', { policyId: 'p2-attacker' })
  check('substitution', verifyReceiptWithDecisionV1(receiptFor(committed), substituted, resolveKey, { boundaryIdentity: BOUNDARY }), {
    valid: false, status: 'invalid', decision_ref_present: true, decision_ref_bound: false,
    decision_output_bound: 'not_applicable', temporal_relation_valid: false,
    errors: ['decision_ref_mismatch'], receipt_status: 'valid', stage_status: 'valid',
  })

  check('no_decision_ref', verifyReceiptWithDecisionV1(receiptFor(permit, false), permit, resolveKey, { boundaryIdentity: BOUNDARY }), {
    valid: false, status: 'invalid', decision_ref_present: false, decision_ref_bound: false,
    decision_output_bound: 'not_applicable', temporal_relation_valid: false,
    errors: ['receipt_invalid', 'stage_invalid', 'DECISION_REF_MISSING'],
    receipt_status: 'invalid', stage_status: 'invalid',
  })

  const deny = evidence(null, { verdict: 'deny' })
  check('deny', verifyReceiptWithDecisionV1(receiptFor(deny), deny, resolveKey, { boundaryIdentity: BOUNDARY }), {
    valid: true, status: 'valid', decision_ref_present: true, decision_ref_bound: true,
    decision_output_bound: true, temporal_relation_valid: true, errors: [],
    receipt_status: 'valid', stage_status: 'valid',
  })

  const tampered = { ...receiptFor(permit), result: { status: 'tampered' } } as ReceiptV1
  check('tampered', verifyReceiptWithDecisionV1(tampered, permit, resolveKey, { boundaryIdentity: BOUNDARY }), {
    valid: false, status: 'invalid', decision_ref_present: false, decision_ref_bound: false,
    decision_output_bound: 'not_applicable', temporal_relation_valid: false,
    errors: ['receipt_invalid', 'receipt_id_mismatch', 'signature_invalid', 'stage_invalid', 'DECISION_RESULT_INVALID'],
    receipt_status: 'invalid', stage_status: 'invalid',
  })

  check('unresolvable_key', verifyReceiptWithDecisionV1(receiptFor(permit), permit, () => undefined, { boundaryIdentity: BOUNDARY }), {
    valid: false, status: 'indeterminate', decision_ref_present: false, decision_ref_bound: false,
    decision_output_bound: 'not_applicable', temporal_relation_valid: false,
    errors: ['receipt_indeterminate', 'signer_authority_indeterminate'],
    receipt_status: 'indeterminate', stage_status: 'valid',
  })

  check('no_boundary', verifyReceiptWithDecisionV1(receiptFor(permit), permit, resolveKey), {
    valid: false, status: 'indeterminate', decision_ref_present: false, decision_ref_bound: false,
    decision_output_bound: 'not_applicable', temporal_relation_valid: false,
    errors: ['receipt_indeterminate', 'stage_indeterminate'],
    receipt_status: 'indeterminate', stage_status: 'indeterminate',
  })

  check('action_result', verifyReceiptWithDecisionV1(actionResultFor(permit, '2099-01-01T00:00:00.000Z'), permit, resolveKey, { boundaryIdentity: BOUNDARY }), {
    valid: true, status: 'valid', decision_ref_present: true, decision_ref_bound: true,
    decision_output_bound: 'not_applicable', temporal_relation_valid: 'not_applicable',
    errors: [], receipt_status: 'valid', stage_status: 'valid',
  })

  const nonCanonical = { ...permit, decision_output: { ...permit.decision_output, constraints: ['b', 'a', 'a'] } }
  const nonCanonicalResult = verifyReceiptWithDecisionV1(actionResultFor(permit, ISSUED_AT), nonCanonical as never, resolveKey, { boundaryIdentity: BOUNDARY })
  assert.deepEqual(Object.keys(nonCanonicalResult), [...OLD_KEYS.slice(0, 8), 'predecessor_bound', 'errors'])
  assert.equal(nonCanonicalResult.predecessor_bound, 'not_checked')
  assert.equal(nonCanonicalResult.valid, false)
  assert.equal(nonCanonicalResult.status, 'invalid')
  assert.equal(nonCanonicalResult.decision_ref_present, true)
  assert.equal(nonCanonicalResult.decision_ref_bound, false)
  assert.equal(nonCanonicalResult.errors[0], 'decision_input_invalid')
})

test('composite: a wrong predecessor makes the composite invalid, the right one makes it valid', () => {
  const { decision, intent, policyDecision, actionResult } = mintChain()
  const options = { boundaryIdentity: BOUNDARY }

  // Control: the same call with no predecessor option is valid and reports not_checked.
  const unchecked = verifyReceiptWithDecisionV1(actionResult, decision, resolveKey, options)
  assert.equal(unchecked.valid, true)
  assert.equal(unchecked.predecessor_bound, 'not_checked')

  // The correct predecessor: the only field that moves is the new one.
  const bound = verifyReceiptWithDecisionV1(actionResult, decision, resolveKey, { ...options, predecessor: policyDecision })
  assert.equal(bound.valid, true)
  assert.equal(bound.status, 'valid')
  assert.equal(bound.predecessor_bound, true)
  assert.deepEqual({ ...bound, predecessor_bound: 'not_checked' as const }, unchecked,
    'supplying a predecessor that binds changes nothing but the predecessor axis')

  // The wrong predecessor: the composite is invalid and names its own code.
  const wrong = verifyReceiptWithDecisionV1(actionResult, decision, resolveKey, { ...options, predecessor: intent })
  assert.equal(wrong.valid, false)
  assert.equal(wrong.status, 'invalid')
  assert.equal(wrong.predecessor_bound, false)
  assert.ok(wrong.errors.includes('predecessor_not_bound'))
  assert.ok(wrong.errors.includes('predecessor_not_policy_decision'))
  // The earlier binding axes still report what they established before this one ran.
  assert.equal(wrong.decision_ref_present, true)
  assert.equal(wrong.decision_ref_bound, true)

  // A predecessor supplied for a policy-decision record: the axis does not apply, and that
  // does not make the composite fail.
  const notApplicable = verifyReceiptWithDecisionV1(policyDecision, decision, resolveKey, { ...options, predecessor: intent })
  assert.equal(notApplicable.valid, true)
  assert.equal(notApplicable.predecessor_bound, 'not_applicable')

  // An explicitly null predecessor is the same as supplying none.
  const explicitNull = verifyReceiptWithDecisionV1(actionResult, decision, resolveKey, { ...options, predecessor: null })
  assert.deepEqual(explicitNull, unchecked)
})
