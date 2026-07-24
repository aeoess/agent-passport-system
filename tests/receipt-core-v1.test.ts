// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { publicKeyFromPrivate } from '../src/crypto/keys.js'
import { buildDecisionRefV1, computeDecisionComponentRefV1, normalizeCoreDecisionOutputV1 } from '../src/v2/receipt-core/decision-ref.js'
import { createReceiptV1, computeReceiptIdV1, verifyReceiptV1 } from '../src/v2/receipt-core/receipt.js'
import { parseStrictIJson, strictJCS } from '../src/v2/receipt-core/jcs.js'
import { buildEvidenceBundleBodyV2, buildEvidenceBundleProofV2, classifySupportingRecordFormat, createSupportingRecordV1, verifyEvidenceBundleBodyV2, verifyEvidenceBundleProofV2, verifySupportingRecordV1 } from '../src/v2/receipt-core/supporting-record.js'

const privateKey = '00'.repeat(32)
const publicKey = publicKeyFromPrivate(privateKey)
const hex = (c: string) => c.repeat(64)
const KAT = {
  decision_ref: '2157809a9a722314ae19dce7a242ea3b54a8948230fab2fab5d5dc15bd663dc2',
  receipt_id: '89b0b77807e99845aab403f01bcdaa2f02949f6c9db84e1aca6c0a8449e4d023',
  receipt_sig: '83deb713568bbdf0c85e1a6d46345530e84dbe86cdefe1cb608b0f14372c176a9e69e0033db11c4c44ff84be3de3bee5e212707eb84206f6c34455206d37f90b',
  merkle_root: '03700eeba1b453086063612d3df73f711827735c3fe30cf8a8a2a6379a6f6d5f',
  record_id: '7d73684a65444088e841f2b30f0ecf139fbadbeab277d57d20d1a2ef5fe2a7b2',
  record_sig: '56a2116eb4e259a336c36a646e69322cf2e7850b7202f2093c5957e4e6a100cf4cae8048cb4647bbc557447bea531dd7e69c117e9298515cc767110cf0f7d809',
  proof_root: 'dab9f2f5f3571345327f0144f2eafbb6e835ac5cbb48e9d789224e135ce16247',
  proof_left: 'f3bdfcf031dea9da3129ae67bdf7f69caefc41660541d0acb015e1b49ae95470',
}

test('decision_ref is content-derived and event fields cannot enter it', () => {
  const a = buildDecisionRefV1({
    action_ref: hex('a'),
    authority_state: { scope: ['read'], revoked: false },
    policy_input: { id: 'p1', version: '1' },
    decision_context: { tenant: 't1' },
    decision_output: { verdict: 'permit', constraints: [] },
  })
  assert.equal(a.decision_ref, KAT.decision_ref)
  const b = buildDecisionRefV1({
    action_ref: hex('a'), authority_state: { revoked: false, scope: ['read'] },
    policy_input: { version: '1', id: 'p1' }, decision_context: { tenant: 't1' },
    decision_output: { constraints: [], verdict: 'permit' },
  })
  assert.equal(a.decision_ref, b.decision_ref)
  assert.notEqual(a.decision_ref, buildDecisionRefV1({
    action_ref: hex('a'), authority_state: { scope: ['write'], revoked: false },
    policy_input: { id: 'p1', version: '1' }, decision_context: { tenant: 't1' },
    decision_output: { verdict: 'permit', constraints: [] },
  }).decision_ref)
})

test('core decision output normalizes a set of constraints', () => {
  const out = normalizeCoreDecisionOutputV1({ profile: 'aps-core-decision-output-v1', verdict: 'narrow', effective_authority_ref: hex('b'), constraints: ['é', 'read', 'e\u0301', 'read'], valid_until: '2026-04-08T12:00:05.000Z' })
  assert.deepEqual(out.constraints, ['read', 'é'])
})

test('receipt binds id, signer descriptor, and signed content', () => {
  const receipt = createReceiptV1({
    profile: 'aps-receipt-v1', receipt_type: 'aps:action:v1', issuer: 'did:example:issuer',
    subject_agent: 'did:example:agent', action_ref: hex('a'), delegation_ref: hex('b'),
    decision_ref: hex('c'), issued_at: '2026-07-18T12:00:00.000Z',
    evidence_refs: [{ artifact_type: 'z', sha256: hex('e') }, { artifact_type: 'a', sha256: hex('d') }],
    result: { status: 'success', detail: null },
  }, [{ signer: 'did:example:issuer', key_id: 'key-1', private_key: privateKey }])
  assert.equal(receipt.receipt_id, computeReceiptIdV1(receipt))
  assert.equal(receipt.receipt_id, KAT.receipt_id)
  assert.equal(receipt.signatures[0].value, KAT.receipt_sig)
  assert.equal(verifyReceiptV1(receipt, () => publicKey).valid, true)
  assert.deepEqual(receipt.evidence_refs.map(e => e.artifact_type), ['a', 'z'])
  const relabeled = structuredClone(receipt)
  relabeled.signatures[0].key_id = 'key-2'
  assert.equal(verifyReceiptV1(relabeled, () => publicKey).valid, false)
  const tampered = structuredClone(receipt)
  tampered.result.status = 'failure'
  assert.equal(verifyReceiptV1(tampered, () => publicKey).valid, false)
})

test('supporting record and evidence bundle v2 bind type, member id, type, and payload', () => {
  const payloads = { m1: { value: null }, m2: { value: 2 } }
  const bundle = buildEvidenceBundleBodyV2([
    { member_id: 'm2', member_type: 'two', payload: payloads.m2 },
    { member_id: 'm1', member_type: 'one', payload: payloads.m1 },
  ])
  assert.equal(bundle.merkle_root, KAT.merkle_root)
  assert.equal(verifyEvidenceBundleBodyV2(bundle, payloads), true)
  const record = createSupportingRecordV1({
    profile: 'aps-supporting-record-v1', record_type: 'aps:evidence-bundle:v2',
    issuer: 'did:example:issuer', issuer_key_id: 'key-1', issued_at: '2026-07-18T12:00:00.000Z',
    body: bundle, sig_alg: 'Ed25519',
  }, privateKey)
  assert.equal(record.record_id, KAT.record_id)
  assert.equal(record.sig, KAT.record_sig)
  assert.equal(verifySupportingRecordV1(record, publicKey).valid, true)
  const relabeled = { ...record, record_type: 'aps:accountability:v1' }
  assert.equal(verifySupportingRecordV1(relabeled, publicKey).valid, false)
  const changed = structuredClone(bundle)
  changed.members[0].member_type = 'changed'
  assert.equal(verifyEvidenceBundleBodyV2(changed, payloads), false)

  const three = buildEvidenceBundleBodyV2([
    { member_id: 'm3', member_type: 'three', payload: { value: 3 } },
    { member_id: 'm1', member_type: 'one', payload: { value: 1 } },
    { member_id: 'm2', member_type: 'two', payload: { value: 2 } },
  ])
  const proof = buildEvidenceBundleProofV2(three.members, 'm3')
  assert.equal(three.merkle_root, KAT.proof_root)
  assert.deepEqual(proof.path, [{ position: 'promote' }, { position: 'left', sha256: KAT.proof_left }])
  assert.equal(proof.path.some(step => step.position === 'promote'), true)
  assert.equal(verifyEvidenceBundleProofV2(proof, three.merkle_root, { value: 3 }), true)
  assert.equal(verifyEvidenceBundleProofV2({ ...proof, leaf_count: 4 }, three.merkle_root, { value: 3 }), false)
})

test('legacy dispatch is explicit and never guesses from canonical bytes', () => {
  assert.deepEqual(classifySupportingRecordFormat({ manifest: { profile: 'aps:evidence-bundle:v1' } }).format, 'evidence-bundle-v1')
  assert.deepEqual(classifySupportingRecordFormat({ profile: 'aps-supporting-record-v1' }).legacy, false)
  assert.deepEqual(classifySupportingRecordFormat({ profile: 'future' }).format, 'unknown')
  assert.throws(() => strictJCS({ integer: 9007199254740992 }), /IEEE 754/)
  assert.throws(() => parseStrictIJson('{"a":1,"\\u0061":2}'), /duplicate object member/)
  assert.equal(strictJCS(parseStrictIJson('{"a":null}')), '{"a":null}')
})

test('core decision output binds valid_until into the hashed preimage', () => {
  const permit = { profile: 'aps-core-decision-output-v1' as const, verdict: 'permit' as const, effective_authority_ref: hex('b'), constraints: ['commerce:read'], valid_until: '2026-04-08T12:00:05.000Z' }
  const first = computeDecisionComponentRefV1('output', normalizeCoreDecisionOutputV1(permit) as never)
  const later = computeDecisionComponentRefV1('output', normalizeCoreDecisionOutputV1({ ...permit, valid_until: '2026-04-08T12:00:06.000Z' }) as never)
  assert.notEqual(first, later)

  const deny = normalizeCoreDecisionOutputV1({ profile: 'aps-core-decision-output-v1', verdict: 'deny', effective_authority_ref: null, constraints: [], valid_until: null })
  assert.equal(deny.valid_until, null)
  assert.ok(/^[0-9a-f]{64}$/.test(computeDecisionComponentRefV1('output', deny as never)))

  assert.throws(() => normalizeCoreDecisionOutputV1({ ...permit, valid_until: null } as never), /valid_until/)
  assert.throws(() => normalizeCoreDecisionOutputV1({ profile: 'aps-core-decision-output-v1', verdict: 'deny', effective_authority_ref: null, constraints: [], valid_until: '2026-04-08T12:00:05.000Z' } as never), /valid_until/)
  const { valid_until: _omitted, ...missing } = permit
  assert.throws(() => normalizeCoreDecisionOutputV1(missing as never), /valid_until/)
  assert.throws(() => normalizeCoreDecisionOutputV1({ ...permit, valid_until: '2026-04-08T12:00:05Z' } as never), /valid_until/)
})
