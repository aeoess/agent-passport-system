// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// An execution envelope establishes nothing about itself.
// ══════════════════════════════════════════════════════════════════
// The envelope is a signed statement that SOME agent was permitted SOME
// action under SOME policy, by SOME evaluator, and it names the key that
// signed it. Every one of those is the envelope's own claim. Verifying the
// outer signature against the key the envelope carries answers "is this
// document internally consistent", and an attacker's document is internally
// consistent by construction: the audit's reproduction signed an envelope
// granting itself `admin:*` with its own key, wrote a trusted evaluator's DID
// into it, put the four-word string "not-a-signature" in the evaluator
// signature field and "not-a-date" in the evaluation time, and got back
// valid: true with every sub-flag true.
//
// So the relying party has to supply four things the envelope cannot: which
// keys it accepts as signers, the evaluator key, the decision the envelope's
// decision block projects, and what the envelope is expected to be about.
// Absent any of them the corresponding result is 'unresolved' rather than
// true, and the overall result is false.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize, canonicalizeForWrite } from '../src/core/canonical.js'
import {
  createExecutionEnvelope, createMinimalEnvelope, verifyExecutionEnvelope,
} from '../src/core/execution-envelope.js'
import { createDelegation, createReceipt } from '../src/core/delegation.js'
import type { ActionIntent, PolicyDecision, PolicyReceipt } from '../src/types/policy.js'
import type { ExecutionEnvelope } from '../src/types/execution-envelope.js'

const agent = generateKeyPair()
const evaluator = generateKeyPair()
const gateway = generateKeyPair()
const human = generateKeyPair()
const attacker = generateKeyPair()

function signObject<T extends Record<string, unknown>>(body: T, privateKey: string): T & { signature: string } {
  return { ...body, signature: sign(canonicalizeForWrite(body), privateKey) }
}

/** A real chain: agent signs the intent, evaluator signs the decision,
 *  gateway signs the envelope. The only thing a negative changes is the one
 *  field under test. */
function chain(): { intent: ActionIntent; decision: PolicyDecision; envelope: ExecutionEnvelope } {
  const intent = signObject({
    intentId: 'intent_env_0001',
    agentId: 'agent-env',
    agentPublicKey: agent.publicKey,
    delegationId: 'del-env',
    action: { type: 'commerce:purchase', target: 'store', scopeRequired: 'commerce:purchase' },
    context: null,
    createdAt: new Date().toISOString(),
  }, agent.privateKey) as unknown as ActionIntent

  const decision = signObject({
    decisionId: 'pdec_env_0001',
    intentId: intent.intentId,
    evaluatorId: 'evaluator-env',
    evaluatorPublicKey: evaluator.publicKey,
    verdict: 'permit',
    evaluationMethod: 'deterministic',
    principlesEvaluated: [],
    reason: 'within floor',
    floorVersion: 'floor-env',
    evaluatedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 600_000).toISOString(),
  }, evaluator.privateKey) as unknown as PolicyDecision

  const delegation = createDelegation({
    delegatedTo: agent.publicKey, delegatedBy: human.publicKey,
    scope: ['commerce:purchase'], privateKey: human.privateKey,
  })
  const actionReceipt = createReceipt({
    agentId: 'agent-env', delegationId: delegation.delegationId, delegation,
    action: { type: 'commerce:purchase', target: 'store', scopeUsed: 'commerce:purchase' },
    result: { status: 'success', summary: 'ok' },
    delegationChain: [human.publicKey, agent.publicKey],
    privateKey: agent.privateKey,
  })
  const policyReceipt: PolicyReceipt = {
    policyReceiptId: 'prec_env_0001',
    intentId: intent.intentId,
    decisionId: decision.decisionId,
    receiptId: actionReceipt.receiptId,
    chain: {
      intentSignature: intent.signature,
      decisionSignature: decision.signature,
      receiptSignature: actionReceipt.signature,
    },
    verifiedAt: new Date().toISOString(),
    signature: 'unused-by-the-envelope',
  }

  const envelope = createExecutionEnvelope({
    intent, decision, receipt: policyReceipt, delegation,
    runId: 'run-env', agentDid: 'did:aps:agent-env',
    evaluatorDid: 'did:aps:evaluator-env',
    revocationStatus: 'active', chainDepth: 1, evaluationMethod: 'deterministic',
    signerPrivateKey: gateway.privateKey, signerPublicKey: gateway.publicKey,
  })
  return { intent, decision, envelope }
}

/** Everything a relying party must state for the envelope to be verifiable. */
function fullTrust(intent: ActionIntent, decision: PolicyDecision) {
  return {
    trustedSignerPublicKeys: [gateway.publicKey],
    originalDecision: decision,
    evaluatorPublicKey: evaluator.publicKey,
    expected: {
      agentDid: 'did:aps:agent-env',
      runId: 'run-env',
      actionId: intent.intentId,
      policyRef: 'floor-env',
      evaluatorDid: 'did:aps:evaluator-env',
      allowedScope: ['commerce:purchase'],
      verdict: 'permit' as const,
    },
  }
}

describe('the envelope establishes nothing without caller-supplied trust', () => {
  it('accepts an envelope every stated expectation holds for', () => {
    const { intent, decision, envelope } = chain()
    const result = verifyExecutionEnvelope(envelope, fullTrust(intent, decision))
    assert.equal(result.valid, true, result.errors.join('; '))
    assert.equal(result.signerAuthority, 'verified')
    assert.equal(result.evaluatorAuthority, 'verified')
    assert.equal(result.contextValid, true)
  })

  it('the audit reproduction: a self-signed admin:* envelope is refused', () => {
    // Signed by the attacker's own key, claiming a trusted evaluator's DID,
    // with a four-word string where the evaluator signature belongs and a
    // four-word string where the evaluation time belongs.
    const forged = createMinimalEnvelope({
      agentDid: 'did:aps:attacker', runId: 'run-attacker', actionId: 'action-admin',
      scope: ['admin:*'], revocationStatus: 'active',
      decisionHash: 'sha256:attacker-controlled', policyRef: 'fake-policy',
      evaluationMethod: 'deterministic', verdict: 'permit',
      evaluatedAt: 'not-a-date',
      evaluatorDid: 'did:aps:claimed-trusted-evaluator',
      evaluatorSignature: 'not-a-signature',
      receiptHash: 'sha256:attacker-controlled',
      signerPrivateKey: attacker.privateKey, signerPublicKey: attacker.publicKey,
    })
    const result = verifyExecutionEnvelope(forged, {
      maxDecisionAgeMs: 1,
      evaluatorPublicKey: evaluator.publicKey,
      trustedSignerPublicKeys: [gateway.publicKey],
      expected: { allowedScope: ['commerce:purchase'] },
      // A minimal envelope carries no decision, so the caller has none to
      // supply; that is the case, and it is why the evaluator signature can
      // never be established for one.
      originalDecision: undefined as never,
    })
    assert.equal(result.valid, false)
    assert.equal(result.signerAuthority, 'rejected')
    assert.notEqual(result.evaluatorAuthority, 'verified')
    assert.equal(result.decisionFresh, false)
    assert.equal(result.contextValid, false)
  })

  it('supplying an evaluator key is never worse than omitting it', () => {
    // It used to be strictly worse: the branch the key opened set
    // evaluatorSignatureValid = true unconditionally, so a caller doing the
    // more careful thing got the weaker answer.
    const { envelope } = chain()
    // Partial trust inputs, which the types now refuse: the point of the case
    // is what an untyped caller gets, so the omission is made deliberate.
    const without = verifyExecutionEnvelope(envelope, {
      trustedSignerPublicKeys: [gateway.publicKey],
    } as never)
    const withKey = verifyExecutionEnvelope(envelope, {
      trustedSignerPublicKeys: [gateway.publicKey],
      evaluatorPublicKey: evaluator.publicKey,
    } as never)
    assert.equal(without.evaluatorSignatureValid, false)
    assert.equal(withKey.evaluatorSignatureValid, false)
    assert.equal(withKey.evaluatorAuthority, 'unresolved')
  })

  it('a non-empty evaluator signature is never accepted on its own', () => {
    const { envelope } = chain()
    for (const junk of ['not-a-signature', 'x', 'f'.repeat(128), '0'.repeat(128)]) {
      const forged = JSON.parse(JSON.stringify(envelope))
      forged.decision.evaluator_signature = junk
      forged.signature.value = sign(
        canonicalize(Object.fromEntries(Object.entries(forged).filter(([k]) => k !== 'signature'))),
        gateway.privateKey)
      const result = verifyExecutionEnvelope(forged, {
        trustedSignerPublicKeys: [gateway.publicKey],
        evaluatorPublicKey: evaluator.publicKey,
        originalDecision: chain().decision,
        expected: { actionId: envelope.action_id },
      })
      assert.equal(result.evaluatorSignatureValid, false, `accepted ${junk.slice(0, 16)}`)
      assert.equal(result.valid, false)
    }
  })

  it('an evaluator key different from the one that signed the decision is refused', () => {
    const { intent, decision, envelope } = chain()
    const result = verifyExecutionEnvelope(envelope, {
      ...fullTrust(intent, decision),
      evaluatorPublicKey: attacker.publicKey,
    })
    assert.equal(result.valid, false)
    assert.equal(result.evaluatorAuthority, 'rejected')
  })

  it('a decision the envelope does not project is refused', () => {
    const { intent, envelope } = chain()
    // A real decision, correctly signed, about something else.
    const other = signObject({
      decisionId: 'pdec_other',
      intentId: 'intent_other',
      evaluatorId: 'evaluator-env',
      evaluatorPublicKey: evaluator.publicKey,
      verdict: 'permit',
      evaluationMethod: 'deterministic',
      principlesEvaluated: [],
      reason: 'other',
      floorVersion: 'floor-other',
      evaluatedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
    }, evaluator.privateKey) as unknown as PolicyDecision
    const result = verifyExecutionEnvelope(envelope, {
      ...fullTrust(intent, other),
      originalDecision: other,
    })
    assert.equal(result.valid, false)
    assert.equal(result.evaluatorAuthority, 'rejected')
  })

  it('a verdict rewritten in the envelope no longer matches the decision', () => {
    const { intent, decision, envelope } = chain()
    const forged = JSON.parse(JSON.stringify(envelope))
    forged.decision.verdict = 'deny'
    forged.signature.value = sign(
      canonicalize(Object.fromEntries(Object.entries(forged).filter(([k]) => k !== 'signature'))),
      gateway.privateKey)
    const result = verifyExecutionEnvelope(forged, fullTrust(intent, decision))
    assert.equal(result.signatureValid, true, 'the envelope signature must still be valid')
    assert.equal(result.valid, false)
    assert.equal(result.evaluatorAuthority, 'rejected')
  })
})

describe('every expected-context field is checked on its own', () => {
  const mismatches: Array<[string, Record<string, unknown>]> = [
    ['agent', { agentDid: 'did:aps:someone-else' }],
    ['run', { runId: 'run-someone-else' }],
    ['action', { actionId: 'intent_someone_else' }],
    ['policy', { policyRef: 'floor-someone-else' }],
    ['evaluator', { evaluatorDid: 'did:aps:someone-else' }],
    ['verdict', { verdict: 'deny' }],
    ['scope', { allowedScope: ['read:public'] }],
  ]

  for (const [field, override] of mismatches) {
    it(`refuses a mismatched ${field}`, () => {
      const { intent, decision, envelope } = chain()
      const trust = fullTrust(intent, decision)
      const result = verifyExecutionEnvelope(envelope, {
        ...trust,
        expected: { ...trust.expected, ...override },
      })
      assert.equal(result.valid, false, `${field} mismatch was accepted`)
      assert.equal(result.contextValid, false)
    })
  }

  it('states plainly when no context was checked at all', () => {
    const { intent, decision, envelope } = chain()
    const trust = fullTrust(intent, decision)
    // `expected` is required in the types. An empty object satisfies the type
    // and states nothing, which is the case worth pinning: a caller can hand
    // over the shape without filling it in, and the result must say so rather
    // than look like a context check that happened.
    const result = verifyExecutionEnvelope(envelope, { ...trust, expected: {} })
    assert.equal(result.contextChecked, false)
    assert.equal(result.contextValid, false)
    assert.equal(result.valid, false)
    assert.ok(result.errors.some(e => e.includes('context not established')))
  })

  it('an envelope scope outside the allowed set is refused even when the rest matches', () => {
    const { intent, decision, envelope } = chain()
    const trust = fullTrust(intent, decision)
    const widened = verifyExecutionEnvelope(envelope, {
      ...trust,
      expected: { ...trust.expected, allowedScope: ['commerce:purchase', 'admin:*'] },
    })
    assert.equal(widened.valid, true, 'a superset of the claimed scope is fine')

    const narrowed = verifyExecutionEnvelope(envelope, {
      ...trust,
      expected: { ...trust.expected, allowedScope: [] },
    })
    assert.equal(narrowed.valid, false)
  })
})

describe('freshness and revocation still hold their own', () => {
  it('an unreadable evaluation time is not fresh', () => {
    const { intent, decision, envelope } = chain()
    const forged = JSON.parse(JSON.stringify(envelope))
    forged.decision.evaluated_at = 'not-a-date'
    forged.signature.value = sign(
      canonicalize(Object.fromEntries(Object.entries(forged).filter(([k]) => k !== 'signature'))),
      gateway.privateKey)
    const result = verifyExecutionEnvelope(forged, {
      ...fullTrust(intent, decision),
      maxDecisionAgeMs: 600_000,
    })
    assert.equal(result.decisionFresh, false)
    assert.equal(result.valid, false)
  })

  it('a revoked capability is refused', () => {
    const { intent, decision, envelope } = chain()
    const forged = JSON.parse(JSON.stringify(envelope))
    forged.capability_ref.revocation_status = 'revoked'
    forged.signature.value = sign(
      canonicalize(Object.fromEntries(Object.entries(forged).filter(([k]) => k !== 'signature'))),
      gateway.privateKey)
    const result = verifyExecutionEnvelope(forged, fullTrust(intent, decision))
    assert.equal(result.capabilityActive, false)
    assert.equal(result.valid, false)
  })
})
