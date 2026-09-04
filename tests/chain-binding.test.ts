// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// An artifact about a chain must be bound to the chain it is about.
// ══════════════════════════════════════════════════════════════════
// Both surfaces here restate values they do not carry, and both used to accept
// the restatement as if signing it made it true.
//
// verifyDecisionArtifact took three trust anchors and read one. The intent and
// the decision were each verified against a key carried inside themselves, so
// a caller passing the correct anchors got no benefit from passing them and a
// caller passing the wrong ones got no warning. Nothing checked that the
// decision decided the intent, and nothing compared the artifact's projected
// verdict, evaluator, decision id, principles or copied signatures against the
// sources they claim to project.
//
// verifyPolicyReceipt was documented as verifying the full chain and tested
// three strings for non-emptiness. The receipt carries ids and copies of the
// three signature strings, never the objects those signatures were made over,
// so the chain cannot be checked from the receipt alone. It takes them from
// the caller now, with an anchor for each, and a call that omits them is not a
// verification and does not report one.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalizeForWrite } from '../src/core/canonical.js'
import {
  createContentAddressableIntent, createDecisionArtifact, verifyDecisionArtifact,
} from '../src/core/decision-semantics.js'
import {
  createActionIntent, createPolicyReceipt, verifyPolicyReceipt, verifyPolicyReceiptEnvelope,
} from '../src/core/policy.js'
import { createDelegation, createReceipt } from '../src/core/delegation.js'
import type { ActionIntent, PolicyDecision } from '../src/types/policy.js'
import type { DecisionArtifact } from '../src/types/decision-semantics.js'

const agent = generateKeyPair()
const evaluator = generateKeyPair()
const artifactSigner = generateKeyPair()
const wrongAnchor = generateKeyPair()
const unrelatedEvaluator = generateKeyPair()

const FUTURE = () => new Date(Date.now() + 600_000).toISOString()

function signDecision(body: Omit<PolicyDecision, 'signature'>, privateKey: string): PolicyDecision {
  return { ...body, signature: sign(canonicalizeForWrite(body), privateKey) }
}

async function chainFixture(): Promise<{
  intent: ActionIntent
  decision: PolicyDecision
  artifact: DecisionArtifact
}> {
  const intent = await createContentAddressableIntent({
    agentId: 'agent-chain',
    agentPublicKey: agent.publicKey,
    delegationId: 'del-chain',
    action: { type: 'admin', target: 'system', scopeRequired: 'admin:*' },
    privateKey: agent.privateKey,
  })
  const decision = signDecision({
    decisionId: 'pdec_chain_0001',
    intentId: intent.intentId,
    evaluatorId: 'evaluator-chain',
    evaluatorPublicKey: evaluator.publicKey,
    verdict: 'permit',
    evaluationMethod: 'deterministic',
    principlesEvaluated: [],
    reason: 'permitted',
    floorVersion: 'floor-chain',
    evaluatedAt: new Date().toISOString(),
    expiresAt: FUTURE(),
  }, evaluator.privateKey)
  const artifact = await createDecisionArtifact({
    intent, decision, engine: 'aps', signerPrivateKey: artifactSigner.privateKey,
  })
  return { intent, decision, artifact }
}

const anchors = () => ({
  intentSignerPublicKey: agent.publicKey,
  decisionSignerPublicKey: evaluator.publicKey,
  artifactSignerPublicKey: artifactSigner.publicKey,
})

describe('verifyDecisionArtifact uses every anchor it accepts', () => {
  it('accepts the artifact it was built from, with the right anchors', async () => {
    const { intent, decision, artifact } = await chainFixture()
    const result = await verifyDecisionArtifact(artifact, anchors(), intent, decision)
    assert.equal(result.valid, true, result.errors.join('; '))
    assert.equal(result.linkageValid, true)
    assert.equal(result.projectionValid, true)
  })

  it('refuses a wrong intent anchor', async () => {
    const { intent, decision, artifact } = await chainFixture()
    const result = await verifyDecisionArtifact(
      artifact, { ...anchors(), intentSignerPublicKey: wrongAnchor.publicKey }, intent, decision)
    assert.equal(result.valid, false)
    assert.equal(result.intentSignatureValid, false)
  })

  it('refuses a wrong decision anchor', async () => {
    const { intent, decision, artifact } = await chainFixture()
    const result = await verifyDecisionArtifact(
      artifact, { ...anchors(), decisionSignerPublicKey: wrongAnchor.publicKey }, intent, decision)
    assert.equal(result.valid, false)
    assert.equal(result.decisionSignatureValid, false)
  })

  it('refuses an unrelated but validly signed decision', async () => {
    const { intent, artifact } = await chainFixture()
    // A real decision, correctly signed by a real evaluator, about a different
    // intent. Every signature on it verifies; it just does not decide this.
    const unrelated = signDecision({
      decisionId: 'pdec_unrelated',
      intentId: 'intent_some_other_request',
      evaluatorId: 'evaluator-unrelated',
      evaluatorPublicKey: unrelatedEvaluator.publicKey,
      verdict: 'permit',
      evaluationMethod: 'deterministic',
      principlesEvaluated: [],
      reason: 'unrelated',
      floorVersion: 'floor-chain',
      evaluatedAt: new Date().toISOString(),
      expiresAt: FUTURE(),
    }, unrelatedEvaluator.privateKey)
    const result = await verifyDecisionArtifact(
      artifact,
      { ...anchors(), decisionSignerPublicKey: unrelatedEvaluator.publicKey },
      intent,
      unrelated)
    assert.equal(result.valid, false)
    assert.equal(result.linkageValid, false)
  })

  const substitutions: Array<[string, (a: DecisionArtifact) => void]> = [
    ['verdict', a => { a.evaluation.verdict = 'deny' }],
    ['evaluator', a => { a.evaluation.evaluatorId = 'evaluator-someone-else' }],
    ['decision id', a => { a.evaluation.decisionId = 'pdec_substituted' }],
    ['principles', a => { a.evaluation.principlesChecked = ['F-001', 'F-002'] }],
    ['intent id', a => { a.intent.intentId = 'intent_substituted' }],
    ['agent id', a => { a.intent.agentId = 'agent-someone-else' }],
    ['action scope', a => { a.intent.action.scopeRequired = 'read:public' }],
    ['copied intent signature', a => { a.proof.intentSignature = 'f'.repeat(128) }],
    ['copied decision signature', a => { a.proof.decisionSignature = 'f'.repeat(128) }],
    ['semantic decomposition', a => { a.semantics.structuralVerdict = 'deny' }],
  ]

  for (const [what, mutate] of substitutions) {
    it(`refuses a substituted ${what}, re-signed by the artifact signer`, async () => {
      const { intent, decision, artifact } = await chainFixture()
      const tampered = JSON.parse(JSON.stringify(artifact)) as DecisionArtifact
      mutate(tampered)
      // Re-signed, so the artifact envelope signature is valid and the only
      // thing wrong is that the projection no longer matches its source. That
      // is the case the old verifier could not see at all.
      const { proof, ...body } = tampered
      const bodyWithPartialProof = {
        ...body,
        proof: { intentSignature: proof.intentSignature, decisionSignature: proof.decisionSignature },
      }
      tampered.proof.artifactSignature = sign(
        canonicalizeForWrite(bodyWithPartialProof), artifactSigner.privateKey)

      const result = await verifyDecisionArtifact(tampered, anchors(), intent, decision)
      assert.equal(result.artifactSignatureValid, true, 'the envelope signature must still be valid')
      assert.equal(result.valid, false, `substituted ${what} was accepted`)
      assert.equal(result.projectionValid, false)
    })
  }

  it('refuses an artifact that carries no content hash', async () => {
    const { intent, decision, artifact } = await chainFixture()
    const stripped = JSON.parse(JSON.stringify(artifact))
    delete stripped.intent.contentHash
    const result = await verifyDecisionArtifact(stripped, anchors(), intent, decision)
    // The content hash is the artifact's only self-contained binding to the
    // intent's full content. Omitting it used to leave zero bindings and still
    // return valid, because the error was pushed inside the presence check.
    assert.equal(result.valid, false)
    assert.equal(result.contentHashValid, false)
  })

  it('refuses null and non-object inputs instead of throwing', async () => {
    const { intent, decision, artifact } = await chainFixture()
    for (const [a, i, d] of [
      [null, intent, decision], [artifact, null, decision], [artifact, intent, null],
    ] as const) {
      const result = await verifyDecisionArtifact(a as never, anchors(), i as never, d as never)
      assert.equal(result.valid, false)
    }
  })
})

describe('verifyPolicyReceipt verifies the chain it names', () => {
  const human = generateKeyPair()

  async function receiptFixture() {
    const intent = createActionIntent({
      agentId: 'agent-receipt',
      agentPublicKey: agent.publicKey,
      delegationId: 'del-receipt',
      action: { type: 'execute', target: 'build', scopeRequired: 'code_execution' },
      privateKey: agent.privateKey,
    })
    const decision = signDecision({
      decisionId: 'pdec_receipt_0001',
      intentId: intent.intentId,
      evaluatorId: 'evaluator-receipt',
      evaluatorPublicKey: evaluator.publicKey,
      verdict: 'permit',
      evaluationMethod: 'deterministic',
      principlesEvaluated: [],
      reason: 'permitted',
      floorVersion: 'floor-receipt',
      evaluatedAt: new Date().toISOString(),
      expiresAt: FUTURE(),
    }, evaluator.privateKey)
    const delegation = createDelegation({
      delegatedTo: agent.publicKey, delegatedBy: human.publicKey,
      scope: ['code_execution'], privateKey: human.privateKey,
    })
    const receipt = createReceipt({
      agentId: 'agent-receipt', delegationId: delegation.delegationId, delegation,
      action: { type: 'execute', target: 'build', scopeUsed: 'code_execution' },
      result: { status: 'success', summary: 'built' },
      delegationChain: [human.publicKey, agent.publicKey],
      privateKey: agent.privateKey,
    })
    const policyReceipt = createPolicyReceipt({
      intent, decision, receipt, verifierPrivateKey: artifactSigner.privateKey,
    })
    const chain = {
      intent, decision, receipt,
      intentSignerPublicKey: agent.publicKey,
      decisionSignerPublicKey: evaluator.publicKey,
      receiptSignerPublicKey: agent.publicKey,
    }
    return { policyReceipt, chain }
  }

  it('accepts a receipt whose chain verifies against the supplied anchors', async () => {
    const { policyReceipt, chain } = await receiptFixture()
    const result = verifyPolicyReceipt(policyReceipt, artifactSigner.publicKey, chain)
    assert.equal(result.valid, true, result.errors.join('; '))
    assert.equal(result.chainVerified, true)
  })

  it('is not a verification when the chain is not supplied', async () => {
    const { policyReceipt } = await receiptFixture()
    // `chain` is required in the types, so reaching this path means an
    // untyped caller; the cast makes that deliberate. It must reject rather
    // than throw, because the reject verdict is what a caller branches on.
    const result = verifyPolicyReceipt(
      policyReceipt, artifactSigner.publicKey, undefined as never)
    assert.equal(result.valid, false)
    assert.equal(result.chainVerified, false)
    // The envelope is intact; that is a different and much smaller claim, and
    // it now has its own name.
    assert.equal(result.envelopeSignatureValid, true)
    assert.equal(verifyPolicyReceiptEnvelope(policyReceipt, artifactSigner.publicKey).valid, true)
  })

  it('refuses garbage inner signatures', async () => {
    const { policyReceipt, chain } = await receiptFixture()
    const forged = JSON.parse(JSON.stringify(policyReceipt))
    forged.chain = {
      intentSignature: 'garbage-intent',
      decisionSignature: 'garbage-decision',
      receiptSignature: 'garbage-receipt',
    }
    forged.signature = sign(
      canonicalizeForWrite(Object.fromEntries(
        Object.entries(forged).filter(([k]) => k !== 'signature'))),
      artifactSigner.privateKey)

    // The envelope is validly signed by the key the caller trusts; the three
    // strings inside it are not signatures on anything. That combination used
    // to return { valid: true, errors: [] }.
    assert.equal(verifyPolicyReceiptEnvelope(forged, artifactSigner.publicKey).valid, true)
    const result = verifyPolicyReceipt(forged, artifactSigner.publicKey, chain)
    assert.equal(result.valid, false)
    assert.equal(result.chainVerified, false)
  })

  it('refuses a wrong anchor for each role in turn', async () => {
    const { policyReceipt, chain } = await receiptFixture()
    for (const role of ['intentSignerPublicKey', 'decisionSignerPublicKey', 'receiptSignerPublicKey'] as const) {
      const result = verifyPolicyReceipt(policyReceipt, artifactSigner.publicKey, {
        ...chain, [role]: wrongAnchor.publicKey,
      })
      assert.equal(result.valid, false, `${role} was not used`)
      assert.equal(result.chainVerified, false)
    }
  })

  it('refuses an id that names something other than the object supplied', async () => {
    const { policyReceipt, chain } = await receiptFixture()
    for (const field of ['intentId', 'decisionId', 'receiptId'] as const) {
      const mismatched = { ...policyReceipt, [field]: 'not-the-object-supplied' }
      mismatched.signature = sign(
        canonicalizeForWrite(Object.fromEntries(
          Object.entries(mismatched).filter(([k]) => k !== 'signature'))),
        artifactSigner.privateKey)
      const result = verifyPolicyReceipt(mismatched, artifactSigner.publicKey, chain)
      assert.equal(result.valid, false, `${field} link was not checked`)
    }
  })

  it('refuses a receipt attesting to a denied decision', async () => {
    const { policyReceipt, chain } = await receiptFixture()
    const denied = signDecision({
      ...Object.fromEntries(Object.entries(chain.decision).filter(([k]) => k !== 'signature')),
      verdict: 'deny',
    } as never, evaluator.privateKey)
    // createPolicyReceipt refuses to build this; a forger assembling the object
    // directly must not get past the verifier either.
    const result = verifyPolicyReceipt(policyReceipt, artifactSigner.publicKey,
      { ...chain, decision: denied })
    assert.equal(result.valid, false)
  })
})
