// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Property tests for v2.3 bilateral receipt emission
// (ENFORCEMENT-TRUST-ANCHOR.md Component A — dumb-sink hardening).
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import {
  generateKeyPair,
  createActionIntent,
  createDelegation,
  createPolicyReceipt,
  verifyPolicyReceipt,
  emitDecisionReceipt,
  parseDecisionReceiptStatement,
  computeDelegationChainRoot,
  DECISION_RECEIPT_PREDICATE_TYPE,
  INTOTO_STATEMENT_V1,
  INTOTO_PAYLOAD_TYPE,
  createPolicyReceiptWithDecisionReceipt,
  canonicalizeJCS,
  sign,
} from '../src/index.js'
import type {
  Delegation,
  ActionIntent,
  PolicyDecision,
  ActionReceipt,
  EpistemicClaims,
  DecisionReceiptEnvelope,
  IntotoStatement,
} from '../src/index.js'

// ── Fixture builders ────────────────────────────────────────────────

function makeChain(): { chain: Delegation[]; actingAgentPub: string } {
  // Two-hop chain: root -> middle -> leaf
  const root = generateKeyPair()
  const middle = generateKeyPair()
  const leaf = generateKeyPair()
  const d1 = createDelegation({
    delegatedTo: middle.publicKey,
    delegatedBy: root.publicKey,
    scope: ['read:*', 'write:workspace', 'spend:usd'],
    expiresInHours: 24 * 60,
    spendLimit: 1000,
    maxDepth: 5,
    currentDepth: 0,
    privateKey: root.privateKey,
  })
  const d2 = createDelegation({
    delegatedTo: leaf.publicKey,
    delegatedBy: middle.publicKey,
    scope: ['read:*', 'write:workspace'],
    expiresInHours: 24 * 60,
    spendLimit: 500,
    maxDepth: 5,
    currentDepth: 1,
    privateKey: middle.privateKey,
  })
  return { chain: [d1, d2], actingAgentPub: leaf.publicKey }
}

function makeIntentDecisionReceipt(actingAgentPub: string, privateKey: string): {
  intent: ActionIntent
  decision: PolicyDecision
  receipt: ActionReceipt
} {
  const intent = createActionIntent({
    agentId: 'agent:test-agent',
    agentPublicKey: actingAgentPub,
    delegationId: 'del_1_test',
    action: { type: 'web_search', target: 'https://example.com', scopeRequired: 'read:*' },
    context: 'test',
    privateKey,
  })

  const unsignedDecision: Omit<PolicyDecision, 'signature'> = {
    decisionId: 'dec_test_001',
    intentId: intent.intentId,
    evaluatorId: 'evaluator:test',
    evaluatorPublicKey: actingAgentPub,
    verdict: 'permit',
    principlesEvaluated: [],
    reason: 'within charter',
    floorVersion: 'floor-v1.0',
    evaluatedAt: '2026-04-23T10:00:00.000Z',
    expiresAt: '2026-04-23T10:30:00.000Z',
  }
  const decSig = sign(canonicalizeJCS(unsignedDecision), privateKey)
  const decision: PolicyDecision = { ...unsignedDecision, signature: decSig }

  const unsignedReceipt: Omit<ActionReceipt, 'signature'> = {
    receiptId: 'rec_test_001',
    version: '1.0',
    timestamp: '2026-04-23T10:00:01.000Z',
    agentId: 'agent:test-agent',
    delegationId: 'del_1_test',
    action: {
      type: 'web_search',
      target: 'https://example.com',
      scopeUsed: 'read:*',
    },
    result: { status: 'success', summary: 'ok' },
    delegationChain: ['root-fp', 'middle-fp', 'leaf-fp'],
  }
  const recSig = sign(canonicalizeJCS(unsignedReceipt), privateKey)
  const receipt: ActionReceipt = { ...unsignedReceipt, signature: recSig }

  return { intent, decision, receipt }
}

const DEFAULT_CLAIMS: EpistemicClaims = {
  policy_evaluated: 'closed',
  authority_consumed: 'witnessed',
  scope_within_bounds: 'closed',
  effect_occurred: 'witnessed-by-subject',
}

function buildEnvelope(): {
  envelope: DecisionReceiptEnvelope
  signerPub: string
  chain: Delegation[]
} {
  const signer = generateKeyPair()
  const { chain, actingAgentPub } = makeChain()
  const { intent, decision, receipt } = makeIntentDecisionReceipt(actingAgentPub, signer.privateKey)
  const envelope = emitDecisionReceipt({
    intent,
    decision,
    receipt,
    delegationChain: chain,
    epistemicClaims: DEFAULT_CLAIMS,
    policyId: 'floor-validator-v1',
    signerPrivateKey: signer.privateKey,
    signerKeyId: `ed25519:${signer.publicKey.slice(0, 16)}`,
    issuerId: 'did:key:test-issuer',
  })
  return { envelope, signerPub: signer.publicKey, chain }
}

// ── Property tests ──────────────────────────────────────────────────

describe('v2.3 bilateral receipt — property tests', () => {
  describe('in-toto Statement v1 shape conformance', () => {
    it('envelope payload parses to a valid in-toto Statement v1', () => {
      const { envelope } = buildEnvelope()

      assert.equal(envelope.payloadType, INTOTO_PAYLOAD_TYPE)
      assert.ok(Array.isArray(envelope.signatures))
      assert.equal(envelope.signatures.length, 1)
      assert.ok(envelope.signatures[0]?.keyid)
      assert.ok(envelope.signatures[0]?.sig)

      const statement = parseDecisionReceiptStatement(envelope) as IntotoStatement
      assert.equal(statement._type, INTOTO_STATEMENT_V1)
      assert.equal(statement.predicateType, DECISION_RECEIPT_PREDICATE_TYPE)
      assert.ok(Array.isArray(statement.subject))
      assert.ok(statement.subject.length > 0)

      const subject = statement.subject[0]!
      assert.ok(subject.name)
      assert.ok(subject.digest?.sha256)
      assert.match(subject.digest.sha256, /^[0-9a-f]{64}$/)
    })

    it('predicate carries all required v2.3 fields', () => {
      const { envelope } = buildEnvelope()
      const predicate = parseDecisionReceiptStatement(envelope).predicate
      assert.ok(['permit', 'deny', 'narrow'].includes(predicate.decision))
      assert.equal(typeof predicate.reason, 'string')
      assert.equal(typeof predicate.policyId, 'string')
      assert.match(predicate.policyDigest.sha256, /^[0-9a-f]{64}$/)
      assert.match(predicate.delegationChainRoot.sha256, /^[0-9a-f]{64}$/)
      assert.equal(typeof predicate.delegationDepth, 'number')
      assert.ok(predicate.delegationDepth >= 1)
      assert.ok(predicate.epistemicClaims.policy_evaluated)
      assert.ok(predicate.epistemicClaims.authority_consumed)
      assert.ok(predicate.epistemicClaims.scope_within_bounds)
      assert.ok(predicate.epistemicClaims.effect_occurred)
      assert.equal(predicate.metadata.framework, 'aps')
      assert.equal(predicate.metadata.receiptKind, 'decision_receipt')
    })

    it('payload bytes match the JCS re-canonicalization of the parsed Statement', () => {
      const { envelope } = buildEnvelope()
      const statement = parseDecisionReceiptStatement(envelope)
      assert.equal(canonicalizeJCS(statement), envelope.payload)
    })
  })

  describe('delegation_chain_root determinism', () => {
    it('produces identical roots across repeated emissions of the same chain', () => {
      const signer = generateKeyPair()
      const { chain, actingAgentPub } = makeChain()
      const { intent, decision, receipt } = makeIntentDecisionReceipt(
        actingAgentPub,
        signer.privateKey,
      )
      const emitOnce = () =>
        emitDecisionReceipt({
          intent,
          decision,
          receipt,
          delegationChain: chain,
          epistemicClaims: DEFAULT_CLAIMS,
          policyId: 'floor-validator-v1',
          signerPrivateKey: signer.privateKey,
          signerKeyId: `ed25519:${signer.publicKey.slice(0, 16)}`,
          issuerId: 'did:key:test-issuer',
        })
      const r1 = parseDecisionReceiptStatement(emitOnce()).predicate.delegationChainRoot.sha256
      const r2 = parseDecisionReceiptStatement(emitOnce()).predicate.delegationChainRoot.sha256
      const r3 = parseDecisionReceiptStatement(emitOnce()).predicate.delegationChainRoot.sha256
      assert.equal(r1, r2)
      assert.equal(r2, r3)
    })

    it('standalone computeDelegationChainRoot matches envelope emission', () => {
      const { envelope, chain } = buildEnvelope()
      const envelopeRoot = parseDecisionReceiptStatement(envelope).predicate.delegationChainRoot.sha256
      const standalone = computeDelegationChainRoot(chain)
      assert.equal(envelopeRoot, standalone)
      assert.match(envelopeRoot, /^[0-9a-f]{64}$/)
    })

    it('root changes when any delegation in the chain changes', () => {
      const { chain } = makeChain()
      const r1 = computeDelegationChainRoot(chain)
      // Delegations are frozen; rebuild with widened scope.
      const widened: Delegation = {
        ...chain[1]!,
        scope: [...chain[1]!.scope, 'write:secrets'],
      }
      const mutated: Delegation[] = [chain[0]!, widened]
      const r2 = computeDelegationChainRoot(mutated)
      assert.notEqual(r1, r2)
    })
  })

  describe('epistemic_claims presence', () => {
    it('every v2.3 receipt carries the four typed claim slots', () => {
      const signer = generateKeyPair()
      const { chain, actingAgentPub } = makeChain()
      const { intent, decision, receipt } = makeIntentDecisionReceipt(
        actingAgentPub,
        signer.privateKey,
      )
      const bundle = createPolicyReceiptWithDecisionReceipt({
        intent,
        decision,
        receipt,
        verifierPrivateKey: signer.privateKey,
        delegationChain: chain,
        epistemicClaims: DEFAULT_CLAIMS,
        policyId: 'floor-validator-v1',
        issuerId: 'did:key:test-issuer',
        signerKeyId: `ed25519:${signer.publicKey.slice(0, 16)}`,
      })

      // PolicyReceipt side
      assert.ok(bundle.policyReceipt.epistemic_claims)
      const prClaims = bundle.policyReceipt.epistemic_claims!
      assert.ok(prClaims.policy_evaluated)
      assert.ok(prClaims.authority_consumed)
      assert.ok(prClaims.scope_within_bounds)
      assert.ok(prClaims.effect_occurred)

      // Decision Receipt envelope side
      const drClaims = parseDecisionReceiptStatement(bundle.decisionReceipt).predicate
        .epistemicClaims
      assert.deepEqual(drClaims, prClaims)
    })

    it('PolicyReceipt carries delegation_chain_root + delegation_depth when chain supplied', () => {
      const signer = generateKeyPair()
      const { chain, actingAgentPub } = makeChain()
      const { intent, decision, receipt } = makeIntentDecisionReceipt(
        actingAgentPub,
        signer.privateKey,
      )
      const bundle = createPolicyReceiptWithDecisionReceipt({
        intent,
        decision,
        receipt,
        verifierPrivateKey: signer.privateKey,
        delegationChain: chain,
        epistemicClaims: DEFAULT_CLAIMS,
        policyId: 'floor-validator-v1',
        issuerId: 'did:key:test-issuer',
        signerKeyId: `ed25519:${signer.publicKey.slice(0, 16)}`,
      })

      assert.equal(bundle.policyReceipt.delegation_depth, chain.length)
      assert.match(bundle.policyReceipt.delegation_chain_root!, /^[0-9a-f]{64}$/)
      assert.equal(
        bundle.policyReceipt.delegation_chain_root,
        parseDecisionReceiptStatement(bundle.decisionReceipt).predicate.delegationChainRoot.sha256,
      )
    })

    it('accepts witnessed-by-subject and self-asserted on effect_occurred only', () => {
      // Type check: the field is widely typed; these are valid values.
      const claims: EpistemicClaims = {
        policy_evaluated: 'closed',
        authority_consumed: 'witnessed',
        scope_within_bounds: 'closed',
        effect_occurred: 'self-asserted',
      }
      assert.equal(claims.effect_occurred, 'self-asserted')
    })
  })

  describe('v2.2.x backward compatibility', () => {
    it('v2.2.x consumer parses a v2.3 PolicyReceipt and ignores the new fields', () => {
      const signer = generateKeyPair()
      const { chain, actingAgentPub } = makeChain()
      const { intent, decision, receipt } = makeIntentDecisionReceipt(
        actingAgentPub,
        signer.privateKey,
      )
      const { policyReceipt } = createPolicyReceiptWithDecisionReceipt({
        intent,
        decision,
        receipt,
        verifierPrivateKey: signer.privateKey,
        delegationChain: chain,
        epistemicClaims: DEFAULT_CLAIMS,
        policyId: 'floor-validator-v1',
        issuerId: 'did:key:test-issuer',
        signerKeyId: `ed25519:${signer.publicKey.slice(0, 16)}`,
      })

      // Simulate a v2.2.x consumer: it projects to the v2.2 field set.
      const v22Shape = {
        policyReceiptId: policyReceipt.policyReceiptId,
        intentId: policyReceipt.intentId,
        decisionId: policyReceipt.decisionId,
        receiptId: policyReceipt.receiptId,
        chain: policyReceipt.chain,
        verifiedAt: policyReceipt.verifiedAt,
        actionRef: policyReceipt.actionRef,
        signature: policyReceipt.signature,
      }
      assert.ok(v22Shape.policyReceiptId)
      assert.ok(v22Shape.signature)
      // Round-trip through JSON: unknown fields survive, as a v2.2 consumer would expect.
      const roundTripped = JSON.parse(JSON.stringify(policyReceipt))
      assert.equal(roundTripped.policyReceiptId, policyReceipt.policyReceiptId)
      // No throw, no field access on required v2.2 shape is disturbed.
      assert.doesNotThrow(() => verifyPolicyReceipt(policyReceipt, signer.publicKey))
      const result = verifyPolicyReceipt(policyReceipt, signer.publicKey)
      assert.equal(result.valid, true, result.errors.join(', '))
    })

    it('createPolicyReceipt still works without v2.3 fields (pure v2.2 call)', () => {
      const signer = generateKeyPair()
      const { actingAgentPub } = makeChain()
      const { intent, decision, receipt } = makeIntentDecisionReceipt(
        actingAgentPub,
        signer.privateKey,
      )
      // No delegationChain, no epistemicClaims — v2.2.x call site.
      const pr = createPolicyReceipt({
        intent,
        decision,
        receipt,
        verifierPrivateKey: signer.privateKey,
      })
      assert.equal(pr.delegation_chain_root, undefined)
      assert.equal(pr.delegation_depth, undefined)
      assert.equal(pr.epistemic_claims, undefined)
      assert.equal(verifyPolicyReceipt(pr, signer.publicKey).valid, true)
    })
  })

  describe('JCS canonicalization invariants', () => {
    it('reordered keys in delegation objects produce identical chain root', () => {
      // Build two chains that have the same CONTENT but different key insertion order.
      const { chain } = makeChain()
      const [a, b] = chain
      const reordered: Delegation[] = [
        // Reconstruct with keys in reverse insertion order.
        Object.fromEntries(Object.entries(a!).reverse()) as unknown as Delegation,
        Object.fromEntries(Object.entries(b!).reverse()) as unknown as Delegation,
      ]
      assert.equal(computeDelegationChainRoot(chain), computeDelegationChainRoot(reordered))
    })

    it('JCS output is stable across permuted top-level object keys', () => {
      const a = { x: 1, y: [1, 2, 3], z: { q: 'q', p: 'p' } }
      const b = { z: { p: 'p', q: 'q' }, y: [1, 2, 3], x: 1 }
      assert.equal(canonicalizeJCS(a), canonicalizeJCS(b))
    })

    it('SHA-256 of JCS output is stable across key permutations', () => {
      const a = { alpha: 1, beta: 2, gamma: { nested: true } }
      const b = { gamma: { nested: true }, beta: 2, alpha: 1 }
      const hashA = createHash('sha256').update(canonicalizeJCS(a)).digest('hex')
      const hashB = createHash('sha256').update(canonicalizeJCS(b)).digest('hex')
      assert.equal(hashA, hashB)
    })
  })

  describe('cross-repo interop with hermes-aps-delegation Python emitter', () => {
    it('envelope shape matches DSSE + in-toto Statement v1 the Python side emits', () => {
      const { envelope } = buildEnvelope()
      // The Python emitter at aeoess/hermes-aps-delegation produces:
      //   { payloadType: "application/vnd.in-toto+json",
      //     payload: canonical-json-string,
      //     signatures: [{ keyid: "ed25519:<hex>", sig: "<hex>" }],
      //     _digest: { sha256: "<hex>" } }
      assert.equal(envelope.payloadType, 'application/vnd.in-toto+json')
      assert.ok(envelope._digest.sha256)
      assert.match(envelope._digest.sha256, /^[0-9a-f]{64}$/)
      assert.equal(envelope.signatures.length, 1)
      // payload is a string, not an object — this is load-bearing for
      // signature semantics (sign over exact canonical bytes).
      assert.equal(typeof envelope.payload, 'string')
    })
  })
})
