// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Cross-Engine Signed Execution Envelope — Implementation
// ══════════════════════════════════════════════════════════════════
// Reference: docs/RFC-SIGNED-EXECUTION-ENVELOPE.md
//
// createExecutionEnvelope() assembles our existing 3-signature chain
// (ActionIntent → PolicyDecision → PolicyReceipt) into the
// standardized envelope format any governance engine can verify.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize, canonicalizeForWrite } from './canonical.js'
import { parseRfc3339 } from './rfc3339.js'
import type { ActionIntent, PolicyDecision, PolicyReceipt } from '../types/policy.js'
import type { Delegation } from '../types/passport.js'
import { normalizeTrustAnchors } from '../verification/trust-anchors.js'
import type {
  ExecutionEnvelope, EnvelopeVerification, EnvelopeSignerAuthority,
  EvaluationMethod, EnvelopeVerdict, RevocationStatus
} from '../types/execution-envelope.js'

/**
 * Create a cross-engine signed execution envelope from APS primitives.
 *
 * Maps our 3-signature chain to the standardized envelope format:
 * - ActionIntent → action_id, agent_did
 * - PolicyDecision → decision block
 * - PolicyReceipt → attestation block
 * - Delegation → capability_ref block
 */
export function createExecutionEnvelope(opts: {
  intent: ActionIntent
  decision: PolicyDecision
  receipt: PolicyReceipt
  delegation: Delegation
  /** Task/run context ID */
  runId: string
  /** Agent's DID (e.g., did:aps:publickey) */
  agentDid: string
  /** Evaluator's DID */
  evaluatorDid: string
  /** Whether the delegation chain is currently active */
  revocationStatus: RevocationStatus
  /** Delegation chain depth */
  chainDepth: number
  /** Evaluation method for this decision */
  evaluationMethod: EvaluationMethod
  /** Signer's private key (for envelope signature) */
  signerPrivateKey: string
  /** Signer's public key */
  signerPublicKey: string
}): ExecutionEnvelope {

  // Hash the delegation scope as capability manifest
  const manifestHash = createHash('sha256')
    .update(canonicalizeForWrite(opts.delegation.scope))
    .digest('hex')

  // Hash the full policy decision
  const decisionHash = createHash('sha256')
    .update(canonicalizeForWrite(opts.decision))
    .digest('hex')

  // Hash the execution receipt
  const receiptHash = createHash('sha256')
    .update(canonicalizeForWrite(opts.receipt))
    .digest('hex')

  // Determine narrowing from decision
  const narrowing = opts.decision.verdict === 'narrow' && opts.decision.constraints
    ? opts.decision.constraints.join('; ')
    : null

  // Build the envelope body (everything except the outer signature)
  const envelopeBody = {
    schema: 'execution-envelope.v0.1' as const,
    agent_did: opts.agentDid,
    run_id: opts.runId,
    action_id: opts.intent.intentId,
    ...(opts.intent.actionRef ? { action_ref: opts.intent.actionRef } : {}),

    capability_ref: {
      manifest_hash: `sha256:${manifestHash}`,
      scope: opts.delegation.scope,
      delegation_chain_depth: opts.chainDepth,
      revocation_status: opts.revocationStatus
    },

    decision: {
      decision_hash: `sha256:${decisionHash}`,
      policy_ref: opts.decision.floorVersion,
      evaluation_method: opts.evaluationMethod,
      verdict: opts.decision.verdict as 'permit' | 'deny' | 'narrow',
      narrowing,
      evaluated_at: opts.decision.evaluatedAt,
      evaluator_did: opts.evaluatorDid,
      evaluator_signature: opts.decision.signature
    },

    attestation: {
      receipt_hash: `sha256:${receiptHash}`,
      receipt_type: 'PolicyReceipt',
      chain_signatures: {
        intent: opts.receipt.chain.intentSignature,
        decision: opts.receipt.chain.decisionSignature,
        receipt: opts.receipt.chain.receiptSignature
      }
    },

    timestamp: new Date().toISOString()
  }

  // Sign the entire envelope body
  const canonical = canonicalizeForWrite(envelopeBody)
  const signatureValue = sign(canonical, opts.signerPrivateKey)

  return {
    ...envelopeBody,
    signature: {
      algorithm: 'Ed25519' as const,
      public_key: opts.signerPublicKey,
      value: signatureValue
    }
  }
}

/** The relying party's expectation of what this envelope is about. Every
 *  field is optional and every one supplied is compared exactly; a field left
 *  out is not checked, and `contextChecked` reports whether any were.
 *
 *  These are the questions an envelope cannot answer about itself. An envelope
 *  is a signed statement that SOME agent was permitted SOME action under SOME
 *  policy; that it is the agent, action and policy this caller is about to act
 *  on is the caller's to state. */
export interface ExpectedEnvelopeContext {
  agentDid?: string
  runId?: string
  actionId?: string
  actionRef?: string
  /** Every scope the envelope claims must appear here. Extra entries in the
   *  caller's set are fine; an envelope scope outside it is not. */
  allowedScope?: string[]
  policyRef?: string
  evaluatorDid?: string
  verdict?: EnvelopeVerdict
}

export interface VerifyEnvelopeOptions {
  /** Public keys this relying party accepts as envelope signers. Normalized
   *  through the same helper every other trust-anchor option in the SDK uses,
   *  so a malformed value is a configuration error rather than either "no
   *  anchors" or "all anchors". An empty or absent list means this verifier
   *  holds no anchors; it does not mean trust anyone. */
  trustedSignerPublicKeys?: string[]
  /** The PolicyDecision the envelope's decision block projects. Required to
   *  establish the evaluator signature: the envelope carries a hash, and
   *  Ed25519 here is not prehashed, so the signed bytes exist nowhere else. */
  originalDecision?: PolicyDecision
  /** The evaluator key this relying party accepts. */
  evaluatorPublicKey?: string
  /** Maximum age of the decision in milliseconds. */
  maxDecisionAgeMs?: number
  /** What this envelope is expected to be about. */
  expected?: ExpectedEnvelopeContext
}

/**
 * Verify a cross-engine signed execution envelope.
 *
 * SCOPE OF CLAIM.
 *   Establishes, when `valid` is true: the envelope's bytes are unaltered and
 *     were signed by one of the keys the caller named; the evaluator signature
 *     it carries is the signature of the caller's evaluator key over the
 *     decision the caller supplied; the envelope's decision block projects
 *     that decision faithfully; the capability was active at emission; the
 *     decision was evaluated inside the caller's freshness window; and every
 *     expected-context field the caller stated matched.
 *   Does NOT establish: that the delegation is unrevoked NOW —
 *     `revocation_status` is a literal the emitter typed at emission and is
 *     not a live check; that the evaluator was entitled to permit this action;
 *     that the action described actually happened; or that
 *     `evaluation_method` is the method the decision recorded, which is a
 *     separate caller parameter at construction and is bound to nothing.
 *
 * WHY THE DECISION HAS TO BE PASSED IN. The envelope carries
 * `decision.decision_hash`, not the decision. `evaluator_signature` is
 * `PolicyDecision.signature`, made over the canonical form of the decision
 * with the signature member removed. Of that preimage's twelve members the
 * envelope carries three exactly (evaluated_at, floorVersion as policy_ref,
 * intentId as action_id), one lossily, and not at all: decisionId,
 * evaluatorId, evaluatorPublicKey, expiresAt, reason, principlesEvaluated.
 * The last two are free text. And decision_hash is over the decision INCLUDING
 * its signature, so it commits to a different string than the signature does;
 * it could not substitute even if the bytes were otherwise recoverable, since
 * this SDK's Ed25519 is not prehashed and verify() needs the message. So the
 * bytes cannot be reconstructed from the envelope by anyone, and a verifier
 * that reports them as verified is reporting something it did not do.
 *
 * Previously it did exactly that: `evaluatorSignatureValid` was
 * `!!envelope.decision.evaluator_signature`, and supplying an evaluator key
 * made it strictly worse, because the branch that key opened set the flag to
 * true unconditionally. The string "not-a-signature" passed. It is now
 * 'unresolved' with no decision supplied, and the overall result fails.
 */
export function verifyExecutionEnvelope(
  envelope: ExecutionEnvelope,
  opts?: VerifyEnvelopeOptions
): EnvelopeVerification {
  const errors: string[] = []

  // 1. Envelope integrity, under the key the envelope carries. This is proof
  //    of possession and nothing more: the key is the envelope's own claim
  //    about itself, and an attacker signs their own envelope with their own
  //    key all day. It is reported separately from whether that key is one
  //    anyone trusts.
  const { signature, ...body } = envelope
  const canonical = canonicalize(body)
  const signatureValid = verify(canonical, signature.value, signature.public_key)
  if (!signatureValid) errors.push('Envelope signature invalid')

  // 2. Is the signer one this relying party accepts? The embedded key may only
  //    SELECT among the caller's keys; it may never establish trust.
  const anchors = normalizeTrustAnchors(opts?.trustedSignerPublicKeys)
  let signerAuthority: EnvelopeSignerAuthority
  if (anchors.malformed) {
    signerAuthority = 'rejected'
    errors.push(`Invalid trustedSignerPublicKeys option: ${anchors.reason}`)
  } else if (anchors.anchors.length === 0) {
    signerAuthority = 'unresolved'
    errors.push(
      'Envelope signer not established: no trusted signer keys were supplied. ' +
      'The key an envelope carries is its own claim about itself.'
    )
  } else if (anchors.anchors.includes(signature.public_key)) {
    signerAuthority = signatureValid ? 'verified' : 'rejected'
  } else {
    signerAuthority = 'rejected'
    errors.push('Envelope signer is not one of the supplied trusted signer keys')
  }

  // 3. Capability status as recorded at emission.
  const capabilityActive = envelope.capability_ref.revocation_status === 'active'
  if (!capabilityActive) errors.push('Capability revoked at execution time')

  // 4. Decision freshness.
  let decisionFresh = true
  if (opts?.maxDecisionAgeMs) {
    const evaluatedAt = parseRfc3339(envelope.decision.evaluated_at)
    if (!evaluatedAt.ok) {
      // An evaluation time this verifier cannot read bounds no freshness window.
      decisionFresh = false
      errors.push(`Invalid decision evaluated_at (${evaluatedAt.reason})`)
    } else {
      const decisionAge = Date.now() - evaluatedAt.ms
      if (decisionAge > opts.maxDecisionAgeMs) {
        decisionFresh = false
        errors.push(`Decision too old: ${Math.round(decisionAge / 1000)}s > ${Math.round(opts.maxDecisionAgeMs / 1000)}s max`)
      }
    }
  }

  // 5. Evaluator signature, over bytes the caller supplies.
  const evaluator = verifyEvaluatorSignature(envelope, opts)
  const evaluatorAuthority = evaluator.authority
  const evaluatorSignatureValid = evaluatorAuthority === 'verified'
  errors.push(...evaluator.errors)

  // 6. Expected context.
  const context = matchExpectedContext(envelope, opts?.expected)
  errors.push(...context.errors)
  if (!context.checked) {
    errors.push(
      'Envelope context not established: no expected agent, action, scope, policy or ' +
      'evaluator was supplied, so the envelope was not checked against anything it is about.'
    )
  }

  return {
    valid: errors.length === 0,
    signatureValid,
    signerAuthority,
    evaluatorSignatureValid,
    evaluatorAuthority,
    capabilityActive,
    decisionFresh,
    contextChecked: context.checked,
    contextValid: context.checked && context.errors.length === 0,
    errors
  }
}

/** Verify decision.evaluator_signature against the caller's evaluator key,
 *  over the caller's copy of the decision, and check that the envelope's
 *  decision block projects that decision faithfully. */
function verifyEvaluatorSignature(
  envelope: ExecutionEnvelope,
  opts?: VerifyEnvelopeOptions
): { authority: EnvelopeSignerAuthority; errors: string[] } {
  const errors: string[] = []
  const carried = envelope.decision.evaluator_signature

  if (!carried) {
    errors.push('Evaluator signature missing')
    return { authority: 'rejected', errors }
  }
  if (!opts?.originalDecision || !opts?.evaluatorPublicKey) {
    errors.push(
      'Evaluator signature not established: the original PolicyDecision and an evaluator ' +
      'key are both required. The envelope carries a hash of the decision, not the decision, ' +
      'so the signed bytes are not present in it.'
    )
    return { authority: 'unresolved', errors }
  }

  const decision = opts.originalDecision
  const { signature: decisionSignature, ...unsigned } = decision
  if (!verify(canonicalize(unsigned), carried, opts.evaluatorPublicKey)) {
    errors.push('Evaluator signature does not verify under the supplied evaluator key')
    return { authority: 'rejected', errors }
  }
  if (carried !== decisionSignature) {
    errors.push('Envelope carries an evaluator signature that is not the supplied decision\'s')
    return { authority: 'rejected', errors }
  }

  // The envelope's decision block restates the decision. Verifying the
  // signature proves the decision is authentic; it says nothing about whether
  // the block beside it describes THAT decision.
  const projections: Array<[string, unknown, unknown]> = [
    ['decision.verdict', envelope.decision.verdict, decision.verdict],
    ['decision.policy_ref', envelope.decision.policy_ref, decision.floorVersion],
    ['decision.evaluated_at', envelope.decision.evaluated_at, decision.evaluatedAt],
    ['action_id', envelope.action_id, decision.intentId],
    ['decision.decision_hash', envelope.decision.decision_hash,
      `sha256:${createHash('sha256').update(canonicalize(decision)).digest('hex')}`],
  ]
  for (const [field, got, want] of projections) {
    if (canonicalize(got) !== canonicalize(want)) {
      errors.push(`Envelope ${field} does not match the supplied decision`)
    }
  }
  return { authority: errors.length === 0 ? 'verified' : 'rejected', errors }
}

/** Compare the envelope against what the caller says it should be about. */
function matchExpectedContext(
  envelope: ExecutionEnvelope,
  expected?: ExpectedEnvelopeContext
): { checked: boolean; errors: string[] } {
  const errors: string[] = []
  if (!expected) return { checked: false, errors }

  const pairs: Array<[string, unknown, unknown]> = [
    ['agent_did', envelope.agent_did, expected.agentDid],
    ['run_id', envelope.run_id, expected.runId],
    ['action_id', envelope.action_id, expected.actionId],
    ['action_ref', envelope.action_ref, expected.actionRef],
    ['decision.policy_ref', envelope.decision.policy_ref, expected.policyRef],
    ['decision.evaluator_did', envelope.decision.evaluator_did, expected.evaluatorDid],
    ['decision.verdict', envelope.decision.verdict, expected.verdict],
  ]
  let checked = false
  for (const [field, got, want] of pairs) {
    if (want === undefined) continue
    checked = true
    if (got !== want) errors.push(`Envelope ${field} is ${String(got)}, expected ${String(want)}`)
  }

  if (expected.allowedScope !== undefined) {
    checked = true
    const allowed = new Set(expected.allowedScope)
    const outside = envelope.capability_ref.scope.filter(s => !allowed.has(s))
    if (outside.length > 0) {
      errors.push(`Envelope claims scope outside the allowed set: ${outside.join(', ')}`)
    }
  }

  return { checked, errors }
}

/**
 * Create a minimal envelope from non-APS sources.
 * For engines that don't have the full 3-signature chain,
 * this accepts raw fields directly.
 */
export function createMinimalEnvelope(opts: {
  agentDid: string
  runId: string
  actionId: string
  scope: string[]
  revocationStatus: RevocationStatus
  decisionHash: string
  policyRef: string
  evaluationMethod: EvaluationMethod
  verdict: 'permit' | 'deny' | 'narrow' | 'audit'
  evaluatedAt: string
  evaluatorDid: string
  evaluatorSignature: string
  receiptHash: string
  signerPrivateKey: string
  signerPublicKey: string
}): ExecutionEnvelope {

  const envelopeBody = {
    schema: 'execution-envelope.v0.1' as const,
    agent_did: opts.agentDid,
    run_id: opts.runId,
    action_id: opts.actionId,
    capability_ref: {
      manifest_hash: createHash('sha256').update(canonicalizeForWrite(opts.scope)).digest('hex'),
      scope: opts.scope,
      delegation_chain_depth: 1,
      revocation_status: opts.revocationStatus
    },
    decision: {
      decision_hash: opts.decisionHash,
      policy_ref: opts.policyRef,
      evaluation_method: opts.evaluationMethod,
      verdict: opts.verdict,
      narrowing: null,
      evaluated_at: opts.evaluatedAt,
      evaluator_did: opts.evaluatorDid,
      evaluator_signature: opts.evaluatorSignature
    },
    attestation: {
      receipt_hash: opts.receiptHash,
      receipt_type: 'GenericReceipt'
    },
    timestamp: new Date().toISOString()
  }

  const canonical = canonicalizeForWrite(envelopeBody)
  const signatureValue = sign(canonical, opts.signerPrivateKey)

  return {
    ...envelopeBody,
    signature: {
      algorithm: 'Ed25519' as const,
      public_key: opts.signerPublicKey,
      value: signatureValue
    }
  }
}
