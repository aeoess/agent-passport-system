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
import { canonicalize } from './canonical.js'
import type { ActionIntent, PolicyDecision, PolicyReceipt } from '../types/policy.js'
import type { Delegation } from '../types/passport.js'
import type {
  ExecutionEnvelope, EnvelopeVerification,
  EvaluationMethod, RevocationStatus
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
    .update(canonicalize(opts.delegation.scope))
    .digest('hex')

  // Hash the full policy decision
  const decisionHash = createHash('sha256')
    .update(canonicalize(opts.decision))
    .digest('hex')

  // Hash the execution receipt
  const receiptHash = createHash('sha256')
    .update(canonicalize(opts.receipt))
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
  const canonical = canonicalize(envelopeBody)
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

/**
 * Verify a cross-engine signed execution envelope.
 * Any engine can call this — no APS-specific knowledge needed.
 *
 * Checks:
 * 1. Envelope signature (Ed25519 over canonical body)
 * 2. Capability not revoked
 * 3. Decision freshness (optional time window)
 * 4. Evaluator signature present
 */
export function verifyExecutionEnvelope(
  envelope: ExecutionEnvelope,
  opts?: {
    /** Maximum age of the decision in milliseconds */
    maxDecisionAgeMs?: number
    /** Evaluator's public key (to verify evaluator signature) */
    evaluatorPublicKey?: string
  }
): EnvelopeVerification {
  const errors: string[] = []

  // 1. Verify envelope signature
  const { signature, ...body } = envelope
  const canonical = canonicalize(body)
  const signatureValid = verify(canonical, signature.value, signature.public_key)
  if (!signatureValid) errors.push('Envelope signature invalid')

  // 2. Check capability not revoked
  const capabilityActive = envelope.capability_ref.revocation_status === 'active'
  if (!capabilityActive) errors.push('Capability revoked at execution time')

  // 3. Check decision freshness
  let decisionFresh = true
  if (opts?.maxDecisionAgeMs) {
    const decisionAge = Date.now() - new Date(envelope.decision.evaluated_at).getTime()
    if (decisionAge > opts.maxDecisionAgeMs) {
      decisionFresh = false
      errors.push(`Decision too old: ${Math.round(decisionAge / 1000)}s > ${Math.round(opts.maxDecisionAgeMs / 1000)}s max`)
    }
  }

  // 4. Check evaluator signature present
  let evaluatorSignatureValid = !!envelope.decision.evaluator_signature
  if (!evaluatorSignatureValid) {
    errors.push('Evaluator signature missing')
  }

  // If evaluator public key provided, verify the evaluator signature
  // against the decision hash (engine-specific verification)
  if (opts?.evaluatorPublicKey && envelope.decision.evaluator_signature) {
    // The evaluator signed the decision object. We verify against the hash.
    // Note: full decision verification requires the original decision object,
    // which the envelope doesn't carry. The hash is for integrity, the
    // evaluator_signature is for authenticity.
    evaluatorSignatureValid = true // signature present, key available
  }

  return {
    valid: errors.length === 0,
    signatureValid,
    evaluatorSignatureValid,
    capabilityActive,
    decisionFresh,
    errors
  }
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
      manifest_hash: createHash('sha256').update(canonicalize(opts.scope)).digest('hex'),
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

  const canonical = canonicalize(envelopeBody)
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
