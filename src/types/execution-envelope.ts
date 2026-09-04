// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Cross-Engine Signed Execution Envelope — Types
// ══════════════════════════════════════════════════════════════════
// Reference: docs/RFC-SIGNED-EXECUTION-ENVELOPE.md
//
// A minimal signed envelope that any governance engine can emit
// and any verifier can check, without depending on a specific
// trust backend. The APS SDK generates every field from its
// existing 3-signature chain.
// ══════════════════════════════════════════════════════════════════

import type { EffectInstantiationBlock } from '../core/reversibility-fold.js'

export type EvaluationMethod = 'deterministic' | 'probabilistic' | 'model_dependent' | 'hybrid'
export type EnvelopeVerdict = 'permit' | 'deny' | 'narrow' | 'audit'
export type RevocationStatus = 'active' | 'revoked'

export interface ExecutionEnvelope {
  schema: 'execution-envelope.v0.1'

  /** DID of the agent that executed the action */
  agent_did: string
  /** Unique identifier for the task/run context */
  run_id: string
  /** Unique identifier for this specific action */
  action_id: string
  /** Content-addressed request identity (A2A#1672). Optional for backward compat. */
  action_ref?: string

  capability_ref: {
    /** Hash of the capability manifest (delegation scope) at evaluation time */
    manifest_hash: string
    /** Delegation scopes that authorized this action */
    scope: string[]
    /** Depth of the delegation chain */
    delegation_chain_depth: number
    /** Revocation status at execution time */
    revocation_status: RevocationStatus
  }

  decision: {
    /** Hash of the full policy decision object */
    decision_hash: string
    /** Identifier + version of the policy that produced the decision */
    policy_ref: string
    /** Whether the decision can be replayed (deterministic) or only verified (probabilistic) */
    evaluation_method: EvaluationMethod
    /** The verdict: permit, deny, narrow, or audit */
    verdict: EnvelopeVerdict
    /** If verdict is 'narrow', what constraints were applied */
    narrowing: string | null
    /** When the decision was made */
    evaluated_at: string
    /** DID of the evaluator */
    evaluator_did: string
    /** Evaluator's signature over the decision */
    evaluator_signature: string
  }

  attestation: {
    /** Hash of the execution receipt */
    receipt_hash: string
    /** Type of receipt (e.g., 'PolicyReceipt', 'ActionReceipt') */
    receipt_type: string
    /** Full signature chain (if engine supports multi-signature) */
    chain_signatures?: {
      intent: string
      decision: string
      receipt: string
    }
  }

  /** When the envelope was created */
  timestamp: string

  /** OPTIONAL effect-instantiation block (reversibility fold, spec v2 section 3).
   *  Absent on existing receipts, which stay valid unchanged. A fold over a
   *  receipt lacking it is incomplete, never irreversible. When present the
   *  block is part of the signed body; its presence does not change any
   *  existing validation path. */
  effect_instantiation?: EffectInstantiationBlock

  signature: {
    algorithm: 'Ed25519'
    /** Public key of the signer */
    public_key: string
    /** Signature over the canonical envelope (excluding signature block) */
    value: string
  }
}

/** Whether a signer was shown to be one the relying party accepts.
 *  Mirrors `key_authority` in src/v2/identity-binding/types.ts, and for the
 *  same reason: 'unresolved' means the verifier could not establish the fact,
 *  which is not the same claim as having disproved it, and neither is an
 *  acceptance. */
export type EnvelopeSignerAuthority = 'verified' | 'unresolved' | 'rejected'

/** Result of verifying an execution envelope */
export interface EnvelopeVerification {
  /** The conjunction of every property below. True only when the envelope was
   *  signed by a key the caller trusts, the evaluator signature was checked
   *  against caller-supplied bytes and a caller-supplied key, the capability
   *  was active, the decision was fresh, and every expected-context field the
   *  caller stated matched. Never true on the envelope's self-consistency
   *  alone. */
  valid: boolean
  /** The envelope's bytes verify under the key the envelope itself carries.
   *  This is integrity plus proof of possession, NOT authorization: the key is
   *  the envelope's own claim about itself. True on some rejected results. */
  signatureValid: boolean
  /** Whether the key that signed the envelope is one the caller named as
   *  trusted. 'unresolved' when the caller named none. */
  signerAuthority: EnvelopeSignerAuthority
  /** Whether the evaluator's signature over the original decision verified
   *  under the evaluator key the caller supplied. Never true on the strength
   *  of the field being a non-empty string. */
  evaluatorSignatureValid: boolean
  /** Whether that check could be made at all. The envelope carries a hash of
   *  the decision, not the decision, and Ed25519 here is not prehashed, so the
   *  signed bytes cannot be reconstructed from the envelope: without the
   *  original decision this is 'unresolved'. */
  evaluatorAuthority: EnvelopeSignerAuthority
  /** Capability not revoked */
  capabilityActive: boolean
  /** Decision not expired (if expiry window provided) */
  decisionFresh: boolean
  /** Whether the caller stated any expected context to match against. False
   *  means the envelope's agent, action, scope, policy and evaluator were
   *  read but not checked against anything. */
  contextChecked: boolean
  /** Whether every expected-context field the caller stated matched. Always
   *  false when none was stated. */
  contextValid: boolean
  /** Errors encountered */
  errors: string[]
}
