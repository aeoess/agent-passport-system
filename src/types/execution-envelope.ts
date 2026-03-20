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

  signature: {
    algorithm: 'Ed25519'
    /** Public key of the signer */
    public_key: string
    /** Signature over the canonical envelope (excluding signature block) */
    value: string
  }
}

/** Result of verifying an execution envelope */
export interface EnvelopeVerification {
  /** Overall validity */
  valid: boolean
  /** Envelope signature verified */
  signatureValid: boolean
  /** Evaluator signature verified */
  evaluatorSignatureValid: boolean
  /** Capability not revoked */
  capabilityActive: boolean
  /** Decision not expired (if expiry window provided) */
  decisionFresh: boolean
  /** Errors encountered */
  errors: string[]
}
