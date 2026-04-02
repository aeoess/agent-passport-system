// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Execution Attestation — Type Definitions (Checkpoint 3)
// ══════════════════════════════════════════════════════════════════
// Closes the authorization→execution gap identified by QueBallSharken
// and desiorac on OWASP#802 and qntm#6.
//
// Problem: PolicyReceipt proves what was AUTHORIZED but NOT what was
// EXECUTED. The receipt is signed before execution — a lying agent can
// do something different than what was authorized.
//
// Solution: The execution environment (sandbox/container/runtime)
// produces a Tier 1 infrastructure attestation of what actually ran,
// signed by the environment — NOT the agent. Infrastructure testimony
// the agent can't fabricate.
// ══════════════════════════════════════════════════════════════════

// ── Execution Drift ──
// When intent parameters don't match execution parameters.
export interface ExecutionDrift {
  fields: Array<{
    field: string
    intentValueHash: string      // SHA-256 of what was declared
    executionValueHash: string   // SHA-256 of what actually ran
  }>
  severity: ExecutionDriftSeverity
}

export type ExecutionDriftSeverity = 'none' | 'benign' | 'suspicious' | 'critical'

// ── Attestor Type ──
export type AttestorType = 'sandbox' | 'container' | 'runtime' | 'gateway' | 'orchestrator'

// ── Execution Attestation ──
// Signed by infrastructure that witnessed execution — NOT by the agent.
// Binds to PolicyReceipt via policyReceiptId and executionFrameId.
export interface ExecutionAttestation {
  executionId: string              // unique ID for this execution event
  agentId: string                  // which agent executed
  attestorId: string               // which infrastructure witnessed (DID or URI)
  attestorType: AttestorType

  // What actually happened
  toolName: string                 // which tool/action was invoked
  parameterHash: string            // SHA-256 of actual parameters executed
  resultHash: string               // SHA-256 of actual result returned

  // Binding to authorization
  policyReceiptId: string          // links back to the PolicyReceipt
  executionFrameId: string         // matches PolicyReceipt.compoundDigest frame
  intentParameterHash: string      // SHA-256 of declared intent parameters

  // Verification
  match: boolean                   // parameterHash === intentParameterHash
  drift: ExecutionDrift            // always present; severity 'none' when match=true

  // Timing
  executionStartedAt: string       // ISO 8601
  executionCompletedAt: string     // ISO 8601
  attestedAt: string               // ISO 8601

  // Cryptographic proof
  signature: string                // Ed25519 signed by attestor key

  // Trust context at execution time (AV: 0xbrainkid NVIDIA#682)
  trust_context?: {
    score_at_execution: number     // trust score (0-1) when this tool was invoked
    grade_at_execution: number     // passport grade (0-3) at execution time
    source: string                 // where the score came from (gateway URL)
  }
}

// ── Execution Attestation Verification Result ──
export interface ExecutionAttestationVerification {
  valid: boolean
  signatureValid: boolean
  receiptBindingValid: boolean     // policyReceiptId + executionFrameId present
  parameterMatch: boolean          // intent params match execution params
  timingValid: boolean             // execution timestamps are sensible
  drift: ExecutionDrift
  errors: string[]
}

// ── Create Execution Attestation Input ──
// What the sandbox/runtime passes to create an attestation.
export interface CreateExecutionAttestationInput {
  agentId: string
  attestorId: string
  attestorType: AttestorType

  toolName: string
  actualParameters: Record<string, unknown>
  actualResult: Record<string, unknown>

  policyReceiptId: string
  executionFrameId: string
  intentParameters: Record<string, unknown>

  executionStartedAt: string
  executionCompletedAt: string
  /** Execution context for drift classification (e.g. 'payment', 'search', 'auth') */
  executionContext?: string
  /** Trust context at execution time (0xbrainkid NVIDIA#682) */
  trust_context?: {
    score_at_execution: number
    grade_at_execution: number
    source: string
  }
}

// ── Drift Classification Rule ──
// Pluggable rules for classifying drift severity.
export interface DriftClassificationRule {
  field: string              // field name pattern (exact or '*' for default)
  context?: string           // execution context ('payment' | 'search' | 'auth' | '*')
  severity: ExecutionDriftSeverity
  reason: string
}

// ── Default drift rules ──
// Fields that commonly change for benign reasons get lower severity.
export const DEFAULT_DRIFT_RULES: DriftClassificationRule[] = [
  { field: 'timestamp', severity: 'benign', reason: 'Timestamps may differ between intent and execution' },
  { field: 'requestId', severity: 'benign', reason: 'Request IDs are generated at execution time' },
  { field: 'nonce', severity: 'benign', reason: 'Nonces are expected to differ' },
  { field: 'query', severity: 'suspicious', reason: 'Query modification may indicate intent drift' },
  { field: 'target', severity: 'critical', reason: 'Target change indicates possible hijacking' },
  { field: 'recipient', severity: 'critical', reason: 'Recipient change indicates possible exfiltration' },
  { field: 'amount', severity: 'critical', reason: 'Amount change indicates possible theft' },
  { field: '*', severity: 'suspicious', reason: 'Unknown field drift requires investigation' },
]
