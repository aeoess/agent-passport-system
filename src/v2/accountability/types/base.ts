// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * @fileoverview Accountability primitive foundation.
 *
 * Verbal confessions, not brain scans. APS receipts are signed declarations
 * about what the system observed, not causal proofs of agent cognition.
 * Every accountability receipt MUST declare its scope_of_claim explicitly.
 */

export type CaptureMode =
  | 'gateway_observed'
  | 'runtime_attested'
  | 'self_attested'
  | 'partial'
  | 'unknown'

export type Completeness = 'complete' | 'partial' | 'best_effort'

export interface ScopeOfClaim {
  /** 1-2 sentences: what this receipt claims cryptographically. */
  asserts: string
  /** Explicit list of what this receipt does NOT prove. */
  does_not_assert: string[]
  capture_mode: CaptureMode
  completeness: Completeness
  /** True when the agent itself signed without independent attestation.
   *  Self-attested receipts have lower evidentiary weight. */
  self_attested: boolean
}

export interface AccountabilityReceiptBase {
  /** e.g. 'aps:action:v1', 'aps:authority_boundary:v1' */
  claim_type: string
  /** sha256(jcs(this excluding signature)) — content-addressed identity */
  receipt_id: string
  /** ISO 8601 UTC with milliseconds, ending Z */
  timestamp: string
  /** Ed25519 hex pubkey of signer */
  signer_did: string
  /** Required honest scope declaration */
  scope_of_claim: ScopeOfClaim
  /** Ed25519 signature over JCS(this excluding signature), hex */
  signature: string
}
