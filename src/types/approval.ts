// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Approval — Multi-Class Threshold Policies
// ══════════════════════════════════════════════════════════════════
// Consilium Q5 resolution: Multi-class M-of-N Ed25519 counting.
// NOT FROST/Shamir — simple threshold counting per key class for v1.
//
// A MultiClassThresholdPolicy defines:
//   - Multiple key classes (board, recovery, counsel, operations)
//   - Each class has its own M-of-N requirement
//   - ALL class requirements must be satisfied (conjunction)
//   - Timeout behavior (reject or escalate)
//   - Revocation-aware re-evaluation
// ══════════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════════
// Key Class Requirement
// ══════════════════════════════════════════════════════════════════

/** A single requirement within a multi-class threshold policy.
 *  E.g. "2 of 3 board members must sign" or "1 of 2 recovery keys". */
export interface KeyClassRequirement {
  /** Key class role name (e.g. 'board', 'recovery', 'counsel', 'operations') */
  role: string
  /** How many signatures from this class are required */
  requiredSignatures: number
  /** Ed25519 public keys (hex) eligible to sign for this class */
  eligibleKeys: string[]
}

// ══════════════════════════════════════════════════════════════════
// Multi-Class Threshold Policy
// ══════════════════════════════════════════════════════════════════

/** Multi-class M-of-N threshold policy. ALL requirements must be
 *  satisfied (conjunction across key classes) for the policy to pass.
 *
 *  Example: A charter amendment might require:
 *    - 2 of 3 board keys
 *    - 1 of 2 counsel keys
 *  Both conditions must be met simultaneously. */
export interface MultiClassThresholdPolicy {
  /** Unique policy identifier */
  policyId: string
  /** ALL requirements must be satisfied (conjunction) */
  requirements: KeyClassRequirement[]
  /** Seconds allowed to collect all required signatures */
  collectionTimeoutSeconds: number
  /** What happens if the timeout expires before threshold is met */
  onTimeout: 'reject' | 'escalate'
  /** If a signer revokes during collection, re-evaluate threshold (GPT Q5) */
  reevaluateOnRevocation: boolean
}

// ══════════════════════════════════════════════════════════════════
// General-Purpose Approval Policy
// ══════════════════════════════════════════════════════════════════

/** Approval strategy. Multi-class threshold is the most powerful;
 *  simpler modes exist for common patterns. */
export type ApprovalType =
  | 'threshold'       // multi-class M-of-N threshold
  | 'role_required'   // specific office holders must sign
  | 'sequential'      // signatures collected in a defined order
  | 'unanimous'       // every eligible key must sign

/** A general-purpose approval policy for actions beyond charter amendments.
 *  Used for: delegation approval, escrow release, dispute resolution, etc. */
export interface ApprovalPolicy {
  /** Unique policy identifier */
  policyId: string
  /** Which approval strategy to use */
  type: ApprovalType
  /** For 'threshold' — the multi-class threshold policy to apply */
  threshold?: MultiClassThresholdPolicy
  /** For 'role_required' — office IDs whose holders must sign */
  requiredRoles?: string[]
  /** For 'sequential' — office IDs in required signing order */
  sequentialOrder?: string[]
  /** What happens if timeout expires */
  timeoutAction: 'deny' | 'escalate'
  /** Seconds before this approval request expires */
  timeoutSeconds: number
}

// ══════════════════════════════════════════════════════════════════
// Approval Signature
// ══════════════════════════════════════════════════════════════════

/** A single signature collected for an approval request. */
export interface ApprovalSignature {
  /** Ed25519 public key (hex) of the signer */
  publicKey: string
  /** Key class this signer belongs to (matches KeyClassRequirement.role) */
  keyClass: string
  /** If the signer currently holds an office, which one */
  officeId?: string
  /** ISO timestamp */
  signedAt: string
  /** Ed25519 signature over canonical approval content */
  signature: string
}

// ══════════════════════════════════════════════════════════════════
// Approval Request
// ══════════════════════════════════════════════════════════════════

/** What kind of action is being approved. Typed to prevent freeform abuse. */
export type ApprovalSubjectType =
  | 'charter_amendment'
  | 'delegation'
  | 'office_transfer'
  | 'dissolution'
  | 'escrow_release'
  | 'dispute_resolution'

/** A request for multi-party approval of an action. Tracks signature
 *  collection against a policy and determines when threshold is met. */
export interface ApprovalRequest {
  /** Unique request identifier */
  requestId: string
  /** Which approval policy governs this request */
  policyId: string
  /** What is being approved (artifactId, amendmentId, etc.) */
  subject: string
  /** Type of subject — determines how to interpret the subject ID */
  subjectType: ApprovalSubjectType
  /** Who initiated this approval request (public key) */
  requestedBy: string
  /** ISO timestamp */
  requestedAt: string
  /** ISO timestamp — when this request expires */
  expiresAt: string
  /** Signatures collected so far */
  signatures: ApprovalSignature[]
  /** Current status of the approval request */
  status: 'pending' | 'approved' | 'rejected' | 'expired'
}

// ══════════════════════════════════════════════════════════════════
// Approval Verification Results
// ══════════════════════════════════════════════════════════════════

/** Result of evaluating whether an approval request meets its policy. */
export interface ApprovalEvaluation {
  /** Whether the policy threshold has been met */
  met: boolean
  /** Per-class status: which classes are satisfied, which still need sigs */
  classStatus: KeyClassStatus[]
  /** Total valid signatures collected */
  totalValidSignatures: number
  /** Total signatures required across all classes */
  totalRequired: number
  /** Whether the request has expired */
  expired: boolean
  errors: string[]
}

/** Status of signature collection for a single key class. */
export interface KeyClassStatus {
  /** Key class role name */
  role: string
  /** Signatures required for this class */
  required: number
  /** Valid signatures collected for this class */
  collected: number
  /** Whether this class requirement is satisfied */
  satisfied: boolean
}
