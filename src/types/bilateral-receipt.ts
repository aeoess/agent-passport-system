// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Bilateral Receipt — Type Definitions
// ══════════════════════════════════════════════════════════════════
// Co-signed interaction records where BOTH agents sign the same
// outcome. Structurally stronger than unilateral gateway receipts
// against Sybil manipulation — you can't inflate reputation
// without collusion from the counterparty.
//
// Reference: viftode4's co-signed interaction model
//            IETF draft-pouwelse-trustchain-01
// ══════════════════════════════════════════════════════════════════

// ── Interaction Outcome ──
// What both parties agree happened.
export interface InteractionOutcome {
  toolName: string
  requestHash: string         // SHA-256 of the canonical request
  responseHash: string        // SHA-256 of the canonical response
  status: 'success' | 'failure' | 'partial'
  summary: string
  /** Optional spend amount attributed to this interaction */
  spend?: { amount: number; currency: string }
}

// ── Bilateral Receipt ──
// Both requesting and serving agents sign the same record.
// Optional gateway countersignature as a third witness.
export interface BilateralReceipt {
  receiptId: string
  version: '1.0'

  // Participants
  requestingAgentId: string
  servingAgentId: string
  delegationId?: string          // if the interaction was delegation-scoped

  // What happened (both parties agree on this)
  outcome: InteractionOutcome

  // Timing
  requestedAt: string            // ISO 8601 — when the request was made
  completedAt: string            // ISO 8601 — when the response was delivered
  agreedAt: string               // ISO 8601 — when both parties signed

  // Three-signature chain
  requestingAgentSignature: string  // Ed25519 by requesting agent
  servingAgentSignature: string     // Ed25519 by serving agent
  gatewaySignature?: string         // optional Ed25519 by witnessing gateway

  // Evidence commitments (external attestations bound into the receipt)
  evidenceCommitments?: EvidenceCommitment[]

  /**
   * Optional audience binding. When present, this receipt is bound to the named
   * recipient identifier(s); a verifier rejects it when presented to any other
   * recipient (see src/v2/audience-binding). Additive and versioned: a receipt
   * that OMITS this field signs and serializes byte-for-byte as before, so
   * existing receipts remain valid. Both co-signers sign over it when present.
   */
  aud?: import('../v2/audience-binding/types.js').AudienceBinding
  // Field-disclosure profile (additive, versioned slot).
  // Commits to a payload by hash + URI with a per-field disclosure policy so
  // raw sensitive payloads are never embedded. Optional: a receipt that omits
  // it is byte-identical to one built before this slot existed (canonicalize
  // strips undefined keys), so existing receipt signatures are unaffected.
  // Shape: FieldDisclosureProfile from src/v2/hash-pointer. Typed as unknown
  // here to keep this v1 type file free of a v2 import; the builder and
  // verifier in src/v2/hash-pointer carry the concrete type.
  fieldDisclosureProfile?: unknown
}

// ── Evidence Commitment ──
// Binds an external attestation into a receipt by hash commitment.
// The full attestation is NOT embedded — only a hash.
// Verifier fetches the attestation out-of-band and checks hash match.
// Reference: douglasborthwick-crypto's credential_hash pattern.
export interface EvidenceCommitment {
  type: string                   // e.g. 'wallet_state', 'compliance_check', 'identity_verification'
  credentialHash: string         // SHA-256 of the full signed credential (JWT, JWS, etc.)
  issuerKid?: string             // key ID of the credential issuer
  jwks?: string                  // JWKS endpoint for offline verification
  pass?: boolean                 // whether the credential check passed
  committedAt: string            // ISO 8601
  // How the committing party obtained the key it used when it checked the
  // credential behind credentialHash. Additive and optional: a commitment
  // that omits it serializes and signs byte-for-byte as before (the receipt
  // body is canonicalized with canonicalize(), which strips undefined keys).
  // Shape and validation rules live in src/v2/verification-source.
  verificationSource?: import('../v2/verification-source/types.js').VerificationSource
}

// ── Revocation Reason ──
// Why a delegation was revoked. Different reasons have different
// verification semantics (especially 'compromise').
export type RevocationReason =
  | 'key_rotation'     // planned rotation, pre-revocation proofs safe
  | 'compromise'       // key compromised, ALL proofs suspect
  | 'decommission'     // agent retired, pre-revocation proofs safe
  | 'policy_violation' // agent violated policy, pre-revocation proofs safe
  | 'manual'           // human-initiated, pre-revocation proofs safe

// ── Bilateral Receipt Verification ──
export interface BilateralReceiptVerification {
  valid: boolean
  requestingAgentSignatureValid: boolean
  servingAgentSignatureValid: boolean
  gatewaySignatureValid: boolean | null  // null if no gateway signature
  outcomeConsistent: boolean             // both signatures cover same outcome
  timingValid: boolean
  errors: string[]
}

// ── Compromise Window Check ──
// Result of checking a proof timestamp against a compromise window.
export interface CompromiseWindowCheck {
  status: 'safe' | 'warn' | 'error'
  reason: string
  proofTimestamp: string
  revokedAt: string
  compromisedSince?: string
}
