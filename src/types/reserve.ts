// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Reserve Attestation — Funding Proof for Delegations
// ══════════════════════════════════════════════════════════════════
// GPT correction #15: needs liability semantics.
// Gemini: build AFTER CharterCore (funding claims need institutional context).
//
// A ReserveAttestation is a signed claim that a delegation has
// actual funds behind it. Without this, spend limits are unverifiable
// promises. The assurance class indicates HOW the reserve was verified.
//
// Key invariant: attestations MUST expire. No permanent reserve claims.
// ══════════════════════════════════════════════════════════════════

/** How the reserve was verified. Ordered by strength:
 *  unbacked < self_attested < gateway_attested < escrow_backed < externally_attested */
export type ReserveAssuranceClass =
  | 'unbacked'              // spend authority with no reserve proof
  | 'self_attested'         // agent/principal claims reserves exist
  | 'gateway_attested'      // gateway verified reserve connection
  | 'escrow_backed'         // funds held in escrow
  | 'externally_attested'   // third-party oracle confirms reserves

/** How the attestation basis was established (GPT #15). */
export type AttestationBasis =
  | 'api_balance_check'     // programmatic balance check via API
  | 'bank_statement'        // document-based verification
  | 'escrow_lock'           // funds locked in escrow contract
  | 'self_declaration'      // unverified self-report

/** What happens if the attestation is false (GPT #15). */
export type FalseAttestationPenalty =
  | 'reputation_slash'      // attester's reputation is penalized
  | 'bond_forfeit'          // attester loses posted bond
  | 'dispute_eligible'      // opens dispute resolution path
  | 'none'                  // no penalty (unbacked)

/** Liability semantics for a reserve attestation (GPT #15).
 *  Answers: what happens if this attestation turns out to be false? */
export interface ReserveAttestationLiability {
  /** How the reserve was verified */
  attestationBasis: AttestationBasis
  /** Can the attester revoke this attestation unilaterally? */
  isRevocable: boolean
  /** Penalty for false attestation */
  falseAttestationPenalty: FalseAttestationPenalty
  /** Optional description of verification method */
  verificationMethod?: string
}

// ══════════════════════════════════════════════════════════════════
// Reserve Attestation
// ══════════════════════════════════════════════════════════════════

/** A signed claim that a delegation has actual reserves behind it.
 *  Without this, spend limits on delegations are unverifiable promises.
 *
 *  Institutional context is required (GPT: meaningless without charter anchor).
 *  The attestation must identify WHICH charter and WHICH office authorized it. */
export interface ReserveAttestation {
  /** Unique attestation identifier */
  attestationId: string
  /** Delegation this attestation covers */
  delegationId: string
  /** Assurance class — how the reserve was verified */
  assuranceClass: ReserveAssuranceClass
  /** Amount attested */
  attestedAmount: { value: number; currency: string }
  /** Who created this attestation (public key) */
  attestedBy: string
  /** Which charter backs this attestation (institutional context) */
  charterAnchor?: string
  /** Which office authorized the attestation */
  officeId?: string
  /** Liability semantics (GPT #15) */
  liability: ReserveAttestationLiability
  /** ISO datetime — when attested */
  attestedAt: string
  /** ISO datetime — MUST expire. No permanent reserve claims. */
  expiresAt: string
  /** Ed25519 signature over canonical attestation content */
  signature: string
}
