// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Foreign Counterparty — Non-APS Entity Handling
// ══════════════════════════════════════════════════════════════════
// GPT correction #14: needs expiration + reclassification.
// Not every agent in a transaction will have an APS passport.
// ForeignCounterpartyEnvelope wraps non-APS entities with:
//   - Provenance classification (unknown, partially governed, legacy, human)
//   - Trust classification (untrusted → probationary → attested → vouched)
//   - Sandbox policy (constrained operations)
//   - Lifecycle management (expiry, auto-promotion, auto-demotion)
//
// Key invariant: foreign trust MUST expire. No permanent foreign trust.
// ══════════════════════════════════════════════════════════════════

/** How the foreign entity's governance posture is classified.
 *  Determines the baseline sandbox restrictions. */
export type ForeignProvenanceClass =
  | 'unknown'              // no governance information available
  | 'partially_governed'   // some governance signals (e.g. API key auth, rate limits)
  | 'legacy_api'           // traditional API with no agent governance
  | 'human_operated'       // human behind a non-APS interface

/** Trust level earned through interaction history.
 *  Monotonically upgradeable via receipts; demotable on dispute. */
export type ForeignTrustClass =
  | 'untrusted'            // default — maximum sandbox restrictions
  | 'probationary'         // some successful interactions, still restricted
  | 'attested'             // gateway has verified governance signals
  | 'vouched'              // an APS agent vouches for this entity

// ══════════════════════════════════════════════════════════════════
// Sandbox Policy
// ══════════════════════════════════════════════════════════════════

/** Operational constraints applied to foreign entities.
 *  All foreign interactions are sandboxed — the gateway enforces these limits. */
export interface ForeignSandboxPolicy {
  /** Maximum spend per single action */
  maxSpendPerAction: number
  /** Whether a witness must attest all foreign interactions (true for v1) */
  requireWitness: boolean
  /** Whether escrow is required for all foreign transactions */
  requireEscrow: boolean
  /** Whether data can leave the gateway to the foreign entity */
  dataEgressAllowed: boolean
  /** Maximum concurrent actions this foreign entity can have in-flight */
  maxConcurrentActions: number
}

// ══════════════════════════════════════════════════════════════════
// Reclassification Rules (GPT #14)
// ══════════════════════════════════════════════════════════════════

/** Rules for automatically promoting or demoting foreign trust.
 *  Trust is not static — it changes based on interaction history. */
export interface ForeignReclassificationRules {
  /** Number of successful receipts needed to auto-promote trust class */
  autoPromoteAfterReceipts?: number
  /** Automatically demote trust class on any dispute */
  autoDemoteOnDispute: boolean
  /** Seconds between mandatory reviews of this foreign entity */
  reviewIntervalSeconds: number
}

// ══════════════════════════════════════════════════════════════════
// Foreign Counterparty Envelope
// ══════════════════════════════════════════════════════════════════

/** Gateway-issued envelope wrapping a non-APS entity for interaction.
 *  Every foreign interaction goes through this envelope — no raw foreign access. */
export interface ForeignCounterpartyEnvelope {
  /** Unique envelope identifier */
  envelopeId: string
  /** APS-internal alias for this foreign entity */
  localAlias: string
  /** How the entity's governance posture is classified */
  provenanceClass: ForeignProvenanceClass
  /** Trust level earned through interaction history */
  trustClass: ForeignTrustClass
  /** Operations this foreign entity is allowed to perform */
  admissibleOperations: string[]
  /** Sandbox constraints enforced by the gateway */
  sandboxPolicy: ForeignSandboxPolicy
  // ── Lifecycle (GPT correction #14) ──
  /** ISO datetime — when this envelope was issued */
  issuedAt: string
  /** ISO datetime — MUST expire. No permanent foreign trust. */
  expiresAt: string
  /** ISO datetime — last review of this envelope */
  reviewedAt?: string
  /** Rules for automatic trust promotion/demotion */
  reclassificationRules: ForeignReclassificationRules
  // ── Vouching ──
  /** APS agent public key that vouches for this entity */
  vouchedBy?: string
  /** ISO datetime — when the vouch expires */
  vouchExpiresAt?: string
  // ── Gateway ──
  /** Gateway that issued this envelope */
  gatewayId: string
  /** Gateway signature over the envelope */
  gatewaySignature: string
}
