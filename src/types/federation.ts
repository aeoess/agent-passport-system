// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Federation — Cross-Gateway Portability (WS-2, WS-3)
// ══════════════════════════════════════════════════════════════════
// WS-2: Receipt Portability — receipts from one gateway accepted by another
// WS-3: Reputation Portability — signed reputation attestations
//
// Gemini S2 Q6: WS-1→WS-2→WS-3 only. WS-4,5 explicitly OUT for Level 1.
// WS-4 (cross-gateway delegation) and WS-5 (cross-gateway dispute)
// require 2PC/consensus — deferred to Level 2 (British Empire).
//
// Key design: Do NOT export full receipt histories. Signed attestation only.
// Foreign gateways see summary proofs, not raw data.
// ══════════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════════
// WS-2: Receipt Portability
// ══════════════════════════════════════════════════════════════════

/** A receipt from one gateway wrapped for import by another gateway.
 *  The importing gateway evaluates the receipt against its import policy
 *  and signs its import decision. */
export interface ForeignReceiptEnvelope {
  /** Receipt being imported */
  receiptId: string
  /** Gateway that originally issued the receipt */
  originGatewayId: string
  /** Original gateway's signature over the receipt */
  originGatewaySignature: string
  /** Agent who performed the action */
  agentId: string
  /** Agent's signature over the receipt */
  agentSignature: string
  /** SHA-256 hash of the full receipt content */
  receiptHash: string
  /** Importing gateway's decision */
  importDecision: 'accepted' | 'rejected'
  /** ISO datetime — when the import decision was made */
  importedAt: string
  /** Importing gateway's signature over the import decision */
  importingGatewaySignature: string
}

// ══════════════════════════════════════════════════════════════════
// WS-3: Reputation Portability
// ══════════════════════════════════════════════════════════════════

/** A signed reputation attestation for cross-gateway portability.
 *  Gemini S2: Do NOT export full receipt histories. Signed attestation only.
 *  The origin gateway vouches for an agent's tier and diversity score
 *  without revealing the underlying receipt data. */
export interface VouchedReputation {
  /** Agent whose reputation is being vouched */
  agentId: string
  /** Gateway that computed and attested this reputation */
  originGatewayId: string
  /** Attested authority tier (from reputation-authority system) */
  attestedTier: number
  /** Attested evidence diversity score */
  attestedDiversityScore: number
  /** ISO datetime — when this attestation was created */
  attestedAt: string
  /** ISO datetime — MUST expire. Reputation is time-bounded. */
  expiresAt: string
  /** Origin gateway's Ed25519 signature */
  originGatewaySignature: string
}
