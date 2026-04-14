// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Consent — citation requires the cited principal's sign-off
// ══════════════════════════════════════════════════════════════════
// Triggered by the Apr 14 A2A#1734 pattern: an agent cited a third-party
// principal's scoped position as support for a broader governance claim
// the cited principal never made. This primitive makes that impossible
// inside binding artifacts (charters, settlements, completion receipts):
// a citation without a signed AttributionReceipt is rejected by
// checkArtifactCitations().
// ══════════════════════════════════════════════════════════════════

import type { HybridTimestamp } from '../../types/time.js'

export type AgentDID = string
export type PrincipalDID = string
export type ContextID = string
export type Ed25519Signature = string

/** A binding artifact-shaped object that may carry citations. */
export interface CitingArtifact {
  citations?: ArtifactCitation[]
  [k: string]: unknown
}

/** One citation referenced from an artifact. Points at a receipt by id,
 *  repeats the content + principal so tampering with the artifact alone
 *  cannot silently swap out what was cited. */
export interface ArtifactCitation {
  receipt_id: string
  cited_principal: PrincipalDID
  citation_content: string
}

export interface AttributionReceipt {
  /** sha256 hex of the canonical unsigned core (no signatures included). */
  id: string
  version: '1.0'
  citer: AgentDID
  /** Public key (hex) of the citer — used to verify citer_signature offline. */
  citer_public_key: string
  cited_principal: PrincipalDID
  /** Public key (hex) of the cited principal — used to verify the consent
   *  signature when it is added. */
  cited_principal_public_key: string
  /** The quoted or paraphrased claim being attributed to cited_principal. */
  citation_content: string
  /** The binding artifact this citation is intended for (charter id,
   *  settlement id, completion receipt id, etc). A receipt is scoped to
   *  a single binding context. */
  binding_context: ContextID
  created_at: HybridTimestamp
  expires_at: HybridTimestamp
  /** Ed25519 signature by the citer over the unsigned core. */
  citer_signature: Ed25519Signature
  /** Ed25519 signature by the cited principal over the unsigned core.
   *  Present once consent has been granted. */
  cited_principal_signature?: Ed25519Signature
}

export interface AttributionConsentResult {
  valid: boolean
  reason?: string
}
