// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Attribution Consent — citation requires the cited principal's sign-off
// ══════════════════════════════════════════════════════════════════
// Triggered by the Apr 14 A2A#1734 pattern: an agent cited a third-party
// principal's scoped position as support for a broader governance claim
// the cited principal never made.
//
// WHAT THIS ESTABLISHES. A citation is accepted only when the artifact
// presents an AttributionReceipt whose cited_principal consented, where
// consenting means a signature by the key that principal's DID commits to.
// Each party is named twice, as a DID and as a key, and the two are bound:
// without that, the principal whose consent is being proved would be
// supplying the key that proves it, and naming any victim would cost an
// attacker nothing. Binding uses the self-certifying rule from the
// credential surfaces, so a DID that commits to no key is refused rather
// than assumed; this SDK resolves no DID documents here.
//
// WHAT IT DOES NOT ESTABLISH. That the citation is a fair reading of what
// the principal said, only that they signed this citation_content. And it
// binds nothing that does not call checkArtifactCitations(): verifyCharter()
// and verifyCompletionReceipt() do. SettlementRecord in
// types/data-contribution.ts declares a citations field that nothing checks:
// its verifySettlement() is a stub that throws, the type is exported from no
// index, and it has no other reader. So a settlement carrying citations is not
// gated by this primitive today. Note this is NOT the SettlementRecord in
// v2/attribution-settlement, a different type with the same name, which has no
// citations field and is verified by verifySettlementRecord().
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
