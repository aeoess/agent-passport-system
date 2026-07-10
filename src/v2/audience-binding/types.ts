// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
/**
 * @fileoverview Audience-binding types: a versioned, additive `aud` profile for
 * delegation and receipt proofs.
 *
 * ── WHAT THIS IS ──────────────────────────────────────────────────────────
 * A passport (delegation or receipt) issued for recipient A must be rejected
 * when presented to recipient B. The `aud` field names the intended
 * recipient(s); a verifier holding its own recipient identity checks
 * membership. This is the proof-object analogue of the OAuth `aud` claim
 * (RFC 7519 §4.1.3 / RFC 8693 token exchange) and reuses the same
 * array-normalize + membership-check algorithm already in
 * src/adapters/oauth-rfc8693.
 *
 * ── WHY VERSIONED AND ADDITIVE ────────────────────────────────────────────
 * The `aud` slot is OPTIONAL on the proof object. A proof that OMITS it signs
 * and serializes byte-for-byte as it did before this module existed; nothing
 * about an audience-free proof changes. The slot is only "required" relative
 * to a verifier POLICY (`requireAudience`) or to a named PROFILE; it is never
 * issuer-asserted assurance. Audience binding is a mechanical fact (which
 * recipient identifier the issuer named), not a verifier-derived assurance
 * scalar.
 *
 * ── RELATION TO cross_chain ───────────────────────────────────────────────
 * cross_chain (src/types/cross-chain.ts) prevents the confused-deputy problem
 * at the DATA-FLOW layer: it stops authority from principal X being combined
 * with a destination governed by principal Y unless a CrossChainPermit
 * authorizes it. Audience binding operates at the PROOF-PRESENTATION layer: it
 * stops a proof minted for recipient A from being replayed at recipient B.
 * They are complementary, not competing. `reconcileAudienceWithCrossChain`
 * (see reconcile.ts) keeps a single denial from being counted twice.
 */

/**
 * The audience descriptor carried additively on a proof. A proof object gains
 * a single optional `aud` field of this shape. When absent, the proof is
 * audience-unbound and serializes exactly as before.
 *
 * `recipients` is the set of recipient identifiers the proof was issued for.
 * An identifier is an opaque string the relying parties agree on out of band
 * (a DID, a public key hex, a service URL, a logical recipient name). This
 * module does not interpret the identifier; it only checks membership.
 */
export interface AudienceBinding {
  /**
   * Profile/version tag for the audience-binding slot. Fixed for this version.
   * Lets a future breaking change to the slot bump the version without
   * silently reinterpreting old proofs.
   */
  profile: 'aps:audience-binding:v1'
  /**
   * One or more recipient identifiers this proof is bound to. MUST be
   * non-empty when present: an empty audience is meaningless and is rejected
   * as malformed rather than treated as "any recipient".
   */
  recipients: string[]
}

/** Fixed profile identifier for the audience-binding slot. */
export const AUDIENCE_BINDING_PROFILE = 'aps:audience-binding:v1' as const

/**
 * Verifier-side acceptance policy for audience checks. This is a relying-party
 * policy input, never read from the proof.
 */
export interface AudiencePolicy {
  /**
   * The relying party's own recipient identifier. A bound proof is accepted
   * only if `recipientId` is a member of the proof's `aud.recipients`.
   */
  recipientId: string
  /**
   * When true, a proof that OMITS `aud` is rejected (the profile requires
   * audience binding). When false or omitted, an audience-unbound proof is
   * accepted on the audience facet (it neither passes nor fails membership;
   * the facet is not_applicable).
   */
  requireAudience?: boolean
}

/**
 * The four-valued status of an audience check, consistent with the Belnap
 * ConstraintStatus lattice (src/types/gateway.ts):
 *   - 'pass'           : the proof is bound and the relying party is a member.
 *   - 'fail'           : the proof is bound and the relying party is NOT a
 *                        member, OR the profile required binding and it is
 *                        absent, OR the binding is malformed.
 *   - 'not_applicable' : the proof is unbound and the policy does not require
 *                        binding. Audience does not constrain this proof.
 *   - 'unknown'        : insufficient information to evaluate (e.g. the policy
 *                        carries no recipientId to check against).
 */
export type AudienceStatus = 'pass' | 'fail' | 'not_applicable' | 'unknown'

/** Precise reason codes for an audience check, for negative-path testing. */
export type AudienceReason =
  | 'audience_match'           // pass: relying party is a named recipient
  | 'audience_mismatch'        // fail: relying party not in the named set
  | 'audience_required_absent' // fail: policy required binding, proof omits it
  | 'audience_malformed'       // fail: aud present but empty/ill-formed
  | 'audience_unbound'         // not_applicable: unbound, binding not required
  | 'audience_unknown'         // unknown: no recipientId in policy to check

/** Result of an audience check against a single proof. */
export interface AudienceCheckResult {
  status: AudienceStatus
  reason: AudienceReason
  /** The recipient set the proof named, when it was bound. */
  recipients?: string[]
  /** The relying party identifier the check was run for. */
  checkedAgainst?: string
  /** Human-readable explanation (for logs, not for parsing). */
  message: string
}
