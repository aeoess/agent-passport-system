// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Mutual Authentication v1 — types
// ══════════════════════════════════════════════════════════════════
// Closes the asymmetry in APS where agents authenticate to systems
// but systems do not authenticate to agents. This module specifies
// the envelope format and handshake semantics for two-way attested
// auth between an Agent and an Information System (IS).
//
// Scope boundary (deliberate):
//   - local verification against carried trust anchors
//   - no federation, no gossip, no distributed CA
//   - no transparency log, no consensus revocation
//   - trust anchor bundle format is portable and signed
//   - revocation is local-cache + expiry; federation-distributed
//     revocation (if it ever exists) would layer on top
// ══════════════════════════════════════════════════════════════════

import type { SignedPassport, Delegation } from '../../types/passport.js'

// ── Certificate (agent or IS) ──

/** Role of the party this certificate identifies. */
export type MutualAuthRole = 'agent' | 'information_system'

/** Minimal certificate carried by a party for mutual-auth handshake.
 *
 *  For an agent, the certificate is a thin wrapper over the existing
 *  APS passport plus active delegation context. For an IS, it is a
 *  first-class shape this module defines: a signed statement that
 *  this endpoint is authorized to serve the named resource domain.
 */
export interface MutualAuthCertificate {
  spec_version: '1.0'
  role: MutualAuthRole
  subject_id: string
  issuer_id: string
  issuer_role: MutualAuthRole | 'trust_anchor'
  issuer_pubkey_hex: string
  subject_pubkey_hex: string
  /** Earliest time this cert is valid (unix ms). */
  not_before: number
  /** Latest time this cert is valid (unix ms). */
  not_after: number
  /** For agents: APS passport agent_id they are acting under.
   *  For IS: resource domain they are authorized to serve
   *  (e.g. "api.bank.example.com"). */
  binding: string
  /** Optional APS attestation grade for an agent cert (0..3). */
  attestation_grade?: 0 | 1 | 2 | 3
  /** Protocol versions the subject supports, highest first. Used for
   *  downgrade-attack detection during handshake. */
  supported_versions: string[]
  /** Optional list of session-level capabilities this cert grants.
   *  Treated as a set; absence means no capabilities. */
  capabilities?: string[]
  /** Ed25519 signature over the canonical form of this object with
   *  `signature_b64` omitted. */
  signature_b64: string
}

// ── Trust anchor bundle ──

/** Self-contained trust anchor entry carried locally by a party.
 *  Local verification matches a certificate's `issuer_pubkey_hex`
 *  against this list. No network call is performed. */
export interface TrustAnchor {
  anchor_id: string
  display_name: string
  role: MutualAuthRole | 'trust_anchor'
  pubkey_hex: string
  not_before: number
  not_after: number
  /** Optional: constrain this anchor to vouch only for certs whose
   *  `binding` matches one of these patterns (glob, prefix, or
   *  exact). Empty/omitted means unconstrained. */
  binding_constraints?: string[]
}

export interface TrustAnchorBundle {
  spec_version: '1.0'
  bundle_id: string
  issued_at: number
  anchors: TrustAnchor[]
  /** Parties carrying this bundle refresh it at or before this time. */
  refresh_after: number
  /** Optional: short-form revocation of specific anchor_ids that were
   *  valid in a prior bundle snapshot. */
  revoked_anchors?: string[]
  /** Signature over the canonical form with `signature_b64` omitted,
   *  by the bundle publisher's Ed25519 key. Verifiers MAY additionally
   *  require the bundle to be signed by a configured root key. */
  signature_b64: string
  /** Publisher pubkey (hex). Must itself be trusted by root
   *  configuration, not by the bundle alone. */
  publisher_pubkey_hex: string
}

// ── Handshake ──

/** One nonce round of the two-way handshake. */
export interface MutualAuthHello {
  spec_version: '1.0'
  role: MutualAuthRole
  supported_versions: string[]
  nonce_b64: string
  /** Timestamp (unix ms) the initiator produced the hello. */
  timestamp: number
}

/** Response a party returns after validating the counterparty's
 *  certificate. The signature commits the party to
 *    (chosen_version || peer_nonce_b64 || own_nonce_b64 || own_cert_id)
 *  which is the downgrade-attack defence. */
export interface MutualAuthAttest {
  spec_version: '1.0'
  role: MutualAuthRole
  chosen_version: string
  own_nonce_b64: string
  peer_nonce_b64: string
  certificate: MutualAuthCertificate
  /** Signature over the canonical form with `signature_b64` omitted.
   *  The canonical form MUST include chosen_version, both nonces,
   *  and the embedded certificate. */
  signature_b64: string
  /** Timestamp (unix ms). */
  timestamp: number
}

export interface MutualAuthSession {
  spec_version: '1.0'
  /** Stable content-hash identifier for this session. */
  session_id: string
  agent_cert: MutualAuthCertificate
  is_cert: MutualAuthCertificate
  chosen_version: string
  agent_nonce_b64: string
  is_nonce_b64: string
  established_at: number
  /** Session ends at or before this time; both sides enforce. */
  expires_at: number
}

// ── Verification outcome ──

export type MutualAuthFailureReason =
  | 'expired_certificate'
  | 'not_yet_valid_certificate'
  | 'unknown_issuer'
  | 'revoked_anchor'
  | 'signature_invalid'
  | 'binding_mismatch'
  | 'downgrade_detected'
  | 'nonce_mismatch'
  | 'version_unsupported'
  | 'expired_session'
  | 'replay_detected'
  | 'grade_insufficient'

export interface MutualAuthResult {
  ok: boolean
  session?: MutualAuthSession
  failure?: {
    reason: MutualAuthFailureReason
    detail?: string
  }
}

// ── Policy ──

/** Local trust policy a party applies when accepting a peer cert. */
export interface MutualAuthPolicy {
  /** Minimum agent attestation grade (0..3). Only applies when the
   *  peer is an agent. */
  min_agent_grade?: 0 | 1 | 2 | 3
  /** Protocol versions this party accepts, highest preference first. */
  accepted_versions: string[]
  /** Required capabilities the peer cert must carry. */
  required_capabilities?: string[]
  /** Maximum allowed clock skew (milliseconds) when comparing
   *  timestamps. */
  max_clock_skew_ms?: number
  /** Maximum session lifetime accepted (milliseconds). */
  max_session_ms?: number
}

// ── Passport bridge ──

/** Signed envelope binding an APS passport + active delegation into
 *  a MutualAuthCertificate. This is how an agent carries its APS
 *  identity into the mutual-auth layer without changing the passport
 *  spec itself. */
export interface AgentCertBinding {
  passport: SignedPassport
  delegation: Delegation
  certificate: MutualAuthCertificate
}
