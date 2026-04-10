// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Credential Check Policy — verification timing for governance metadata
// ══════════════════════════════════════════════════════════════════
// Proposed by @piiiico on a2aproject/A2A governance metadata thread.
//
// A credential (delegation, attestation, capability token) needs to
// declare WHEN it should be re-verified. Different credential types have
// different trust decay profiles and should be checkable at different
// points in the lifecycle.
//
// Modes:
//   on-accept — verify once at credential acceptance time. Cheap. Trusts
//               the snapshot. Use for long-lived session credentials where
//               live revocation cost is prohibitive and staleness is OK.
//   on-process — verify on every action evaluation. Expensive. Catches
//                live revocation. Default for most delegations.
//   both — verify at acceptance AND at process time. For high-stakes
//          actions (large spend, irreversible operations, cross-org
//          transactions) where you want both checks.
// ══════════════════════════════════════════════════════════════════

export type CredentialCheckMode = 'on-accept' | 'on-process' | 'both'

export interface CredentialCheckPolicy {
  mode: CredentialCheckMode
  /**
   * Maximum age of the acceptance stamp in seconds. Only meaningful when
   * mode is 'on-accept' or 'both'. If unset, the acceptance stamp does
   * not expire.
   */
  max_acceptance_age?: number
}

/**
 * Acceptance-time verification stamp. Produced by verifyOnAccept() and
 * held by the verifying party (typically the gateway). Not part of the
 * delegation signature itself — this is a runtime artifact tracked by
 * the relying party.
 */
export interface AcceptanceStamp {
  delegation_id: string
  /** ISO 8601 timestamp when the credential passed acceptance-time verification. */
  verified_at: string
  /** Optional identifier of the party that performed the acceptance check. */
  verifier_id?: string
}

/**
 * Denial reason codes specific to the credential check policy gate.
 *
 *  - CREDENTIAL_NOT_ACCEPTED — policy is on-accept or both, but no
 *    acceptance stamp is on file for this delegation
 *  - CREDENTIAL_ACCEPT_STALE — acceptance stamp exists but is older than
 *    policy.max_acceptance_age
 *  - ACCEPT_TIME_INVALID — acceptance-time verification itself failed
 *    (signature invalid, expired at acceptance, etc.)
 *  - PROCESS_TIME_INVALID — live state check failed (revoked between
 *    acceptance and process time, etc.)
 */
export type CredentialCheckDenialCode =
  | 'CREDENTIAL_NOT_ACCEPTED'
  | 'CREDENTIAL_ACCEPT_STALE'
  | 'ACCEPT_TIME_INVALID'
  | 'PROCESS_TIME_INVALID'

export interface CredentialCheckResult {
  permitted: boolean
  /** Resolved mode actually applied (default 'on-process' when unspecified). */
  mode: CredentialCheckMode
  /**
   * Whether the caller still needs to perform a live revocation/state check.
   * False when mode is 'on-accept' and a valid stamp is present (the
   * acceptance check is treated as authoritative).
   */
  requiresLiveCheck: boolean
  denialCode?: CredentialCheckDenialCode
  reason?: string
}
