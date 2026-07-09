// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Trust Root Policy (W2-B1): types
// ══════════════════════════════════════════════════════════════════
// A trust-root-policy is a signed, versioned artifact a relying party
// carries to decide which issuers/keys it accepts for a receipt, how
// keys resolve, how rotation is tolerated, and what to do when an
// endpoint is stale or offline. It composes the existing surfaces and
// adds NO issuer-written assurance: a verdict is a verifier-derived
// OUTPUT computed against THIS policy, never a field read off a receipt.
//
// Reuse map (do not duplicate):
//   - TrustAnchor / TrustAnchorBundle / verifyBundle / checkAnchor from
//     v2/mutual-auth (local trust-anchor resolution; root-signed bundle).
//   - KeyResolver / KeyLocator / KeyResolution / FailurePolicy from
//     v2/key-resolution (M3): how a pinned/declared key is fetched.
//   - canonicalizeJCS + crypto/keys sign/verify (sign-over-canonical
//     with the signature field omitted), the universal APS pattern.
//   - ScopeOfClaim from v2/accountability/types/base.
//
// SECURITY POSTURE (inherited from M3): fail-closed by default. An
// endpoint that could not be reached is NEVER "key valid". Offline and
// stale behaviors are EXPLICIT, opt-in, and surfaced in the verdict.
// ══════════════════════════════════════════════════════════════════

import type { TrustAnchor } from '../mutual-auth/types.js'
import type { FailurePolicy, KeyLocator } from '../key-resolution/types.js'

export const TRUST_ROOT_POLICY_SPEC_VERSION = '1.0' as const

// ── Pinned key ────────────────────────────────────────────────────

/** A key the policy pins by exact public-key bytes. A receipt signed by
 *  a key not on the pin set (when pinning is enforced for the issuer)
 *  is rejected. The pin is matched on the 64-char lowercase hex form
 *  the M3 resolver and crypto/keys verify() consume. */
export interface PinnedKey {
  /** Stable label for audit references. */
  key_id: string
  /** 64-char lowercase hex Ed25519 public key. */
  pubkey_hex: string
  /** Optional locator the verifier MAY use to confirm the live endpoint
   *  still asserts this key (reuses the M3 KeyLocator shape). Resolution
   *  is point-in-time; a mismatch with the live endpoint is reported,
   *  never silently trusted. */
  locator?: KeyLocator
  /** Optional validity window (unix ms). When set, a verdict outside the
   *  window reports the key as out-of-window rather than accepted. */
  not_before?: number
  not_after?: number
}

// ── Trusted issuer ────────────────────────────────────────────────

/** Behavior when a pinned key for an issuer fails to resolve live, or
 *  the locator is unreachable. Mirrors the M3 FailurePolicy posture but
 *  is declared per-issuer on the policy.
 *   - 'closed' (DEFAULT): unresolved/unreachable rejects.
 *   - 'open'  : opt-in; relaxes ONLY the unreachable/transient case to a
 *     degraded verdict carrying NO accepted-as-valid signal. */
export type StaleBehavior = FailurePolicy

/** How a relying party treats a fully-offline evaluation (no network).
 *   - 'cached_pins_only' (DEFAULT): accept only matches against the
 *     pinned-key bytes carried in the policy; never reach the network.
 *   - 'reject': refuse to render a verdict offline.
 *  Offline verification against a cached, signed policy is the supported
 *  path; it uses the pinned bytes and performs no resolution. */
export type OfflineBehavior = 'cached_pins_only' | 'reject'

/** A single trusted issuer in the policy: its identity, the keys it is
 *  pinned to, and how the policy resolves and tolerates change for it.
 *  Where it overlaps the mutual-auth TrustAnchor model, it carries an
 *  optional anchor so verifyBundle/checkAnchor can be reused directly. */
export interface TrustedIssuer {
  /** Issuer identity (DID or stable id). Matched against a receipt's
   *  signer/issuer field by the verifier. */
  issuer_id: string
  display_name: string
  /** Keys this issuer is pinned to. A non-empty list means pinning is
   *  enforced for this issuer: a signer key not in the set is rejected. */
  pinned_keys: PinnedKey[]
  /** Optional mutual-auth TrustAnchor for this issuer, so the existing
   *  checkAnchor() binding logic can be reused without re-spec. */
  anchor?: TrustAnchor
  /** Optional binding constraints (glob/prefix/exact) the issuer's certs
   *  must satisfy, evaluated with the same matcher checkAnchor uses. */
  binding_constraints?: string[]
  /** Per-issuer stale behavior. Defaults to the policy default. */
  stale_behavior?: StaleBehavior
}

// ── Resolver rule ─────────────────────────────────────────────────

/** A resolver rule pins, for a DID method or issuer prefix, the failure
 *  policy and timeout the verifier MUST apply when resolving a key. It
 *  is the policy-level expression of an M3 KeyResolverConfig; the policy
 *  carries the rule, the verifier instantiates the resolver. */
export interface ResolverRule {
  /** A DID method ('did:web', 'did:key', 'did:cycles') or an issuer-id
   *  prefix this rule applies to. */
  applies_to: string
  /** Failure posture for resolution under this rule. Default 'closed'. */
  failure_policy?: FailurePolicy
  /** Fetch timeout (ms) for this rule. */
  timeout_ms?: number
}

// ── Rotation rule ─────────────────────────────────────────────────

/** Rotation tolerance. A policy author can permit a graceful window in
 *  which BOTH the old pinned key and a newly-rotated key are accepted,
 *  bounded by an overlap deadline. Outside the window only the current
 *  pin is accepted. This is a SHOULD-level tolerance the verifier
 *  reports on; it never widens acceptance silently. */
export interface RotationRule {
  /** Overlap window (ms) during which a superseded pinned key is still
   *  accepted after a successor is pinned. 0 means no overlap. */
  overlap_ms: number
  /** key_ids that are superseded but still inside their overlap window,
   *  with the unix-ms time each was retired. */
  superseded?: { key_id: string; retired_at: number }[]
}

// ── The policy artifact ───────────────────────────────────────────

/** Unsigned policy body. Signed by signTrustRootPolicy over the
 *  canonical form with signature_b64 omitted. */
export interface TrustRootPolicyBody {
  spec_version: typeof TRUST_ROOT_POLICY_SPEC_VERSION
  /** Stable identifier for this policy lineage (NOT per-version). */
  policy_id: string
  /** Monotonic integer version. Anti-rollback: a verifier configured
   *  with a known-minimum version MUST reject any policy whose version
   *  is below it. Strictly increasing within a policy_id lineage. */
  policy_version: number
  /** When this policy version was issued (unix ms). */
  issued_at: number
  /** Verifiers SHOULD refresh at or before this time (unix ms). */
  refresh_after: number
  trusted_issuers: TrustedIssuer[]
  resolver_rules: ResolverRule[]
  rotation: RotationRule
  /** Default stale behavior when an issuer does not set its own. */
  default_stale_behavior: StaleBehavior
  /** Offline evaluation behavior. */
  offline_behavior: OfflineBehavior
  /** Publisher pubkey (hex). Must be root-trusted by verifier config,
   *  not by the policy alone, same posture as TrustAnchorBundle. */
  publisher_pubkey_hex: string
}

/** A signed trust-root-policy artifact. */
export interface TrustRootPolicy extends TrustRootPolicyBody {
  /** Ed25519 signature (base64) over the canonical body with
   *  signature_b64 omitted, by the publisher key. */
  signature_b64: string
}

// ── Anti-rollback / verification of the artifact itself ───────────

export type PolicyVerifyReason =
  | 'signature_invalid'
  | 'untrusted_publisher'
  | 'policy_expired'
  | 'not_yet_valid'
  | 'version_rolled_back'
  | 'malformed'

export interface PolicyVerifyOutcome {
  ok: boolean
  reason?: PolicyVerifyReason
  /** Echo the accepted policy_version for audit, when ok. */
  policy_version?: number
}

// ── The verdict (verifier-derived OUTPUT, never an issuer field) ──

/** Closed taxonomy of verdict reasons. Each is a mechanical fact about
 *  how a SPECIFIC receipt evaluated against a SPECIFIC signed policy
 *  version. None is read from the receipt. */
export type TrustPolicyVerdictReason =
  | 'accepted'
  | 'issuer_not_trusted'
  | 'pinned_key_mismatch'
  | 'key_out_of_window'
  | 'policy_rejected'
  | 'key_unresolved'
  | 'offline_no_pin_match'
  | 'degraded_unreachable'

/** Four-valued acceptance status, consistent with the Belnap-style
 *  ConstraintStatus used elsewhere (pass/fail/not_applicable/unknown).
 *  A trust-policy verdict is a SET/lattice point, never a scalar ladder:
 *   - 'pass'           : the receipt's signer is trusted and pinned by
 *                        this policy version.
 *   - 'fail'           : the policy rejects (untrusted/mismatch/rolled
 *                        back / out of window).
 *   - 'not_applicable' : the policy says nothing about this issuer and
 *                        the policy does not enforce a closed allowlist.
 *   - 'unknown'        : resolution was needed but unreachable (degraded
 *                        under fail-open): NOT an acceptance. */
export type TrustPolicyStatus = 'pass' | 'fail' | 'not_applicable' | 'unknown'

/** The verifier-derived verdict. This is the OUTPUT a relying party
 *  computes; it is labeled a relying-party-policy result and is NEVER
 *  serialized onto a receipt or read back from one. */
export interface TrustPolicyVerdict {
  /** Always present: this is a relying-party-policy OUTPUT, computed by
   *  the verifier against the named policy version. */
  computed_by: 'verifier'
  status: TrustPolicyStatus
  reason: TrustPolicyVerdictReason
  /** The policy lineage and version this verdict was computed against,   *  the audit anchor for "which policy said what". */
  policy_id: string
  policy_version: number
  /** The issuer the receipt's signer was matched against, when matched. */
  matched_issuer_id?: string
  /** The pinned key_id that matched, when a pin matched. */
  matched_key_id?: string
  /** True only when a fail-open stale behavior produced a degraded,
   *  non-accepting result. Mirrors KeyResolution.degraded. A degraded
   *  verdict MUST NOT be read as acceptance. */
  degraded?: boolean
  /** Human-readable, non-sensitive explanation. */
  detail?: string
}
