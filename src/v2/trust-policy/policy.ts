// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Trust Root Policy (W2-B1): build, sign, verify (anti-rollback)
// ══════════════════════════════════════════════════════════════════
// Mirrors the existing TrustAnchorBundle build/sign/verify pattern in
// v2/mutual-auth/trust-bundle.ts exactly: sign over canonicalizeJCS of
// the body with signature_b64 omitted; verify membership of the
// publisher key in a root-trusted set BEFORE the signature; check the
// freshness window. The one addition over the bundle is an explicit
// anti-rollback version gate.
// ══════════════════════════════════════════════════════════════════

import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import { sign as edSignHex, verify as edVerifyHex } from '../../crypto/keys.js'
import {
  TRUST_ROOT_POLICY_SPEC_VERSION,
  type TrustRootPolicy,
  type TrustRootPolicyBody,
  type TrustedIssuer,
  type ResolverRule,
  type RotationRule,
  type StaleBehavior,
  type OfflineBehavior,
  type PolicyVerifyOutcome,
} from './types.js'

// ── Construction ──

export interface BuildTrustRootPolicyInput {
  policy_id: string
  policy_version: number
  issued_at: number
  refresh_after: number
  trusted_issuers: TrustedIssuer[]
  resolver_rules?: ResolverRule[]
  rotation?: RotationRule
  default_stale_behavior?: StaleBehavior
  offline_behavior?: OfflineBehavior
}

/** Build an unsigned trust-root-policy body. Defaults preserve the
 *  fail-closed / pins-only posture. Call signTrustRootPolicy next. */
export function buildTrustRootPolicy(
  input: BuildTrustRootPolicyInput,
  publisher_pubkey_hex: string,
): TrustRootPolicyBody {
  if (!Number.isInteger(input.policy_version) || input.policy_version < 0) {
    throw new Error('policy_version must be a non-negative integer')
  }
  return {
    spec_version: TRUST_ROOT_POLICY_SPEC_VERSION,
    policy_id: input.policy_id,
    policy_version: input.policy_version,
    issued_at: input.issued_at,
    refresh_after: input.refresh_after,
    trusted_issuers: input.trusted_issuers,
    resolver_rules: input.resolver_rules ?? [],
    rotation: input.rotation ?? { overlap_ms: 0 },
    default_stale_behavior: input.default_stale_behavior ?? 'closed',
    offline_behavior: input.offline_behavior ?? 'cached_pins_only',
    publisher_pubkey_hex,
  }
}

export function signTrustRootPolicy(
  unsigned: TrustRootPolicyBody,
  publisher_sk_hex: string,
): TrustRootPolicy {
  const canonical = canonicalizeJCS(unsigned)
  const sig_hex = edSignHex(canonical, publisher_sk_hex)
  const sig_b64 = Buffer.from(sig_hex, 'hex').toString('base64')
  return { ...unsigned, signature_b64: sig_b64 }
}

// ── Verification (anti-rollback) ──

export interface VerifyTrustRootPolicyOptions {
  /** The verifier's root-trusted publisher key set. The policy MUST be
   *  signed by one of these, not merely self-signed. */
  trusted_publisher_pubkeys_hex: string[]
  /** Current time (unix ms). */
  now_ms: number
  /** Anti-rollback floor. When supplied, a policy whose policy_version is
   *  strictly below this is rejected as version_rolled_back. A verifier
   *  persists the highest accepted version per policy_id and feeds it
   *  back here; this is what prevents an attacker re-serving an older,
   *  weaker signed policy. */
  min_policy_version?: number
}

/** Verify a trust-root-policy: publisher membership, signature,
 *  freshness window, then the anti-rollback version gate. Same order and
 *  posture as verifyBundle, with the added version check. */
export function verifyTrustRootPolicy(
  policy: TrustRootPolicy,
  options: VerifyTrustRootPolicyOptions,
): PolicyVerifyOutcome {
  const { trusted_publisher_pubkeys_hex, now_ms, min_policy_version } = options

  if (policy.spec_version !== TRUST_ROOT_POLICY_SPEC_VERSION) {
    return { ok: false, reason: 'malformed' }
  }
  if (!Number.isInteger(policy.policy_version) || policy.policy_version < 0) {
    return { ok: false, reason: 'malformed' }
  }
  if (!trusted_publisher_pubkeys_hex.includes(policy.publisher_pubkey_hex)) {
    return { ok: false, reason: 'untrusted_publisher' }
  }

  const { signature_b64, ...rest } = policy
  const canonical = canonicalizeJCS(rest)
  const sig_hex = Buffer.from(signature_b64, 'base64').toString('hex')
  const sigOk = edVerifyHex(canonical, sig_hex, policy.publisher_pubkey_hex)
  if (!sigOk) return { ok: false, reason: 'signature_invalid' }

  if (now_ms < policy.issued_at) return { ok: false, reason: 'not_yet_valid' }
  if (now_ms > policy.refresh_after) return { ok: false, reason: 'policy_expired' }

  // Anti-rollback: reject a correctly-signed but stale version.
  if (
    min_policy_version !== undefined &&
    policy.policy_version < min_policy_version
  ) {
    return { ok: false, reason: 'version_rolled_back' }
  }

  return { ok: true, policy_version: policy.policy_version }
}
