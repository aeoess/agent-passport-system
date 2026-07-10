// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Trust Root Policy (W2-B1): the verifier: receipt → verdict
// ══════════════════════════════════════════════════════════════════
// evaluateReceiptAgainstPolicy is the relying-party verifier. It takes a
// SIGNED policy and the minimal signer facts of a receipt, and returns a
// TrustPolicyVerdict that is a verifier-derived OUTPUT. It reads NO
// assurance field off the receipt; the only inputs from the receipt are
// the mechanical signer facts (which issuer, which signing key).
//
// Reuse:
//   - M3 KeyResolver to confirm a pinned key still resolves live
//     (online path); fail-closed by default, fail-open only relaxes the
//     unreachable case into a DEGRADED ('unknown') verdict carrying no
//     acceptance.
//   - The mutual-auth binding matcher semantics (exact / prefix-glob),
//     applied to optional issuer binding_constraints.
//
// The offline path performs NO resolution: it matches the receipt's
// signer key bytes against the policy's pinned bytes only.
// ══════════════════════════════════════════════════════════════════

import type { KeyResolver, KeyLocator } from '../key-resolution/types.js'
import type {
  TrustRootPolicy,
  TrustedIssuer,
  PinnedKey,
  TrustPolicyVerdict,
  StaleBehavior,
} from './types.js'

/** The mechanical signer facts the verifier reads off a receipt. These
 *  are facts about WHICH key signed WHICH claim, never an assurance the
 *  issuer set. */
export interface ReceiptSignerFacts {
  /** The issuer/signer identity to match against trusted_issuers. For a
   *  Cycles receipt this is the receipt.signer (raw hex) or the DID URI
   *  before the '#'. */
  issuer_id: string
  /** 64-char lowercase hex Ed25519 public key that actually signed the
   *  receipt. For a DID-URI signer the verifier resolves this; for a raw
   *  hex signer it IS the signer string. */
  signer_pubkey_hex: string
}

export interface EvaluateOptions {
  /** Current time (unix ms). Used for key-window and rotation checks. */
  now_ms: number
  /** When true, evaluate fully offline: pinned-byte matching only, no
   *  resolver call. Honors the policy's offline_behavior. */
  offline?: boolean
  /** Online key resolver (M3). Required for the online live-confirm path
   *  when a pinned key carries a locator; ignored when offline. */
  resolver?: KeyResolver
}

/** Evaluate a receipt's signer facts against a SIGNED, already-verified
 *  trust-root-policy and return a verifier-derived verdict.
 *
 *  Precondition: the caller verified the policy artifact itself with
 *  verifyTrustRootPolicy (signature + freshness + anti-rollback) before
 *  calling this. This function decides acceptance of a SIGNER under a
 *  KNOWN-GOOD policy version; it does not re-verify the policy. */
export async function evaluateReceiptAgainstPolicy(
  receipt: ReceiptSignerFacts,
  policy: TrustRootPolicy,
  options: EvaluateOptions,
): Promise<TrustPolicyVerdict> {
  const base = {
    computed_by: 'verifier' as const,
    policy_id: policy.policy_id,
    policy_version: policy.policy_version,
  }

  const issuer = matchIssuer(policy.trusted_issuers, receipt.issuer_id)
  if (!issuer) {
    // No matching issuer. If the policy declares any trusted issuers it
    // is a closed allowlist and this is a rejection; an empty issuer set
    // is not-applicable (the policy pins nothing).
    if (policy.trusted_issuers.length === 0) {
      return {
        ...base,
        status: 'not_applicable',
        reason: 'issuer_not_trusted',
        detail: 'policy declares no trusted issuers',
      }
    }
    return {
      ...base,
      status: 'fail',
      reason: 'issuer_not_trusted',
      detail: `issuer ${receipt.issuer_id} is not in the policy allowlist`,
    }
  }

  // Optional binding-constraint gate (exact / prefix-glob), reusing the
  // mutual-auth matcher semantics against the issuer id as the binding.
  if (issuer.binding_constraints && issuer.binding_constraints.length > 0) {
    const ok = issuer.binding_constraints.some((p) =>
      matchBinding(p, receipt.issuer_id),
    )
    if (!ok) {
      return {
        ...base,
        status: 'fail',
        reason: 'issuer_not_trusted',
        matched_issuer_id: issuer.issuer_id,
        detail: 'issuer binding constraints not satisfied',
      }
    }
  }

  // Pinning is enforced when the issuer has a non-empty pin set.
  if (issuer.pinned_keys.length === 0) {
    return {
      ...base,
      status: 'not_applicable',
      reason: 'issuer_not_trusted',
      matched_issuer_id: issuer.issuer_id,
      detail: 'issuer is trusted but pins no keys; policy does not bind a key',
    }
  }

  const pin = findPin(issuer.pinned_keys, receipt.signer_pubkey_hex)
  if (!pin) {
    return {
      ...base,
      status: 'fail',
      reason: 'pinned_key_mismatch',
      matched_issuer_id: issuer.issuer_id,
      detail: 'signer key bytes match no pinned key for this issuer',
    }
  }

  // Rotation gate: a pin whose key_id is marked superseded in the
  // rotation rule is accepted ONLY while inside its overlap window. A
  // current (non-superseded) pin is not gated here. This never widens
  // acceptance: a superseded key past its window is rejected.
  const retiredAt = supersededRetiredAt(policy, pin.key_id)
  if (retiredAt !== undefined) {
    const overlap = policy.rotation.overlap_ms
    if (!overlap || overlap <= 0 || options.now_ms > retiredAt + overlap) {
      return {
        ...base,
        status: 'fail',
        reason: 'pinned_key_mismatch',
        matched_issuer_id: issuer.issuer_id,
        matched_key_id: pin.key_id,
        detail: 'superseded key is past its rotation overlap window',
      }
    }
    return {
      ...base,
      status: 'pass',
      reason: 'accepted',
      matched_issuer_id: issuer.issuer_id,
      matched_key_id: pin.key_id,
      detail: 'signer key accepted within rotation overlap window',
    }
  }

  // Key-window check.
  if (!isKeyInWindow(pin, options.now_ms)) {
    return {
      ...base,
      status: 'fail',
      reason: 'key_out_of_window',
      matched_issuer_id: issuer.issuer_id,
      matched_key_id: pin.key_id,
      detail: 'pinned key is outside its validity window',
    }
  }

  // OFFLINE PATH: pinned-byte match is sufficient; no resolution.
  if (options.offline) {
    if (policy.offline_behavior === 'reject') {
      return {
        ...base,
        status: 'fail',
        reason: 'offline_no_pin_match',
        matched_issuer_id: issuer.issuer_id,
        matched_key_id: pin.key_id,
        detail: 'policy offline_behavior is reject',
      }
    }
    // cached_pins_only: the pinned bytes matched, accept offline.
    return {
      ...base,
      status: 'pass',
      reason: 'accepted',
      matched_issuer_id: issuer.issuer_id,
      matched_key_id: pin.key_id,
      detail: 'accepted offline against cached pinned key bytes',
    }
  }

  // ONLINE PATH: optionally confirm the live endpoint still asserts the
  // pinned bytes. Absent a locator, the pinned-byte match already binds.
  if (!pin.locator) {
    return {
      ...base,
      status: 'pass',
      reason: 'accepted',
      matched_issuer_id: issuer.issuer_id,
      matched_key_id: pin.key_id,
      detail: 'accepted against pinned key bytes (no live locator declared)',
    }
  }

  const stale: StaleBehavior =
    issuer.stale_behavior ?? policy.default_stale_behavior

  if (!options.resolver) {
    // No resolver supplied but a locator is declared: cannot confirm.
    // Treat as the stale/unreachable case under the declared posture.
    return staleVerdict(base, issuer, pin, stale, 'no resolver supplied for live confirmation')
  }

  const resolution = await options.resolver.resolve(pin.locator as KeyLocator)
  if (resolution.ok && resolution.publicKeyHex) {
    if (resolution.publicKeyHex.toLowerCase() === pin.pubkey_hex.toLowerCase()) {
      return {
        ...base,
        status: 'pass',
        reason: 'accepted',
        matched_issuer_id: issuer.issuer_id,
        matched_key_id: pin.key_id,
        detail: 'live endpoint asserts the pinned key',
      }
    }
    // Endpoint resolved a DIFFERENT key than the pin: a hard mismatch.
    return {
      ...base,
      status: 'fail',
      reason: 'pinned_key_mismatch',
      matched_issuer_id: issuer.issuer_id,
      matched_key_id: pin.key_id,
      detail: 'live endpoint asserts a key different from the pin',
    }
  }

  // Resolution failed. 'unreachable' is the only transient case; under
  // fail-open it degrades to 'unknown' (NOT acceptance). Everything else
  // is a hard fail-closed rejection.
  if (resolution.status === 'unreachable') {
    return staleVerdict(base, issuer, pin, stale, resolution.reason ?? 'endpoint unreachable')
  }
  return {
    ...base,
    status: 'fail',
    reason: 'key_unresolved',
    matched_issuer_id: issuer.issuer_id,
    matched_key_id: pin.key_id,
    detail: `live confirmation failed: ${resolution.status}`,
  }
}

// ── helpers ───────────────────────────────────────────────────────

type VerdictBase = {
  computed_by: 'verifier'
  policy_id: string
  policy_version: number
}

function staleVerdict(
  base: VerdictBase,
  issuer: TrustedIssuer,
  pin: PinnedKey,
  stale: StaleBehavior,
  reason: string,
): TrustPolicyVerdict {
  if (stale === 'open') {
    // Fail-open: a degraded, non-accepting 'unknown' verdict.
    return {
      ...base,
      status: 'unknown',
      reason: 'degraded_unreachable',
      matched_issuer_id: issuer.issuer_id,
      matched_key_id: pin.key_id,
      degraded: true,
      detail: `fail-open degraded (no acceptance): ${reason}`,
    }
  }
  // Fail-closed (default): rejection.
  return {
    ...base,
    status: 'fail',
    reason: 'key_unresolved',
    matched_issuer_id: issuer.issuer_id,
    matched_key_id: pin.key_id,
    degraded: false,
    detail: `fail-closed: ${reason}`,
  }
}

function matchIssuer(
  issuers: TrustedIssuer[],
  issuer_id: string,
): TrustedIssuer | undefined {
  return issuers.find((i) => i.issuer_id === issuer_id)
}

function findPin(
  pins: PinnedKey[],
  pubkey_hex: string,
): PinnedKey | undefined {
  const want = pubkey_hex.toLowerCase()
  return pins.find((p) => p.pubkey_hex.toLowerCase() === want)
}

function isKeyInWindow(pin: PinnedKey, now_ms: number): boolean {
  if (pin.not_before !== undefined && now_ms < pin.not_before) return false
  if (pin.not_after !== undefined && now_ms > pin.not_after) return false
  return true
}

/** When the given pinned key_id is marked superseded in the rotation
 *  rule, return its retired_at (unix ms); otherwise undefined. A current
 *  (non-superseded) pin returns undefined and is not rotation-gated. */
function supersededRetiredAt(
  policy: TrustRootPolicy,
  key_id: string,
): number | undefined {
  const superseded = policy.rotation.superseded ?? []
  const match = superseded.find((s) => s.key_id === key_id)
  return match ? match.retired_at : undefined
}

/** Binding matcher: exact, or trailing-'*' prefix glob. Same semantics
 *  as the mutual-auth certificate matcher (kept module-local to avoid
 *  importing a non-exported helper). */
function matchBinding(pattern: string, binding: string): boolean {
  if (pattern === binding) return true
  if (pattern.endsWith('*')) return binding.startsWith(pattern.slice(0, -1))
  return false
}
