// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Mutual Authentication v1 — trust anchor bundle build, sign, verify
// ══════════════════════════════════════════════════════════════════

import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import { sign as edSignHex, verify as edVerifyHex } from '../../crypto/keys.js'
import type { TrustAnchorBundle, TrustAnchor } from './types.js'

const SPEC_VERSION = '1.0' as const

// ── Construction ──

export interface BuildBundleInput {
  bundle_id: string
  anchors: TrustAnchor[]
  issued_at: number
  refresh_after: number
  revoked_anchors?: string[]
}

export function buildBundle(
  input: BuildBundleInput,
  publisher_pubkey_hex: string,
): Omit<TrustAnchorBundle, 'signature_b64'> {
  return {
    spec_version: SPEC_VERSION,
    bundle_id: input.bundle_id,
    issued_at: input.issued_at,
    anchors: input.anchors,
    refresh_after: input.refresh_after,
    revoked_anchors: input.revoked_anchors,
    publisher_pubkey_hex,
  }
}

export function signBundle(
  unsigned: Omit<TrustAnchorBundle, 'signature_b64'>,
  publisher_sk_hex: string,
): TrustAnchorBundle {
  const canonical = canonicalizeJCS(unsigned)
  const sig_hex = edSignHex(canonical, publisher_sk_hex)
  const sig_b64 = Buffer.from(sig_hex, 'hex').toString('base64')
  return { ...unsigned, signature_b64: sig_b64 }
}

// ── Verification ──

export type BundleVerifyReason =
  | 'signature_invalid'
  | 'untrusted_publisher'
  | 'bundle_expired'
  | 'not_yet_valid'

export interface BundleVerifyOutcome {
  ok: boolean
  reason?: BundleVerifyReason
}

/** Verify a bundle's signature and freshness. The verifier supplies
 *  a root-trusted publisher key list; the bundle MUST be signed by
 *  one of them, not merely self-signed. */
export function verifyBundle(
  bundle: TrustAnchorBundle,
  trusted_publisher_pubkeys_hex: string[],
  now_ms: number,
): BundleVerifyOutcome {
  if (!trusted_publisher_pubkeys_hex.includes(bundle.publisher_pubkey_hex)) {
    return { ok: false, reason: 'untrusted_publisher' }
  }
  const { signature_b64, ...rest } = bundle
  const canonical = canonicalizeJCS(rest)
  const sig_hex = Buffer.from(signature_b64, 'base64').toString('hex')
  const ok = edVerifyHex(canonical, sig_hex, bundle.publisher_pubkey_hex)
  if (!ok) return { ok: false, reason: 'signature_invalid' }
  if (now_ms < bundle.issued_at) return { ok: false, reason: 'not_yet_valid' }
  if (now_ms > bundle.refresh_after) {
    return { ok: false, reason: 'bundle_expired' }
  }
  return { ok: true }
}
