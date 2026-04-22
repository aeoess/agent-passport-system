// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Mutual Authentication v1 — certificate build, sign, verify
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import { sign as edSignHex, verify as edVerifyHex } from '../../crypto/keys.js'
import type {
  MutualAuthCertificate,
  MutualAuthRole,
  TrustAnchor,
} from './types.js'

const SPEC_VERSION = '1.0' as const

// ── Construction ──

export interface BuildCertificateInput {
  role: MutualAuthRole
  subject_id: string
  subject_pubkey_hex: string
  issuer_id: string
  issuer_role: MutualAuthRole | 'trust_anchor'
  binding: string
  not_before: number
  not_after: number
  supported_versions: string[]
  attestation_grade?: 0 | 1 | 2 | 3
  capabilities?: string[]
}

/** Build an unsigned certificate. Call signCertificate next. */
export function buildCertificate(
  input: BuildCertificateInput,
  issuer_pubkey_hex: string,
): Omit<MutualAuthCertificate, 'signature_b64'> {
  return {
    spec_version: SPEC_VERSION,
    role: input.role,
    subject_id: input.subject_id,
    issuer_id: input.issuer_id,
    issuer_role: input.issuer_role,
    issuer_pubkey_hex,
    subject_pubkey_hex: input.subject_pubkey_hex,
    not_before: input.not_before,
    not_after: input.not_after,
    binding: input.binding,
    attestation_grade: input.attestation_grade,
    supported_versions: input.supported_versions,
    capabilities: input.capabilities,
  }
}

/** Sign an unsigned certificate with the issuer's private key (hex). */
export function signCertificate(
  unsigned: Omit<MutualAuthCertificate, 'signature_b64'>,
  issuer_sk_hex: string,
): MutualAuthCertificate {
  const canonical = canonicalizeJCS(unsigned)
  const sig_hex = edSignHex(canonical, issuer_sk_hex)
  const sig_b64 = Buffer.from(sig_hex, 'hex').toString('base64')
  return { ...unsigned, signature_b64: sig_b64 }
}

/** Stable content-hash identifier for a certificate (for session_id
 *  derivation, audit references, etc.). Does not include the signature
 *  so equivalent unsigned certificates produce the same id. */
export function certificateId(cert: MutualAuthCertificate): string {
  const { signature_b64: _sig, ...rest } = cert
  const canonical = canonicalizeJCS(rest)
  return 'sha256:' + createHash('sha256').update(canonical).digest('hex')
}

// ── Verification (signature only; policy check is separate) ──

export interface VerifyCertificateOutcome {
  ok: boolean
  reason?: 'signature_invalid' | 'expired' | 'not_yet_valid' | 'version_empty'
}

export function verifyCertificateSignature(
  cert: MutualAuthCertificate,
): VerifyCertificateOutcome {
  if (!cert.supported_versions || cert.supported_versions.length === 0) {
    return { ok: false, reason: 'version_empty' }
  }
  const { signature_b64, ...rest } = cert
  const canonical = canonicalizeJCS(rest)
  const sig_hex = Buffer.from(signature_b64, 'base64').toString('hex')
  const ok = edVerifyHex(canonical, sig_hex, cert.issuer_pubkey_hex)
  if (!ok) return { ok: false, reason: 'signature_invalid' }
  return { ok: true }
}

/** Check validity window using a supplied now() (unix ms). */
export function isCertificateTemporallyValid(
  cert: MutualAuthCertificate,
  now_ms: number,
  max_clock_skew_ms = 0,
): VerifyCertificateOutcome {
  if (now_ms + max_clock_skew_ms < cert.not_before) {
    return { ok: false, reason: 'not_yet_valid' }
  }
  if (now_ms - max_clock_skew_ms > cert.not_after) {
    return { ok: false, reason: 'expired' }
  }
  return { ok: true }
}

// ── Trust anchor check ──

export interface AnchorCheckOutcome {
  ok: boolean
  anchor?: TrustAnchor
  reason?: 'unknown_issuer' | 'revoked_anchor' | 'binding_mismatch'
}

/** Given a certificate and a local trust-anchor list, determine if
 *  the certificate was issued by a trusted anchor and whether the
 *  anchor's binding constraints (if any) permit this cert's binding. */
export function checkAnchor(
  cert: MutualAuthCertificate,
  anchors: TrustAnchor[],
  revoked_anchor_ids: string[] = [],
): AnchorCheckOutcome {
  const anchor = anchors.find((a) => a.pubkey_hex === cert.issuer_pubkey_hex)
  if (!anchor) return { ok: false, reason: 'unknown_issuer' }
  if (revoked_anchor_ids.includes(anchor.anchor_id)) {
    return { ok: false, anchor, reason: 'revoked_anchor' }
  }
  if (anchor.binding_constraints && anchor.binding_constraints.length > 0) {
    const matched = anchor.binding_constraints.some((pat) =>
      matchBinding(pat, cert.binding),
    )
    if (!matched) return { ok: false, anchor, reason: 'binding_mismatch' }
  }
  return { ok: true, anchor }
}

function matchBinding(pattern: string, binding: string): boolean {
  if (pattern === binding) return true
  if (pattern.endsWith('*')) {
    return binding.startsWith(pattern.slice(0, -1))
  }
  return false
}
