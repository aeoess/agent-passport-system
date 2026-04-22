// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Mutual Authentication v1 — handshake primitives
// ══════════════════════════════════════════════════════════════════
// Flow:
//   1. Initiator sends MutualAuthHello (nonce_i, supported_versions)
//   2. Responder replies with MutualAuthAttest (chosen_version, own
//      nonce_r, peer nonce_i, own certificate, signed commitment
//      over all four).
//   3. Initiator verifies the Attest, then replies with its own
//      MutualAuthAttest (chosen_version must match, nonces swapped).
//   4. Responder verifies the initiator's Attest.
//   5. Both sides derive an identical MutualAuthSession (shared
//      hash of the two Attests → session_id).
//
// Downgrade defence:
//   The Attest signature commits to the chosen_version alongside
//   both nonces and both certs. An attacker who can tamper with
//   supported_versions at the transport layer cannot forge a valid
//   Attest that advertises a lower version without also breaking
//   the signature.
//
// Replay defence:
//   The nonces are 128-bit random, the Attest timestamp is bounded
//   by max_clock_skew_ms, and the session_id derivation includes
//   both nonces.
// ══════════════════════════════════════════════════════════════════

import { createHash, randomBytes } from 'node:crypto'
import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import { sign as edSignHex, verify as edVerifyHex } from '../../crypto/keys.js'
import {
  certificateId,
  checkAnchor,
  isCertificateTemporallyValid,
  verifyCertificateSignature,
} from './certificate.js'
import type {
  MutualAuthAttest,
  MutualAuthCertificate,
  MutualAuthFailureReason,
  MutualAuthHello,
  MutualAuthPolicy,
  MutualAuthResult,
  MutualAuthRole,
  MutualAuthSession,
  TrustAnchor,
} from './types.js'

const SPEC_VERSION = '1.0' as const

// ── Nonce generation ──

export function newNonce(): string {
  return randomBytes(16).toString('base64')
}

// ── Hello ──

export function buildHello(
  role: MutualAuthRole,
  supported_versions: string[],
  now_ms: number,
  nonce_b64 = newNonce(),
): MutualAuthHello {
  return {
    spec_version: SPEC_VERSION,
    role,
    supported_versions,
    nonce_b64,
    timestamp: now_ms,
  }
}

// ── Version negotiation ──

/** Choose the highest mutually supported version. Returns null if
 *  there is no overlap. Both sides MUST run the same algorithm. */
export function chooseVersion(
  peer_supported: string[],
  own_accepted: string[],
): string | null {
  for (const v of own_accepted) {
    if (peer_supported.includes(v)) return v
  }
  return null
}

// ── Attest build + sign ──

export interface BuildAttestInput {
  role: MutualAuthRole
  chosen_version: string
  own_nonce_b64: string
  peer_nonce_b64: string
  certificate: MutualAuthCertificate
  now_ms: number
}

export function buildAttest(
  input: BuildAttestInput,
  own_sk_hex: string,
): MutualAuthAttest {
  const unsigned: Omit<MutualAuthAttest, 'signature_b64'> = {
    spec_version: SPEC_VERSION,
    role: input.role,
    chosen_version: input.chosen_version,
    own_nonce_b64: input.own_nonce_b64,
    peer_nonce_b64: input.peer_nonce_b64,
    certificate: input.certificate,
    timestamp: input.now_ms,
  }
  const canonical = canonicalizeJCS(unsigned)
  const sig_hex = edSignHex(canonical, own_sk_hex)
  return {
    ...unsigned,
    signature_b64: Buffer.from(sig_hex, 'hex').toString('base64'),
  }
}

// ── Attest verify (signature + policy + cert chain) ──

export interface VerifyAttestInput {
  attest: MutualAuthAttest
  expected_peer_nonce_b64: string
  expected_own_nonce_b64: string
  policy: MutualAuthPolicy
  trust_anchors: TrustAnchor[]
  revoked_anchor_ids?: string[]
  now_ms: number
}

export interface VerifyAttestOutcome {
  ok: boolean
  reason?: MutualAuthFailureReason
  detail?: string
}

export function verifyAttest(input: VerifyAttestInput): VerifyAttestOutcome {
  const { attest, policy, trust_anchors, now_ms } = input
  const skew = policy.max_clock_skew_ms ?? 0

  // 1. Version negotiated must be one we accept
  if (!policy.accepted_versions.includes(attest.chosen_version)) {
    return { ok: false, reason: 'version_unsupported' }
  }

  // 2. Nonces must match what we expect (replay + mitm defence)
  if (attest.peer_nonce_b64 !== input.expected_peer_nonce_b64) {
    return { ok: false, reason: 'nonce_mismatch', detail: 'peer_nonce' }
  }
  if (attest.own_nonce_b64 !== input.expected_own_nonce_b64) {
    return { ok: false, reason: 'nonce_mismatch', detail: 'own_nonce' }
  }

  // 3. Timestamp must be within clock skew
  if (Math.abs(now_ms - attest.timestamp) > Math.max(skew, 60_000)) {
    return { ok: false, reason: 'replay_detected', detail: 'timestamp_skew' }
  }

  // 4. Embedded certificate must be temporally valid
  const temporal = isCertificateTemporallyValid(
    attest.certificate,
    now_ms,
    skew,
  )
  if (!temporal.ok) {
    return {
      ok: false,
      reason:
        temporal.reason === 'expired'
          ? 'expired_certificate'
          : temporal.reason === 'not_yet_valid'
            ? 'not_yet_valid_certificate'
            : 'signature_invalid',
    }
  }

  // 5. Certificate signature must verify
  const certSig = verifyCertificateSignature(attest.certificate)
  if (!certSig.ok) {
    return { ok: false, reason: 'signature_invalid', detail: 'certificate' }
  }

  // 6. Certificate must be vouched for by a known trust anchor
  const anchor = checkAnchor(
    attest.certificate,
    trust_anchors,
    input.revoked_anchor_ids,
  )
  if (!anchor.ok) {
    return {
      ok: false,
      reason:
        anchor.reason === 'unknown_issuer'
          ? 'unknown_issuer'
          : anchor.reason === 'revoked_anchor'
            ? 'revoked_anchor'
            : 'binding_mismatch',
    }
  }

  // 7. Downgrade detection: the chosen_version MUST be the highest
  //    we and the peer both support. If peer's supported_versions in
  //    the embedded cert offers something higher that we also accept,
  //    a downgrade was forced.
  const peerSupported = attest.certificate.supported_versions
  const expectedChoice = chooseVersion(peerSupported, policy.accepted_versions)
  if (expectedChoice !== null && expectedChoice !== attest.chosen_version) {
    return { ok: false, reason: 'downgrade_detected' }
  }

  // 8. Agent grade policy (only applies when peer is an agent)
  if (attest.certificate.role === 'agent' && policy.min_agent_grade !== undefined) {
    const grade = attest.certificate.attestation_grade ?? 0
    if (grade < policy.min_agent_grade) {
      return { ok: false, reason: 'grade_insufficient' }
    }
  }

  // 9. Required capabilities (policy check)
  if (policy.required_capabilities && policy.required_capabilities.length > 0) {
    const caps = attest.certificate.capabilities ?? []
    for (const required of policy.required_capabilities) {
      if (!caps.includes(required)) {
        return {
          ok: false,
          reason: 'binding_mismatch',
          detail: `missing_capability:${required}`,
        }
      }
    }
  }

  // 10. Verify the attest signature itself (commits to chosen_version
  //     + both nonces + cert — this is the downgrade defence).
  const { signature_b64, ...rest } = attest
  const canonical = canonicalizeJCS(rest)
  const sig_hex = Buffer.from(signature_b64, 'base64').toString('hex')
  const sigOk = edVerifyHex(
    canonical,
    sig_hex,
    attest.certificate.subject_pubkey_hex,
  )
  if (!sigOk) return { ok: false, reason: 'signature_invalid', detail: 'attest' }

  return { ok: true }
}

// ── Session derivation ──

/** Derive the shared session record from both sides' Attests. Both
 *  parties MUST compute identical session_id values given identical
 *  inputs (canonical JCS + sha256). */
export function deriveSession(
  agent_attest: MutualAuthAttest,
  is_attest: MutualAuthAttest,
  policy: MutualAuthPolicy,
  now_ms: number,
): MutualAuthResult {
  if (agent_attest.chosen_version !== is_attest.chosen_version) {
    return { ok: false, failure: { reason: 'downgrade_detected' } }
  }
  if (agent_attest.certificate.role !== 'agent') {
    return {
      ok: false,
      failure: { reason: 'binding_mismatch', detail: 'agent_attest_role' },
    }
  }
  if (is_attest.certificate.role !== 'information_system') {
    return {
      ok: false,
      failure: { reason: 'binding_mismatch', detail: 'is_attest_role' },
    }
  }

  const agent_cert_id = certificateId(agent_attest.certificate)
  const is_cert_id = certificateId(is_attest.certificate)

  const sessionMaterial = canonicalizeJCS({
    spec_version: SPEC_VERSION,
    chosen_version: agent_attest.chosen_version,
    agent_cert_id,
    is_cert_id,
    agent_nonce_b64: agent_attest.own_nonce_b64,
    is_nonce_b64: is_attest.own_nonce_b64,
  })
  const session_id = 'sha256:' + createHash('sha256').update(sessionMaterial).digest('hex')

  const max_session =
    policy.max_session_ms ??
    Math.min(
      agent_attest.certificate.not_after,
      is_attest.certificate.not_after,
    ) - now_ms

  const session: MutualAuthSession = {
    spec_version: SPEC_VERSION,
    session_id,
    agent_cert: agent_attest.certificate,
    is_cert: is_attest.certificate,
    chosen_version: agent_attest.chosen_version,
    agent_nonce_b64: agent_attest.own_nonce_b64,
    is_nonce_b64: is_attest.own_nonce_b64,
    established_at: now_ms,
    expires_at: now_ms + Math.max(0, max_session),
  }

  if (session.expires_at <= session.established_at) {
    return { ok: false, failure: { reason: 'expired_session' } }
  }

  return { ok: true, session }
}

/** Check whether a MutualAuthSession is still alive. */
export function isSessionActive(
  session: MutualAuthSession,
  now_ms: number,
): boolean {
  return (
    now_ms >= session.established_at &&
    now_ms <= session.expires_at &&
    now_ms <= session.agent_cert.not_after &&
    now_ms <= session.is_cert.not_after
  )
}
