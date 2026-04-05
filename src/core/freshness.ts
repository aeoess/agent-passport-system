// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// AttestationFreshness — Typed Evidence Staleness
// ══════════════════════════════════════════════════════════════════
// Thread claim (A2A#1712, VCOne-AI):
//   ttl: null on snapshot attestations is semantically wrong. TPM quotes
//   are point-in-time snapshots (need explicit staleness policy);
//   SPIFFE SVIDs rotate continuously (have implicit lifetime).
//
// We distinguish three evidence shapes:
//   - rotating: has ttl (SPIFFE SVID, short-lived JWT)
//   - snapshot: has maxAge (TPM quote, point-in-time attestation)
//   - static:   never expires by age alone (e.g. long-lived CA-issued
//               certificates, managed externally by the issuer)
//
// The `grade` on a passport remains the quick-filter index. `freshness`
// is the detailed staleness metadata consumers check for high-assurance
// contexts.
// ══════════════════════════════════════════════════════════════════

import type { AttestationFreshness } from '../types/passport.js'

/**
 * Seconds elapsed since the evidence was produced (`validAt`).
 * Returns 0 if validAt is in the future (clock skew); never negative.
 */
export function computeEvidenceAge(freshness: AttestationFreshness, now?: Date): number {
  const then = new Date(freshness.validAt).getTime()
  const current = (now ?? new Date()).getTime()
  const ageMs = current - then
  return ageMs < 0 ? 0 : Math.floor(ageMs / 1000)
}

/**
 * Whether the evidence is still fresh for its type.
 *   rotating: now - validAt < ttl (ttl required; missing ttl → not fresh)
 *   snapshot: now - validAt < maxAge; if maxAge omitted → fresh (conservative default)
 *   static:   always true
 */
export function isEvidenceFresh(freshness: AttestationFreshness, now?: Date): boolean {
  const age = computeEvidenceAge(freshness, now)
  switch (freshness.type) {
    case 'rotating':
      if (typeof freshness.ttl !== 'number') return false
      return age < freshness.ttl
    case 'snapshot':
      if (typeof freshness.maxAge !== 'number') return true
      return age < freshness.maxAge
    case 'static':
      return true
  }
}

/**
 * Construct a snapshot freshness record (TPM quote, point-in-time attestation).
 * `maxAge` is the recommended staleness window in seconds.
 */
export function createSnapshotFreshness(validAt: string, maxAge?: number): AttestationFreshness {
  return { type: 'snapshot', validAt, maxAge }
}

/**
 * Construct a rotating freshness record (SPIFFE SVID, short-lived JWT).
 * `ttl` is the evidence lifetime in seconds.
 */
export function createRotatingFreshness(validAt: string, ttl: number): AttestationFreshness {
  return { type: 'rotating', validAt, ttl }
}
