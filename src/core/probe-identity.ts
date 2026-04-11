// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Probe Identity — Content-Addressable Hashing for Evaluation Probes
// ══════════════════════════════════════════════════════════════════
// Reference: Nanook PDR v2.19 §5.9 (MD5 hash prompt identity verification),
// gap audit §3 row 16 / §5 rank 7.
//
// Nanook §5.9 uses an MD5 hash of the evaluation probe prompt to
// eliminate input variation as a confound: every scoring run can prove
// it used byte-identical input. APS has canonical JSON serialization in
// canonical.ts but no probe-prompt identity verification protocol. This
// utility ships that protocol.
//
// Algorithm choice:
//   APS defaults to SHA-256 because the rest of the SDK uses it
//   (canonical.ts, signatures, content hashing). MD5 is available as an
//   opt-in for interop with Nanook's existing probe bank. Callers pick
//   via opts.algorithm. Both produce hex strings.
//
// Canonicalization:
//   The point of this utility is that two JSON objects with the same
//   content but different key declaration order produce the same hash.
//   canonicalize() from canonical.ts (RFC 8785 JCS) guarantees this by
//   sorting keys alphabetically and stripping null/undefined. Do NOT use
//   JSON.stringify() directly — declaration order would leak through.
//
// Array semantics:
//   canonicalize() preserves array order because array order is semantic
//   in JSON. [1, 2, 3] and [3, 2, 1] produce different hashes. This is
//   correct: a probe that asks the agent to compute things in a specific
//   sequence should be a different probe if the sequence changes.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalize } from './canonical.js'

/** A content-addressable identifier for an evaluation probe. The hash
 *  is the canonical JSON of the probe digested with the named algorithm.
 *  Two probes with the same content (regardless of property declaration
 *  order in the source) produce the same hash. */
export interface ProbeIdentity {
  /** Hex-encoded digest. Length depends on algorithm: 64 for sha256, 32 for md5. */
  hash: string
  /** Hash algorithm used. SHA-256 by default; MD5 for Nanook interop. */
  algorithm: 'sha256' | 'md5'
  /** ISO 8601 timestamp of when the hash was computed. The only clock read in this module. */
  computedAt: string
}

/** Result of verifying a probe against an expected hash. The function
 *  does NOT throw on mismatch; the caller decides what to do. */
export interface ProbeIdentityVerification {
  /** True iff computedHash === expectedHash. */
  match: boolean
  /** The hash the caller said the probe should have. */
  expectedHash: string
  /** The hash actually computed from the probe. */
  computedHash: string
  /** Algorithm used for the recomputation. */
  algorithm: 'sha256' | 'md5'
}

/**
 * Compute a content-addressable identity for an evaluation probe.
 *
 * The probe is canonicalized via canonicalize() from canonical.ts (RFC
 * 8785 JCS) before hashing. This means two probes with the same content
 * but different property declaration order produce identical hashes,
 * which is the entire point of the utility — it lets a downstream
 * scoring system prove that the probe it scored is byte-identical to the
 * probe the issuer published, even after a JSON round-trip that may have
 * reordered keys.
 *
 * Pure in algorithmic terms: same input + same algorithm always
 * produces the same hash. The only side effect is the ISO timestamp
 * captured in computedAt, which is set from new Date(). Callers that
 * need fully deterministic output (e.g. test fixtures) should compare
 * the hash field directly and ignore computedAt.
 *
 * @param probe  Any JSON-serializable value. Typically a FidelityChallenge
 *               or similar evaluation probe object.
 * @param opts.algorithm  'sha256' (default) or 'md5' for Nanook interop.
 *
 * Reference: Nanook PDR v2.19 §5.9, gap audit §3 row 16 / §5 rank 7.
 */
export function computeProbeIdentity(
  probe: unknown,
  opts?: { algorithm?: 'sha256' | 'md5' },
): ProbeIdentity {
  const algorithm = opts?.algorithm ?? 'sha256'
  const canonical = canonicalize(probe)
  const hash = createHash(algorithm).update(canonical).digest('hex')
  return {
    hash,
    algorithm,
    computedAt: new Date().toISOString(),
  }
}

/**
 * Verify that a probe matches an expected hash.
 *
 * Recomputes the hash from the probe via canonicalize() + the chosen
 * algorithm and compares to the expected hash. Returns a verification
 * result with both hashes exposed for diagnostic visibility.
 *
 * Does NOT throw on mismatch. Callers decide what to do with a false
 * match: log it, deny the action, fall back to a different probe, etc.
 * The function is purely informational.
 *
 * Algorithm mismatch case: if the caller passes an expectedHash that was
 * produced under a different algorithm than the one passed via opts
 * (e.g. expectedHash is a SHA-256 digest but opts.algorithm is 'md5'),
 * the function recomputes under the requested algorithm and reports
 * match: false. The function does not try to detect the mismatch
 * automatically — the algorithm is a caller-provided assertion about how
 * the expectedHash was originally computed.
 *
 * @param probe         Any JSON-serializable value.
 * @param expectedHash  Hex-encoded digest the caller asserts the probe should produce.
 * @param opts.algorithm  Algorithm to use for the recomputation. Default 'sha256'.
 */
export function verifyProbeIdentity(
  probe: unknown,
  expectedHash: string,
  opts?: { algorithm?: 'sha256' | 'md5' },
): ProbeIdentityVerification {
  const algorithm = opts?.algorithm ?? 'sha256'
  const canonical = canonicalize(probe)
  const computedHash = createHash(algorithm).update(canonical).digest('hex')
  return {
    match: computedHash === expectedHash,
    expectedHash,
    computedHash,
    algorithm,
  }
}
