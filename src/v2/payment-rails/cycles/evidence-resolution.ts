// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Cycles external-evidence resolution: claimed vs resolved (W2-A2)
// ══════════════════════════════════════════════════════════════════
// A cycles receipt carries a CyclesEvidenceRef: a `cycles_evidence_url`
// plus a CLAIMED content hash `cycles_evidence_id_sha256`. The receipt
// signature covers that claimed hash, so a signature check shows only
// that SOMEONE signed a pointer to a hash. It does NOT show that an
// envelope exists at the URL, nor that the envelope there hashes to the
// claimed value.
//
// This module closes the explicit join-integrity gap (the TODO at
// cycles/index.ts) WITHOUT making the SDK perform network egress. The
// caller supplies an EvidenceResolver (the M3 caller-supplied-resolver
// pattern: an interface that fetches the envelope behind the caller's
// own transport). The resolver returns the fetched envelope bytes; this
// module recomputes the Cycles content-hash recipe (JCS-canonical
// envelope with `evidence_id` AND `signature` emptied, sha256 hex) and
// compares it byte-for-byte against the claimed hash on the receipt.
//
// SECURITY POSTURE (mirrors M3 key-resolution): default fail-closed.
// "Could not fetch the envelope" is never "envelope matched". A
// degraded/unreachable resolution MUST NOT read as resolved=true.
//
// SCOPE: this is an SDK slot/format/hook. It defines the resolver
// INTERFACE, the recompute-and-match operation, and a descriptor INPUT
// the verifier emits. It ships no hosted resolution service, no
// registry, no cross-tenant aggregation, and reaches no global `fetch`
// directly: the egress lives entirely behind the caller's resolver.
// ══════════════════════════════════════════════════════════════════

import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { sha256Hex } from '../canonicalize.js'
import type { ScopeOfClaim } from '../../accountability/types/base.js'
import type { CyclesEvidenceRef } from './types.js'

// ── Fetched-envelope structural shape ─────────────────────────────
// The full signed CyclesEvidence envelope (with `evidence_id` and
// `signature` members) has no full TS type in-repo; its canonical
// schema lives upstream in cycles-protocol. We type only the structural
// subset the content-hash recipe touches: the two members that get
// emptied before canonicalization. Everything else on the envelope is
// preserved through canonicalizeJCS, so an index signature carries the
// remaining body verbatim.

/** The signed CyclesEvidence envelope as fetched from the URL. The two
 *  named members are the ones the content-hash recipe empties; all
 *  other members ride through canonicalization unchanged. */
export interface FetchedCyclesEvidenceEnvelope {
  /** The envelope's own content-addressed id. Emptied before hashing. */
  evidence_id?: string
  /** The envelope's signature. Emptied before hashing. */
  signature?: string
  /** Remaining envelope body, preserved verbatim through JCS. */
  [key: string]: unknown
}

// ── Resolution status taxonomy (mirrors KeyResolutionStatus, M3) ──
// How an envelope resolution finished. Only `matched` is a positive
// outcome; every other status carries no positive match and a verifier
// MUST surface claimed-not-resolved.

/**
 *  - 'matched'        : envelope fetched and its recomputed content hash
 *                       equals the claimed cycles_evidence_id_sha256.
 *  - 'hash_mismatch'  : envelope fetched but recomputed hash differs from
 *                       the claimed hash. Fail-closed always (a body that
 *                       loads but hashes wrong is NOT transient).
 *  - 'malformed'      : envelope fetched but was not a structurally usable
 *                       object. Fail-closed always.
 *  - 'not_found'      : the resolver loaded the endpoint but no envelope
 *                       was present at the reference. Fail-closed always.
 *  - 'unreachable'    : network error, timeout, non-200, or non-JSON body.
 *                       The ONLY status a fail-open policy may relax to a
 *                       degraded (still non-matching) outcome.
 *  - 'no_resolver'    : no resolver was supplied; the receipt's claimed
 *                       hash was never tested against a fetched envelope.
 */
export type EvidenceResolutionStatus =
  | 'matched'
  | 'hash_mismatch'
  | 'malformed'
  | 'not_found'
  | 'unreachable'
  | 'no_resolver'

/** Failure posture, mirrors M3 FailurePolicy. Default 'closed'. */
export type EvidenceFailurePolicy = 'closed' | 'open'

/**
 * What the caller's resolver returns. When `ok` is true the resolver
 * fetched an envelope and `envelope` is the parsed object; this module
 * then recomputes and compares the hash. When `ok` is false the
 * resolver reports a non-fetch outcome via `status` and the envelope is
 * absent. The resolver MUST NOT itself decide `matched`: matching is
 * this module's job, so the resolver never returns 'matched' or
 * 'hash_mismatch'.
 */
export interface EvidenceFetchResult {
  ok: boolean
  /** A resolver-side non-fetch status. Only 'not_found' | 'unreachable'
   *  | 'malformed' are meaningful here; the match verdict is computed by
   *  resolveEvidenceRef, never by the resolver. */
  status?: 'not_found' | 'unreachable' | 'malformed'
  /** The fetched envelope, present iff ok. */
  envelope?: FetchedCyclesEvidenceEnvelope
  /** Human-readable, non-sensitive explanation. */
  reason?: string
}

/**
 * Caller-supplied envelope resolver (the M3 caller-supplied-resolver
 * pattern). The SDK hardcodes no network egress: the caller owns the
 * transport, HTTPS enforcement, timeout, and caching. `canResolve`
 * lets a caller decline a URL scheme it does not handle. `resolve`
 * MUST always resolve its promise; transport failure is reported via
 * the result's `ok`/`status`, never by rejecting.
 */
export interface EvidenceResolver {
  /** True iff this resolver handles the given evidence URL. */
  canResolve(url: string): boolean
  /** Fetch the envelope at the URL. Never rejects on transport failure;
   *  reports it via the returned EvidenceFetchResult. */
  resolve(url: string): Promise<EvidenceFetchResult>
}

// ── Resolution result (the verifier-derived descriptor input) ─────

/**
 * The outcome of resolving (or declining to resolve) a CyclesEvidenceRef.
 *
 * This is the SHARP claimed-vs-resolved distinction the verifier
 * surfaces. `claimed_sha256` is always the hash the receipt signed over.
 * `resolved` is true ONLY when an envelope was fetched and its recomputed
 * hash matched. `resolved_sha256` is the hash this module actually
 * recomputed from the fetched envelope (present whenever an envelope was
 * fetched, whether or not it matched), so a mismatch is auditable.
 *
 * `degraded` is true only when a fail-open policy turned an 'unreachable'
 * condition into a non-rejecting outcome. A degraded result is NOT
 * `resolved`; it MUST NOT be read as a positive match.
 */
export interface EvidenceResolutionResult {
  /** The receipt's claimed content hash (signature-covered). */
  claimed_sha256: string
  /** True iff an envelope was fetched AND recomputed-hash === claimed. */
  resolved: boolean
  status: EvidenceResolutionStatus
  /** The hash recomputed from the fetched envelope, when one was
   *  fetched. Present on 'matched' and 'hash_mismatch'. */
  resolved_sha256?: string
  /** True iff a fail-open policy produced a non-rejecting degraded
   *  outcome from an unreachable endpoint. Never true with resolved. */
  degraded?: boolean
  /** Human-readable, non-sensitive explanation. */
  reason?: string
  /** Scope-of-claim for the resolution, dogfooding the descriptor. */
  scope_of_claim?: ScopeOfClaim
  /** The fetched envelope, present whenever one was retrieved (on 'matched'
   *  AND 'hash_mismatch'). Surfaced so a downstream signer-AUTHORITY check
   *  (#43) can verify the envelope's own signature — independent of this
   *  receipt↔envelope hash join. */
  envelope?: FetchedCyclesEvidenceEnvelope
}

// ── Config ────────────────────────────────────────────────────────

/** Resolution config. `failurePolicy` defaults to 'closed'. */
export interface ResolveEvidenceConfig {
  failurePolicy?: EvidenceFailurePolicy
}

// ── Content-hash recipe ───────────────────────────────────────────

/**
 * Recompute the Cycles content-addressed id of a fetched envelope:
 * JCS-canonical bytes of the envelope with both `evidence_id` and
 * `signature` set to empty string, then sha256 hex. Reproduces the
 * recipe documented on CyclesEvidenceRef.cycles_evidence_id_sha256 and
 * matched by the Cycles server, so the recomputed value is comparable
 * byte-for-byte against the claimed hash.
 */
export function recomputeEvidenceContentHash(
  envelope: FetchedCyclesEvidenceEnvelope,
): string {
  const canonical = canonicalizeJCS({
    ...envelope,
    evidence_id: '',
    signature: '',
  })
  return sha256Hex(canonical)
}

// ── Scope-of-claim assertions (dogfood the descriptor) ────────────

function matchedScope(): ScopeOfClaim {
  return {
    asserts:
      'aps:cycles.evidence.resolve:matched. An envelope was fetched at the receipt cycles_evidence_url and its recomputed content hash equals the claimed cycles_evidence_id_sha256.',
    does_not_assert: [
      'the envelope content is itself truthful about the underlying rail event',
      'the envelope endpoint asserts the same bytes at any later time',
      'the budget reservation settled',
    ],
    capture_mode: 'gateway_observed',
    completeness: 'complete',
    self_attested: false,
  }
}

function claimedOnlyScope(): ScopeOfClaim {
  return {
    asserts:
      'aps:cycles.evidence.resolve:claimed_only. The receipt signature covers a pointer to a content hash; no envelope was fetched and matched, so only that someone signed a reference to the hash is shown.',
    does_not_assert: [
      'an envelope exists at the cycles_evidence_url',
      'the envelope at the URL hashes to the claimed cycles_evidence_id_sha256',
      'the claimed hash corresponds to any real rail event',
    ],
    capture_mode: 'unknown',
    completeness: 'best_effort',
    self_attested: false,
  }
}

// ── resolveEvidenceRef: the claimed-vs-resolved operation ─────────

/**
 * Resolve a CyclesEvidenceRef against a caller-supplied resolver and
 * report the claimed-vs-resolved verdict.
 *
 * Records failure, never throws. A missing resolver yields a
 * 'no_resolver' result (claimed-not-resolved), NOT an error. A resolver
 * that reports unreachable yields 'unreachable' (degraded under
 * fail-open, still non-matching). Only a fetched envelope whose
 * recomputed hash equals the claimed hash yields resolved=true.
 *
 * @param ref       the receipt's cycles_evidence join shape
 * @param resolver  caller-supplied envelope resolver, or undefined
 * @param config    failure policy (default fail-closed)
 */
export async function resolveEvidenceRef(
  ref: CyclesEvidenceRef,
  resolver: EvidenceResolver | undefined,
  config: ResolveEvidenceConfig = {},
): Promise<EvidenceResolutionResult> {
  const claimed = ref.cycles_evidence_id_sha256
  const failurePolicy = config.failurePolicy ?? 'closed'

  // No resolver supplied: the claimed hash was never tested. This is the
  // fail-closed default for "the caller did not opt into resolution".
  if (!resolver || !resolver.canResolve(ref.cycles_evidence_url)) {
    return {
      claimed_sha256: claimed,
      resolved: false,
      status: 'no_resolver',
      reason: resolver
        ? 'resolver declined this evidence url'
        : 'no evidence resolver supplied; claimed hash not tested',
      scope_of_claim: claimedOnlyScope(),
    }
  }

  let fetched: EvidenceFetchResult
  try {
    fetched = await resolver.resolve(ref.cycles_evidence_url)
  } catch (err) {
    // A resolver SHOULD NOT reject, but if it does we record it as
    // unreachable rather than letting it throw out of the verifier.
    return unreachableResult(claimed, failurePolicy, `resolver threw: ${safeMsg(err)}`)
  }

  if (!fetched.ok || !fetched.envelope) {
    const status = fetched.status ?? 'unreachable'
    if (status === 'unreachable') {
      return unreachableResult(claimed, failurePolicy, fetched.reason ?? 'envelope unreachable')
    }
    // not_found / malformed always fail closed (loaded-but-wrong is not
    // a transient condition).
    return {
      claimed_sha256: claimed,
      resolved: false,
      status,
      reason: fetched.reason ?? `envelope ${status}`,
      scope_of_claim: claimedOnlyScope(),
    }
  }

  // Envelope fetched: recompute and compare.
  let recomputed: string
  try {
    recomputed = recomputeEvidenceContentHash(fetched.envelope)
  } catch (err) {
    return {
      claimed_sha256: claimed,
      resolved: false,
      status: 'malformed',
      reason: `envelope canonicalization failed: ${safeMsg(err)}`,
      scope_of_claim: claimedOnlyScope(),
    }
  }

  if (recomputed === claimed) {
    return {
      claimed_sha256: claimed,
      resolved: true,
      status: 'matched',
      resolved_sha256: recomputed,
      scope_of_claim: matchedScope(),
      envelope: fetched.envelope,
    }
  }

  return {
    claimed_sha256: claimed,
    resolved: false,
    status: 'hash_mismatch',
    resolved_sha256: recomputed,
    reason: 'fetched envelope hash does not equal claimed cycles_evidence_id_sha256',
    scope_of_claim: claimedOnlyScope(),
    envelope: fetched.envelope,
  }
}

// ── helpers ───────────────────────────────────────────────────────

function unreachableResult(
  claimed: string,
  failurePolicy: EvidenceFailurePolicy,
  reason: string,
): EvidenceResolutionResult {
  // fail-open relaxes ONLY unreachable into a degraded, still
  // non-matching outcome. fail-closed (default) is identical except for
  // the degraded flag; neither ever sets resolved=true.
  return {
    claimed_sha256: claimed,
    resolved: false,
    status: 'unreachable',
    degraded: failurePolicy === 'open',
    reason:
      failurePolicy === 'open'
        ? `fail-open degraded: ${reason}`
        : `fail-closed: ${reason}`,
    scope_of_claim: claimedOnlyScope(),
  }
}

function safeMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

// ── W2-A1 descriptor input (mechanical facts only) ────────────────
// The W2-A1 verifier descriptor reports mechanical facts about a
// receipt and the evidence it claims. This is the INPUT slot W2-A1
// consumes for the external-evidence axis. It reports ONLY mechanical
// facts: the claimed hash, whether the envelope was fetched-and-matched,
// and the observation basis. It carries NO issuer-set assurance scalar
// and NO verifier advisory: any policy scalar that sits on top of the
// descriptor is W2-A1's to compute, not this module's.
//
// FULL WIRING NOTE: W2-A1 is a sibling branch. This interface defines
// the contract both branches build against; the descriptor composition
// (folding this input into the full lattice the A1 descriptor reports)
// lands when A1 and A2 merge. A2 produces the input; A1 consumes it.

/**
 * The external-evidence observation basis, a mechanical fact for the
 * W2-A1 descriptor. It distinguishes the two evidentiary states the
 * brief names:
 *  - 'signature_only'      : the receipt signature covers a pointer to a
 *                            hash; no envelope was fetched and matched.
 *  - 'counterparty_resolved': an envelope was fetched at the URL and its
 *                            recomputed content hash matched the claim.
 */
export type EvidenceObservationBasis =
  | 'signature_only'
  | 'counterparty_resolved'

/**
 * The mechanical descriptor input the W2-A1 verifier descriptor consumes
 * for a cycles receipt's external-evidence axis. Mechanical facts only;
 * no assurance scalar, no ladder. A1 derives any policy output on top.
 */
export interface EvidenceDescriptorInput {
  /** The receipt's claimed content hash (always present; signed-over). */
  claimed_sha256: string
  /** signature_only vs counterparty_resolved, the sharp distinction. */
  observation_basis: EvidenceObservationBasis
  /** True iff observation_basis === 'counterparty_resolved'. */
  envelope_matched: boolean
  /** The recomputed hash, when an envelope was fetched (matched or not). */
  resolved_sha256?: string
  /** The underlying resolution status, preserved for the A1 lattice. */
  resolution_status: EvidenceResolutionStatus
  /** True iff a fail-open degraded outcome produced this input. */
  degraded?: boolean
}

/**
 * Project a resolution result into the W2-A1 descriptor input. Pure,
 * mechanical, total. `counterparty_resolved` iff the envelope was
 * fetched and matched; every other status is `signature_only` (the
 * receipt signature still stands on its own; it simply was not
 * corroborated by a fetched envelope).
 */
export function toEvidenceDescriptorInput(
  result: EvidenceResolutionResult,
): EvidenceDescriptorInput {
  const input: EvidenceDescriptorInput = {
    claimed_sha256: result.claimed_sha256,
    observation_basis: result.resolved ? 'counterparty_resolved' : 'signature_only',
    envelope_matched: result.resolved,
    resolution_status: result.status,
  }
  if (result.resolved_sha256 !== undefined) {
    input.resolved_sha256 = result.resolved_sha256
  }
  if (result.degraded !== undefined) {
    input.degraded = result.degraded
  }
  return input
}
