// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// M4. Verifier production-hardening (reference primitives)
// ══════════════════════════════════════════════════════════════════
// Four small, additive verification-time checks that a verifier can run
// over a receipt and its inputs, plus the metadata shapes to record the
// outcomes. Every check is a pure function or a self-contained reference
// implementation. None of them is a service: persistence, aggregation,
// alerting, and cross-tenant logic are the integrator's responsibility and
// live outside this SDK.
//
// (a) clock skew. One uniform allowedClockSkewMs helper, consolidating the
//     per-verifier skews already present in ap2 (clock_skew_seconds) and
//     instruction-provenance (clockSkewMs). Those remain available; this is
//     the uniform millisecond-based option.
// (b) replay. A MUST-enforce hook with a reference in-memory seen-set keyed
//     on jti / evidence_id. Durable persistence is the integrator's job
//     (documented). The seen-set here is for a single process lifetime.
// (c) revocation-freshness recording. Produces a RevocationFreshnessRecord
//     (checked-at, source, max staleness, result, allowed-despite-stale),
//     reusing AttestationFreshness from src/types/passport.ts.
// (d) sequence-chaining. Detects a missing receipt via a monotonic counter
//     gap or a broken previousReceiptHash link. The messaging-audit
//     sequenceNumber pattern is the reference.
//
// Claims language: these primitives are "specified / tested / validated".
// They are NOT "proved / guaranteed". See PROOF BOX below.
//
// ──────────────────────────── PROOF BOX ────────────────────────────
// Proves: a hardened receipt proves the verifier checked skew, replay,
//   revocation-freshness, and sequence continuity at verification time and
//   recorded the outcomes.
// Does NOT prove: that the revocation source itself was current beyond the
//   recorded staleness, nor that a stale-but-allowed decision was safe. A
//   'skipped' or 'unavailable' freshness result records the absence of a
//   check, not its success. A passing sequence check proves local continuity
//   of the receipts presented, not that no receipt was withheld upstream of
//   the first one seen.
// Dogfood: callers that emit an accountability receipt for this check SHOULD
//   attach a ScopeOfClaim (src/v2/accountability/types/base.ts) that mirrors
//   the box above. buildHardeningScopeOfClaim() returns exactly that.
// ════════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalize } from '../../core/canonical.js'
import { isEvidenceFresh, computeEvidenceAge } from '../../core/freshness.js'
import type { AttestationFreshness } from '../../types/passport.js'
import type { ActionReceipt } from '../../types/passport.js'
import type {
  RevocationFreshnessRecord,
  RevocationFreshnessResult,
} from '../../types/policy.js'
import type { ScopeOfClaim } from '../accountability/types/base.js'

// ══════════════════════════════════════════════════════════════════
// (a) Uniform clock skew
// ══════════════════════════════════════════════════════════════════

/** Default uniform clock skew (5 minutes), matching instruction-provenance. */
export const DEFAULT_CLOCK_SKEW_MS = 5 * 60 * 1000

export type SkewVerdict = 'valid' | 'not_yet_valid' | 'expired'

export interface SkewCheckResult {
  verdict: SkewVerdict
  /** Milliseconds the timestamp is outside the tolerated window (0 when valid). */
  outsideByMs: number
}

/**
 * Check a single timestamp window against a uniform clock skew.
 *
 * A timestamp `iat` is `not_yet_valid` only when it exceeds `now + skew`.
 * An `exp` is `expired` only when it precedes `now - skew`. Exactly at the
 * boundary (`iat === now + skew` or `exp === now - skew`) the verdict is
 * `valid`: the boundary is inclusive. This matches the ap2 and
 * instruction-provenance comparisons (`>` / `<`, not `>=` / `<=`).
 */
export function checkClockSkew(opts: {
  /** Issued-at (not-before) instant. */
  iat?: Date | string | number
  /** Expiry instant. */
  exp?: Date | string | number
  /** Verifier clock; defaults to now. */
  now?: Date
  /** Allowed skew in milliseconds; defaults to {@link DEFAULT_CLOCK_SKEW_MS}. */
  allowedClockSkewMs?: number
}): SkewCheckResult {
  const skew = opts.allowedClockSkewMs ?? DEFAULT_CLOCK_SKEW_MS
  const nowMs = (opts.now ?? new Date()).getTime()

  const iatMs = toMs(opts.iat)
  if (iatMs !== undefined && iatMs > nowMs + skew) {
    return { verdict: 'not_yet_valid', outsideByMs: iatMs - (nowMs + skew) }
  }

  const expMs = toMs(opts.exp)
  if (expMs !== undefined && expMs < nowMs - skew) {
    return { verdict: 'expired', outsideByMs: (nowMs - skew) - expMs }
  }

  return { verdict: 'valid', outsideByMs: 0 }
}

function toMs(t?: Date | string | number): number | undefined {
  if (t === undefined) return undefined
  if (t instanceof Date) return t.getTime()
  if (typeof t === 'number') return t
  const parsed = Date.parse(t)
  return Number.isNaN(parsed) ? undefined : parsed
}

// ══════════════════════════════════════════════════════════════════
// (b) Replay check. MUST-enforce hook plus reference in-memory seen-set
// ══════════════════════════════════════════════════════════════════
//
// VERIFIER RESPONSIBILITY (MUST): a verifier MUST reject the second and any
// later submission of a receipt bearing the same jti / evidence_id. The SDK
// supplies the hook (SeenSet) and a reference in-memory implementation
// (InMemorySeenSet). Durable, cross-process, cross-restart persistence is the
// integrator's responsibility. An in-memory seen-set protects a single
// process lifetime only; a restart forgets every id it has seen.

/** Minimal hook a verifier calls to enforce single-use of an identifier. */
export interface SeenSet {
  /** Record `id` as seen. Returns true if this is the FIRST time `id` is
   *  recorded (accept), false if `id` was already present (replay, reject). */
  recordIfFirst(id: string): boolean
  /** Whether `id` has already been recorded, without recording it. */
  has(id: string): boolean
}

/** Reference in-memory seen-set. Single process lifetime only. NOT durable. */
export class InMemorySeenSet implements SeenSet {
  private readonly seen = new Set<string>()

  recordIfFirst(id: string): boolean {
    if (this.seen.has(id)) return false
    this.seen.add(id)
    return true
  }

  has(id: string): boolean {
    return this.seen.has(id)
  }

  /** Number of distinct ids recorded. For tests and metering by the caller. */
  get size(): number {
    return this.seen.size
  }
}

export type ReplayVerdict = 'accepted' | 'rejected_replay' | 'rejected_missing_id'

export interface ReplayCheckResult {
  verdict: ReplayVerdict
  /** The id that was checked, when one was present. */
  id?: string
}

/**
 * Enforce single-use of a receipt's `jti` / `evidence_id` against a seen-set.
 *
 * Returns `accepted` on the first submission of an id, `rejected_replay` on a
 * repeat, and `rejected_missing_id` when no id is present (a verifier that
 * MUST enforce replay cannot do so for an id-less receipt; surfacing this is
 * the safe default rather than silently accepting).
 */
export function checkReplay(id: string | undefined, seen: SeenSet): ReplayCheckResult {
  if (!id) return { verdict: 'rejected_missing_id' }
  const first = seen.recordIfFirst(id)
  return first
    ? { verdict: 'accepted', id }
    : { verdict: 'rejected_replay', id }
}

// ══════════════════════════════════════════════════════════════════
// (c) Revocation-freshness recording
// ══════════════════════════════════════════════════════════════════

/**
 * Build a {@link RevocationFreshnessRecord} for the policy receipt.
 *
 * Reuses {@link AttestationFreshness} for the staleness shape. The `result`
 * is derived as follows:
 *   - 'skipped'     when the verifier did not consult a source.
 *   - 'unavailable' when the source could not be reached.
 *   - 'fresh'       when the source was reached and isEvidenceFresh() holds
 *                   AND the measured age is within maxStalenessMs.
 *   - 'stale'       when the source was reached but is older than tolerated.
 *
 * `allowedDespiteStale` records whether the verifier proceeded anyway. It is
 * an explicit, auditable risk acceptance, never inferred.
 */
export function recordRevocationFreshness(opts: {
  source: string
  maxStalenessMs: number
  checkedAt?: Date
  /** Omit when the verifier chose not to check (→ 'skipped'). */
  freshness?: AttestationFreshness
  /** True when the source could not be reached (→ 'unavailable'). */
  unavailable?: boolean
  /** When true, the verifier proceeded even on a non-fresh result. */
  allowDespiteStale?: boolean
}): RevocationFreshnessRecord {
  const checkedAt = (opts.checkedAt ?? new Date()).toISOString()
  let result: RevocationFreshnessResult

  if (opts.unavailable) {
    result = 'unavailable'
  } else if (!opts.freshness) {
    result = 'skipped'
  } else {
    const ageMs = computeEvidenceAge(opts.freshness, opts.checkedAt) * 1000
    const withinTyped = isEvidenceFresh(opts.freshness, opts.checkedAt)
    const withinWindow = ageMs <= opts.maxStalenessMs
    result = withinTyped && withinWindow ? 'fresh' : 'stale'
  }

  const allowedDespiteStale =
    result !== 'fresh' && (opts.allowDespiteStale ?? false)

  const record: RevocationFreshnessRecord = {
    checkedAt,
    source: opts.source,
    maxStalenessMs: opts.maxStalenessMs,
    result,
    allowedDespiteStale,
  }
  if (opts.freshness) record.freshness = opts.freshness
  return record
}

// ══════════════════════════════════════════════════════════════════
// (d) Receipt sequence-chaining. Detect a missing receipt
// ══════════════════════════════════════════════════════════════════

/** Hash of a receipt for use as the previous-hash link in the next receipt.
 *  Excludes the `signature` so a receipt's link is stable before signing,
 *  and is independent of the action_ref preimage. */
export function hashReceiptForChain(receipt: ActionReceipt): string {
  const { signature, ...unsigned } = receipt
  return createHash('sha256').update(canonicalize(unsigned)).digest('hex')
}

export type SequenceGapKind = 'counter_gap' | 'hash_break' | 'out_of_order'

export interface SequenceGap {
  kind: SequenceGapKind
  /** 0-based index in the supplied stream where the gap was detected. */
  atIndex: number
  detail: string
}

export interface SequenceCheckResult {
  /** True only when no gaps were detected across the whole stream. */
  continuous: boolean
  gaps: SequenceGap[]
}

/**
 * Verify continuity across an ordered receipt stream from a single issuer.
 *
 * Two independent signals make a deleted receipt detectable:
 *   - monotonic counter: consecutive `sequenceNumber`s must increase by 1.
 *     A jump (n, n+2) flags a `counter_gap`; a non-increase flags
 *     `out_of_order`.
 *   - hash link: each receipt's `previousReceiptHash` must equal the chain
 *     hash of its predecessor. A mismatch flags a `hash_break`.
 *
 * A receipt missing both signals is skipped for that signal (the check is
 * additive and back-compatible). The result is `continuous` only when every
 * present signal is intact. Detecting a gap does NOT prove which receipt was
 * removed, only that one is missing between two presented receipts.
 */
export function verifyReceiptSequence(receipts: ActionReceipt[]): SequenceCheckResult {
  const gaps: SequenceGap[] = []

  for (let i = 1; i < receipts.length; i++) {
    const prev = receipts[i - 1]
    const cur = receipts[i]

    // Monotonic counter signal.
    if (typeof prev.sequenceNumber === 'number' && typeof cur.sequenceNumber === 'number') {
      const delta = cur.sequenceNumber - prev.sequenceNumber
      if (delta > 1) {
        gaps.push({
          kind: 'counter_gap',
          atIndex: i,
          detail: `sequenceNumber jumped ${prev.sequenceNumber} → ${cur.sequenceNumber} (${delta - 1} missing)`,
        })
      } else if (delta <= 0) {
        gaps.push({
          kind: 'out_of_order',
          atIndex: i,
          detail: `sequenceNumber did not increase: ${prev.sequenceNumber} → ${cur.sequenceNumber}`,
        })
      }
    }

    // Hash link signal.
    if (cur.previousReceiptHash !== undefined) {
      const expected = hashReceiptForChain(prev)
      if (cur.previousReceiptHash !== expected) {
        gaps.push({
          kind: 'hash_break',
          atIndex: i,
          detail: `previousReceiptHash does not match predecessor (expected ${expected.slice(0, 12)}…)`,
        })
      }
    }
  }

  return { continuous: gaps.length === 0, gaps }
}

// ══════════════════════════════════════════════════════════════════
// Dogfood. ScopeOfClaim for a hardening check
// ══════════════════════════════════════════════════════════════════

/** The proof box rendered as a ScopeOfClaim, for callers that emit an
 *  accountability receipt covering a hardening check. Mirrors the PROOF BOX. */
export function buildHardeningScopeOfClaim(): ScopeOfClaim {
  return {
    asserts:
      'The verifier checked clock skew, replay, revocation-freshness, and ' +
      'receipt-sequence continuity at verification time and recorded the outcomes.',
    does_not_assert: [
      'That the revocation source itself was current beyond the recorded staleness.',
      'That a stale-but-allowed decision was safe.',
      'That no receipt was withheld upstream of the first receipt presented.',
    ],
    capture_mode: 'gateway_observed',
    completeness: 'best_effort',
    self_attested: false,
  }
}
