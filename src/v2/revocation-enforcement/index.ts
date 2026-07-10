// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// W2-B3. Revocation enforcement, ephemeral tokens, refresh, SET emission
// ══════════════════════════════════════════════════════════════════
// Four additive primitives that extend the M4 verifier-hardening surface
// (src/v2/verifier-hardening/index.ts) with the DECISION layer M4 leaves to
// the relying party:
//
// (1) freshness_policy - given an M4 RevocationFreshnessRecord, apply a
//     relying-party policy (fail_open | fail_closed | bounded_staleness) with
//     an action_on_stale, and return an allow/deny decision. The record is
//     produced by recordRevocationFreshness; this module never re-derives
//     freshness, it only decides what to do with the recorded result.
//
// (2) ephemeral capability token - a short-lived token FORMAT for high-risk
//     action classes. Lifetime is the reused 'rotating' AttestationFreshness
//     shape; expiry is checked with isEvidenceFresh and single-use with an M4
//     SeenSet. The SDK ships the format and the local checks; distribution is
//     the gateway's job.
//
// (3) delegation refresh - proves the same trace_id and a not-revoked original,
//     then reissues through the existing renewV2Delegation path. No new
//     authority is minted: the reissued delegation keeps the original scope.
//
// (4) RFC 8417 SET emission - builds a Security Event Token claim set in the
//     CAEP session-revoked shape. This module ships the FORMAT and the build
//     HOOK only. JWT signing is the emitter's existing Signer; stream
//     distribution and Bloom-filter propagation are the gateway's job.
//
// Claims language: these primitives are "specified / tested / validated", not
// "proved / guaranteed". See the PROOF BOX below.
//
// State boundary: like delegation-v2 and core/delegation, any single-use state
// lives in-process for a single process lifetime. Durable, cross-restart,
// cross-process persistence is the integrator's responsibility.
//
// ──────────────────────────── PROOF BOX ────────────────────────────
// Proves: the verifier applied the configured freshness policy to the recorded
//   revocation-freshness result and reached an allow/deny decision, that a
//   refresh reissued only when the original was not revoked and the trace_id
//   matched, and that a conformant SET claim set was emitted on a revocation.
// Does NOT prove: that the revocation source was globally current beyond the
//   staleness recorded by M4. A 'fresh' result is fresh only relative to the
//   recorded check; a 'bounded_staleness' allow proves the recorded age was
//   within the window, not that no revocation occurred between the source's
//   own snapshot and verification time. Emitting a SET does not deliver it:
//   distribution, ordering, and receiver acknowledgement are out of scope.
// Dogfood: callers that emit an accountability receipt for an enforcement
//   decision SHOULD attach buildRevocationEnforcementScopeOfClaim(), which
//   mirrors this box.
// ════════════════════════════════════════════════════════════════════

import { randomUUID } from 'node:crypto'
import { computeEvidenceAge, isEvidenceFresh, createRotatingFreshness } from '../../core/freshness.js'
import {
  recordRevocationFreshness,
  checkReplay,
  type SeenSet,
} from '../verifier-hardening/index.js'
import {
  getV2Delegation,
  validateV2Delegation,
  renewV2Delegation,
} from '../delegation-v2.js'
import type { AttestationFreshness } from '../../types/passport.js'
import type { RevocationFreshnessRecord } from '../../types/policy.js'
import type { PolicyContext, RiskClass, V2Delegation } from '../types.js'
import type { ScopeOfClaim } from '../accountability/types/base.js'
import type {
  FreshnessPolicy,
  FreshnessDecision,
  StaleAction,
  EphemeralCapabilityToken,
  EphemeralTokenVerdict,
  RefreshOutcome,
  SecurityEventTokenClaims,
  CAEPRevocationEvent,
  CAEPEventType,
} from './types.js'

export * from './types.js'

const CAEP_SESSION_REVOKED: CAEPEventType =
  'https://schemas.openid.net/secevent/caep/event-type/session-revoked'

// ══════════════════════════════════════════════════════════════════
// (1) freshness_policy - decide on a recorded revocation-freshness result
// ══════════════════════════════════════════════════════════════════

/**
 * Apply a relying-party freshness policy to an M4 RevocationFreshnessRecord.
 *
 * The record's `result` ('fresh' | 'stale' | 'unavailable' | 'skipped') is
 * produced by {@link recordRevocationFreshness}; this function does not
 * re-derive it. A 'fresh' result always allows. For any non-fresh result the
 * decision follows the configured mode:
 *
 *   - 'fail_open':         allow (action_on_stale defaults to 'allow';
 *                          'deny' / 'downgrade' are honoured if set).
 *   - 'fail_closed':       deny, always (action_on_stale is forced to 'deny').
 *   - 'bounded_staleness': allow while the recorded age is within
 *                          boundedStalenessMs (INCLUSIVE boundary), otherwise
 *                          apply action_on_stale (default 'deny').
 *
 * 'downgrade' resolves to an allow with `downgraded: true`, an advisory the
 * relying party computes; it is never read from or written to a receipt.
 */
export function decideFreshness(
  record: RevocationFreshnessRecord,
  policy: FreshnessPolicy,
  now?: Date,
): FreshnessDecision {
  const base = (effect: 'allow' | 'deny', downgraded: boolean, reason: string): FreshnessDecision => ({
    effect, downgraded, mode: policy.mode, result: record.result, reason, record,
  })

  if (record.result === 'fresh') {
    return base('allow', false, 'revocation source fresh within tolerance')
  }

  // fail_closed: any non-fresh result denies. action_on_stale is forced.
  if (policy.mode === 'fail_closed') {
    return base('deny', false, `fail_closed: revocation result '${record.result}' is not fresh`)
  }

  // fail_open: proceed unless the caller explicitly chose otherwise.
  if (policy.mode === 'fail_open') {
    const action: StaleAction = policy.action_on_stale ?? 'allow'
    return resolveStaleAction(action, record.result, policy.mode, record,
      `fail_open: revocation result '${record.result}'`)
  }

  // bounded_staleness: within the window allows; past the window applies
  // action_on_stale (default deny).
  const bound = policy.boundedStalenessMs
  if (typeof bound !== 'number') {
    // Misconfiguration: a bounded policy without a bound is treated as the
    // strictest safe default rather than silently allowing.
    return base('deny', false, 'bounded_staleness: boundedStalenessMs not configured')
  }

  // 'unavailable' and 'skipped' carry no measurable age, so the window cannot
  // be satisfied; apply action_on_stale (default deny).
  if (!record.freshness) {
    const action: StaleAction = policy.action_on_stale ?? 'deny'
    return resolveStaleAction(action, record.result, policy.mode, record,
      `bounded_staleness: no measurable age for result '${record.result}'`)
  }

  const ageMs = computeEvidenceAge(record.freshness, now ?? new Date(record.checkedAt)) * 1000
  if (ageMs <= bound) {
    return base('allow', false,
      `bounded_staleness: age ${ageMs}ms within bound ${bound}ms`)
  }
  const action: StaleAction = policy.action_on_stale ?? 'deny'
  return resolveStaleAction(action, record.result, policy.mode, record,
    `bounded_staleness: age ${ageMs}ms exceeds bound ${bound}ms`)
}

function resolveStaleAction(
  action: StaleAction,
  result: RevocationFreshnessRecord['result'],
  mode: FreshnessPolicy['mode'],
  record: RevocationFreshnessRecord,
  context: string,
): FreshnessDecision {
  switch (action) {
    case 'allow':
      return { effect: 'allow', downgraded: false, mode, result, reason: `${context} → allow`, record }
    case 'downgrade':
      return { effect: 'allow', downgraded: true, mode, result, reason: `${context} → allow (downgraded)`, record }
    case 'deny':
      return { effect: 'deny', downgraded: false, mode, result, reason: `${context} → deny`, record }
  }
}

/**
 * Convenience composition: consult a revocation source (via the M4 recorder),
 * then decide under a freshness policy in one call. The recorder inputs are
 * passed straight through; this only chains record → decide so a caller does
 * not have to thread the intermediate record by hand.
 */
export function enforceFreshnessPolicy(
  opts: {
    source: string
    maxStalenessMs: number
    checkedAt?: Date
    freshness?: AttestationFreshness
    unavailable?: boolean
    allowDespiteStale?: boolean
  },
  policy: FreshnessPolicy,
): FreshnessDecision {
  const record = recordRevocationFreshness(opts)
  return decideFreshness(record, policy, opts.checkedAt)
}

// ══════════════════════════════════════════════════════════════════
// (2) Ephemeral capability token - FORMAT + local checks
// ══════════════════════════════════════════════════════════════════

/**
 * Mint a short-lived capability token for a high-risk action class.
 *
 * The lifetime is the reused 'rotating' {@link AttestationFreshness} shape:
 * `validAt` is the mint instant and `ttl` is the lifetime in seconds. No new
 * staleness type is introduced. The token is a FORMAT; the gateway distributes
 * and propagates revocation, this SDK only mints and checks.
 */
export function mintEphemeralToken(params: {
  delegation_id: string
  trace_id: string
  action_class: string
  risk_class: RiskClass
  /** Lifetime in seconds. Short by construction for high-risk classes. */
  ttlSeconds: number
  /** Mint instant; defaults to now. */
  issuedAt?: Date
  /** Token id; defaults to a random UUID. */
  jti?: string
}): EphemeralCapabilityToken {
  if (params.ttlSeconds <= 0) {
    throw new Error('mintEphemeralToken: ttlSeconds must be positive')
  }
  const issuedAt = (params.issuedAt ?? new Date()).toISOString()
  const lifetime: AttestationFreshness = createRotatingFreshness(issuedAt, params.ttlSeconds)
  return {
    version: 'aps-eph-token/1',
    jti: params.jti ?? randomUUID(),
    delegation_id: params.delegation_id,
    trace_id: params.trace_id,
    action_class: params.action_class,
    risk_class: params.risk_class,
    lifetime,
  }
}

/**
 * Validate an ephemeral token's lifetime and single-use.
 *
 * Expiry uses {@link isEvidenceFresh} on the token's 'rotating' lifetime, the
 * same helper M4 uses; no bespoke comparator. Single-use is enforced against
 * an M4 {@link SeenSet} via {@link checkReplay}. A token replayed inside its
 * lifetime is 'replayed'; an expired token is 'expired'. Expiry is checked
 * BEFORE replay so an expired token does not consume a seen-set slot.
 */
export function validateEphemeralToken(
  token: EphemeralCapabilityToken,
  seen: SeenSet,
  now?: Date,
): EphemeralTokenVerdict {
  if (token.version !== 'aps-eph-token/1' || token.lifetime.type !== 'rotating' || !token.jti) {
    return { verdict: 'malformed', reason: 'token is not a well-formed aps-eph-token/1' }
  }
  if (!isEvidenceFresh(token.lifetime, now)) {
    return { verdict: 'expired', jti: token.jti, reason: 'token lifetime (ttl) elapsed' }
  }
  const replay = checkReplay(token.jti, seen)
  if (replay.verdict === 'rejected_replay') {
    return { verdict: 'replayed', jti: token.jti, reason: 'token jti already presented (single-use)' }
  }
  return { verdict: 'valid', jti: token.jti, reason: 'within lifetime and first use' }
}

// ══════════════════════════════════════════════════════════════════
// (3) Delegation refresh - same trace_id, not revoked, then reissue
// ══════════════════════════════════════════════════════════════════

/**
 * Refresh (reissue) a delegation behind an ephemeral token.
 *
 * Two preconditions, both mechanical:
 *   - the original delegation MUST validate as not-revoked / not-superseded
 *     (via {@link validateV2Delegation}); a revoked original is refused.
 *   - the supplied trace_id MUST match the token's trace_id, binding the
 *     refresh to the same trace.
 *
 * On success it reissues through the existing {@link renewV2Delegation} path,
 * which supersedes the original keeping its scope (no authority expansion). A
 * refresh therefore reissues authority that already existed; it does not mint
 * new authority.
 */
export function refreshDelegation(params: {
  token: EphemeralCapabilityToken
  /** The trace_id presented with the refresh request. Must equal the token's. */
  trace_id: string
  /** New policy context for the reissued delegation (fresh validity window). */
  policy_context: PolicyContext
  delegator_private_key: string
  renewal_reason: string
  now?: Date
}): RefreshOutcome {
  const original: V2Delegation | undefined = getV2Delegation(params.token.delegation_id)
  if (!original) {
    return { reissued: false, reason: 'not_found' }
  }

  if (params.trace_id !== params.token.trace_id) {
    return { reissued: false, reason: 'trace_mismatch' }
  }

  const validity = validateV2Delegation(original, params.now)
  if (!validity.valid) {
    if (validity.reason === 'Revoked') return { reissued: false, reason: 'revoked' }
    if (validity.reason === 'Superseded') return { reissued: false, reason: 'superseded' }
    return { reissued: false, reason: 'invalid' }
  }

  const reissued = renewV2Delegation({
    original_delegation_id: original.id,
    policy_context: params.policy_context,
    delegator_private_key: params.delegator_private_key,
    renewal_reason: params.renewal_reason,
  })

  return { reissued: true, new_delegation_id: reissued.id }
}

// ══════════════════════════════════════════════════════════════════
// (4) RFC 8417 SET emission - CAEP shape (FORMAT + HOOK)
// ══════════════════════════════════════════════════════════════════

/**
 * Build a Security Event Token claim set (RFC 8417 §2.2) carrying a CAEP
 * session-revoked event for a revoked delegation / agent.
 *
 * Returns the UNSIGNED claim set. The emitter signs it as a JWT using its
 * existing Signer (the SDK does not introduce a second JWT signer here), and
 * the gateway delivers it over a stream (out of scope). The `events` map is
 * keyed by the CAEP event-type URI per RFC 8417, so a standard SSF/CAEP
 * receiver can route it.
 */
export function buildRevocationSET(params: {
  /** SET issuer ('iss'). */
  issuer: string
  /** The revoked subject id (delegation id or agent id). */
  subject_id: string
  /** When the revocation took effect; defaults to issuedAt. */
  revokedAt?: Date
  /** SET issued-at; defaults to now. */
  issuedAt?: Date
  /** Intended audience ('aud'), when known. */
  audience?: string | string[]
  /** Reason recorded by the emitter (advisory; e.g. a validateV2Delegation
   *  reason). The SET does not assert the reason is true. */
  reason?: string
  /** SET id ('jti'); defaults to a random UUID. */
  jti?: string
}): SecurityEventTokenClaims {
  const issuedAtDate = params.issuedAt ?? new Date()
  const iat = Math.floor(issuedAtDate.getTime() / 1000)
  const eventTs = Math.floor((params.revokedAt ?? issuedAtDate).getTime() / 1000)

  const event: CAEPRevocationEvent = {
    subject: { format: 'opaque', id: params.subject_id },
    event_timestamp: eventTs,
  }
  if (params.reason !== undefined) event.reason = params.reason

  const events = { [CAEP_SESSION_REVOKED]: event } as Record<CAEPEventType, CAEPRevocationEvent>

  const claims: SecurityEventTokenClaims = {
    iss: params.issuer,
    iat,
    jti: params.jti ?? randomUUID(),
    events,
  }
  if (params.audience !== undefined) claims.aud = params.audience
  return claims
}

/**
 * Structural conformance check for a SET claim set against RFC 8417 §2.2 and
 * the CAEP event shape this module emits. Mechanical only: presence and type
 * of the required claims, exactly one recognized event-type URI, and a
 * well-formed event object. It does NOT verify a signature (the claim set is
 * unsigned here) and does not assert the revocation is true.
 */
export function isWellFormedSET(value: unknown): value is SecurityEventTokenClaims {
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  if (typeof v.iss !== 'string' || v.iss.length === 0) return false
  if (typeof v.iat !== 'number' || !Number.isFinite(v.iat)) return false
  if (typeof v.jti !== 'string' || v.jti.length === 0) return false
  if (typeof v.events !== 'object' || v.events === null) return false

  const events = v.events as Record<string, unknown>
  const keys = Object.keys(events)
  if (keys.length !== 1 || keys[0] !== CAEP_SESSION_REVOKED) return false

  const event = events[CAEP_SESSION_REVOKED]
  if (typeof event !== 'object' || event === null) return false
  const e = event as Record<string, unknown>
  if (typeof e.event_timestamp !== 'number' || !Number.isFinite(e.event_timestamp)) return false
  const subject = e.subject
  if (typeof subject !== 'object' || subject === null) return false
  const s = subject as Record<string, unknown>
  if (s.format !== 'opaque' || typeof s.id !== 'string' || s.id.length === 0) return false

  return true
}

// ══════════════════════════════════════════════════════════════════
// Dogfood. ScopeOfClaim for an enforcement decision
// ══════════════════════════════════════════════════════════════════

/** The proof box rendered as a ScopeOfClaim, for callers that emit an
 *  accountability receipt covering a revocation-enforcement decision. */
export function buildRevocationEnforcementScopeOfClaim(): ScopeOfClaim {
  return {
    asserts:
      'The verifier applied the configured freshness policy to the recorded ' +
      'revocation-freshness result, reissued a delegation only when the ' +
      'original was not revoked and the trace_id matched, and emitted a ' +
      'conformant Security Event Token on a revocation.',
    does_not_assert: [
      'That the revocation source was globally current beyond the recorded staleness.',
      'That no revocation occurred between the source snapshot and verification time.',
      'That an emitted Security Event Token was delivered, ordered, or acknowledged.',
    ],
    capture_mode: 'gateway_observed',
    completeness: 'best_effort',
    self_attested: false,
  }
}
