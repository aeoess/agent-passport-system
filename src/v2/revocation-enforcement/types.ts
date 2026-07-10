// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// W2-B3. Revocation enforcement - type surface (additive, optional)
// ══════════════════════════════════════════════════════════════════
// These types sit on top of the M4 verifier-hardening recorder
// (src/v2/verifier-hardening/index.ts). M4 records WHAT a revocation
// source reported (a RevocationFreshnessRecord). This module decides
// what a relying party DOES with that record, under a stated policy.
//
// Layer boundary: the SDK ships the policy shape, the ephemeral-token
// FORMAT, the refresh check, and the SET emission HOOK. Distribution
// (Bloom filters, push channels, transparency logs) is the gateway's
// job and is out of scope here. See the proof box in ./index.ts.
//
// Claims language: these primitives are "specified / tested / validated",
// never "proved / guaranteed". A freshness-policy decision applies the
// configured rule to the recorded staleness; it does not assert the
// revocation source was globally current beyond that recorded staleness.

import type { RevocationFreshnessRecord } from '../../types/policy.js'
import type { RiskClass } from '../types.js'
import type { AttestationFreshness } from '../../types/passport.js'

// ══════════════════════════════════════════════════════════════════
// Freshness policy
// ══════════════════════════════════════════════════════════════════

/** How a relying party reacts to a revocation source that is stale or
 *  unreachable at verification time.
 *   - 'fail_open':         proceed even when the source is stale/unavailable
 *                          (availability over safety; the weakest posture).
 *   - 'fail_closed':       deny when the source is anything but 'fresh'
 *                          (safety over availability; the strictest posture).
 *   - 'bounded_staleness': accept while the recorded age is within an
 *                          explicit window, deny once it is past the window.
 *
 *  These three names extend the core RevocationCheckPolicy
 *  ('fail_open' | 'fail_closed' | 'cache_grace') in src/core/delegation.ts:
 *  'bounded_staleness' is the windowed analogue of 'cache_grace', expressed
 *  against the M4 RevocationFreshnessRecord rather than a cached boolean. */
export type FreshnessPolicyMode = 'fail_open' | 'fail_closed' | 'bounded_staleness'

/** What a verifier does for a non-fresh result under the configured mode.
 *   - 'allow':           proceed (records an explicit risk acceptance).
 *   - 'deny':            refuse the action.
 *   - 'downgrade':       proceed but mark the decision for downstream policy
 *                        (a relying-party-policy advisory, never an issuer
 *                        input; the caller decides what 'downgrade' means). */
export type StaleAction = 'allow' | 'deny' | 'downgrade'

/** Configuration a relying party hands the enforcer. All fields are caller
 *  policy, never read from a receipt. */
export interface FreshnessPolicy {
  mode: FreshnessPolicyMode
  /** What to do on a stale / unavailable result. For 'fail_closed' this is
   *  forced to 'deny' regardless of the supplied value (documented below).
   *  For 'fail_open' it defaults to 'allow'. For 'bounded_staleness' it is
   *  the action once the bound is exceeded. */
  action_on_stale?: StaleAction
  /** Maximum staleness, in milliseconds, the relying party tolerates under
   *  'bounded_staleness'. Required for that mode; ignored by the others.
   *  The boundary is INCLUSIVE: age === boundedStalenessMs is accepted,
   *  age === boundedStalenessMs + 1 is not. This mirrors the inclusive
   *  boundary M4 checkClockSkew uses. */
  boundedStalenessMs?: number
}

/** The decision a relying party reached for one revocation-freshness record
 *  under one policy. Mechanical facts only: which mode ran, what the record
 *  said, whether the action proceeds, and why. */
export interface FreshnessDecision {
  /** 'allow' or 'deny'; 'downgrade' resolves to allow with a flag set. */
  effect: 'allow' | 'deny'
  /** True when the action proceeds but the relying party flagged it for
   *  downstream policy. Advisory; computed by the verifier, never on the wire. */
  downgraded: boolean
  /** The policy mode that produced this decision. */
  mode: FreshnessPolicyMode
  /** The freshness result the decision was made against. */
  result: RevocationFreshnessRecord['result']
  /** Human-readable reason string. Stable for tests. */
  reason: string
  /** Echoed back so callers can attach the underlying record to an audit log. */
  record: RevocationFreshnessRecord
}

// ══════════════════════════════════════════════════════════════════
// Ephemeral capability token (FORMAT only)
// ══════════════════════════════════════════════════════════════════

/** A short-lived capability token for high-risk action classes. The lifetime
 *  is modelled as the M4 / freshness 'rotating' shape with a ttl, NOT a new
 *  staleness type. The token is a FORMAT the SDK ships: minting, validating
 *  expiry, and single-use enforcement are local checks. Distribution and
 *  revocation propagation are the gateway's job. */
export interface EphemeralCapabilityToken {
  /** Schema version. Lets a consumer reject unknown future shapes. */
  version: 'aps-eph-token/1'
  /** Unique token id (jti). Used as the replay / single-use key against an
   *  M4 SeenSet. */
  jti: string
  /** The delegation this token draws authority from. */
  delegation_id: string
  /** The trace this token belongs to. Refresh requires the same trace_id. */
  trace_id: string
  /** The high-risk action class this token authorizes (e.g. 'funds_transfer').
   *  The risk band that justified the short lifetime. */
  action_class: string
  risk_class: RiskClass
  /** Lifetime expressed as the reused 'rotating' freshness shape. validAt is
   *  the mint instant; ttl is the lifetime in seconds. Checked with the M4
   *  recorder / isEvidenceFresh, never a bespoke comparator. */
  lifetime: AttestationFreshness
}

/** Verdict from validating an ephemeral token's lifetime + single-use. */
export interface EphemeralTokenVerdict {
  /** 'valid' only when within lifetime AND not previously seen. */
  verdict: 'valid' | 'expired' | 'replayed' | 'malformed'
  jti?: string
  reason: string
}

// ══════════════════════════════════════════════════════════════════
// Delegation refresh (reissue)
// ══════════════════════════════════════════════════════════════════

/** Result of a delegation-refresh attempt. A refresh proves the same trace_id
 *  and a not-revoked original, then reissues via the existing renewal path
 *  (renewV2Delegation → supersedeV2Delegation). It does NOT fabricate a new
 *  authority: the reissued delegation keeps the original scope. */
export interface RefreshOutcome {
  /** True only when the original was not revoked AND the trace_id matched. */
  reissued: boolean
  /** Why a refresh was refused, when it was. Stable for tests. */
  reason?: 'revoked' | 'trace_mismatch' | 'not_found' | 'superseded' | 'invalid'
  /** The id of the reissued (superseding) delegation, when reissued. */
  new_delegation_id?: string
}

// ══════════════════════════════════════════════════════════════════
// RFC 8417 Security Event Token (SET) - CAEP shape (FORMAT + HOOK)
// ══════════════════════════════════════════════════════════════════

/** A single CAEP-style event subject. RFC 8417 §1.2 / RFC 8935 carry events
 *  keyed by an event-type URI; the value is an event-specific object. We model
 *  the subset CAEP uses for a revocation: a subject identifier plus the change
 *  metadata. No transport, no signing-by-this-module: a SET is normally a
 *  signed JWT, and signing is the emitter's existing Signer responsibility. */
export interface SETSubjectId {
  /** Subject identifier format per RFC 8417 'sub_id'. We use 'opaque' for an
   *  APS delegation/agent id, the conservative default. */
  format: 'opaque'
  id: string
}

/** The CAEP event object carried under the event-type URI. Mirrors the CAEP
 *  'session-revoked' / token-revocation shape: a subject, the reason the
 *  relying party recorded, and the instant the change took effect. */
export interface CAEPRevocationEvent {
  subject: SETSubjectId
  /** Free-form reason recorded by the emitter (e.g. a validateV2Delegation
   *  reason string). Advisory; the SET does not assert the reason is true. */
  reason?: string
  /** Seconds since the Unix epoch when the revocation took effect (CAEP
   *  'event_timestamp'). */
  event_timestamp: number
}

/** The CAEP event-type URI this module emits. Distribution / discovery of the
 *  stream is the gateway's job; this constant is only the event key. */
export type CAEPEventType =
  | 'https://schemas.openid.net/secevent/caep/event-type/session-revoked'

/** A Security Event Token claim set (RFC 8417 §2.2). This is the UNSIGNED
 *  payload. The emitter signs it as a JWT using its existing Signer; this
 *  module ships the claim-set FORMAT and the build HOOK, not a JWT signer and
 *  not a delivery channel. */
export interface SecurityEventTokenClaims {
  /** RFC 8417 'iss' - the issuer of the SET. */
  iss: string
  /** RFC 8417 'iat' - issued-at, seconds since the Unix epoch. */
  iat: number
  /** RFC 8417 'jti' - unique SET id (replay key for receivers). */
  jti: string
  /** RFC 8417 'aud' - intended audience(s). Optional per spec; populated when
   *  the emitter knows the receiver. */
  aud?: string | string[]
  /** RFC 8417 'sub' - optional subject of the SET as a whole. */
  sub?: string
  /** RFC 8417 'events' - map from event-type URI to the event object. */
  events: Record<CAEPEventType, CAEPRevocationEvent>
}
