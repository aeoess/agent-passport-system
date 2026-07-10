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
   *  the emitter knows the receiver. This is the RFC 8417 SET audience claim,
   *  a JWT-level receiver hint. It is NOT the APS AudienceBinding shape (the
   *  in-body receipt binding verified by checkAudience); the two live at
   *  different layers and are never interchangeable. */
  aud?: string | string[]
  /** RFC 8417 'sub' - optional subject of the SET as a whole. */
  sub?: string
  /** RFC 8417 'events' - map from event-type URI to the event object. */
  events: Record<CAEPEventType, CAEPRevocationEvent>
}

// ══════════════════════════════════════════════════════════════════
// RevocationObservation (T7 / FREEZE-VWE F4) - verifier-side record
// ══════════════════════════════════════════════════════════════════

/** Which revocation signal an observation is based on.
 *  - kind 'source': the verifier consulted a revocation source directly
 *    (a CRL URL, a registry id; the RevocationFreshnessRecord.source value).
 *  - kind 'set': the verifier received an RFC 8417 Security Event Token and
 *    the jti is that SET's replay key (SecurityEventTokenClaims.jti). */
export type RevocationStatusSource =
  | { kind: 'source'; id: string }
  | { kind: 'set'; jti: string }

/** The decision slot of an observation. Reuses the FreshnessDecision
 *  vocabulary: effect is 'allow' | 'deny' and a downgrade resolves to an
 *  allow with `downgraded: true`. No third verdict value exists. */
export interface RevocationObservationDecision {
  effect: 'allow' | 'deny'
  downgraded?: boolean
}

/** A verifier-side record that a specific revocation signal was OBSERVED,
 *  from which source, for which authority, covering which scope, and what
 *  the relying party then did.
 *
 *  This is an observation under a stated freshness contract: it records that
 *  the verifier saw a signal (or failed to obtain one) at observed_at, with
 *  maximum_staleness_ms naming the staleness the relying party was willing to
 *  tolerate. It does not assert instant or universal revocation: a revocation
 *  becomes effective for a relying party when that party observes it within
 *  its freshness contract, and nothing here claims the signal reached every
 *  relying party or reached this one immediately. */
export interface RevocationObservation {
  /** The revoked (or checked) delegation / agent id. Opaque string, the same
   *  convention SETSubjectId.id uses. */
  authority_ref: string
  /** Where the revocation status came from. */
  status_source: RevocationStatusSource
  /** When the revocation took effect, ISO 8601, when a revocation was
   *  observed. A SET carries epoch seconds (CAEPRevocationEvent
   *  .event_timestamp); ingestion converts to ISO 8601 so the SDK-wide
   *  timestamp convention holds. Absent when no revocation signal was
   *  obtained (fresh, stale, or unavailable consults). */
  revoked_at?: string
  /** When the verifier made this observation, ISO 8601. */
  observed_at: string
  /** The maximum staleness, in milliseconds, the relying party's freshness
   *  contract tolerated for this observation. Milliseconds everywhere: SET
   *  epoch seconds are converted at ingestion, never stored as a third
   *  convention. */
  maximum_staleness_ms: number
  /** The scope subtree the revocation covers, when the signal carried one.
   *  Uses the cascade reference language of draft-pidlisnyi-aps-03 revocation
   *  evidence: an opaque reference to the originating revocation and its
   *  cascade transaction identity, so a verifier can reconstruct from the
   *  records why a descendant died. */
  affected_scope?: string
  /** What the relying party decided under its freshness policy. */
  decision: RevocationObservationDecision
  /** What the relying party did next, when it did something recordable:
   *  a refresh attempt outcome (reissued, or refused with a reason). */
  workflow_response?: RefreshOutcome
}

/** A RevocationObservation signed by the observing verifier. The signature
 *  covers the canonical form of every field except `signature` itself,
 *  following the module-wide signable-subset discipline. observer_key is the
 *  raw Ed25519 public key hex the signature verifies against; observer_key_id
 *  follows the ed25519:<first-16-hex> convention. */
export interface SignedRevocationObservation extends RevocationObservation {
  observer_key: string
  observer_key_id: string
  signature: string
}

/** The seven derived outcome labels for an observation. DERIVED by
 *  classifyObservation, never stored in the signed object: a label is a
 *  verifier-report word, not wire surface. */
export type RevocationOutcomeLabel =
  | 'revoked_blocked'
  | 'fresh_valid'
  | 'stale_denied'
  | 'stale_permitted'
  | 'running_terminated'
  | 'unavailable_fail_closed'
  | 'unavailable_fail_open'

/** Verdict from verifyRevocationObservation. Mechanical: structural
 *  well-formedness plus signature validity against observer_key. It does not
 *  assert the observed revocation is true, current, or universally visible. */
export interface ObservationVerifyResult {
  valid: boolean
  reason: string
}
