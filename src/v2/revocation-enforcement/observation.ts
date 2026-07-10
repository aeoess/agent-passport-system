// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// T7 / FREEZE-VWE F4. RevocationObservation - build, verify, classify, ingest
// ══════════════════════════════════════════════════════════════════
// The module's emitter side (buildRevocationSET) and decision side
// (decideFreshness) existed; this file adds the verifier-side OBSERVATION
// record: that a specific revocation signal was observed, from which source,
// for which authority, covering which scope, and what the relying party then
// did under its stated freshness contract.
//
// Claims language: an observation is evidence of what one verifier saw and
// decided within its freshness contract (maximum_staleness_ms). Nothing here
// claims instant or universal revocation: a revocation takes effect for a
// relying party when that party observes it within the contract, and a signal
// the source has not yet propagated is, by construction, not yet observable.
//
// ──────────────────────────── PROOF BOX ────────────────────────────
// Proves: the observing verifier signed this record of a revocation signal
//   (or of the failure to obtain one) and of the decision it reached under
//   its freshness policy at observed_at.
// Does NOT prove: that the revocation is true, globally current, or visible
//   to any other relying party; that no revocation occurred after
//   observed_at; or that the decision was the right one. Outcome labels are
//   derived reporting vocabulary and are never part of the signed bytes.
// ════════════════════════════════════════════════════════════════════

import { canonicalize } from '../../core/canonical.js'
import { verify } from '../../crypto/keys.js'
import { defaultKeyId } from '../../adapters/remote-signer/types.js'
import type { Signer } from '../../adapters/remote-signer/types.js'
import type { RevocationFreshnessResult } from '../../types/policy.js'
import type {
  RevocationObservation,
  RevocationObservationDecision,
  RevocationOutcomeLabel,
  RevocationStatusSource,
  SignedRevocationObservation,
  ObservationVerifyResult,
  SecurityEventTokenClaims,
  CAEPRevocationEvent,
  RefreshOutcome,
} from './types.js'

const CAEP_SESSION_REVOKED =
  'https://schemas.openid.net/secevent/caep/event-type/session-revoked' as const

// ══════════════════════════════════════════════════════════════════
// Build (signed via the SDK Signer interface)
// ══════════════════════════════════════════════════════════════════

/** Input to buildRevocationObservation. Field semantics are those of
 *  {@link RevocationObservation}; timestamps accept Date for convenience and
 *  are stored ISO 8601. */
export interface BuildObservationParams {
  authority_ref: string
  status_source: RevocationStatusSource
  revoked_at?: Date | string
  /** Defaults to now. */
  observed_at?: Date | string
  maximum_staleness_ms: number
  affected_scope?: string
  /** The decision reached under the relying party's freshness policy. A full
   *  FreshnessDecision may be passed; only effect and downgraded are stored
   *  (the frozen field shape), the rest stays verifier-local. */
  decision: RevocationObservationDecision & { [extra: string]: unknown }
  workflow_response?: RefreshOutcome
}

function toISO(value: Date | string): string {
  const d = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(d.getTime())) {
    throw new Error(`revocation-observation: invalid timestamp '${String(value)}'`)
  }
  return d.toISOString()
}

/**
 * Build and sign a RevocationObservation.
 *
 * Signing follows the module's Signer discipline: like buildRevocationSET,
 * this builder does not introduce its own key handling; the caller supplies
 * the SDK {@link Signer} (local or remote custody) and the signature is that
 * signer's Ed25519 signature over the canonical form of the record with the
 * `signature` field absent. observer_key and observer_key_id are taken from
 * the signer and are covered by the signature, so the record binds its own
 * verification key material.
 *
 * The record asserts an observation under a stated freshness contract. It
 * does not assert instant or universal revocation.
 */
export async function buildRevocationObservation(
  params: BuildObservationParams,
  signer: Signer,
): Promise<SignedRevocationObservation> {
  if (!params.authority_ref) {
    throw new Error('revocation-observation: authority_ref is required')
  }
  if (!Number.isFinite(params.maximum_staleness_ms) || params.maximum_staleness_ms < 0) {
    throw new Error('revocation-observation: maximum_staleness_ms must be a non-negative number')
  }
  if (params.decision.effect !== 'allow' && params.decision.effect !== 'deny') {
    throw new Error("revocation-observation: decision.effect must be 'allow' or 'deny'")
  }

  const observation: RevocationObservation = {
    authority_ref: params.authority_ref,
    status_source: params.status_source,
    observed_at: toISO(params.observed_at ?? new Date()),
    maximum_staleness_ms: params.maximum_staleness_ms,
    decision: params.decision.downgraded === undefined
      ? { effect: params.decision.effect }
      : { effect: params.decision.effect, downgraded: params.decision.downgraded },
  }
  if (params.revoked_at !== undefined) observation.revoked_at = toISO(params.revoked_at)
  if (params.affected_scope !== undefined) observation.affected_scope = params.affected_scope
  if (params.workflow_response !== undefined) observation.workflow_response = params.workflow_response

  const observer_key = await signer.publicKeyHex()
  const observer_key_id = (await signer.keyId()) || defaultKeyId(observer_key)
  const signable: Omit<SignedRevocationObservation, 'signature'> = {
    ...observation,
    observer_key,
    observer_key_id,
  }
  const signature = await signer.sign(canonicalize(signable))
  return { ...signable, signature }
}

// ══════════════════════════════════════════════════════════════════
// Verify
// ══════════════════════════════════════════════════════════════════

/**
 * Verify a signed observation: structural well-formedness, then the Ed25519
 * signature over the canonical record with `signature` absent, against the
 * record's own observer_key (or a caller-pinned expected key).
 *
 * Verifying proves the named observer signed this observation. It does not
 * prove the observed revocation is true or current beyond the freshness
 * contract the record states, and it does not prove any other relying party
 * observed the same signal.
 */
export function verifyRevocationObservation(
  record: SignedRevocationObservation,
  opts?: { expectedObserverKey?: string },
): ObservationVerifyResult {
  if (typeof record !== 'object' || record === null) {
    return { valid: false, reason: 'not an object' }
  }
  if (typeof record.authority_ref !== 'string' || record.authority_ref.length === 0) {
    return { valid: false, reason: 'authority_ref missing or empty' }
  }
  const src = record.status_source
  const srcOk =
    typeof src === 'object' && src !== null &&
    ((src.kind === 'source' && typeof (src as { id?: unknown }).id === 'string') ||
      (src.kind === 'set' && typeof (src as { jti?: unknown }).jti === 'string'))
  if (!srcOk) {
    return { valid: false, reason: "status_source must be {kind:'source',id} or {kind:'set',jti}" }
  }
  if (typeof record.observed_at !== 'string' || Number.isNaN(new Date(record.observed_at).getTime())) {
    return { valid: false, reason: 'observed_at missing or not a parseable timestamp' }
  }
  if (record.revoked_at !== undefined &&
      (typeof record.revoked_at !== 'string' || Number.isNaN(new Date(record.revoked_at).getTime()))) {
    return { valid: false, reason: 'revoked_at present but not a parseable timestamp' }
  }
  if (typeof record.maximum_staleness_ms !== 'number' || !Number.isFinite(record.maximum_staleness_ms) || record.maximum_staleness_ms < 0) {
    return { valid: false, reason: 'maximum_staleness_ms missing or negative' }
  }
  if (typeof record.decision !== 'object' || record.decision === null ||
      (record.decision.effect !== 'allow' && record.decision.effect !== 'deny')) {
    return { valid: false, reason: "decision.effect must be 'allow' or 'deny'" }
  }
  if (typeof record.observer_key !== 'string' || record.observer_key.length !== 64) {
    return { valid: false, reason: 'observer_key missing or not 32-byte hex' }
  }
  if (typeof record.signature !== 'string' || record.signature.length !== 128) {
    return { valid: false, reason: 'signature missing or not 64-byte hex' }
  }
  if (opts?.expectedObserverKey !== undefined && opts.expectedObserverKey !== record.observer_key) {
    return { valid: false, reason: 'observer_key does not match the pinned expected key' }
  }

  const { signature, ...signable } = record
  const ok = verify(canonicalize(signable), signature, record.observer_key)
  return ok
    ? { valid: true, reason: 'signature valid over canonical record (signature field absent)' }
    : { valid: false, reason: 'signature verification failed' }
}

// ══════════════════════════════════════════════════════════════════
// Classify (labels are derived, never stored)
// ══════════════════════════════════════════════════════════════════

/**
 * Derive the outcome label for an observation. The label is verifier-report
 * vocabulary: it is computed on demand and never stored in the signed record.
 *
 * Derivation:
 *  - a revocation was observed (revoked_at present):
 *      - workflow_response refused a refresh because the original was revoked
 *        (reissued false, reason 'revoked'): 'running_terminated', the in
 *        flight workflow was cut short by the observed revocation;
 *      - decision deny: 'revoked_blocked'.
 *  - no revocation signal (revoked_at absent): the record's frozen decision
 *    slot carries effect and downgraded only, which cannot distinguish a
 *    fresh source from a stale or unreachable one. The caller supplies the
 *    freshness result it recorded (RevocationFreshnessRecord.result) as
 *    classification CONTEXT; it is consumed here and never stored:
 *      - 'fresh': 'fresh_valid';
 *      - 'stale': 'stale_denied' or 'stale_permitted' by decision effect;
 *      - 'unavailable' or 'skipped' (no signal obtained either way):
 *        'unavailable_fail_closed' or 'unavailable_fail_open' by effect.
 *
 * Throws on combinations outside the seven labels (an observed revocation
 * that was allowed without a terminating workflow response, a fresh deny, or
 * a missing freshness context when no revocation was observed): those states
 * are not representable outcomes of decideFreshness and indicate a
 * malformed observation rather than an eighth category.
 */
export function classifyObservation(
  observation: RevocationObservation,
  freshness?: { result: RevocationFreshnessResult },
): RevocationOutcomeLabel {
  if (observation.revoked_at !== undefined) {
    const wf = observation.workflow_response
    if (wf !== undefined && wf.reissued === false && wf.reason === 'revoked') {
      return 'running_terminated'
    }
    if (observation.decision.effect === 'deny') {
      return 'revoked_blocked'
    }
    throw new Error(
      'classifyObservation: an observed revocation with an allow decision and no ' +
      'terminating workflow response is not one of the seven outcome labels',
    )
  }

  if (!freshness) {
    throw new Error(
      'classifyObservation: no revocation was observed, so the freshness result ' +
      "(RevocationFreshnessRecord.result) is required as context to distinguish " +
      'fresh, stale, and unavailable outcomes; the frozen record shape does not carry it',
    )
  }

  switch (freshness.result) {
    case 'fresh':
      if (observation.decision.effect === 'allow') return 'fresh_valid'
      throw new Error('classifyObservation: a fresh result with a deny decision is not a defined outcome')
    case 'stale':
      return observation.decision.effect === 'deny' ? 'stale_denied' : 'stale_permitted'
    case 'unavailable':
    case 'skipped':
      return observation.decision.effect === 'deny'
        ? 'unavailable_fail_closed'
        : 'unavailable_fail_open'
  }
}

// ══════════════════════════════════════════════════════════════════
// SET ingestion
// ══════════════════════════════════════════════════════════════════

/**
 * Map a received Security Event Token claim set into builder params for a
 * RevocationObservation.
 *
 * Wiring per the freeze: status_source becomes {kind: 'set', jti} carrying
 * the SET's replay key, and the CAEP event_timestamp (seconds since the Unix
 * epoch) is converted to ISO 8601 for revoked_at, keeping the SDK-wide
 * timestamp convention; milliseconds and epoch seconds are never mixed in
 * one field.
 *
 * Audience note: a SET's `aud` is the RFC 8417 JWT audience claim, a
 * receiver hint on the event token. It is not the APS AudienceBinding shape
 * (the in-body receipt binding checked by checkAudience), and this helper
 * does not read it: whether the SET was addressed to this receiver is the
 * transport layer's check, made before ingestion.
 *
 * Callers SHOULD validate the claim set with isWellFormedSET first; this
 * helper re-asserts only the fields it dereferences. Receiving a SET is an
 * observation of one emitter's signal under this receiver's freshness
 * contract; it is not proof of instant or universal revocation.
 */
export function observationParamsFromSET(
  set: SecurityEventTokenClaims,
  params: {
    decision: RevocationObservationDecision
    maximum_staleness_ms: number
    observed_at?: Date | string
    affected_scope?: string
    workflow_response?: RefreshOutcome
  },
): BuildObservationParams {
  const event: CAEPRevocationEvent | undefined = set?.events?.[CAEP_SESSION_REVOKED]
  if (!event || typeof event.event_timestamp !== 'number' || !Number.isFinite(event.event_timestamp)) {
    throw new Error('observationParamsFromSET: claim set carries no well-formed CAEP session-revoked event')
  }
  if (typeof set.jti !== 'string' || set.jti.length === 0) {
    throw new Error('observationParamsFromSET: claim set has no jti')
  }
  if (typeof event.subject?.id !== 'string' || event.subject.id.length === 0) {
    throw new Error('observationParamsFromSET: event subject has no id')
  }

  const out: BuildObservationParams = {
    authority_ref: event.subject.id,
    status_source: { kind: 'set', jti: set.jti },
    revoked_at: new Date(event.event_timestamp * 1000).toISOString(),
    maximum_staleness_ms: params.maximum_staleness_ms,
    decision: params.decision,
  }
  if (params.observed_at !== undefined) out.observed_at = params.observed_at
  if (params.affected_scope !== undefined) out.affected_scope = params.affected_scope
  if (params.workflow_response !== undefined) out.workflow_response = params.workflow_response
  return out
}
