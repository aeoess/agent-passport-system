// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. Evaluating a set of lifecycle causes at one instant.
// See ./types.ts for the specification position: nothing here is required by
// draft-pidlisnyi-aps-03, and nothing here changes any existing exported behaviour.

import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import { verify as verifyEd25519 } from '../../crypto/keys.js'
import { lifecycleState, notEstablished } from '../lifecycle-state/state.js'
import type { LifecycleStateResult, OutstandingCause } from '../lifecycle-state/types.js'
import {
  PAUSE_KINDS,
  RELEASE_STANDINGS,
  SUSPENSION_CAUSE_TYPE,
  SUSPENSION_RELEASE_TYPE,
  type CauseDisposition,
  type PauseStateExplanation,
  type PauseStateInput,
  type ReleaseCauseDisposition,
  type ReleaseDisposition,
  type SuspensionCause,
  type SuspensionRelease,
} from './types.js'

/** Thrown when the INPUT is malformed, never as a verdict.
 *
 *  The line this module draws: a record that is well formed but fails a check is a
 *  disposition and feeds the verdict. A caller who passes a non-array, a cause with no
 *  `cause_id`, two causes sharing one `cause_id` or a resolver that answers off the
 *  vocabulary has made a programming error, and a programming error is not a finding about
 *  anybody's authority. Same split, and same shape, as `LifecycleStateError`. */
export class SuspensionCauseError extends Error {
  readonly code: string

  constructor(code: string, message: string) {
    super(message)
    this.name = 'SuspensionCauseError'
    this.code = code
  }
}

/** The signed preimage of a cause or release record: every member except `signature` and
 *  `record_id`, canonicalized under RFC 8785 by this SDK's own canonicalizer.
 *
 *  `record_id` is excluded because where a record carries one it is a content address over
 *  these very bytes and cannot be inside its own preimage. `src/v2/instruction-provenance`
 *  already excludes its `receipt_id` on the same reasoning, so this is the SDK's existing
 *  convention rather than a new one. Every other member signs, including members this
 *  module does not read, so an extension cannot be added to a record after signing. */
export function suspensionRecordPreimage(record: Readonly<Record<string, unknown>>): string {
  const body: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(record)) {
    if (key === 'signature' || key === 'record_id') continue
    body[key] = value
  }
  return canonicalizeJCS(body)
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0
}

function assertCauseShape(cause: SuspensionCause, index: number): void {
  if (cause === null || typeof cause !== 'object') {
    throw new SuspensionCauseError('CAUSE_MALFORMED', `causes[${index}] is not an object`)
  }
  for (const field of [
    'record_type',
    'cause_id',
    'delegation_id',
    'imposed_by',
    'issued_at',
    'reason_code',
    'verification_method',
    'signature',
  ] as const) {
    if (!isNonEmptyString(cause[field])) {
      throw new SuspensionCauseError(
        'CAUSE_MALFORMED',
        `causes[${index}].${field} must be a non-empty string`,
      )
    }
  }
  if (!(PAUSE_KINDS as readonly string[]).includes(cause.kind)) {
    throw new SuspensionCauseError(
      'CAUSE_KIND_UNKNOWN',
      `causes[${index}].kind must be one of ${PAUSE_KINDS.join(', ')}`,
    )
  }
}

function assertReleaseShape(release: SuspensionRelease, index: number): void {
  if (release === null || typeof release !== 'object') {
    throw new SuspensionCauseError('RELEASE_MALFORMED', `releases[${index}] is not an object`)
  }
  for (const field of [
    'record_type',
    'release_id',
    'delegation_id',
    'issuer',
    'issued_at',
    'verification_method',
    'signature',
  ] as const) {
    if (!isNonEmptyString(release[field])) {
      throw new SuspensionCauseError(
        'RELEASE_MALFORMED',
        `releases[${index}].${field} must be a non-empty string`,
      )
    }
  }
  if (!Array.isArray(release.cause_ids)) {
    throw new SuspensionCauseError(
      'RELEASE_MALFORMED',
      `releases[${index}].cause_ids must be an array`,
    )
  }
  for (const [i, causeId] of release.cause_ids.entries()) {
    if (!isNonEmptyString(causeId)) {
      throw new SuspensionCauseError(
        'RELEASE_MALFORMED',
        `releases[${index}].cause_ids[${i}] must be a non-empty string`,
      )
    }
  }
}

function signatureVerifies(
  record: Readonly<Record<string, unknown>>,
  signer: string,
  input: PauseStateInput,
): boolean {
  const method = record.verification_method as string
  let publicKey: string | null
  try {
    publicKey = input.resolveVerificationKey(signer, method)
  } catch {
    return false
  }
  if (!isNonEmptyString(publicKey)) return false
  try {
    return verifyEd25519(suspensionRecordPreimage(record), record.signature as string, publicKey)
  } catch {
    return false
  }
}

/** Which disposition a cause gets, or `CAUSE_IN_EVIDENCE` when it survives every check.
 *
 *  The order matters and is the order below: a record that is not this artifact's cause is
 *  not judged on its signature, and a record not yet in evidence at this instant is not
 *  judged on anything else. */
function disposeCause(cause: SuspensionCause, input: PauseStateInput): CauseDisposition {
  if (cause.delegation_id !== input.delegationId) {
    return { cause_id: cause.cause_id, disposition: 'CAUSE_NOT_ON_DELEGATION' }
  }
  if (cause.record_type !== SUSPENSION_CAUSE_TYPE) {
    return { cause_id: cause.cause_id, disposition: 'CAUSE_RECORD_TYPE_UNRECOGNISED' }
  }
  if (cause.issued_at > input.atInstant) {
    return { cause_id: cause.cause_id, disposition: 'CAUSE_NOT_YET_IN_EVIDENCE' }
  }
  // An unverified claim must not become a lifecycle state. A cause record whose signature
  // does not verify holds nothing: reporting `suspended` on it would convert an
  // unauthenticated assertion into a pause the artifact never carried.
  if (!signatureVerifies(cause, cause.imposed_by, input)) {
    return { cause_id: cause.cause_id, disposition: 'CAUSE_SIGNATURE_UNVERIFIED' }
  }
  if (!cause.verification_method.startsWith(`${cause.imposed_by}#`)) {
    return { cause_id: cause.cause_id, disposition: 'CAUSE_IMPOSER_BINDING_MISMATCH' }
  }
  return { cause_id: cause.cause_id, disposition: 'CAUSE_IN_EVIDENCE' }
}

/** Apply one release record. A record-level rejection releases nothing and reports no
 *  per-cause entries, because the record was never applied to any cause. */
function disposeRelease(
  release: SuspensionRelease,
  inEvidence: ReadonlyMap<string, SuspensionCause>,
  input: PauseStateInput,
): ReleaseDisposition {
  if (release.delegation_id !== input.delegationId) {
    return { release_id: release.release_id, disposition: 'RELEASE_NOT_ON_DELEGATION', causes: [] }
  }
  if (release.record_type !== SUSPENSION_RELEASE_TYPE) {
    return {
      release_id: release.release_id,
      disposition: 'RELEASE_RECORD_TYPE_UNRECOGNISED',
      causes: [],
    }
  }
  if (!signatureVerifies(release, release.issuer, input)) {
    return {
      release_id: release.release_id,
      disposition: 'RELEASE_SIGNATURE_UNVERIFIED',
      causes: [],
    }
  }
  if (!release.verification_method.startsWith(`${release.issuer}#`)) {
    return {
      release_id: release.release_id,
      disposition: 'RELEASE_ISSUER_BINDING_MISMATCH',
      causes: [],
    }
  }
  // A release recorded after the instant being evaluated is not in evidence there. It is in
  // evidence at a later one, and nothing about the record changes in between. The proposed
  // text says nothing about when a release takes effect, so this is a reading: see the
  // module's open questions in CHANGELOG.
  if (release.issued_at > input.atInstant) {
    return {
      release_id: release.release_id,
      disposition: 'RELEASE_AFTER_EVALUATION_INSTANT',
      causes: [],
    }
  }

  // Per named cause, independently. A record naming three causes from a party holding
  // standing over two of them clears exactly those two. Naming a cause in a release is not
  // the same as being able to release it.
  const causes: ReleaseCauseDisposition[] = []
  for (const causeId of release.cause_ids) {
    const cause = inEvidence.get(causeId)
    if (cause === undefined) {
      causes.push({ cause_id: causeId, disposition: 'CAUSE_NOT_PRESENTED' })
      continue
    }
    if (release.issued_at < cause.issued_at) {
      causes.push({ cause_id: causeId, disposition: 'RELEASE_PRECEDES_IMPOSITION' })
      continue
    }
    const standing = input.resolveReleaseStanding(release, cause)
    if (!(RELEASE_STANDINGS as readonly string[]).includes(standing)) {
      throw new SuspensionCauseError(
        'STANDING_ANSWER_UNKNOWN',
        `resolveReleaseStanding must answer one of ${RELEASE_STANDINGS.join(', ')}`,
      )
    }
    if (standing === 'has_standing') {
      causes.push({ cause_id: causeId, disposition: 'CAUSE_RELEASED' })
    } else if (standing === 'no_standing') {
      causes.push({ cause_id: causeId, disposition: 'RELEASER_WITHOUT_STANDING' })
    } else {
      causes.push({ cause_id: causeId, disposition: 'RELEASE_STANDING_NOT_ESTABLISHED' })
    }
  }
  return { release_id: release.release_id, disposition: 'RELEASE_IN_EVIDENCE', causes }
}

/**
 * Evaluate a set of lifecycle causes against one authority artifact at one instant, with
 * the audit trail behind the answer.
 *
 * `evaluatePauseState` is the same computation returning only `state`. Use this one when
 * you have to record why each record did or did not move the answer.
 *
 * WHAT THE VERDICT MEANS, AND WHAT IT DOES NOT. This module looked at causes and releases.
 * It did not verify a chain, did not resolve a revocation and did not read a time facet.
 * So a `valid` verdict here means exactly "no cause holds this artifact paused at this
 * instant" and NOTHING MORE. It is not a statement that the artifact confers authority.
 * Compose it with a chain result through `composeChainAndPause` before anything treats the
 * artifact as exercisable, and read that function's doc comment for why the order is not
 * negotiable.
 *
 * Proposed. Concept source: aeoess/agent-authority-lifecycle, invariant L8 and invariant
 * candidate CAND-05.
 */
export function explainPauseState(input: PauseStateInput): PauseStateExplanation {
  if (input === null || typeof input !== 'object') {
    throw new SuspensionCauseError('INPUT_MALFORMED', 'input is not an object')
  }
  if (!isNonEmptyString(input.delegationId)) {
    throw new SuspensionCauseError('INPUT_MALFORMED', 'delegationId must be a non-empty string')
  }
  if (!isNonEmptyString(input.atInstant)) {
    throw new SuspensionCauseError('INPUT_MALFORMED', 'atInstant must be a non-empty string')
  }
  if (!Array.isArray(input.causes)) {
    throw new SuspensionCauseError('INPUT_MALFORMED', 'causes must be an array')
  }
  if (!Array.isArray(input.releases)) {
    throw new SuspensionCauseError('INPUT_MALFORMED', 'releases must be an array')
  }
  if (typeof input.resolveReleaseStanding !== 'function') {
    throw new SuspensionCauseError('INPUT_MALFORMED', 'resolveReleaseStanding must be a function')
  }
  if (typeof input.resolveVerificationKey !== 'function') {
    throw new SuspensionCauseError('INPUT_MALFORMED', 'resolveVerificationKey must be a function')
  }
  input.causes.forEach(assertCauseShape)
  input.releases.forEach(assertReleaseShape)

  const seenCauseIds = new Set<string>()
  for (const cause of input.causes) {
    if (seenCauseIds.has(cause.cause_id)) {
      throw new SuspensionCauseError(
        'DUPLICATE_CAUSE_ID',
        `cause_id ${cause.cause_id} appears more than once`,
      )
    }
    seenCauseIds.add(cause.cause_id)
  }
  const seenReleaseIds = new Set<string>()
  for (const release of input.releases) {
    if (seenReleaseIds.has(release.release_id)) {
      throw new SuspensionCauseError(
        'DUPLICATE_RELEASE_ID',
        `release_id ${release.release_id} appears more than once`,
      )
    }
    seenReleaseIds.add(release.release_id)
  }

  const causeDispositions = input.causes.map(cause => disposeCause(cause, input))
  const inEvidence = new Map<string, SuspensionCause>()
  input.causes.forEach((cause, i) => {
    if (causeDispositions[i].disposition === 'CAUSE_IN_EVIDENCE') {
      inEvidence.set(cause.cause_id, cause)
    }
  })

  const releaseDispositions = input.releases.map(release =>
    disposeRelease(release, inEvidence, input),
  )

  // A cause released by ANY accepted record is released. A cause for which some record got
  // `unknown` standing and no record released it is unresolved: this verifier did not
  // establish whether it still holds.
  const releasedBy = new Map<string, string>()
  const unresolved = new Set<string>()
  for (const disposition of releaseDispositions) {
    for (const entry of disposition.causes) {
      if (entry.disposition === 'CAUSE_RELEASED' && !releasedBy.has(entry.cause_id)) {
        releasedBy.set(entry.cause_id, disposition.release_id)
      } else if (entry.disposition === 'RELEASE_STANDING_NOT_ESTABLISHED') {
        unresolved.add(entry.cause_id)
      }
    }
  }
  for (const causeId of releasedBy.keys()) unresolved.delete(causeId)

  const finalCauses: CauseDisposition[] = causeDispositions.map(disposition => {
    const releaseId = releasedBy.get(disposition.cause_id)
    if (disposition.disposition === 'CAUSE_IN_EVIDENCE' && releaseId !== undefined) {
      return {
        cause_id: disposition.cause_id,
        disposition: 'CAUSE_RELEASED',
        released_by: releaseId,
      }
    }
    return disposition
  })

  // Sorted by cause_id, which is a presentation choice with no claim behind it. CAND-05
  // defines no precedence order among causes and says so, and nothing here depends on one
  // cause outranking another.
  const remaining = [...inEvidence.values()]
    .filter(cause => !releasedBy.has(cause.cause_id))
    .sort((a, b) => (a.cause_id < b.cause_id ? -1 : a.cause_id > b.cause_id ? 1 : 0))

  const outstanding: OutstandingCause[] = remaining.map(cause =>
    Object.freeze({ id: cause.cause_id, kind: cause.kind, reason_code: cause.reason_code }),
  )

  const explanation = (state: LifecycleStateResult): PauseStateExplanation =>
    Object.freeze({
      state,
      causes: Object.freeze(finalCauses.map(d => Object.freeze({ ...d }))),
      releases: Object.freeze(
        releaseDispositions.map(d =>
          Object.freeze({ ...d, causes: Object.freeze(d.causes.map(c => Object.freeze({ ...c }))) }),
        ),
      ),
      // Mirrors `state.outstanding` exactly, and is empty where the state carries none. On a
      // `not_established` verdict that means empty: a verifier that could not establish the
      // pause state has no set to vouch for, and publishing the causes it would have named
      // alongside an admission of ignorance is the collapse this vocabulary prevents.
      outstanding: Object.freeze([...(state.outstanding ?? [])]),
    })

  // An unresolved cause is reported as unresolved. Reporting `suspended` would claim a
  // finding this verifier did not reach, which is the exact collapse the lifecycle
  // vocabulary's two uses of "not established" exist to prevent: failing to establish that
  // a cause was released is not establishing that it still holds. The other reading, that
  // an unreleased cause holds until a release is established, is available and defensible.
  // The proposed text settles neither, and this one is recorded as an open question.
  if (unresolved.size > 0) {
    return explanation(notEstablished(['source'], 'RELEASE_STANDING_NOT_ESTABLISHED'))
  }

  if (remaining.length === 0) {
    let reasonCode: string
    if (input.causes.length === 0) {
      reasonCode = 'NO_CAUSE_PRESENTED'
    } else if (inEvidence.size === 0) {
      reasonCode = 'NO_CAUSE_IN_EVIDENCE'
    } else {
      reasonCode = 'ALL_CAUSES_RELEASED'
    }
    return explanation(lifecycleState({ verdict: 'valid', reason_code: reasonCode }))
  }

  // Any remaining cause of kind `suspension` holds the artifact suspended. With only
  // restrictions left it is restricted, which is the distinction invariant L8 draws:
  // suspension stops the use of authority, a restriction is different again and does not
  // have to pause descendants.
  const anySuspension = remaining.some(cause => cause.kind === 'suspension')
  return explanation(
    lifecycleState({
      verdict: anySuspension ? 'suspended' : 'restricted',
      reason_code: 'CAUSES_OUTSTANDING',
      outstanding,
    }),
  )
}

/**
 * Evaluate a set of lifecycle causes against one authority artifact at one instant.
 *
 * The result's `outstanding` member is the remaining cause set. NEVER A COUNT AND NEVER A
 * BOOLEAN: that member being a list is the whole of CAND-05 in one field. An
 * implementation holding a single suspended flag conforms to every word of invariant L8,
 * which says nothing about arity, and still gets a regulatory suspension lapsing while an
 * unrelated internal restriction stands exactly backwards, because the first effective
 * release looks to it like a full restoration.
 *
 * See `explainPauseState` for the same computation with the per-record audit trail, and
 * `composeChainAndPause` for what a `valid` verdict here does and does not entitle a
 * caller to conclude.
 *
 * Proposed. Concept source: aeoess/agent-authority-lifecycle, invariant L8 and invariant
 * candidate CAND-05.
 */
export function evaluatePauseState(input: PauseStateInput): LifecycleStateResult {
  return explainPauseState(input).state
}

/**
 * Compose a chain result and a pause state into one lifecycle answer, chain first.
 *
 * A RELEASE NEVER CLEARS A REVOCATION THAT HAPPENED MEANWHILE. That is the rule this
 * function exists to make unavoidable, and `OPEN-QUESTIONS.md` states it directly: lifting
 * one suspension should not clear another, "bypass a revocation that happened while the
 * agent was suspended, or recreate rights that changed in the meantime". A grant revoked
 * during its suspension is invalid once every cause has been lifted, because draft-03
 * section 3.5 says verbatim "Revocation is irreversible" and a release record is a later
 * record about the causes, not about the chain. It never reaches the chain result.
 *
 * So: when `chain` is anything other than `valid`, `chain` is returned UNCHANGED and the
 * pause state is not reported. When `chain` is `valid`, the pause state is the answer.
 *
 * Both arguments come from the six-value lifecycle vocabulary. Get `chain` from
 * `mapAuthorityValidationToLifecycle` over a real `AuthorityValidationResult`, which
 * leaves the draft-03 four-value result untouched, and `pause` from `evaluatePauseState`.
 * A caller wanting both raw results side by side has `CompositeAuthorityResult`.
 *
 * WHAT THIS DOES NOT DECIDE. The reverse ordering: a revoked or indeterminate chain with
 * causes still outstanding. This function reports the chain, which is a choice of what to
 * report first and not a claim that the causes stopped mattering. No published text and no
 * proposed text settles it, and the fixture that exercises this area deliberately presents
 * no such vector. Recorded as an open question rather than papered over.
 *
 * Proposed.
 */
export function composeChainAndPause(
  chain: LifecycleStateResult,
  pause: LifecycleStateResult,
): LifecycleStateResult {
  if (chain === null || typeof chain !== 'object' || typeof chain.verdict !== 'string') {
    throw new SuspensionCauseError('INPUT_MALFORMED', 'chain must be a LifecycleStateResult')
  }
  if (pause === null || typeof pause !== 'object' || typeof pause.verdict !== 'string') {
    throw new SuspensionCauseError('INPUT_MALFORMED', 'pause must be a LifecycleStateResult')
  }
  return chain.verdict === 'valid' ? pause : chain
}
