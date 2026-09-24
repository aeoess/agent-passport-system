// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. The multi-source status decision. See ./types.ts for the
// specification position: nothing here is required by draft-pidlisnyi-aps-03, everything
// here is experimental against the aeoess/agent-authority-lifecycle invariant candidate
// BROAD-L7, and nothing here changes any existing exported behaviour.
//
// Pure. No clock, no network, no crypto, no policy grammar and no evaluator. Every
// instant arrives as a string and is parsed with the SDK's own strict RFC 3339 parser, so
// the TypeScript and Python ports agree on what an instant is rather than each reaching
// for a language date library.

import { parseRfc3339 } from '../../core/rfc3339.js'
import { lifecycleState, notEstablished } from '../lifecycle-state/state.js'
import type { BoundaryOutcome, LifecycleStateResult } from '../lifecycle-state/types.js'
import {
  STATUS_ANSWERS,
  type AdmittedSnapshot,
  type CoverageDenominator,
  type DeterminateStatusAnswer,
  type MultiSourceStatusBasis,
  type MultiSourceStatusDecision,
  type MultiSourceStatusInput,
  type StatusAnswer,
  type StatusConflict,
  type StatusCoverage,
  type StatusCoverageReasonCode,
  type StatusSourceLine,
  type StatusUseBasis,
} from './types.js'

/** Thrown when the input is not something the module can decide over. A malformed input
 *  is a programming error, not a verdict: returning `not_established` for a caller that
 *  passed an unparseable instant would report ignorance about the authority when the
 *  defect is in the call. */
export class StatusCoverageError extends Error {
  readonly code: string

  constructor(code: string, message: string) {
    super(message)
    this.name = 'StatusCoverageError'
    this.code = code
  }
}

function requireInstant(value: unknown, field: string): number {
  const parsed = parseRfc3339(value)
  if (!parsed.ok) {
    throw new StatusCoverageError(
      'INSTANT_INVALID',
      `${field} must be an RFC 3339 instant, got ${parsed.reason}`,
    )
  }
  return parsed.ms
}

function requireWholeSecondBound(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new StatusCoverageError(
      'BOUND_INVALID',
      `${field} must be a non-negative whole number of seconds`,
    )
  }
  return value
}

function requireNonEmptyString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new StatusCoverageError('FIELD_INVALID', `${field} must be a non-empty string`)
  }
  return value
}

function isStatusAnswer(value: unknown): value is StatusAnswer {
  return typeof value === 'string' && (STATUS_ANSWERS as readonly string[]).includes(value)
}

/**
 * Decide what an authorization boundary can establish about one authority_ref from a SET
 * of status answers, each measured against the freshness bound declared for its own
 * source.
 *
 * BROAD-L7 in one function, for the source and freshness limbs, plus a declared-set
 * coverage report that is explicitly not a completeness claim. The procedure, in order,
 * and every step is a consequence of the candidate rather than a design preference:
 *
 *   1. Age every answer against `now`. An answer is within bound when its age is at most
 *      the bound declared for its source, inclusive. An answer dated after the boundary
 *      is refused as skew rather than read as fresh.
 *   2. Decide which answers are USED. `unavailable` is never used. Within bound is used.
 *      Past bound is used only where `stalePolicy` says that class of answer still
 *      counts, and the line records which of the two it was.
 *   3. If the used answers carry more than one determinate state, that is a conflict.
 *      Per `conflictPolicy` the boundary denies or returns not established. The artifact
 *      state is NOT ESTABLISHED either way, with the source limb missing, never invalid:
 *      a conflict is the verifier failing to reach a conclusion, not a finding that the
 *      authority ended. A conflict never admits, whatever coverage says.
 *   4. If every used answer is `revoked`, the boundary denies and the artifact state is
 *      invalid. This is checked BEFORE coverage, because an observed revocation from an
 *      accepted source does not need a complete source set to count, and before the
 *      offline branch, because being offline does not soften an observed revocation.
 *   5. Offline mode resolves on the declared snapshot: inside its declared bound and
 *      active, the boundary admits and the basis names the snapshot and the age it
 *      admitted at. Past the bound, the freshness limb is missing. No snapshot answer at
 *      all, the source limb is missing.
 *   6. Online mode admits only when coverage is complete under the declared reading and
 *      every used answer is active. Short of that the reason distinguishes no usable
 *      answer at all, a silent required source, and a required source whose answer was
 *      past its bound.
 *
 * Nothing in the result is the negation of a claim. `not_established` is ignorance about
 * the authority and never a statement that the authority is inactive, active, or anything
 * about the world.
 *
 * Concept source: aeoess/agent-authority-lifecycle, invariant candidate BROAD-L7 and
 * invariant L7. Proposed, and the two policy parameters mark the two places the proposed
 * text does not choose.
 */
export function decideMultiSourceStatus(
  input: MultiSourceStatusInput,
): MultiSourceStatusDecision {
  if (input === null || typeof input !== 'object') {
    throw new StatusCoverageError('INPUT_INVALID', 'input must be an object')
  }
  const authorityRef = requireNonEmptyString(input.authority_ref, 'authority_ref')
  const nowMs = requireInstant(input.now, 'now')

  const policy = input.trustPolicy
  if (policy === null || typeof policy !== 'object') {
    throw new StatusCoverageError('INPUT_INVALID', 'trustPolicy must be an object')
  }
  if (policy.mode !== 'online' && policy.mode !== 'offline') {
    throw new StatusCoverageError('MODE_UNKNOWN', "trustPolicy.mode must be online or offline")
  }
  const sourceSet = policy.sources
  if (sourceSet === null || typeof sourceSet !== 'object' || !Array.isArray(sourceSet.required)) {
    throw new StatusCoverageError(
      'INPUT_INVALID',
      'trustPolicy.sources.required must be an array',
    )
  }
  if (sourceSet.silence_is !== 'coverage_gap' && sourceSet.silence_is !== 'unavailable_answer') {
    throw new StatusCoverageError(
      'SILENCE_POLICY_REQUIRED',
      'trustPolicy.sources.silence_is is required and has no default: it decides whether a ' +
        'silent required source is a coverage gap or an unavailable answer',
    )
  }
  if (sourceSet.required.length === 0) {
    throw new StatusCoverageError(
      'REQUIRED_SET_EMPTY',
      'trustPolicy.sources.required must name at least one source: a verifier that accepts no ' +
        'source for a claim cannot establish it',
    )
  }

  const conflictPolicy = input.conflictPolicy
  if (conflictPolicy !== 'deny_with_conflict' && conflictPolicy !== 'not_established') {
    throw new StatusCoverageError(
      'CONFLICT_POLICY_REQUIRED',
      'conflictPolicy is required and has no default: the proposed text does not choose between ' +
        'denying on a conflict and returning not established',
    )
  }
  const stalePolicy = input.stalePolicy
  if (
    stalePolicy === null ||
    typeof stalePolicy !== 'object' ||
    typeof stalePolicy.stale_revoked_still_counts !== 'boolean' ||
    typeof stalePolicy.stale_active_still_counts !== 'boolean'
  ) {
    throw new StatusCoverageError(
      'STALE_POLICY_REQUIRED',
      'stalePolicy is required with both members set and has no default: whether an answer past ' +
        'its own bound still counts decides the deployment-relevant case and the proposed text ' +
        'does not choose',
    )
  }

  const bounds = new Map<string, number>()
  const requiredIds: string[] = []
  for (const declared of sourceSet.required) {
    const id = requireNonEmptyString(declared?.source_id, 'required[].source_id')
    if (bounds.has(id)) {
      throw new StatusCoverageError(
        'SOURCE_DECLARED_TWICE',
        `source ${id} is declared more than once, so its bound is ambiguous`,
      )
    }
    bounds.set(id, requireWholeSecondBound(declared?.freshness_bound_s, `${id}.freshness_bound_s`))
    requiredIds.push(id)
  }

  let snapshotId: string | null = null
  let snapshotBoundS = 0
  if (policy.mode === 'offline') {
    const snap = policy.snapshot_source
    if (snap === null || snap === undefined) {
      throw new StatusCoverageError(
        'SNAPSHOT_SOURCE_REQUIRED',
        'offline mode requires trustPolicy.snapshot_source with a declared bound: BROAD-L7 forbids ' +
          'admitting on a snapshot with no declared bound',
      )
    }
    snapshotId = requireNonEmptyString(snap.source_id, 'snapshot_source.source_id')
    snapshotBoundS = requireWholeSecondBound(snap.declared_bound_s, 'snapshot_source.declared_bound_s')
    if (bounds.has(snapshotId)) {
      throw new StatusCoverageError(
        'SNAPSHOT_SOURCE_ALSO_REQUIRED',
        `${snapshotId} is both the snapshot source and a required source, so which bound applies is ` +
          'ambiguous',
      )
    }
  } else if (policy.snapshot_source !== undefined) {
    throw new StatusCoverageError(
      'SNAPSHOT_SOURCE_NOT_ALLOWED',
      'trustPolicy.snapshot_source is only meaningful in offline mode',
    )
  }

  if (!Array.isArray(input.answers)) {
    throw new StatusCoverageError('INPUT_INVALID', 'answers must be an array')
  }

  // ── step 1 and 2: age every answer, decide which are used ────────────────
  const lines: StatusSourceLine[] = []
  const seen = new Set<string>()
  for (const supplied of input.answers) {
    const id = requireNonEmptyString(supplied?.source_id, 'answers[].source_id')
    if (seen.has(id)) {
      throw new StatusCoverageError(
        'SOURCE_ANSWERED_TWICE',
        `source ${id} supplied more than one answer, which is a conflict inside one source rather ` +
          'than between two and is not what this module decides',
      )
    }
    seen.add(id)
    if (!isStatusAnswer(supplied?.answer)) {
      throw new StatusCoverageError(
        'ANSWER_UNKNOWN',
        `answers[].answer must be one of ${STATUS_ANSWERS.join(', ')}`,
      )
    }
    const answer: StatusAnswer = supplied.answer
    const accepted = bounds.has(id) || id === snapshotId
    const boundS = id === snapshotId ? snapshotBoundS : (bounds.get(id) ?? null)

    if (!accepted) {
      lines.push(
        freeze({
          source_id: id,
          answer,
          as_of: typeof supplied.as_of === 'string' ? supplied.as_of : null,
          age_s: null,
          freshness_bound_s: null,
          within_bound: false,
          used: false,
          use_basis: 'source_not_accepted' as StatusUseBasis,
        }),
      )
      continue
    }

    if (answer === 'unavailable') {
      // `null` and `undefined` are both "no instant". Treating them differently would make
      // the two SDKs disagree on a JSON vector that writes `"as_of": null`, since Python has
      // one absent value where TypeScript has two.
      if (supplied.as_of !== undefined && supplied.as_of !== null) {
        throw new StatusCoverageError(
          'UNAVAILABLE_CARRIES_AS_OF',
          `source ${id} answered unavailable and also supplied as_of: an unavailable answer dates ` +
            'nothing',
        )
      }
      lines.push(
        freeze({
          source_id: id,
          answer,
          as_of: null,
          age_s: null,
          freshness_bound_s: boundS,
          within_bound: false,
          used: false,
          use_basis: 'source_gave_no_answer' as StatusUseBasis,
        }),
      )
      continue
    }

    const asOfMs = requireInstant(supplied.as_of, `answers[${id}].as_of`)
    const ageS = Math.floor((nowMs - asOfMs) / 1000)
    if (ageS < 0) {
      lines.push(
        freeze({
          source_id: id,
          answer,
          as_of: supplied.as_of as string,
          age_s: ageS,
          freshness_bound_s: boundS,
          within_bound: false,
          used: false,
          use_basis: 'answer_dated_after_boundary' as StatusUseBasis,
        }),
      )
      continue
    }

    const withinBound = boundS !== null && ageS <= boundS
    let used = withinBound
    let basis: StatusUseBasis = 'within_freshness_bound'
    if (!withinBound) {
      if (answer === 'revoked' && stalePolicy.stale_revoked_still_counts) {
        used = true
        basis = 'revocation_observed_outside_bound_still_used'
      } else if (answer === 'active' && stalePolicy.stale_active_still_counts) {
        used = true
        basis = 'stale_active_admitted_by_policy'
      } else {
        used = false
        basis = 'stale_beyond_bound'
      }
    }
    lines.push(
      freeze({
        source_id: id,
        answer,
        as_of: supplied.as_of as string,
        age_s: ageS,
        freshness_bound_s: boundS,
        within_bound: withinBound,
        used,
        use_basis: basis,
      }),
    )
  }

  const byId = new Map(lines.map(l => [l.source_id, l]))
  const silent = requiredIds.filter(id => !byId.has(id)).sort()
  const answeredRequired = requiredIds.filter(id => byId.has(id))
  const usableRequired = requiredIds.filter(id => {
    const line = byId.get(id)
    return line !== undefined && line.used && line.answer !== 'unavailable'
  })

  const measuredOver: CoverageDenominator =
    sourceSet.silence_is === 'coverage_gap' ? 'declared_required_set' : 'sources_that_answered'
  const denominator =
    measuredOver === 'declared_required_set' ? requiredIds.length : answeredRequired.length
  const coverage: StatusCoverage = freeze({
    required: requiredIds.length,
    answered: answeredRequired.length,
    usable_determinate: usableRequired.length,
    silent: Object.freeze([...silent]),
    measured_over: measuredOver,
    complete: denominator > 0 && usableRequired.length === denominator,
  })

  const usedDeterminate = lines.filter(l => l.used && l.answer !== 'unavailable')
  const usedStates = [
    ...new Set(usedDeterminate.map(l => l.answer as DeterminateStatusAnswer)),
  ].sort()
  const anyStale = lines.some(
    l => l.use_basis === 'stale_beyond_bound' || l.use_basis === 'answer_dated_after_boundary',
  )

  /** Which of BROAD-L7's three limbs were missing, computed MECHANICALLY from what the
   *  boundary actually had, in the canonical order source, freshness, coverage.
   *
   *  More than one can be missing at once and all of them are reported. A denial that
   *  names one limb when two were missing understates what the verifier did not have, and
   *  the reason code, not the limb list, is what says which gap the module treated as the
   *  headline.
   *
   *   - source    no accepted source produced a usable determinate answer, or two
   *               accepted sources are in unresolved conflict. Both are BROAD-L7's source
   *               limb as the lifecycle-state vocabulary states it.
   *   - freshness at least one answer was past the bound declared for its source, or was
   *               dated after the boundary so no age against the bound was measurable.
   *   - coverage  the answers the boundary had do not cover what the verdict needed, which
   *               is `coverage.complete` being false. Which denominator that was measured
   *               against is `coverage.measured_over`, set by the silence reading, and it
   *               is in the basis so a reader does not have to infer it. This limb is NOT
   *               a completeness claim. See the module header and invariant L12. */
  const missingLimbs = (conflicted: boolean): Array<'source' | 'freshness' | 'coverage'> => {
    const limbs: Array<'source' | 'freshness' | 'coverage'> = []
    if (conflicted || usedDeterminate.length === 0) limbs.push('source')
    if (anyStale) limbs.push('freshness')
    if (!coverage.complete) limbs.push('coverage')
    return limbs
  }

  const makeBasis = (conflict: StatusConflict | null, snapshot: AdmittedSnapshot | null) =>
    freeze({
      authority_ref: authorityRef,
      evaluated_at: input.now,
      verifier_mode: policy.mode,
      required_sources: Object.freeze([...requiredIds]),
      sources_consulted: Object.freeze([...lines]),
      sources_silent: Object.freeze([...silent]),
      coverage,
      conflict,
      snapshot,
      conflict_policy: conflictPolicy,
      stale_policy: freeze({
        stale_revoked_still_counts: stalePolicy.stale_revoked_still_counts,
        stale_active_still_counts: stalePolicy.stale_active_still_counts,
      }),
      silence_is: sourceSet.silence_is,
    }) as MultiSourceStatusBasis

  const decide = (
    outcome: BoundaryOutcome,
    lifecycle: LifecycleStateResult,
    reasonCode: StatusCoverageReasonCode,
    basis: MultiSourceStatusBasis,
  ): MultiSourceStatusDecision =>
    freeze({ outcome, lifecycle, reason_code: reasonCode, basis }) as MultiSourceStatusDecision

  // ── step 3: conflict. Never admits, whatever coverage says ────────────────
  if (usedStates.length > 1) {
    const conflict: StatusConflict = freeze({
      states: Object.freeze([...usedStates]),
      sources: Object.freeze(usedDeterminate.map(l => l.source_id).sort()),
    })
    // The ARTIFACT state is not established under either conflict policy, never invalid:
    // a conflict is the verifier failing to reach a conclusion about the authority, not a
    // finding that the authority ended. What the policy changes is only the BOUNDARY
    // outcome, which is the whole content of the unresolved question.
    const lifecycle = notEstablished(missingLimbs(true), 'STATUS_SOURCES_CONFLICT')
    const outcome: BoundaryOutcome =
      conflictPolicy === 'deny_with_conflict' ? 'denied' : 'not_established'
    return decide(outcome, lifecycle, 'STATUS_SOURCES_CONFLICT', makeBasis(conflict, null))
  }

  // ── step 4: revoked, before coverage and before the offline branch ────────
  // Before coverage, because an observed revocation from an accepted source does not need
  // a complete source set to count. Before the offline branch, because being offline does
  // not soften an observed revocation.
  if (usedStates.length === 1 && usedStates[0] === 'revoked') {
    return decide(
      'denied',
      lifecycleState({ verdict: 'invalid', reason_code: 'STATUS_REVOKED' }),
      'STATUS_REVOKED',
      makeBasis(null, null),
    )
  }

  // ── step 5: offline resolves on the declared snapshot ─────────────────────
  if (policy.mode === 'offline') {
    const snapLine = snapshotId === null ? undefined : byId.get(snapshotId)
    if (snapLine !== undefined && snapLine.used && snapLine.answer === 'active') {
      const snapshot: AdmittedSnapshot = freeze({
        source_id: snapLine.source_id,
        as_of: snapLine.as_of as string,
        age_s: snapLine.age_s as number,
        declared_bound_s: snapshotBoundS,
      })
      return decide(
        'authorized',
        lifecycleState({
          verdict: 'valid',
          reason_code: 'ADMITTED_ON_SNAPSHOT_WITHIN_DECLARED_BOUND',
        }),
        'ADMITTED_ON_SNAPSHOT_WITHIN_DECLARED_BOUND',
        makeBasis(null, snapshot),
      )
    }
    if (
      snapLine !== undefined &&
      (snapLine.use_basis === 'stale_beyond_bound' ||
        snapLine.use_basis === 'answer_dated_after_boundary')
    ) {
      return decide(
        'not_established',
        notEstablished(missingLimbs(false), 'STATUS_STALE_BEYOND_BOUND'),
        'STATUS_STALE_BEYOND_BOUND',
        makeBasis(null, null),
      )
    }
    return decide(
      'not_established',
      notEstablished(missingLimbs(false), 'STATUS_NO_USABLE_OBSERVATION'),
      'STATUS_NO_USABLE_OBSERVATION',
      makeBasis(null, null),
    )
  }

  // ── step 6: online ────────────────────────────────────────────────────────
  if (coverage.complete && usedStates.length === 1 && usedStates[0] === 'active') {
    return decide(
      'authorized',
      lifecycleState({ verdict: 'valid', reason_code: 'STATUS_ACTIVE_ALL_SOURCES_AGREE' }),
      'STATUS_ACTIVE_ALL_SOURCES_AGREE',
      makeBasis(null, null),
    )
  }

  // Not complete, or nothing usable. The reason code says which gap the module treats as
  // the headline, and it distinguishes an empty answer set from a silent required source
  // from a required source whose answer was past its bound. The limb list is computed
  // separately and can carry more than one limb.
  const blockingStale = requiredIds.some(id => {
    const line = byId.get(id)
    return (
      line !== undefined &&
      (line.use_basis === 'stale_beyond_bound' ||
        line.use_basis === 'answer_dated_after_boundary')
    )
  })
  let reasonCode: StatusCoverageReasonCode
  if (usedDeterminate.length === 0) {
    reasonCode = 'STATUS_NO_USABLE_OBSERVATION'
  } else if (silent.length > 0 && measuredOver === 'declared_required_set') {
    reasonCode = 'STATUS_COVERAGE_INCOMPLETE'
  } else if (blockingStale) {
    reasonCode = 'STATUS_STALE_BEYOND_BOUND'
  } else {
    // A required source answered `unavailable`, so the declared set is not covered and no
    // bound was exceeded to blame it on.
    reasonCode = 'STATUS_COVERAGE_INCOMPLETE'
  }
  return decide(
    'not_established',
    notEstablished(missingLimbs(false), reasonCode),
    reasonCode,
    makeBasis(null, null),
  )
}

function freeze<T>(value: T): T {
  return Object.freeze(value)
}
