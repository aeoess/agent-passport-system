// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. Multi-source status observation with per-source freshness bounds.
//
// NOT REQUIRED BY draft-pidlisnyi-aps-03. Draft-03 section 3.3 rules exactly one
// revocation result per chain member and closes chain verification at, verbatim:
// "Verification returns one of valid, invalid, indeterminate, or unsupported with a
// stable failure code." It says nothing about two sources answering about the same
// chain member, nothing about a per-source freshness bound, nothing about coverage over
// a declared source set, and nothing about an offline admission on a snapshot. Proposed
// draft-04 adds nothing here either.
//
// So everything in this module is EXPERIMENTAL and proposed. Concept source: the
// aeoess/agent-authority-lifecycle concept document, invariant candidate BROAD-L7, all
// three limbs, whose broadened statement reads: any claim about current lifecycle state
// is established only from a source the authority model accepts for that claim, within
// a freshness bound the model declares, over the coverage the claim requires. Also
// invariant L7 (unknown revocation state is not active), which is the published-text
// half, and invariant candidate CAND-01's second limb. Every one of those is proposed.
//
// What this module does NOT change. `AuthorityValidationState`,
// `AuthorityValidationResult` and everything `verifyAuthorityDelegationChain` returns
// are byte for byte what they were. `FreshnessPolicy`, `FreshnessDecision`,
// `decideFreshness`, `enforceFreshnessPolicy`, `RevocationObservation` and
// `SignedRevocationObservation` in src/v2/revocation-enforcement/ are untouched: this
// module sits beside them and decides a different question, over a SET of answers rather
// than one record. A caller that never imports this module sees exactly today's
// behaviour.
//
// THE COVERAGE LIMB DOES NOT ESTABLISH COMPLETENESS. `StatusCoverage` expresses a
// DECLARED required-source set and reports whether every member of it produced a usable
// determinate answer. That is all. Invariant L12 (completeness is a separate and
// stronger claim) is open, and OPEN-QUESTIONS.md names three unsettled pieces a
// completeness basis would need. Nothing here answers any of them, and a caller must not
// read a `complete: true` coverage block as a statement that the declared set was every
// source that mattered.
//
// TWO READINGS THE PROPOSED TEXT DOES NOT CHOOSE BETWEEN, so this module refuses to
// choose either and takes both as required parameters with no defaults:
//
//   1. What a conflict returns. Two accepted sources answering determinately and
//      disagreeing can defensibly be a denial carrying a conflict reason, or a
//      not-established state. They differ in what a caller may do next, and two
//      implementations choosing differently are both consistent with the text as
//      written. `ConflictPolicy` is required.
//   2. Whether an answer past its own bound still counts. Draft-03 section 3.5 says
//      "Revocation is irreversible", which argues a `revoked` answer observed once does
//      not become unobserved with age. Read the other way, L7's unavailable-or-stale
//      rule drops it. The two readings give opposite verdicts on a stale revoked answer
//      against a fresh active one. `StaleAnswerPolicy` is required.
//
// A default on either would be this module making a specification decision in code.

import type {
  BoundaryOutcome,
  LifecycleStateResult,
} from '../lifecycle-state/types.js'

/** What one status source said about one authority_ref.
 *
 *  `unavailable` is a source that was consulted and produced no usable answer. It is
 *  not a third determinate state and it is never used as one. Silence, a source that
 *  produced no observation at all, is a different thing again and is carried by
 *  `RequiredSourceSet.silence_is`. */
export const STATUS_ANSWERS = ['active', 'revoked', 'unavailable'] as const

export type StatusAnswer = (typeof STATUS_ANSWERS)[number]

/** The two answers that say something about the authority. Agreement and disagreement
 *  are both measured over this set only. */
export const DETERMINATE_STATUS_ANSWERS = ['active', 'revoked'] as const

export type DeterminateStatusAnswer = (typeof DETERMINATE_STATUS_ANSWERS)[number]

/** One status source the authority model accepts, with the freshness bound the model
 *  declares FOR THAT SOURCE.
 *
 *  Per source, not global. Deployed practice already carries a per-answer bound, and two
 *  sources fetched while writing this module say so. RFC 6960 section 2.4 defines the OCSP
 *  field, verbatim: "thisUpdate      The most recent time at which the status being
 *  indicated is known by the responder to have been correct." The W3C Bitstring Status
 *  List Recommendation of 15 May 2025 states, verbatim: "The `ttl` is an OPTIONAL property
 *  that indicates the "time to live" in milliseconds before a refresh SHOULD be attempted.
 *  If not present, no default value is assumed."
 *
 *  Neither is a source for anything this module requires. They are cited only to show that
 *  a per-answer bound is an existing shape rather than an invention here. BROAD-L7 declares
 *  no number and neither does this module. The bound is the caller's, and a caller that has
 *  no declared bound has nothing to pass here, which is the point: BROAD-L7 forbids
 *  admitting on a stale snapshot with no declared bound.
 *
 *  `freshness_bound_s` is in whole seconds and the comparison is INCLUSIVE: an age equal
 *  to the bound is within it. */
export interface DeclaredStatusSource {
  readonly source_id: string
  readonly freshness_bound_s: number
}

/** One answer, as supplied by the caller. This module reads no network and no clock.
 *
 *  `as_of` is the instant the source says the answer was known correct, RFC 3339. Absent
 *  exactly when the answer dates nothing, which is what `unavailable` means. */
export interface StatusAnswerInput {
  readonly source_id: string
  readonly answer: StatusAnswer
  readonly as_of?: string
}

/** What an accepted source going SILENT means. The proposed text does not say.
 *
 *  - `coverage_gap`       a required source that produced no observation is a hole in
 *                         coverage, and coverage is measured over the declared set.
 *  - `unavailable_answer` silence is read as that source answering `unavailable`, and
 *                         coverage is measured over the sources that answered.
 *
 *  Required, no default, because the two readings decide whether a silent required source
 *  blocks an admission and the text as written supports both. */
export type SilencePolicy = 'coverage_gap' | 'unavailable_answer'

/** The set of sources the RELYING PARTY requires an answer from, declared by the relying
 *  party and never read from any record. Standing to be a status source for a claim is
 *  resolved outside the record, always. */
export interface RequiredSourceSet {
  readonly required: readonly DeclaredStatusSource[]
  readonly silence_is: SilencePolicy
}

/** The offline posture: a snapshot source and the maximum snapshot age the verifier
 *  declared IN ADVANCE that it would admit on.
 *
 *  BROAD-L7 explicitly does not claim liveness is required. A declared offline posture
 *  with a snapshot inside its declared bound satisfies the rule, and the verifier records
 *  what it used. What the rule forbids is the undeclared version, admitting on a stale
 *  snapshot with no declared bound, which is unreachable here because
 *  `declared_bound_s` is required. */
export interface SnapshotSource {
  readonly source_id: string
  readonly declared_bound_s: number
}

export type VerifierMode = 'online' | 'offline'

/** What the verifier accepts, for one authority_ref, at one authorization boundary. */
export interface StatusTrustPolicy {
  readonly mode: VerifierMode
  readonly sources: RequiredSourceSet
  /** Present exactly when `mode` is `offline`. */
  readonly snapshot_source?: SnapshotSource
}

/** What a conflict returns. See the module header, reading 1. Required, no default. */
export type ConflictPolicy = 'deny_with_conflict' | 'not_established'

/** Whether an answer past its own source's bound still counts. See the module header,
 *  reading 2. Both members required, no defaults.
 *
 *  The two are separate because the arguments for them are separate. A stale `revoked`
 *  answer still counting rests on revocation being irreversible. A stale `active` answer
 *  still counting has no such argument behind it, and setting it true is the weakest
 *  posture this module can be put in. */
export interface StaleAnswerPolicy {
  readonly stale_revoked_still_counts: boolean
  readonly stale_active_still_counts: boolean
}

/** Why one answer was or was not used in the decision.
 *
 *  - `within_freshness_bound`                        the answer was inside the bound
 *                                                    declared for its source, so it was
 *                                                    used.
 *  - `revocation_observed_outside_bound_still_used`  a `revoked` answer past its bound,
 *                                                    used because
 *                                                    `stale_revoked_still_counts` is set.
 *  - `stale_active_admitted_by_policy`               an `active` answer past its bound,
 *                                                    used because
 *                                                    `stale_active_still_counts` is set.
 *  - `stale_beyond_bound`                            past its bound and not used.
 *  - `source_gave_no_answer`                         `unavailable`, which is never used.
 *  - `answer_dated_after_boundary`                   `as_of` is later than the boundary
 *                                                    instant, so no age is measurable
 *                                                    against the bound. Not used. The
 *                                                    proposed text does not rule clock
 *                                                    skew at all, and this module refuses
 *                                                    the answer rather than reading a
 *                                                    negative age as fresh. Recorded
 *                                                    distinctly so a reader can tell skew
 *                                                    from staleness.
 *  - `source_not_accepted`                           an answer from a source that is
 *                                                    neither in the required set nor the
 *                                                    declared snapshot source. Not used.
 *                                                    BROAD-L7's source limb covers this:
 *                                                    an answer from a source the model
 *                                                    does not accept for the claim does
 *                                                    not establish it. */
export const STATUS_USE_BASES = [
  'within_freshness_bound',
  'revocation_observed_outside_bound_still_used',
  'stale_active_admitted_by_policy',
  'stale_beyond_bound',
  'source_gave_no_answer',
  'answer_dated_after_boundary',
  'source_not_accepted',
] as const

export type StatusUseBasis = (typeof STATUS_USE_BASES)[number]

/** One source's answer with everything the decision derived from it. The audit half, and
 *  it is not optional: a reader of this line alone can recompute whether the answer was
 *  within its bound and whether it was used. */
export interface StatusSourceLine {
  readonly source_id: string
  readonly answer: StatusAnswer
  readonly as_of: string | null
  readonly age_s: number | null
  /** The bound declared for this source, or null when no bound was declared for it,
   *  which is the `source_not_accepted` case. */
  readonly freshness_bound_s: number | null
  readonly within_bound: boolean
  readonly used: boolean
  readonly use_basis: StatusUseBasis
}

/** Two or more accepted sources in unresolved disagreement about one authority_ref.
 *
 *  `states` is the set of determinate answers that were used, sorted. `sources` is the
 *  sources that carried them, sorted. Both are named because a conflict a record does not
 *  attribute is not actionable. */
export interface StatusConflict {
  readonly states: readonly DeterminateStatusAnswer[]
  readonly sources: readonly string[]
}

/** Which denominator `complete` was measured against, derived from `silence_is` so the
 *  choice is visible in the record rather than implied by a policy field. */
export type CoverageDenominator = 'declared_required_set' | 'sources_that_answered'

/** Coverage over the DECLARED required-source set. Not a completeness claim. See the
 *  module header. */
export interface StatusCoverage {
  /** Size of the declared required set. */
  readonly required: number
  /** Required sources that produced any observation at all. */
  readonly answered: number
  /** Required sources whose answer was used and determinate. */
  readonly usable_determinate: number
  /** Required sources that produced no observation, sorted. */
  readonly silent: readonly string[]
  readonly measured_over: CoverageDenominator
  readonly complete: boolean
}

/** The snapshot an offline admission actually admitted on, with the age it admitted at.
 *
 *  Present exactly when the reason code is `ADMITTED_ON_SNAPSHOT_WITHIN_DECLARED_BOUND`.
 *  This field exists because the proposed text does not require a verifier that admitted
 *  on a snapshot to record which snapshot or how old it was, and without the record the
 *  admission cannot be recomputed afterwards. */
export interface AdmittedSnapshot {
  readonly source_id: string
  readonly as_of: string
  readonly age_s: number
  readonly declared_bound_s: number
}

/** Everything the decision rested on, in recomputable form. Both policies and the silence
 *  reading are echoed back, because a record that does not say which reading produced it
 *  cannot be compared against a record produced under the other. */
export interface MultiSourceStatusBasis {
  readonly authority_ref: string
  readonly evaluated_at: string
  readonly verifier_mode: VerifierMode
  readonly required_sources: readonly string[]
  readonly sources_consulted: readonly StatusSourceLine[]
  readonly sources_silent: readonly string[]
  readonly coverage: StatusCoverage
  readonly conflict: StatusConflict | null
  readonly snapshot: AdmittedSnapshot | null
  readonly conflict_policy: ConflictPolicy
  readonly stale_policy: StaleAnswerPolicy
  readonly silence_is: SilencePolicy
}

/** The reason codes this module emits. Module local and stable, SCREAMING_SNAKE_CASE,
 *  which is what `LifecycleStateResult.reason_code` requires. Not APS vocabulary: these
 *  names are placeholders until the concept text is ruled. */
export const STATUS_COVERAGE_REASON_CODES = [
  /** authorized: every required source answered inside its bound and every used answer
   *  was active. */
  'STATUS_ACTIVE_ALL_SOURCES_AGREE',
  /** authorized: an offline verifier used a snapshot inside the bound it declared, and
   *  the basis names the snapshot and the age. */
  'ADMITTED_ON_SNAPSHOT_WITHIN_DECLARED_BOUND',
  /** denied, lifecycle verdict invalid: an accepted source answered revoked and no used
   *  answer disagreed. */
  'STATUS_REVOKED',
  /** denied or not_established per `ConflictPolicy`, lifecycle verdict not_established
   *  with the source limb missing: two accepted sources disagreed. */
  'STATUS_SOURCES_CONFLICT',
  /** not_established, freshness limb: an answer the verdict needed was older than the
   *  bound declared for its source. */
  'STATUS_STALE_BEYOND_BOUND',
  /** not_established, coverage limb: a source the trust policy requires produced no
   *  answer at all. */
  'STATUS_COVERAGE_INCOMPLETE',
  /** not_established, source limb: no source produced a usable determinate answer. */
  'STATUS_NO_USABLE_OBSERVATION',
] as const

export type StatusCoverageReasonCode = (typeof STATUS_COVERAGE_REASON_CODES)[number]

/** What this module concludes for one authority_ref at one authorization boundary.
 *
 *  TWO SUBJECTS, kept apart, following the lifecycle-state vocabulary:
 *
 *  - `outcome` is the BOUNDARY subject, what the enforcement point decides about the
 *    action here and now: `authorized`, `denied` or `not_established`.
 *  - `lifecycle` is the ARTIFACT subject, what the verifier can say about the
 *    authority's current lifecycle state.
 *
 *  They are not the same answer and a conflict is where that shows. A conflict under
 *  `deny_with_conflict` denies the action while leaving the artifact's state NOT
 *  ESTABLISHED, not invalid: the verifier reached no conclusion about the authority, it
 *  refused the action. Under `not_established` both are not established. Nothing here
 *  ever reports a conflict as a finding that the authority is revoked, and nothing here
 *  claims an answer is false. A stale active answer is an answer the verifier could not
 *  use, not a lie.
 *
 *  Reported ALONGSIDE a chain result, never merged into it. A later boundary that finds a
 *  conflict is a new decision that references the earlier record, and it never rewrites
 *  it. */
export interface MultiSourceStatusDecision {
  readonly outcome: BoundaryOutcome
  readonly lifecycle: LifecycleStateResult
  readonly reason_code: StatusCoverageReasonCode
  readonly basis: MultiSourceStatusBasis
}

/** What `decideMultiSourceStatus` takes. `now` is a string parameter: this module reads
 *  no clock, exactly as the chain verifier does not. */
export interface MultiSourceStatusInput {
  readonly authority_ref: string
  readonly trustPolicy: StatusTrustPolicy
  readonly answers: readonly StatusAnswerInput[]
  readonly conflictPolicy: ConflictPolicy
  readonly stalePolicy: StaleAnswerPolicy
  readonly now: string
}
