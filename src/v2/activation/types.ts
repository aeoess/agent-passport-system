// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. Activation conditions and condition attestation.
//
// NOT REQUIRED BY draft-pidlisnyi-aps-03. The published text states no activation-condition
// rule, no attestor role and no attestation-acceptance rule: a case-insensitive search of
// draft-pidlisnyi-aps-03 for `activation`, `attestor` and `contingen` returns nothing.
// Draft-03 section 3.2 also states, verbatim: "authority contains exactly seven required
// facets: scope, spend, depth, time, reputation, values, and reversibility. A missing facet
// is invalid rather than an implicit unconstrained value." That closes the authority vector,
// so an activation condition can never be a facet. It is a SEPARATE artifact that references
// a `delegation_id`, which is what this module models.
//
// Concept source: the aeoess/agent-authority-lifecycle concept document
// (AUTHORITY-LIFECYCLE.md, "Activation condition" under "Authority and dependencies", marked
// proposed with no public case testing it) and invariant candidates CAND-04 (activation is
// established, not yet effective, or not established), CAND-13 (replacement authority may be
// pre-committed) and BROAD-L7 (any current lifecycle state claim is established only from an
// accepted source, within a declared freshness bound, over the coverage the claim states).
// All three are proposed. Nothing here claims otherwise.
//
// Additive and opt-in. `AuthorityValidationState`, `AuthorityValidationResult`,
// `AuthorityVectorV1` and everything `verifyAuthorityDelegationChain` returns are unchanged.
// A caller that never imports this module sees exactly today's behaviour.
//
// THREE THINGS THE CONCEPT TEXT DOES NOT DECIDE, and how this module refuses to decide them:
//
//   1. WHICH INSTANT an occurrence is measured from. A recorded-event condition carries
//      `instant_basis` and there is no default. CAND-04 v2 reads it as the condition's own
//      occurrence instant, and `attestation_written` exists so a model that reads it the
//      other way has to say so in the record rather than inherit a choice this SDK made.
//   2. HOW MANY acceptable attestations establish a condition. `threshold` is required and
//      there is no default.
//   3. WHO decides a condition. Role standing is resolved through a caller-supplied
//      resolver and is never read off the attestation asserting it. An attestation's
//      `attestor_role` member is the attestor's claim about itself, and this module checks
//      that claim AGAINST the resolver rather than believing it.
//
// A fourth thing it does not decide is whether a waiting grant is `invalid` or
// `not_yet_effective` when the wait is carried by the time facet rather than by an activation
// condition. This module does not touch the time facet and `composeActivation` keeps the
// chain verifier's own answer unless the caller opts out. See ./verify.ts.

import type { EstablishmentGap, LifecycleStateResult } from '../lifecycle-state/types.js'

/** Record type of the activation condition this module owns. The `proposed:` prefix is
 *  deliberate: the conformance suite's CONTRIBUTING.md reserves record fields, failure-class
 *  names and verifier semantics to the schema owner, so nothing here is minted APS
 *  vocabulary and nothing downstream should treat it as stable. */
export const ACTIVATION_CONDITION_TYPE = 'proposed:aps:activation-condition:v0' as const

/** Record type of the activation attestation this module owns. Same caveat as above.
 *  A model may accept condition evidence in a shape this module does not own; see
 *  `ActivationVerificationInput.attestationPreimage`. */
export const ACTIVATION_ATTESTATION_TYPE = 'proposed:aps:activation-attestation:v0' as const

/** The two kinds of activation condition the concept text names in one sentence: "A grant can
 *  be validly issued and still wait on a date or a recorded event." They are answered by
 *  different deciders, which is why they are separate members here rather than one shape with
 *  optional fields. A date condition needs no evidence at all: the verifier reads the date. A
 *  recorded-event condition needs evidence from a source the model accepts for it. */
export const ACTIVATION_CONDITION_KINDS = ['date', 'recorded_event'] as const

export type ActivationConditionKind = (typeof ACTIVATION_CONDITION_KINDS)[number]

/** Which instant a `condition_occurred` attestation is measured against.
 *
 *  - `condition_occurrence`  the instant the condition itself is asserted to have occurred,
 *                            from the record's `occurred_at`. This is CAND-04 v2's reading:
 *                            "A condition that first occurred after an action does not make
 *                            that action exercisable", which is a statement about the
 *                            condition's own instant. Under it, a record written after an
 *                            action can establish a condition that obtained before it, which
 *                            is the normal case for any model built around an
 *                            after-the-fact determination.
 *  - `attestation_written`   the instant the record was written, from `attested_at`. A model
 *                            that keys activation on when someone wrote the determination
 *                            down rather than on when the condition occurred can say so
 *                            here.
 *
 *  THERE IS NO DEFAULT. The concept text groups a date and a recorded event in one sentence
 *  and says nothing about which instant either is measured from, and a default in an SDK is a
 *  ruling made by whoever wrote the SDK. Both readings give opposite verdicts on a
 *  deployment-relevant case (an occurrence before an action, attested after it), so the
 *  condition has to state which one governs.
 *
 *  `instant_basis` does not apply to a `condition_not_occurred_through` record. That
 *  assertion states the interval it covers, and the interval is what the coverage check
 *  reads. Concept source: BROAD-L7's coverage limb. */
export const ACTIVATION_INSTANT_BASES = ['condition_occurrence', 'attestation_written'] as const

export type ActivationInstantBasis = (typeof ACTIVATION_INSTANT_BASES)[number]

/** The two assertions an activation attestation can carry.
 *
 *  - `condition_occurred`             the event occurred, at `occurred_at`.
 *  - `condition_not_occurred_through` the event had not occurred through
 *                                     `not_occurred_through`. A NEGATIVE that is evidence,
 *                                     not an absence of evidence, which is the distinction
 *                                     between `not_yet_effective` and `not_established`.
 *
 *  An absence-triggered condition, where the trigger is that something did NOT happen within
 *  a declared window, is NOT modelled here. CAND-04's own counterexample analysis names it as
 *  the shape most likely to be implemented wrongly in the fail-closed direction, and this
 *  module has no vocabulary for it. `resolveAttestorRole` returning `unknown` is what keeps
 *  that case reachable for a later surface rather than silently answered here. */
export const ACTIVATION_ASSERTIONS = [
  'condition_occurred',
  'condition_not_occurred_through',
] as const

export type ActivationAssertion = (typeof ACTIVATION_ASSERTIONS)[number]

/** Members every activation condition carries. */
export interface ActivationConditionCommonV0 {
  readonly record_type: typeof ACTIVATION_CONDITION_TYPE
  /** Opaque. This module never derives, parses or interprets a condition identifier. */
  readonly condition_id: string
  /** The grant this condition gates. A REFERENCE, never a facet: draft-03 section 3.2 closes
   *  `authority` at seven facets, so a condition cannot ride inside a signed
   *  `AuthorityDelegationV1` at all. */
  readonly delegation_id: string
}

/** A condition that waits on a date. The verifier reads the date and compares it with the
 *  action instant, so an unreached date is always a known negative and never an unknown one.
 *  No attestation is involved and none is consulted. */
export interface DateActivationConditionV0 extends ActivationConditionCommonV0 {
  readonly condition_type: 'date'
  /** RFC 3339, offset required. */
  readonly activation_date: string
}

/** A condition that waits on a recorded event, attested by a party holding a declared role. */
export interface RecordedEventActivationConditionV0 extends ActivationConditionCommonV0 {
  readonly condition_type: 'recorded_event'
  /** Opaque to this module. Compared for equality against an attestation's own member. */
  readonly event_type: string
  /** Opaque to this module. Compared for equality against an attestation's own member. */
  readonly event_id: string
  /** ROLE identifiers, never principals. Who holds a role is the resolver's answer, not the
   *  condition's and never the attestation's. At least one member is required: a condition
   *  that names no accepted source has not stated what it accepts, and this module refuses it
   *  rather than accepting anything. A record from a party holding ANY member is acceptable,
   *  which is a union and not a conjunction; a model needing every named role to attest needs
   *  a rule this module does not express. */
  readonly required_attestor_roles: readonly string[]
  /** How many acceptable attestations establish a finding. At least 1, and there is NO
   *  DEFAULT for what it should be: how many determinations a model requires is a model
   *  decision. The same threshold applies in both directions, so a model wanting one record
   *  to establish an occurrence and two to establish a non-occurrence is not expressible
   *  here. That asymmetry is an open question, not a settled no. */
  readonly threshold: number
  readonly instant_basis: ActivationInstantBasis
}

export type ActivationConditionV0 = DateActivationConditionV0 | RecordedEventActivationConditionV0

/** An activation attestation, as presented.
 *
 *  `record_type` is typed as `string` rather than as this module's own constant because a
 *  model can accept condition evidence in a shape this module does not own. What it accepts
 *  is a model declaration, supplied through
 *  `ActivationVerificationInput.acceptedAttestationRecordTypes`.
 *
 *  `attestor_role` is the attestor's CLAIM ABOUT ITSELF and is never authority for anything.
 *  It is checked against the resolver, and a claim the resolver contradicts is its own
 *  rejection reason rather than being folded into a plain role mismatch, because the two are
 *  different findings: one party is in the wrong place, the other says it is somewhere it is
 *  not. An attestation that makes no role claim is not rejected for that; the required-role
 *  check still runs.
 *
 *  The index signature is deliberate. Extra members ride along, are inside the signed
 *  preimage, and are never interpreted here. */
export interface ActivationAttestationV0 {
  readonly record_type: string
  readonly assertion: string
  readonly attestor: string
  readonly attestor_role?: string
  readonly condition_id: string
  readonly event_type?: string
  readonly event_id?: string
  /** RFC 3339. Present on `condition_occurred`. */
  readonly occurred_at?: string
  /** RFC 3339. Present on `condition_not_occurred_through`. */
  readonly not_occurred_through?: string
  /** RFC 3339. When the record itself was written. Used to select the signing key version
   *  authorized at that instant, per draft-03 section 2.4, and used as the occurrence instant
   *  only under `instant_basis: 'attestation_written'`. */
  readonly attested_at: string
  readonly verification_method: string
  readonly attestation_id: string
  readonly signature: string
  readonly [key: string]: unknown
}

/** What a resolver can say about whether an attestor holds a role at an instant.
 *
 *  THREE VALUES, NOT A BOOLEAN. "This registry does not know" is a distinct answer from "this
 *  party does not hold that role", and collapsing the first into the second turns ignorance
 *  into a denial. That collapse is the failure BROAD-L7 exists to name, and it is the reason
 *  an absence-triggered condition needs `unknown` to stay reachable. */
export const ATTESTOR_ROLE_STANDINGS = ['holds', 'does_not_hold', 'unknown'] as const

export type AttestorRoleStanding = (typeof ATTESTOR_ROLE_STANDINGS)[number]

/** Resolves whether `attestor` held `role` at `atInstant`.
 *
 *  Role standing is resolved OUTSIDE the record, always. This module never reads standing
 *  from the artifact asserting it, which is the single control that separates a real
 *  attestor-role check from a self-declared one. `atInstant` is passed so a registry with its
 *  own history can answer for the right moment; a resolver that ignores it is answering for
 *  "now", which is a choice the resolver makes and not one this module makes for it.
 *
 *  Where role standing comes from, who publishes it and what a verifier consults are not
 *  settled by any published or proposed text. That is why this is a callback and not a
 *  registry type. */
export type AttestorRoleResolver = (
  attestor: string,
  role: string,
  atInstant: string,
) => AttestorRoleStanding

/** What one accepted attestation establishes about the condition at the action instant.
 *
 *  - `occurred_by_action`          the condition's instant is at or before the action instant.
 *  - `occurred_after_action`       the condition's instant is after it. The SAME record
 *                                  establishes the condition for any later action, which is
 *                                  what makes this a wait rather than a failure.
 *  - `not_occurred_through_action` an accepted record states the condition had not occurred
 *                                  through an instant that reaches the action instant. */
export const ACTIVATION_FINDINGS = [
  'occurred_by_action',
  'occurred_after_action',
  'not_occurred_through_action',
] as const

export type ActivationFindingKind = (typeof ACTIVATION_FINDINGS)[number]

/** One accepted attestation and what it established. */
export interface ActivationFinding {
  readonly attestation_id: string
  readonly attestor: string
  readonly finding: ActivationFindingKind
}

/** One rejected attestation and why. A rejected attestation is NOT evidence in either
 *  direction: it cannot establish the condition and it equally cannot establish that the
 *  condition was unmet. That is the whole of the difference between `not_established` and
 *  `not_yet_effective` for a record from a source the model does not accept. */
export interface ActivationRejection {
  readonly attestation_id: string
  readonly attestor: string
  readonly reason_code: ActivationReasonCode
}

/** Every reason code this module emits, verdict-level and rejection-level.
 *
 *  Module-local and SCREAMING_SNAKE_CASE, per the lifecycle-state vocabulary's rule that two
 *  findings sharing a verdict name must be told apart by their codes. Not minted APS
 *  vocabulary. */
export const ACTIVATION_REASON_CODES = [
  // ── verdict-level ──
  /** valid: an accepted record establishes the condition at or before the action instant, or
   *  a date condition's date has been reached. */
  'ACTIVATION_ESTABLISHED',
  /** not_yet_effective: a date condition's activation date is after the action instant. */
  'CONDITION_DATE_NOT_REACHED',
  /** not_yet_effective: an accepted record states the condition had not occurred through an
   *  instant reaching the action instant. */
  'CONDITION_ESTABLISHED_NOT_YET_OCCURRED',
  /** not_yet_effective: an accepted record puts the condition's first occurrence after the
   *  action instant. No retroactive activation: the same record establishes the condition for
   *  a later action, and never for this one. */
  'CONDITION_FIRST_OCCURRED_AFTER_ACTION',
  /** not_established, source: two accepted records disagree about the action instant. Neither
   *  defeats the other and this module has no precedence rule. */
  'CONDITION_EVIDENCE_CONFLICT',
  /** not_established, source: accepted records exist but fewer than `threshold` of them
   *  support the finding. */
  'ACTIVATION_THRESHOLD_NOT_MET',
  /** not_established, source: nothing was presented. */
  'NO_ATTESTATION_PRESENTED',
  /** not_established, coverage: the condition presented gates a different delegation. The
   *  claim does not state that it covers what the verdict needed. */
  'CONDITION_DELEGATION_MISMATCH',
  // ── rejection-level, in check order ──
  /** source: the record's type is not one the model declared it accepts for this condition. */
  'ATTESTATION_RECORD_TYPE_NOT_ACCEPTED',
  /** source: no key resolved for the record's verification method at its own `attested_at`,
   *  or the signature does not verify over the record's canonical bytes. */
  'ATTESTATION_SIGNATURE_UNVERIFIED',
  /** source: the verification method does not belong to the attestor the body names, so a
   *  valid signature says nothing about who attested. */
  'ATTESTATION_ATTESTOR_BINDING_MISMATCH',
  /** source: the resolver does not know whether the attestor holds the role. Ignorance, and
   *  deliberately not folded into a mismatch. */
  'ATTESTATION_ATTESTOR_ROLE_UNKNOWN',
  /** source: the record claims a role the resolver says the attestor does not hold. */
  'ATTESTATION_ROLE_CLAIM_CONFLICT',
  /** source: the attestor holds no role the condition requires. */
  'ATTESTATION_ATTESTOR_ROLE_MISMATCH',
  /** source: the record's condition, event type or event id is not the condition's. */
  'ATTESTATION_CONDITION_MISMATCH',
  /** source: the assertion is not one of the two this module defines, or the member that
   *  assertion needs is absent. */
  'ATTESTATION_UNKNOWN_ASSERTION',
  /** source: an instant on the record is not an RFC 3339 instant this module will compare. */
  'ATTESTATION_INSTANT_MALFORMED',
  /** coverage: a `condition_not_occurred_through` record stops before the action instant, so
   *  it says nothing about the interval between where it stops and the action. */
  'ATTESTATION_DOES_NOT_REACH_ACTION',
] as const

export type ActivationReasonCode = (typeof ACTIVATION_REASON_CODES)[number]

/** Which establishment limb is missing when a reason code produces `not_established`.
 *
 *  `freshness` never appears. A freshness bound is model declared, this module is given none,
 *  and the surface that owns multi-source status observation owns freshness. A mapping that
 *  invented a freshness finding would be claiming something the verifier never measured. */
export const ACTIVATION_GAPS_BY_REASON: Readonly<
  Partial<Record<ActivationReasonCode, readonly EstablishmentGap[]>>
> = Object.freeze({
  CONDITION_DELEGATION_MISMATCH: Object.freeze(['coverage'] as const),
  ATTESTATION_DOES_NOT_REACH_ACTION: Object.freeze(['coverage'] as const),
})

/** What `verifyActivation` concludes.
 *
 *  `state` is a `LifecycleStateResult` in the lifecycle-state vocabulary, so activation shares
 *  one verdict set with every other proposed lifecycle surface instead of spelling a seventh
 *  local copy of the same missing values. Only three of the six verdicts are reachable here:
 *  `valid`, `not_yet_effective` and `not_established`. `invalid` is NEVER one of them. An
 *  unmet activation condition does not make a grant invalid, and whether the grant is valid at
 *  all is chain verification's answer, not this module's.
 *
 *  `findings` and `rejections` are the working, one entry per presented attestation across the
 *  two, so a caller can report which record did what rather than only the verdict. */
export interface ActivationResult {
  readonly state: LifecycleStateResult
  readonly condition_id: string
  readonly condition_type: ActivationConditionKind
  readonly findings: readonly ActivationFinding[]
  readonly rejections: readonly ActivationRejection[]
}

/** Thrown when a condition or a call is malformed. A shape rule broken at the call site is a
 *  programming error, not a verdict, which is the same split `lifecycleState` makes. Evidence
 *  problems are never thrown: they are verdicts. */
export class ActivationError extends Error {
  readonly code: string

  constructor(code: string, message: string) {
    super(message)
    this.name = 'ActivationError'
    this.code = code
  }
}
