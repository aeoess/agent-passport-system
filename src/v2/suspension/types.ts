// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. Suspension and restriction as a SET OF CAUSES.
//
// NOT REQUIRED BY draft-pidlisnyi-aps-03. The published draft states no suspension rule,
// no restriction rule, no release rule and no lifecycle-standing rule: a case-insensitive
// search of the published plain text returns zero occurrences of `suspend` and
// `suspension`, and the only status answer the protocol has is the revocation resolver's
// closed set `'active' | 'revoked' | 'unknown'`. There is nowhere in that type to put one
// cause, let alone three. Section 3.2 closes the authority vector at seven facets and
// says a missing facet is invalid, so no cause can ride inside a signed
// `AuthorityDelegationV1` either. Section 3.3 closes chain verification at four values.
//
// Nothing in this module touches any of that. `AuthorityValidationState`,
// `AuthorityValidationResult`, `RevocationResolution` and everything
// `verifyAuthorityDelegationChain` returns are byte for byte what they were. A caller who
// never imports this module sees exactly today's behaviour.
//
// CONCEPT SOURCE: the aeoess/agent-authority-lifecycle concept document.
//   - invariant L8, "Suspension is not revocation": suspension stops the use of authority
//     and can be lifted, revocation is terminal for the artifact it names, and a
//     restricted state is different again and does not have to pause descendants. L8 is
//     marked proposed there and says nothing about ARITY, so an implementation holding
//     exactly one suspension at a time conforms to every word of it and is still wrong.
//   - invariant candidate CAND-05, "Suspension and restriction causes compose": an
//     authority artifact can be subject to more than one concurrent cause, a verifier
//     must represent them as a SET rather than as a single state, releasing one cause
//     does not release another, a release is effective against a cause only from a source
//     with lifecycle standing over THAT cause (which is not necessarily the source that
//     imposed it), and where any cause remains unreleased the verdict remains suspended
//     or restricted and records which causes remain.
//   - `OPEN-QUESTIONS.md`, "Release from suspension", which says in terms that lifting one
//     suspension should not clear another or bypass a revocation that happened while the
//     agent was suspended, that causes probably need to compose with each released
//     separately, and that none of it is specified yet.
//
// CAND-05 states plainly that composition is FORCED BY THE CORPUS AND EXTERNALLY
// UNSOURCED. This module inherits that: it is one reading of a paragraph that says
// "probably" and "not yet specified", and every identifier here is a placeholder to argue
// about rather than minted vocabulary.

import type { OutstandingCause } from '../lifecycle-state/types.js'

/** Record type of a lifecycle cause. The `proposed:` namespace is deliberate: this is not
 *  an APS record type, nothing published defines it, and it stays namespaced until the
 *  schema owner rules on it. */
export const SUSPENSION_CAUSE_TYPE = 'proposed:aps:suspension-cause:v0' as const

/** Record type of a cause release. Also not an APS record type. */
export const SUSPENSION_RELEASE_TYPE = 'proposed:aps:cause-release:v0' as const

/** The two pause kinds L8 separates.
 *
 *  `suspension` pauses the use of authority and of everything that depends on it.
 *  `restriction` is an external block that can stop some effects while the grant itself
 *  stays valid, and it does not have to pause descendants. This module does not model
 *  descendant propagation for either kind: what it decides is the state of the ONE
 *  artifact its causes name.
 *
 *  Concept source: aeoess/agent-authority-lifecycle, invariant L8. Proposed. */
export const PAUSE_KINDS = ['suspension', 'restriction'] as const

export type PauseKind = (typeof PAUSE_KINDS)[number]

/** What a standing resolver may answer about one release against one cause.
 *
 *  Three values, not two, because "I do not know whether this party holds standing over
 *  this cause" is not the same finding as "this party does not hold standing over it".
 *  CAND-05's standing clause is what blocks an internal process clearing an externally
 *  imposed restriction, and its non-authorship clause blocks the opposite error of
 *  refusing a superior source's release. Neither clause says what to do when the answer
 *  is absent, so this module reports absence as absence: see
 *  `SUSPENSION_REASON_CODES.RELEASE_STANDING_NOT_ESTABLISHED`.
 *
 *  Proposed. */
export const RELEASE_STANDINGS = ['has_standing', 'no_standing', 'unknown'] as const

export type ReleaseStanding = (typeof RELEASE_STANDINGS)[number]

/** One lifecycle cause standing against one authority artifact.
 *
 *  A cause is a SEPARATE SIGNED ARTIFACT that references `delegation_id`. It is not a
 *  facet, not a flag on the delegation and not a field anything existing carries, because
 *  draft-03 section 3.2 closes the authority vector at seven facets and calls a missing
 *  facet invalid. Adding an eighth would break every existing record.
 *
 *  Proposed. Concept source: aeoess/agent-authority-lifecycle, CAND-05 and invariant L8. */
export interface SuspensionCause {
  /** Expected to be `SUSPENSION_CAUSE_TYPE`. A record carrying anything else is not in
   *  evidence: see `CAUSE_RECORD_TYPE_UNRECOGNISED`. */
  readonly record_type: string
  /** Identifies this cause. Unique within one evaluation's cause set. */
  readonly cause_id: string
  /** The authority artifact this cause stands against. */
  readonly delegation_id: string
  readonly kind: PauseKind
  /** The party that imposed this cause. Used to bind the signature to a named imposer,
   *  and available to a standing resolver that wants to implement "only the imposer may
   *  release", which CAND-05 explicitly says is the WRONG reading. */
  readonly imposed_by: string
  /** When the cause was imposed. A cause is not in evidence at an instant before this. */
  readonly issued_at: string
  /** Stable, module-local code naming why the cause was imposed. Carried through to the
   *  outstanding set so a verdict says which causes remain AND what each one is. */
  readonly reason_code: string
  /** The key identifier the signature verifies under. Must be prefixed by `imposed_by`
   *  and `#`, or a valid signature would say nothing about who imposed the cause. */
  readonly verification_method: string
  /** Ed25519 over the RFC 8785 canonical bytes of this record with `signature` and
   *  `record_id` removed. See `suspensionRecordPreimage`. */
  readonly signature: string
  /** ADVISORY ONLY. NEVER CONSULTED BY THIS MODULE.
   *
   *  A cause may name who it believes may release it. `evaluatePauseState` does not read
   *  this member and does not let it decide anything, because cross-cutting constraint 7
   *  of the SDK gap memo is absolute: standing is resolved outside the record, always, and
   *  a verifier never reads standing from the artifact asserting it. A cause that could
   *  nominate its own releaser would let the imposer of a cause decide who may lift it,
   *  which is precisely the superior-authority case CAND-05 says an implementer gets
   *  wrong by reading "standing over that cause" as "the source that imposed it".
   *
   *  It is carried so that a caller's `resolveReleaseStanding` can read it off the cause
   *  it is handed, if that caller's authority model gives it weight. The decision is the
   *  caller's and this module never makes it. `tests/v2/suspension.test.ts` contains a
   *  negative control that sets this member to the releasing party and asserts the release
   *  is still ineffective when the resolver answers `no_standing`. */
  readonly release_authority?: string
  readonly [key: string]: unknown
}

/** A record releasing one or more named causes.
 *
 *  One release MAY clear several causes: CAND-05 says in terms that it does not claim a
 *  single release record cannot clear several, and that one record from a party with
 *  standing over each of them can release all of them. What is forbidden is releasing
 *  cause A having the SIDE EFFECT of clearing cause B. So the record names every cause it
 *  claims to clear and the evaluator clears exactly those the releaser holds standing
 *  over, deciding each one independently. A release record is not a list of assertions a
 *  verifier accepts wholesale.
 *
 *  Proposed. */
export interface SuspensionRelease {
  /** Expected to be `SUSPENSION_RELEASE_TYPE`. */
  readonly record_type: string
  readonly release_id: string
  /** The authority artifact whose causes this record claims to release. */
  readonly delegation_id: string
  /** Every cause this record claims to clear, by `cause_id`. Decided per cause. */
  readonly cause_ids: readonly string[]
  /** The party releasing. Standing is resolved for this party, per cause, by the caller's
   *  resolver. */
  readonly issuer: string
  /** When the release was recorded. A release is not in evidence at an earlier instant. */
  readonly issued_at: string
  /** Must be prefixed by `issuer` and `#`. */
  readonly verification_method: string
  /** Ed25519 over the same preimage rule as a cause. */
  readonly signature: string
  readonly [key: string]: unknown
}

/** Every stable code this module emits, on a verdict or on a disposition.
 *
 *  Module-local and SCREAMING_SNAKE_CASE, per the lifecycle-state vocabulary's rule that
 *  two findings sharing a verdict name must be told apart by their codes. These are a
 *  proposal: the conformance suite's CONTRIBUTING.md reserves failure-class names and
 *  verifier semantics to the schema owner, and a module is not the vehicle for minting
 *  them. */
export const SUSPENSION_REASON_CODES = [
  // --- verdict codes -------------------------------------------------------------
  /** `valid`: the input carried no cause at all. Says nothing about the chain. */
  'NO_CAUSE_PRESENTED',
  /** `valid`: causes were presented and none of them is in evidence at this instant.
   *  Distinct from the above so a caller can see that records were offered and rejected
   *  rather than never supplied. */
  'NO_CAUSE_IN_EVIDENCE',
  /** `valid`: every cause in evidence was released by a party holding standing over it. */
  'ALL_CAUSES_RELEASED',
  /** `suspended` or `restricted`: at least one cause in evidence remains unreleased. The
   *  result's `outstanding` member names every one of them. */
  'CAUSES_OUTSTANDING',
  /** `not_established`, missing `source`: a standing resolver answered `unknown` for a
   *  cause that nothing else released, so whether that cause still holds is not something
   *  this verifier established either way. */
  'RELEASE_STANDING_NOT_ESTABLISHED',

  // --- cause dispositions --------------------------------------------------------
  /** The cause is in evidence at this instant and holds unless released. */
  'CAUSE_IN_EVIDENCE',
  /** The cause names a different `delegation_id`. It is not this artifact's cause. */
  'CAUSE_NOT_ON_DELEGATION',
  /** The cause record carries an unrecognised `record_type`. */
  'CAUSE_RECORD_TYPE_UNRECOGNISED',
  /** `issued_at` is after the instant being evaluated, so the cause is not in evidence
   *  there. The same record is in evidence at a later instant. */
  'CAUSE_NOT_YET_IN_EVIDENCE',
  /** The signature does not verify under the key `verification_method` points at. An
   *  unverified claim does not become a lifecycle state, so this cause holds nothing. */
  'CAUSE_SIGNATURE_UNVERIFIED',
  /** `verification_method` does not belong to the `imposed_by` the body names. */
  'CAUSE_IMPOSER_BINDING_MISMATCH',
  /** The cause was released by a party the resolver placed over it. */
  'CAUSE_RELEASED',

  // --- release record dispositions -----------------------------------------------
  /** The record passed every record-level check and was applied per named cause. */
  'RELEASE_IN_EVIDENCE',
  /** The record names a different `delegation_id`. */
  'RELEASE_NOT_ON_DELEGATION',
  /** Unrecognised `record_type`. */
  'RELEASE_RECORD_TYPE_UNRECOGNISED',
  /** The signature does not verify. The record releases nothing. */
  'RELEASE_SIGNATURE_UNVERIFIED',
  /** `verification_method` does not belong to the `issuer` the body names. */
  'RELEASE_ISSUER_BINDING_MISMATCH',
  /** `issued_at` is after the instant being evaluated, so the record is not in evidence
   *  there and releases nothing at that instant. The same record at a later instant does. */
  'RELEASE_AFTER_EVALUATION_INSTANT',

  // --- per-cause dispositions inside a release ------------------------------------
  /** The named cause id is not one this evaluation holds in evidence. */
  'CAUSE_NOT_PRESENTED',
  /** The release predates the cause it names. A later cause is not cleared by an earlier
   *  record. */
  'RELEASE_PRECEDES_IMPOSITION',
  /** The resolver answered `no_standing`: a genuine, correctly signed record from a real
   *  party that this authority model does not place over this cause. */
  'RELEASER_WITHOUT_STANDING',
] as const

export type SuspensionReasonCode = (typeof SUSPENSION_REASON_CODES)[number]

/** How one cause named inside one release record was decided. */
export interface ReleaseCauseDisposition {
  readonly cause_id: string
  readonly disposition: SuspensionReasonCode
}

/** How one release record was decided, and what it did to each cause it named.
 *
 *  `causes` is empty exactly when the record failed a record-level check, because a record
 *  rejected at record level is never applied to any cause. */
export interface ReleaseDisposition {
  readonly release_id: string
  readonly disposition: SuspensionReasonCode
  readonly causes: readonly ReleaseCauseDisposition[]
}

/** How one cause was decided. `released_by` names the release record that cleared it, and
 *  is present exactly when `disposition` is `CAUSE_RELEASED`. */
export interface CauseDisposition {
  readonly cause_id: string
  readonly disposition: SuspensionReasonCode
  readonly released_by?: string
}

/** Resolves standing for one release against one cause.
 *
 *  Handed both records so a caller's authority model can look at whatever it needs. What
 *  it must NOT be is the identity comparison `release.issuer === cause.imposed_by`:
 *  CAND-05 says explicitly that standing is not authorship, and cites a court's power over
 *  conditions it did not create. A resolver that implements authorship is a defensible
 *  reading of text that does not exist yet, which makes it a finding about the text rather
 *  than a defect, but it is not this module's reading and this module will not supply it. */
export type ReleaseStandingResolver = (
  release: SuspensionRelease,
  cause: SuspensionCause,
) => ReleaseStanding

/** Resolves the public key a record's `verification_method` names, as hex.
 *
 *  Same shape as the chain verifier's own key resolver: caller supplied, no I/O inside
 *  this module, `null` when the key cannot be resolved. A record whose key does not
 *  resolve fails its signature check and is not in evidence. */
export type SuspensionVerificationKeyResolver = (
  signer: string,
  verificationMethod: string,
) => string | null

/** Everything `evaluatePauseState` needs. No clock, no network, no ambient state: the
 *  instant is a parameter and both resolvers are caller supplied, per cross-cutting
 *  constraint 3. */
export interface PauseStateInput {
  /** The authority artifact under evaluation. Every cause and every release must name it. */
  readonly delegationId: string
  /** Every cause offered against this artifact. An empty array is a legitimate input and
   *  gives `valid` / `NO_CAUSE_PRESENTED`. */
  readonly causes: readonly SuspensionCause[]
  /** Every release offered. Order does not matter: a cause released by any one accepted
   *  record is released. */
  readonly releases: readonly SuspensionRelease[]
  /** The instant being evaluated, as an RFC 3339 string compared lexically, which is what
   *  the chain verifier already does with its `now`. */
  readonly atInstant: string
  readonly resolveReleaseStanding: ReleaseStandingResolver
  readonly resolveVerificationKey: SuspensionVerificationKeyResolver
}

/** The full audit trail behind a pause state, for a caller that has to show its work.
 *
 *  `state` is the same value `evaluatePauseState` returns. The two disposition lists are
 *  why: a verdict that names which causes remain is CAND-05's whole content, and a caller
 *  writing evidence needs to say why each record did or did not move the answer. */
export interface PauseStateExplanation {
  readonly state: import('../lifecycle-state/types.js').LifecycleStateResult
  /** One entry per input cause, in input order. */
  readonly causes: readonly CauseDisposition[]
  /** One entry per input release, in input order. */
  readonly releases: readonly ReleaseDisposition[]
  /** The outstanding set, byte for byte what `state.outstanding` carries, and an empty
   *  array where the state carries none. Exposed separately so a caller does not have to
   *  branch on the verdict to read it. */
  readonly outstanding: readonly OutstandingCause[]
}
