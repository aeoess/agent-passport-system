// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. Authority state markers, write fencing, and withdrawal of a recorded
// revocation.
//
// NOT REQUIRED BY draft-pidlisnyi-aps-03. The published text contains no occurrence of
// `epoch`, `fencing`, `snapshot`, `replica` or `restore`, and defines no record for
// withdrawing a revocation. What it does fix, and what this module is careful not to
// disturb, is section 3.3: "Verification returns one of valid, invalid, indeterminate, or
// unsupported with a stable failure code", and section 3.5: "Revocation is irreversible."
// `AuthorityValidationState`, `AuthorityValidationResult`, `AuthorityRevocationStore` and
// everything `verifyAuthorityDelegationChain` returns are unchanged, and a caller that does
// not import this module sees exactly today's behaviour.
//
// Concept source: the aeoess/agent-authority-lifecycle concept document
// (AUTHORITY-LIFECYCLE.md, the `Authority epoch` concept and invariants L3, L7 and L11;
// OPEN-QUESTIONS.md, `Authority rollback`) and its invariant candidates CAND-08 (no silent
// restoration from rollback or stale state) and CAND-02 (later evidence does not rewrite
// earlier evidence). Every one of those is proposed, not specified. Nothing here claims
// otherwise, and `OPEN-QUESTIONS.md` keeps open both the mechanism and what a verifier
// should return after a restore.
//
// Three deliberate non-decisions are encoded as types rather than as behaviour:
//
//  1. The proposed text says an authority epoch is "where a system uses generations" and
//     stops. It does not say who advances one, whether it is global or per delegation,
//     whether it is signed, or what evidence carries it. `StateMarker` is therefore an
//     opaque comparable supplied by the caller, and this module defines only the comparison.
//  2. A verifier with no prior observation has nothing to compare against. That is
//     `unplaceable`, and it is not a verdict. The caller says what to do with it.
//  3. Who may withdraw a revocation is not stated anywhere. Standing is resolved through an
//     injected callback and never read from the record asserting it.

import type { AuthorityRevocationV1 } from '../authority-revocation/types.js'

/** What a marker is counted within. Comparing two markers from different scopes orders
 *  nothing, so the comparison reports `unplaceable` rather than inventing an order.
 *
 *  The proposed text names none of these. They exist because the fixture that forced this
 *  module had to pick one (it picked a global integer on a state view) and recorded that
 *  the choice was not read from the text. Carrying the scope makes that choice visible in
 *  the record instead of implicit in the deployment. Proposed. */
export const STATE_MARKER_SCOPES = ['global', 'per_delegation', 'per_principal', 'per_store'] as const

export type StateMarkerScope = (typeof STATE_MARKER_SCOPES)[number]

/** A monotonic generation marker on authority state.
 *
 *  `value` is a canonical unsigned decimal integer, the same convention the seven-facet
 *  authority vector already uses for spend quantities: no sign, no leading zero, no
 *  separators, arbitrary width. It is a string rather than a number so a marker past
 *  2^53 - 1 stays exact, and it is compared as an integer, never lexically.
 *
 *  Nothing here is signed and nothing here is a wire field. No delegation, revocation or
 *  store in this SDK carries a marker, and none is being given one: a marker is state the
 *  caller has about a state source, handed in at comparison time. Proposed. */
export interface StateMarker {
  readonly value: string
  readonly scope: StateMarkerScope
  /** Which delegation, principal or store this marker is counted within. Required on every
   *  scope except `global`, where it is absent. */
  readonly scope_ref?: string
}

/** The result of placing a presented marker against what a verifier has established.
 *
 *  - `forward`      the presented marker advanced, or held equal. Read the view normally.
 *  - `regressed`    the presented marker went backwards against an established high-water
 *                   mark. CAND-08's refusal case.
 *  - `unplaceable`  there is nothing to compare against, or the two markers are counted in
 *                   different scopes. **Deliberately not a verdict.** A high-water mark has
 *                   to start somewhere and neither the proposed text nor draft-03 says
 *                   whether a first read is trusted or refused. Both are defensible and the
 *                   outcomes differ, so this module reports the fact and the caller
 *                   decides. See `UnplaceableDisposition`. */
export const MONOTONICITY_OUTCOMES = ['forward', 'regressed', 'unplaceable'] as const

export type MonotonicityOutcome = (typeof MONOTONICITY_OUTCOMES)[number]

/** What a caller wants done with an `unplaceable` presented view. Required, with no
 *  default, because the SDK picking one would be the SDK deciding a question its own
 *  concept source records as undecided. */
export const UNPLACEABLE_DISPOSITIONS = ['read_presented', 'refuse'] as const

export type UnplaceableDisposition = (typeof UNPLACEABLE_DISPOSITIONS)[number]

/** What a verifier has established about authority state, as TWO separate inputs.
 *
 *  Splitting them is the whole point of this type. Two verifiers can hold the same
 *  high-water mark and give different answers about the same restored view: the one that
 *  retained the revocation records it observed can establish a revocation from records and
 *  answers `revoked`, and the one that retained only the number cannot, and answers
 *  `unknown`, which draft-03 section 3.3 makes indeterminate. The proposed text does not
 *  distinguish those two verifiers at all, and the distinction turns out to be the
 *  substance of the rollback question. An API taking "the epoch" as one value cannot
 *  express it.
 *
 *  `records` is not a store and does not behave like one. It can answer `revoked` and it
 *  can answer `unknown`. It can never answer `active`: a retained record set says nothing
 *  about the delegations it does not mention, which is the same reason absence from an
 *  `AuthorityRevocationStore` is `unknown` rather than `active`. */
export interface RetainedAuthorityState {
  /** Revocation records the verifier retained at its high-water mark. Each is re-verified
   *  against the delegation in front of it before it can produce a `revoked` answer, so a
   *  record that reached this array by some other route still cannot assert one. */
  readonly records: readonly AuthorityRevocationV1[]
  /** The newest marker this verifier has established, or `null` if it has established
   *  none. */
  readonly highWaterMark: StateMarker | null
}

/** Why a fenced write was refused.
 *
 *  - `stale_fencing_token`     the token went backwards against the highest already seen.
 *                              The only one of the three the source states.
 *  - `fencing_scope_mismatch`  the token is counted in a different scope from the log's, so
 *                              it cannot be ordered against what the log holds.
 *  - `fencing_token_unreadable` the token is absent or not a well-formed `StateMarker`.
 *
 *  A write path that cannot order a token is not fenced, so the second and third refuse
 *  rather than guess. Neither is in any source; both are this module's choice. */
export const FENCED_WRITE_REFUSAL_CODES = [
  'stale_fencing_token',
  'fencing_scope_mismatch',
  'fencing_token_unreadable',
] as const

export type FencedWriteRefusalCode = (typeof FENCED_WRITE_REFUSAL_CODES)[number]

/** An authority-state write carrying the token of whoever claims to be the current
 *  publisher. */
export interface FencedWrite<T> {
  readonly token: StateMarker
  readonly payload: T
}

/** What a fenced log reports about one write.
 *
 *  An EQUAL token is accepted, and that is not an oversight. The rule the source states is
 *  about tokens going backwards, and an equal token has not gone backwards: it is the same
 *  holder retrying, which makes a retry idempotent. */
export type FencedWriteOutcome<T> =
  | { readonly accepted: true; readonly published: StateMarker; readonly payload: T }
  | { readonly accepted: false; readonly code: FencedWriteRefusalCode; readonly published: StateMarker | null }

/** The record type a withdrawal carries.
 *
 *  `proposed:` is load-bearing. Record fields, failure-class names and verifier semantics
 *  are conformance vocabulary reserved to the maintainer, and neither draft-03 nor the
 *  proposed text defines a record for withdrawing a recorded revocation or says what a
 *  verifier should do with one. This is a placeholder to argue about, not APS vocabulary. */
export const REVOCATION_WITHDRAWAL_RECORD_TYPE = 'proposed:aps:revocation-withdrawal:v0' as const
export const REVOCATION_WITHDRAWAL_VERSION = '0' as const

/** A record stating that a recorded revocation was published in error.
 *
 *  It REFERENCES the revocation and never removes it. Inside an `AuthorityRevocationStore`
 *  irreversibility is already structural: the store exposes `track`, `tracks`, `get` and
 *  `insertVerifiedRevocation`, there is no removal method, and this module does not add
 *  one. Draft-03 section 3.5 states "Revocation is irreversible", and a removal method
 *  would be one call away from breaking it.
 *
 *  NOT AUTHENTICATED BY THIS MODULE. There is no canonical preimage here, no signature
 *  field, and no verification function, deliberately: minting the signed form of a record
 *  type is the vocabulary decision this module is not entitled to make. A caller hands in a
 *  withdrawal it has already authenticated, exactly as `insertVerifiedRevocation` takes a
 *  revocation `recordAuthorityRevocation` has already verified. Whoever reaches
 *  `evaluateRevocationWithdrawal` is the party asserting the record is genuine. */
export interface RevocationWithdrawalV0 {
  readonly record_type: typeof REVOCATION_WITHDRAWAL_RECORD_TYPE
  readonly version: typeof REVOCATION_WITHDRAWAL_VERSION
  /** The revocation this record withdraws: `sha256:<64 lowercase hex>`. */
  readonly revocation_id: string
  /** The delegation that revocation named. Carried so a withdrawal that names a revocation
   *  of a different delegation is refusable without a second lookup. */
  readonly delegation_id: string
  /** Who states the withdrawal. Whether this party may is NOT decided here. */
  readonly withdrawn_by: string
  /** Canonical UTC-millisecond time, supplied by the caller, never read from a clock. */
  readonly withdrawn_at: string
  /** Machine-readable ground. No grammar is fixed for one and none is invented here. */
  readonly reason_code: string
  /** OPTIONAL free-text detail. Absent means the key is not present at all. */
  readonly detail?: string
}

/** What an injected standing resolver may answer.
 *
 *  `unknown` is a first-class answer and is not `no_standing`. A verifier that cannot
 *  establish whether the withdrawer had standing has not established that they lacked it,
 *  and the refusal reason says which of the two happened. */
export const WITHDRAWAL_STANDINGS = ['has_standing', 'no_standing', 'unknown'] as const

export type WithdrawalStanding = (typeof WITHDRAWAL_STANDINGS)[number]

/** Decides whether a withdrawal's author may withdraw this revocation.
 *
 *  Injected, never hardcoded, and never read from the withdrawal record itself. Draft-03
 *  section 3.5 states "Any delegation MAY be revoked by its issuer" and the SDK enforces
 *  `revoker === issuer` for a revocation. Nothing anywhere states who may WITHDRAW one.
 *  `withdrawalSignerIsRevoker` is supplied as one resolver, is what the forcing fixture
 *  chose, and is a choice rather than a rule read from any text. */
export type WithdrawalStandingResolver = (
  withdrawal: RevocationWithdrawalV0,
  revocation: AuthorityRevocationV1,
) => WithdrawalStanding

/** Why a withdrawal was accepted or refused. Stable, module-local codes. */
export const WITHDRAWAL_OUTCOME_CODES = [
  /** Accepted as a record. Accepted never means the revocation is gone. */
  'WITHDRAWAL_ACCEPTED',
  /** The record is not a well-formed `RevocationWithdrawalV0`. */
  'WITHDRAWAL_SCHEMA_INVALID',
  /** No revocation in the held set carries the `revocation_id` this record names. */
  'WITHDRAWAL_NAMES_NO_HELD_REVOCATION',
  /** The named revocation exists but is a revocation of a different delegation. */
  'WITHDRAWAL_TARGET_MISMATCH',
  /** The resolver established that this party may not withdraw this revocation. */
  'WITHDRAWAL_SIGNER_WITHOUT_STANDING',
  /** The resolver could not establish standing either way. Not the same finding as the
   *  one above, and reported as `not_established` rather than as a denial. */
  'WITHDRAWAL_STANDING_NOT_ESTABLISHED',
] as const

export type WithdrawalOutcomeCode = (typeof WITHDRAWAL_OUTCOME_CODES)[number]

/** What `evaluateRevocationWithdrawal` concludes about one withdrawal record. */
export interface WithdrawalEvaluation {
  readonly accepted: boolean
  readonly reason_code: WithdrawalOutcomeCode
  /** What the resolver answered, or `null` when evaluation refused before asking it. */
  readonly standing: WithdrawalStanding | null
  /** The record evaluated, unchanged. */
  readonly withdrawal: RevocationWithdrawalV0
}

/** The current position of one revocation together with every withdrawal referencing it.
 *
 *  This is CAND-02 made into a shape. The revocation is present, unchanged, whether or not
 *  a withdrawal was accepted. A later finding is a new record that references the earlier
 *  one and states its own effect; it is never an edit of the earlier one and never its
 *  removal. A verifier that must report "revoked, and the revoker later said this was
 *  recorded in error" reports exactly this. */
export interface CorrectedRevocationView {
  /** The revocation record, byte for byte what it was. */
  readonly revocation: AuthorityRevocationV1
  /** Accepted withdrawals, in the order supplied. Non-empty does NOT make the revocation
   *  ineffective and does NOT change any chain verdict. */
  readonly accepted: readonly WithdrawalEvaluation[]
  /** Refused withdrawals, each with the code saying why. A withdrawal that changes nothing
   *  in silence is indistinguishable from one that was never submitted. */
  readonly refused: readonly WithdrawalEvaluation[]
}
