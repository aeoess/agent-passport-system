// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. Non-time bounds on a grant: purpose, use count and budget, and the
// state "this bound has been reached".
//
// NOT REQUIRED BY draft-pidlisnyi-aps-03. Two sentences of that document constrain
// everything here. Section 3.2, verbatim:
//
//   "authority contains exactly seven required facets: scope, spend, depth, time,
//   reputation, values, and reversibility.  A missing facet is invalid rather than an
//   implicit unconstrained value."
//
// The facet set is closed, so a purpose bound or a use-count bound cannot be carried
// inside a signed `AuthorityDelegationV1` at all. This module therefore declares a
// SEPARATE artifact that references a delegation by its content address, and never
// touches the delegation schema. Section 3.3, verbatim:
//
//   "Verification returns one of valid, invalid, indeterminate, or unsupported with a
//   stable failure code."
//
// That enumeration is closed too. Nothing here changes it. `AuthorityValidationState`,
// `AuthorityValidationResult` and everything `verifyAuthorityDelegationChain` returns are
// byte for byte what they were, and a caller that never imports this module sees exactly
// today's behaviour. What a bound evaluation concludes is reported ALONGSIDE the chain
// result, in the separately named vocabulary `../lifecycle-state/` owns.
//
// A search of draft-03 finds zero occurrences of "exhaust" and zero of "use_count". It
// does use "single-use", of an APPROVAL in section 4.3 ("a first-class consumable
// artifact, bound to the action_ref it approves, single-use, and carrying a bounded
// lifetime"), never of a grant. So the word for the state in this module is minted here.
//
// Concept source: the aeoess/agent-authority-lifecycle concept document. Invariant L10
// (expiry is not revocation), whose "Expiry or exhaustion" concept entry names a use
// count, a budget and a purpose as bounds whose being reached ends authority; and
// invariant candidate CAND-01 (an external event is authority-changing only when
// established), which is why an unauthenticated fulfilment claim here yields
// `not_established` and never `exhausted`. Both are PROPOSED. Nothing published requires
// any of it.

import type { EstablishmentGap, LifecycleStateResult } from '../lifecycle-state/types.js'

/** Record type of the bound declaration. The `proposed:` prefix is load-bearing: this is
 *  not an `aps:` record type, because no published specification defines it. */
export const AUTHORITY_BOUND_TYPE = 'proposed:aps:authority-bound:v0' as const

/** Record type of a fulfilment attestation against a bound. */
export const AUTHORITY_BOUND_FULFILMENT_TYPE =
  'proposed:aps:authority-bound-fulfilment:v0' as const

/** Record type of the optional exhaustion record. See ./record.ts for what it does and
 *  does not attest. */
export const AUTHORITY_EXHAUSTION_TYPE = 'proposed:aps:authority-exhaustion:v0' as const

/** The three bound kinds the case corpus produces.
 *
 *  - `purpose`    the grant states a reason. It is reached when a fulfilment record from a
 *                 party with standing establishes the reason was met. Exercising the grant
 *                 does NOT by itself reach it.
 *  - `use_count`  the grant allows a fixed number of admissions. The admission itself
 *                 reaches it. No fulfilment record is involved.
 *  - `budget`     a cumulative spend ceiling. Listed for completeness and delegated to,
 *                 never reimplemented: `InMemoryAuthorityBudgetLedger` already answers it,
 *                 and draft-03 section 3.4 already states the rule, verbatim: "Signatures
 *                 establish static limits; they do not establish the current cumulative
 *                 total."
 *
 *  Three bases for one state, kept apart on purpose. Proposed. */
export const BOUND_KINDS = ['purpose', 'use_count', 'budget'] as const

export type BoundKind = (typeof BOUND_KINDS)[number]

/** The state of one grant's declared bound, as a verifier can establish it at an instant.
 *
 *  - `not_reached`      established: the bound has not been reached.
 *  - `exhausted`        established: it has. Neither revocation nor expiry. L10.
 *  - `not_established`  the verifier cannot say. A fulfilment claim arrived that could not
 *                       be authenticated, or could not be attributed to a party with
 *                       standing. That establishes neither that the bound was reached nor
 *                       that it was not, and it is never the negation of either. CAND-01.
 *
 *  Proposed. */
export const BOUND_STATES = ['not_reached', 'exhausted', 'not_established'] as const

export type BoundState = (typeof BOUND_STATES)[number]

/** Which ending a bound evaluation reports, in L10's vocabulary.
 *
 *  `exhaustion` and nothing else. This module never reports `expiry` and never reports
 *  `revocation`: both of those are chain-verification answers, they arrive as
 *  `EXPIRED` and `REVOKED` failure codes on an `AuthorityValidationResult`, and a bound
 *  evaluation has no standing to restate them. A grant can be expired AND exhausted at the
 *  same instant, which is why the two are reported side by side and neither overwrites the
 *  other.
 *
 *  Concept source: invariant L10. Proposed. */
export type BoundEnding = 'exhaustion' | null

/** A bound declared on one delegation.
 *
 *  This module does NOT authenticate the bound declaration itself. A bound is an input the
 *  caller has already established, by whatever means its authority model provides: a
 *  principal signature over this body, an entry in a registry the verifier accepts, or a
 *  term of a contract outside the wire format. Saying so plainly matters, because
 *  draft-03's closed facet set means there is no way to put the bound inside the signed
 *  delegation, and a module that silently treated an unauthenticated bound as established
 *  would be inventing the very thing CAND-01 forbids inventing.
 *
 *  What this module DOES authenticate is the fulfilment record, which is the external event
 *  CAND-01 is about. */
export interface AuthorityBound {
  readonly record_type: typeof AUTHORITY_BOUND_TYPE
  /** Caller-chosen stable identifier for this bound. Non-empty. */
  readonly bound_id: string
  /** Content address of the bounded delegation: `sha256:<64 lowercase hex>`. */
  readonly delegation_id: string
  readonly kind: BoundKind
  /** kind `purpose`: a hierarchical colon-separated purpose, the same grammar
   *  `isPurposePermitted` reads for a scope grant.
   *  kind `use_count`: a canonical unsigned decimal integer, no leading zero unless the
   *  value is exactly "0".
   *  kind `budget`: a canonical unsigned decimal integer in the unit's minor units. */
  readonly value: string
  /** Who may attest that this bound was reached. ROLES, not principals, for the reason a
   *  role registry exists at all: the party with standing to say a compressor was installed
   *  is whoever currently holds the maintenance-attestor role, not whoever held it when the
   *  grant was signed. An empty array means nobody but the delegation's issuer, and a
   *  resolver is still what decides whether a given attestor holds the role.
   *
   *  Ignored for kind `use_count` and kind `budget`, where no attestation is involved. */
  readonly fulfilment_attestor_roles: readonly string[]
}

/** The signed content of a fulfilment attestation: the record with `signature` absent.
 *
 *  Modelled on what draft-03 section 3.5.1 requires of a revocation record, which is the
 *  nearest published shape for "a party with standing recorded that an authority artifact's
 *  state changed", verbatim: "A revocation MUST produce a signed revocation record
 *  carrying, at minimum: the revoked delegation's identity; the revocation time, inside the
 *  signed content; a reference to the revoking authority; and a machine-readable reason
 *  code, with optional free-text detail." Each of those four has a member below. Nothing in
 *  draft-03 requires this record to exist. */
export interface AuthorityBoundFulfilmentBody {
  readonly record_type: typeof AUTHORITY_BOUND_FULFILMENT_TYPE
  /** The bound this attestation is about. Compared to `AuthorityBound.bound_id`. */
  readonly bound_id: string
  /** The bounded delegation's identity. Compared to `AuthorityBound.delegation_id`. */
  readonly delegation_id: string
  /** The attesting party. A valid signature establishes WHO signed. It does not establish
   *  that the signer was allowed to make this statement, which is what the role resolver
   *  is for. */
  readonly attestor: string
  /** Which key signed. No local rule relates it to `attestor`: an identifier-to-key
   *  binding is a resolver's answer. */
  readonly verification_method: string
  /** Canonical UTC-millisecond time, inside the signed content, supplied by the caller and
   *  never read from a clock. */
  readonly attested_at: string
  /** Machine-readable outcome. `fulfilled` is the only value that can reach a bound. A
   *  record that says `not_fulfilled` is a statement about the world, and it is why "a
   *  fulfilment record exists" and "it says the purpose was met" stay two facts. */
  readonly outcome: 'fulfilled' | 'not_fulfilled'
  /** Machine-readable reason code. Non-empty, and no grammar is fixed. */
  readonly reason_code: string
  /** OPTIONAL free-text detail. An absent detail is absent, never serialized as null: JCS
   *  has no canonical form for undefined. */
  readonly detail?: string
}

export interface AuthorityBoundFulfilment extends AuthorityBoundFulfilmentBody {
  /** Raw 64-byte Ed25519 signature as 128 lowercase hexadecimal characters. */
  readonly signature: string
}

/** What a resolver says about one attestor's standing at one instant.
 *
 *  Three values, and the third is the point. `unknown` is not `other`: a resolver that
 *  cannot answer has not told the verifier that the attestor lacks the role, and collapsing
 *  the two would turn an unanswered question into a finding. Mirrors the three-value shape
 *  the activation-condition surface uses for the same reason. */
export const ATTESTOR_ROLE_ANSWERS = ['holds_role', 'does_not_hold_role', 'unknown'] as const

export type AttestorRoleAnswer = (typeof ATTESTOR_ROLE_ANSWERS)[number]

/** Resolve whether `attestor` held any of `roles` at `atInstant`.
 *
 *  Roles, not principals: see `AuthorityBound.fulfilment_attestor_roles`. The resolver is
 *  the caller's, because who holds a role is not a local fact. */
export type AttestorRoleResolver = (
  attestor: string,
  roles: readonly string[],
  atInstant: string,
) => AttestorRoleAnswer

/** Resolve the verification key for one attestor's method as of one instant. `null` means
 *  no key was resolved, which is a `source` gap and never a signature failure. The
 *  instant-taking shape matches the historical key resolution invariant L9 describes: a
 *  verifier selects the key version authorized at the record's own timestamp. */
export type BoundVerificationKeyResolver = (
  attestor: string,
  verificationMethod: string,
  attestedAt: string,
) => string | null

/** The reason codes this module emits. Stable, module-local, SCREAMING_SNAKE_CASE. */
export const BOUND_REASON_CODES = [
  /** not_reached: the bound is declared and no accepted evidence reaches it. */
  'BOUND_NOT_REACHED',
  /** exhausted: an accepted fulfilment record established the purpose was met. */
  'PURPOSE_EXHAUSTED',
  /** exhausted: admissions counted against the bound reached its limit. */
  'USE_COUNT_EXHAUSTED',
  /** exhausted: committed plus reserved spend reached the cumulative ceiling. */
  'BUDGET_EXHAUSTED',
  /** not_established: at least one fulfilment claim could not be established, and none
   *  was accepted. The per-record code says which limb failed on which record. */
  'BOUND_STATE_NOT_ESTABLISHED',
] as const

export type BoundReasonCode = (typeof BOUND_REASON_CODES)[number]

/** Per-record codes an assessment carries. A rejected record always says which of the
 *  three failure classes it fell into, because "we did not accept it" is not an answer. */
export const FULFILMENT_REASON_CODES = [
  /** Accepted: structurally sound, signature verified, attestor holds a named role. */
  'FULFILMENT_ACCEPTED',
  /** The record does not have the shape this module reads. */
  'FULFILMENT_SCHEMA_INVALID',
  /** The record names a different bound or a different delegation. */
  'FULFILMENT_NOT_BOUND_TO_BOUND',
  /** The record says the bound was not met. Established, and negative. */
  'FULFILMENT_OUTCOME_NOT_FULFILLED',
  /** `attested_at` is later than the instant being evaluated. A verifier asked about
   *  Tuesday does not get to read Wednesday's records. */
  'FULFILMENT_NOT_YET_ATTESTED',
  /** No key resolved for the attestor's method. A source gap, not a signature failure. */
  'FULFILMENT_KEY_UNRESOLVED',
  /** A key resolved and the signature did not verify over the canonical preimage. */
  'FULFILMENT_SIGNATURE_INVALID',
  /** The signature verified and the resolver says the attestor does not hold a named role.
   *  Authenticated, and by someone without standing. A different failure from the one
   *  above, and this module will not collapse them. */
  'FULFILMENT_ATTESTOR_WITHOUT_STANDING',
  /** The resolver could not say whether the attestor holds a role. Not the same as
   *  `WITHOUT_STANDING`: nobody has told the verifier anything. */
  'FULFILMENT_ATTESTOR_ROLE_UNKNOWN',
  /** The bound's kind takes no fulfilment record. A `use_count` bound is reached by the
   *  admission and a `budget` bound by the ledger. */
  'FULFILMENT_NOT_APPLICABLE_TO_KIND',
] as const

export type FulfilmentReasonCode = (typeof FULFILMENT_REASON_CODES)[number]

/** What this module concluded about ONE fulfilment record. */
export interface FulfilmentAssessment {
  /** `bound_id` plus `attested_at` plus `attestor`, as supplied. Never computed from the
   *  record's own claims about itself. */
  readonly attestor: string
  readonly attested_at: string
  readonly accepted: boolean
  readonly reason_code: FulfilmentReasonCode
  /** The resolver's answer, when one was asked for. */
  readonly role_answer?: AttestorRoleAnswer
  /** Which establishment limb this rejection leaves missing, when the rejection is an
   *  evidential one rather than an established negative. Absent on an accepted record and
   *  on `FULFILMENT_OUTCOME_NOT_FULFILLED`, which is a conclusion, not a gap. */
  readonly missing?: readonly EstablishmentGap[]
}

/** What `evaluateBound` concludes. */
export interface BoundEvaluation {
  readonly bound_id: string
  readonly kind: BoundKind
  readonly bound_state: BoundState
  readonly reason_code: BoundReasonCode
  /** L10's ending vocabulary. `exhaustion` exactly when `bound_state` is `exhausted`, and
   *  `null` otherwise. Never `expiry` and never `revocation`: see `BoundEnding`. */
  readonly ending: BoundEnding
  /** The same conclusion in the `../lifecycle-state/` vocabulary, for reporting alongside
   *  a chain result. `not_reached` is `valid`, `exhausted` is `invalid` (the vocabulary
   *  has no seventh verdict and exhaustion is one of the findings that lands there,
   *  separated by reason code), `not_established` is `not_established` with its limbs. */
  readonly lifecycle: LifecycleStateResult
  /** Every fulfilment record that was looked at, in the order supplied, with what happened
   *  to it. Never a count and never a boolean. */
  readonly fulfilments: readonly FulfilmentAssessment[]
  /** kind `use_count` only: admissions still allowed, as a canonical decimal string.
   *  "0" when exhausted. Absent for the other kinds. */
  readonly remaining?: string
}

/** The signed content of the OPTIONAL exhaustion record: the record with `exhaustion_id`
 *  and `signature` absent.
 *
 *  WHAT THIS RECORD ATTESTS, stated once and stated plainly. It attests that the
 *  enforcement boundary named in `boundary` found, from the evidence it names, that the
 *  bound had been reached. It does NOT attest that the purpose was met in the world. That
 *  distinction is not an invention of this module: draft-03 section 5.3.3 draws the same
 *  one for an action result, verbatim: "An action-result record attests to what the
 *  enforcement boundary observed after dispatch.  External occurrence or settlement
 *  requires separately resolved evidence." A verifier with no access to the boundary's
 *  ledgers cannot reach an exhaustion verdict from signed records alone, and this record
 *  does not pretend otherwise.
 *
 *  WHY IT EXISTS ANYWAY. draft-03 section 3.5.1 gives revocation a signed record, verbatim:
 *  "A revocation MUST produce a signed revocation record carrying, at minimum: the revoked
 *  delegation's identity; the revocation time, inside the signed content; a reference to the
 *  revoking authority; and a machine-readable reason code, with optional free-text detail."
 *  Exhaustion has no published counterpart. Invariant L10 says the difference between the
 *  two endings "matters for evidence and for whether a replacement is expected", and an
 *  ending with no record at all cannot carry that difference anywhere. This record is shaped
 *  deliberately like the section 3.5.1 one so the two endings are comparable evidence and
 *  still never the same record type.
 *
 *  Concept source: invariant L10 and invariant candidate CAND-01. Proposed. */
export interface AuthorityExhaustionBody {
  readonly record_type: typeof AUTHORITY_EXHAUSTION_TYPE
  /** The bound that was reached. */
  readonly bound_id: string
  /** The bounded delegation's identity. */
  readonly delegation_id: string
  readonly kind: BoundKind
  /** The enforcement boundary making the finding. Its own identity, not the principal's:
   *  this is the boundary's statement about what it observed. */
  readonly boundary: string
  readonly verification_method: string
  /** Canonical UTC-millisecond time the finding was made, inside the signed content. */
  readonly found_at: string
  /** One of `BOUND_REASON_CODES`, and the reason the module reached `exhausted`. */
  readonly reason_code: string
  /** The evidence the finding rests on. For a purpose bound, the `attestor` and
   *  `attested_at` of every accepted fulfilment record. For a use-count or budget bound,
   *  an empty array: the basis is the boundary's own ledger, which is exactly the thing an
   *  outside verifier cannot check, and writing a placeholder here would hide that. */
  readonly evidence: readonly { readonly attestor: string; readonly attested_at: string }[]
  /** OPTIONAL free-text detail. Absent means absent, never null. */
  readonly detail?: string
}

export interface AuthorityExhaustion extends AuthorityExhaustionBody {
  /** `sha256:<64 lowercase hex>` over the ID domain tag and JCS of the body. */
  readonly exhaustion_id: string
  /** Raw 64-byte Ed25519 signature as 128 lowercase hexadecimal characters. */
  readonly signature: string
}
