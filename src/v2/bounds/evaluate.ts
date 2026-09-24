// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. Assessing fulfilment records and evaluating a bound's state.
//
// Pure. No clock, no I/O, no network. Every instant compared here is supplied by the
// caller, and every resolver is the caller's. Not required by draft-pidlisnyi-aps-03; see
// ./types.ts for the specification position.

import { lifecycleState, notEstablished } from '../lifecycle-state/state.js'
import type { EstablishmentGap, LifecycleStateResult } from '../lifecycle-state/types.js'
import { verifyAuthorityBoundFulfilmentSignature } from './canonical.js'
import {
  AUTHORITY_BOUND_FULFILMENT_TYPE,
  AUTHORITY_BOUND_TYPE,
  ATTESTOR_ROLE_ANSWERS,
  BOUND_KINDS,
  type AttestorRoleAnswer,
  type AttestorRoleResolver,
  type AuthorityBound,
  type AuthorityBoundFulfilment,
  type BoundEnding,
  type BoundEvaluation,
  type BoundKind,
  type BoundReasonCode,
  type BoundState,
  type BoundVerificationKeyResolver,
  type FulfilmentAssessment,
} from './types.js'

/** Thrown when an input this module cannot read at all is passed. A malformed BOUND is a
 *  programming error, not a verdict: the module was asked a question about nothing. A
 *  malformed FULFILMENT RECORD is different and never throws, because a record somebody
 *  else wrote is data, and the right answer about it is a rejection with a reason code. */
export class AuthorityBoundError extends Error {
  readonly code: string

  constructor(code: string, message: string) {
    super(message)
    this.name = 'AuthorityBoundError'
    this.code = code
  }
}

const CANONICAL_UNSIGNED_INTEGER = /^(0|[1-9][0-9]*)$/
const DELEGATION_ID = /^sha256:[0-9a-f]{64}$/
const SIGNATURE_HEX = /^[0-9a-f]{128}$/

export function isBoundKind(value: unknown): value is BoundKind {
  return typeof value === 'string' && (BOUND_KINDS as readonly string[]).includes(value)
}

export function isAttestorRoleAnswer(value: unknown): value is AttestorRoleAnswer {
  return (
    typeof value === 'string' && (ATTESTOR_ROLE_ANSWERS as readonly string[]).includes(value)
  )
}

/** Shape check for a bound declaration. Throws, for the reason `AuthorityBoundError`
 *  documents. */
export function assertAuthorityBound(bound: AuthorityBound): void {
  if (bound === null || typeof bound !== 'object') {
    throw new AuthorityBoundError('BOUND_MALFORMED', 'bound is not an object')
  }
  if (bound.record_type !== AUTHORITY_BOUND_TYPE) {
    throw new AuthorityBoundError(
      'BOUND_RECORD_TYPE_UNSUPPORTED',
      `record_type must be ${AUTHORITY_BOUND_TYPE}`,
    )
  }
  if (typeof bound.bound_id !== 'string' || bound.bound_id.length === 0) {
    throw new AuthorityBoundError('BOUND_MALFORMED', 'bound_id must be a non-empty string')
  }
  if (typeof bound.delegation_id !== 'string' || !DELEGATION_ID.test(bound.delegation_id)) {
    throw new AuthorityBoundError(
      'BOUND_MALFORMED',
      'delegation_id must be sha256:<64 lowercase hex>',
    )
  }
  if (!isBoundKind(bound.kind)) {
    throw new AuthorityBoundError(
      'BOUND_KIND_UNSUPPORTED',
      `kind must be one of ${BOUND_KINDS.join(', ')}`,
    )
  }
  if (typeof bound.value !== 'string' || bound.value.length === 0) {
    throw new AuthorityBoundError('BOUND_MALFORMED', 'value must be a non-empty string')
  }
  if (bound.kind !== 'purpose' && !CANONICAL_UNSIGNED_INTEGER.test(bound.value)) {
    throw new AuthorityBoundError(
      'BOUND_VALUE_NONCANONICAL',
      `a ${bound.kind} bound's value must be a canonical unsigned decimal integer`,
    )
  }
  if (!Array.isArray(bound.fulfilment_attestor_roles)) {
    throw new AuthorityBoundError(
      'BOUND_MALFORMED',
      'fulfilment_attestor_roles must be an array, empty if nobody but the issuer may attest',
    )
  }
  for (const role of bound.fulfilment_attestor_roles) {
    if (typeof role !== 'string' || role.length === 0) {
      throw new AuthorityBoundError(
        'BOUND_MALFORMED',
        'fulfilment_attestor_roles must contain only non-empty strings',
      )
    }
  }
}

/** True only for a record this module can read far enough to assess. A record that fails
 *  here is rejected with `FULFILMENT_SCHEMA_INVALID`, never thrown on. */
function readableFulfilment(record: AuthorityBoundFulfilment): boolean {
  return (
    record !== null &&
    typeof record === 'object' &&
    record.record_type === AUTHORITY_BOUND_FULFILMENT_TYPE &&
    typeof record.bound_id === 'string' &&
    record.bound_id.length > 0 &&
    typeof record.delegation_id === 'string' &&
    DELEGATION_ID.test(record.delegation_id) &&
    typeof record.attestor === 'string' &&
    record.attestor.length > 0 &&
    typeof record.verification_method === 'string' &&
    record.verification_method.length > 0 &&
    typeof record.attested_at === 'string' &&
    record.attested_at.length > 0 &&
    (record.outcome === 'fulfilled' || record.outcome === 'not_fulfilled') &&
    typeof record.reason_code === 'string' &&
    record.reason_code.length > 0 &&
    typeof record.signature === 'string' &&
    SIGNATURE_HEX.test(record.signature)
  )
}

function assessment(
  attestor: string,
  attestedAt: string,
  accepted: boolean,
  reasonCode: FulfilmentAssessment['reason_code'],
  extra: { role_answer?: AttestorRoleAnswer; missing?: readonly EstablishmentGap[] } = {},
): FulfilmentAssessment {
  const out: {
    attestor: string
    attested_at: string
    accepted: boolean
    reason_code: FulfilmentAssessment['reason_code']
    role_answer?: AttestorRoleAnswer
    missing?: readonly EstablishmentGap[]
  } = { attestor, attested_at: attestedAt, accepted, reason_code: reasonCode }
  if (extra.role_answer !== undefined) out.role_answer = extra.role_answer
  if (extra.missing !== undefined) out.missing = Object.freeze([...extra.missing])
  return Object.freeze(out)
}

export interface AssessFulfilmentInput {
  readonly bound: AuthorityBound
  readonly record: AuthorityBoundFulfilment
  /** The instant the question is asked at. A record attested later than this is not read:
   *  a verifier asked about Tuesday does not get to use Wednesday's evidence. */
  readonly atInstant: string
  readonly resolveAttestorRole: AttestorRoleResolver
  readonly resolveVerificationKey: BoundVerificationKeyResolver
}

/**
 * Assess ONE fulfilment record against one bound.
 *
 * The order of the checks is the substance of this function, not an implementation detail.
 * Standing is asked FIRST and authenticity SECOND, and each produces its own code, because
 * "authenticated by somebody who may not say this" and "not authenticated at all" are
 * different failures and collapsing them loses the distinction CAND-01 turns on. A valid
 * signature establishes who signed. It does not establish that the signer was allowed to
 * make this statement.
 *
 * `FULFILMENT_OUTCOME_NOT_FULFILLED` carries no `missing` limbs, and that is deliberate: a
 * record from a party with standing saying the purpose was NOT met is a conclusion the
 * verifier reached, not a gap in its evidence. Every other rejection names a limb.
 *
 * Concept source: aeoess/agent-authority-lifecycle, invariant candidate CAND-01 and
 * invariant candidate BROAD-L7. Proposed.
 */
export function assessFulfilment(input: AssessFulfilmentInput): FulfilmentAssessment {
  assertAuthorityBound(input.bound)
  const { bound, record, atInstant } = input

  if (bound.kind !== 'purpose') {
    return assessment('', '', false, 'FULFILMENT_NOT_APPLICABLE_TO_KIND', {
      missing: ['coverage'],
    })
  }

  if (!readableFulfilment(record)) {
    return assessment('', '', false, 'FULFILMENT_SCHEMA_INVALID', { missing: ['source'] })
  }

  const attestor = record.attestor
  const attestedAt = record.attested_at

  // The record has to be about THIS bound on THIS delegation. A coverage gap: the claim does
  // not state that it covers what the verdict needed.
  if (record.bound_id !== bound.bound_id || record.delegation_id !== bound.delegation_id) {
    return assessment(attestor, attestedAt, false, 'FULFILMENT_NOT_BOUND_TO_BOUND', {
      missing: ['coverage'],
    })
  }

  if (attestedAt > atInstant) {
    return assessment(attestor, attestedAt, false, 'FULFILMENT_NOT_YET_ATTESTED', {
      missing: ['coverage'],
    })
  }

  const roleAnswer = input.resolveAttestorRole(
    attestor,
    bound.fulfilment_attestor_roles,
    atInstant,
  )
  if (!isAttestorRoleAnswer(roleAnswer)) {
    return assessment(attestor, attestedAt, false, 'FULFILMENT_ATTESTOR_ROLE_UNKNOWN', {
      missing: ['source'],
    })
  }
  if (roleAnswer === 'unknown') {
    return assessment(attestor, attestedAt, false, 'FULFILMENT_ATTESTOR_ROLE_UNKNOWN', {
      role_answer: roleAnswer,
      missing: ['source'],
    })
  }
  if (roleAnswer === 'does_not_hold_role') {
    return assessment(attestor, attestedAt, false, 'FULFILMENT_ATTESTOR_WITHOUT_STANDING', {
      role_answer: roleAnswer,
      missing: ['source'],
    })
  }

  const publicKey = input.resolveVerificationKey(
    attestor,
    record.verification_method,
    attestedAt,
  )
  if (typeof publicKey !== 'string' || publicKey.length === 0) {
    return assessment(attestor, attestedAt, false, 'FULFILMENT_KEY_UNRESOLVED', {
      role_answer: roleAnswer,
      missing: ['source'],
    })
  }
  if (!verifyAuthorityBoundFulfilmentSignature(record, publicKey)) {
    return assessment(attestor, attestedAt, false, 'FULFILMENT_SIGNATURE_INVALID', {
      role_answer: roleAnswer,
      missing: ['source'],
    })
  }

  if (record.outcome !== 'fulfilled') {
    return assessment(attestor, attestedAt, false, 'FULFILMENT_OUTCOME_NOT_FULFILLED', {
      role_answer: roleAnswer,
    })
  }

  return assessment(attestor, attestedAt, true, 'FULFILMENT_ACCEPTED', {
    role_answer: roleAnswer,
  })
}

export interface EvaluateBoundInput {
  readonly bound: AuthorityBound
  /** Every fulfilment claim the caller holds for this bound. Order is preserved in the
   *  result and does not change the verdict: see the resolution rule below. Empty for a
   *  `use_count` or `budget` bound, where no attestation is involved. */
  readonly fulfilments?: readonly AuthorityBoundFulfilment[]
  readonly atInstant: string
  readonly resolveAttestorRole?: AttestorRoleResolver
  readonly resolveVerificationKey?: BoundVerificationKeyResolver
  /** kind `use_count` only: admissions already counted against this bound, as a canonical
   *  unsigned decimal integer string. The caller's ledger owns this number. This module
   *  does not count admissions, because counting them means holding state across events and
   *  a pure function has none. */
  readonly consumed?: string
  /** kind `budget` only: the committed and reserved totals, exactly as
   *  `InMemoryAuthorityBudgetLedger.counter(delegationId)` returns them. The budget kind
   *  delegates to that ledger and never reimplements it: draft-03 section 3.4 already
   *  states the rule, and the ledger already enforces it. */
  readonly budgetCounter?: { readonly committed: string; readonly reserved: string }
}

function decimal(value: string | undefined, fallback: string): bigint {
  const raw = value ?? fallback
  if (!CANONICAL_UNSIGNED_INTEGER.test(raw)) {
    throw new AuthorityBoundError(
      'COUNTER_NONCANONICAL',
      `expected a canonical unsigned decimal integer, got ${JSON.stringify(raw)}`,
    )
  }
  return BigInt(raw)
}

function lifecycleFor(
  state: BoundState,
  reasonCode: BoundReasonCode,
  missing: readonly EstablishmentGap[],
): LifecycleStateResult {
  if (state === 'not_established') return notEstablished(missing, reasonCode)
  return lifecycleState({
    verdict: state === 'exhausted' ? 'invalid' : 'valid',
    reason_code: reasonCode,
  })
}

/**
 * Evaluate one bound's state at one instant.
 *
 * THE RESOLUTION RULE, and why it is this way round. For a purpose bound:
 *
 *   1. If any fulfilment record was ACCEPTED, the state is `exhausted`.
 *   2. Otherwise, if any record was rejected on an EVIDENTIAL ground (signature, standing,
 *      unresolved role, unresolved key, unreadable shape), the state is `not_established`.
 *   3. Otherwise the state is `not_reached`.
 *
 * Step 1 comes before step 2 on purpose, and it is invariant CAND-02's rule made
 * executable: an exhaustion that WAS established is never downgraded by a later claim
 * nobody could authenticate. A later finding is a new record about an earlier one, never a
 * rewrite of it. Because the rule is a fold over the whole set rather than a running
 * mutation, the verdict is the same whatever order the records arrive in, which is what
 * makes it safe for a caller to keep them in an unordered store.
 *
 * Step 3 reads `not_reached` from an empty record set, and that is the one reading here
 * worth arguing with. It is a positive claim: the bound is declared, no evidence reaches
 * it, and under the applicable authority model a purpose that nobody has recorded as met is
 * a purpose that is not met. A model whose default runs the other way (absence of a
 * periodic fulfilment report is itself the trigger) is a model this function cannot
 * express, and a caller in that position should report `not_established` with a `source`
 * limb rather than passing an empty set and reading the answer as a finding. CAND-01's
 * carve-out for a declared default on absence is the reason the disclaimer is here and not
 * a silent assumption.
 *
 * A `use_count` bound needs no records at all: the ADMISSION reaches it, so `consumed`
 * against `value` is the whole computation. A `budget` bound is answered by the ledger's
 * counter, per draft-03 section 3.4, verbatim: "Signatures establish static limits; they do
 * not establish the current cumulative total."
 *
 * Reported ALONGSIDE a chain result, never merged into it, and never in place of it. A
 * grant can be exhausted while its chain still verifies `valid`, which is the whole point:
 * exhaustion is invisible to chain verification. A grant can also be expired AND exhausted,
 * and then the chain result says `EXPIRED` and this says `exhaustion` and neither
 * overwrites the other. Invariant L10.
 *
 * Concept source: aeoess/agent-authority-lifecycle, invariant L10 and invariant candidates
 * CAND-01 and CAND-02. All proposed.
 */
export function evaluateBound(input: EvaluateBoundInput): BoundEvaluation {
  assertAuthorityBound(input.bound)
  const { bound } = input
  if (typeof input.atInstant !== 'string' || input.atInstant.length === 0) {
    throw new AuthorityBoundError('INSTANT_MISSING', 'atInstant must be a non-empty string')
  }

  const assessments: FulfilmentAssessment[] = []
  let state: BoundState
  let reasonCode: BoundReasonCode
  let remaining: string | undefined
  const missing: EstablishmentGap[] = []

  if (bound.kind === 'purpose') {
    const records = input.fulfilments ?? []
    if (records.length > 0) {
      if (typeof input.resolveAttestorRole !== 'function') {
        throw new AuthorityBoundError(
          'ROLE_RESOLVER_MISSING',
          'a purpose bound with fulfilment records needs resolveAttestorRole',
        )
      }
      if (typeof input.resolveVerificationKey !== 'function') {
        throw new AuthorityBoundError(
          'KEY_RESOLVER_MISSING',
          'a purpose bound with fulfilment records needs resolveVerificationKey',
        )
      }
    }
    const resolveAttestorRole = input.resolveAttestorRole ?? (() => 'unknown')
    const resolveVerificationKey = input.resolveVerificationKey ?? (() => null)
    for (const record of records) {
      assessments.push(
        assessFulfilment({
          bound,
          record,
          atInstant: input.atInstant,
          resolveAttestorRole,
          resolveVerificationKey,
        }),
      )
    }
    const accepted = assessments.some(a => a.accepted)
    const unestablished = assessments.filter(a => !a.accepted && a.missing !== undefined)
    if (accepted) {
      state = 'exhausted'
      reasonCode = 'PURPOSE_EXHAUSTED'
    } else if (unestablished.length > 0) {
      state = 'not_established'
      reasonCode = 'BOUND_STATE_NOT_ESTABLISHED'
      for (const a of unestablished) {
        for (const gap of a.missing ?? []) if (!missing.includes(gap)) missing.push(gap)
      }
    } else {
      state = 'not_reached'
      reasonCode = 'BOUND_NOT_REACHED'
    }
  } else if (bound.kind === 'use_count') {
    const limit = decimal(bound.value, '0')
    const consumed = decimal(input.consumed, '0')
    const left = consumed >= limit ? 0n : limit - consumed
    remaining = left.toString(10)
    state = consumed >= limit ? 'exhausted' : 'not_reached'
    reasonCode = state === 'exhausted' ? 'USE_COUNT_EXHAUSTED' : 'BOUND_NOT_REACHED'
  } else {
    const ceiling = decimal(bound.value, '0')
    const committed = decimal(input.budgetCounter?.committed, '0')
    const reserved = decimal(input.budgetCounter?.reserved, '0')
    state = committed + reserved >= ceiling ? 'exhausted' : 'not_reached'
    reasonCode = state === 'exhausted' ? 'BUDGET_EXHAUSTED' : 'BOUND_NOT_REACHED'
  }

  const ending: BoundEnding = state === 'exhausted' ? 'exhaustion' : null
  const result: {
    bound_id: string
    kind: BoundKind
    bound_state: BoundState
    reason_code: BoundReasonCode
    ending: BoundEnding
    lifecycle: LifecycleStateResult
    fulfilments: readonly FulfilmentAssessment[]
    remaining?: string
  } = {
    bound_id: bound.bound_id,
    kind: bound.kind,
    bound_state: state,
    reason_code: reasonCode,
    ending,
    lifecycle: lifecycleFor(state, reasonCode, missing.length > 0 ? missing : ['source']),
    fulfilments: Object.freeze([...assessments]),
  }
  if (remaining !== undefined) result.remaining = remaining
  return Object.freeze(result)
}
