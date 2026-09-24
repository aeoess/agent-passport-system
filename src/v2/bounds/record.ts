// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. Issuing and verifying the two records this module declares.
//
// Neither record is required by draft-pidlisnyi-aps-03 and neither is an `aps:` record type.
// See ./types.ts for what each one attests and, more importantly, what it does not.

import {
  computeAuthorityExhaustionIdForWrite,
  computeAuthorityExhaustionId,
  signAuthorityBoundFulfilment,
  signAuthorityExhaustion,
  verifyAuthorityExhaustionSignature,
} from './canonical.js'
import { AuthorityBoundError } from './evaluate.js'
import {
  AUTHORITY_BOUND_FULFILMENT_TYPE,
  AUTHORITY_EXHAUSTION_TYPE,
  BOUND_KINDS,
  type AuthorityBoundFulfilment,
  type AuthorityBoundFulfilmentBody,
  type AuthorityExhaustion,
  type AuthorityExhaustionBody,
  type BoundEvaluation,
  type BoundKind,
} from './types.js'

export interface IssueFulfilmentInput {
  readonly bound_id: string
  readonly delegation_id: string
  readonly attestor: string
  readonly verification_method: string
  /** Canonical UTC-millisecond time, supplied by the caller. Issuance never reads a clock,
   *  so the same inputs produce the same bytes on every run, which is what makes the
   *  signature reproducible in a test and in a conformance vector. */
  readonly attested_at: string
  readonly outcome: 'fulfilled' | 'not_fulfilled'
  readonly reason_code: string
  /** Omitted from the record entirely when not supplied, never written as null. */
  readonly detail?: string
}

/**
 * Mint a signed fulfilment attestation.
 *
 * What this function does NOT establish: that the holder of `privateKey` is in fact
 * `attestor`, that `verification_method` is one of that party's keys, or that the attestor
 * holds any fulfilment-attestor role. All three are a resolver's answer, not a local one.
 * `assessFulfilment` makes those checks, and it asks about standing BEFORE it asks about the
 * signature, because a record can be perfectly authentic and still come from somebody with
 * no standing to make the statement.
 *
 * Proposed. Concept source: aeoess/agent-authority-lifecycle.
 */
export function issueAuthorityBoundFulfilment(
  input: IssueFulfilmentInput,
  privateKeyHex: string,
): AuthorityBoundFulfilment {
  for (const field of [
    'bound_id',
    'delegation_id',
    'attestor',
    'verification_method',
    'attested_at',
    'reason_code',
  ] as const) {
    const value = input[field]
    if (typeof value !== 'string' || value.length === 0) {
      throw new AuthorityBoundError(
        'FULFILMENT_ISSUE_MALFORMED',
        `${field} must be a non-empty string`,
      )
    }
  }
  if (input.outcome !== 'fulfilled' && input.outcome !== 'not_fulfilled') {
    throw new AuthorityBoundError(
      'FULFILMENT_ISSUE_MALFORMED',
      'outcome must be fulfilled or not_fulfilled',
    )
  }
  const body: AuthorityBoundFulfilmentBody = Object.freeze({
    record_type: AUTHORITY_BOUND_FULFILMENT_TYPE,
    bound_id: input.bound_id,
    delegation_id: input.delegation_id,
    attestor: input.attestor,
    verification_method: input.verification_method,
    attested_at: input.attested_at,
    outcome: input.outcome,
    reason_code: input.reason_code,
    ...(input.detail !== undefined ? { detail: input.detail } : {}),
  })
  return Object.freeze({
    ...body,
    signature: signAuthorityBoundFulfilment(body, privateKeyHex),
  })
}

export interface IssueExhaustionInput {
  readonly boundary: string
  readonly verification_method: string
  /** Canonical UTC-millisecond time the finding was made. Never read from a clock. */
  readonly found_at: string
  readonly detail?: string
}

/**
 * Mint the OPTIONAL signed exhaustion record for a `BoundEvaluation` that reached
 * `exhausted`.
 *
 * REFUSES on any other state, and the refusal is the design. A record that says "I found
 * this bound exhausted" when the evaluation said `not_established` would be a boundary
 * asserting a finding it did not make, which is precisely what CAND-01 forbids. There is no
 * flag to override it.
 *
 * `evidence` is derived from the evaluation's own accepted fulfilment records, and it is
 * EMPTY for a `use_count` or `budget` bound. That emptiness is honest rather than
 * incomplete: the basis for those two is the boundary's own ledger, which is the one thing
 * an outside verifier cannot check, and a placeholder there would hide the gap. The same
 * limit applies to the whole record, and ./types.ts states it: the record attests the
 * boundary's finding, not the state of the world, on the model draft-03 section 5.3.3 uses
 * for an action result.
 *
 * Proposed. Concept source: aeoess/agent-authority-lifecycle, invariant L10.
 */
export function issueAuthorityExhaustion(
  evaluation: BoundEvaluation,
  delegationId: string,
  input: IssueExhaustionInput,
  privateKeyHex: string,
): AuthorityExhaustion {
  if (evaluation === null || typeof evaluation !== 'object') {
    throw new AuthorityBoundError('EXHAUSTION_ISSUE_MALFORMED', 'evaluation is not an object')
  }
  if (evaluation.bound_state !== 'exhausted') {
    throw new AuthorityBoundError(
      'EXHAUSTION_STATE_NOT_EXHAUSTED',
      `an exhaustion record can only be minted for bound_state exhausted, not ${String(
        evaluation.bound_state,
      )}`,
    )
  }
  for (const field of ['boundary', 'verification_method', 'found_at'] as const) {
    const value = input[field]
    if (typeof value !== 'string' || value.length === 0) {
      throw new AuthorityBoundError(
        'EXHAUSTION_ISSUE_MALFORMED',
        `${field} must be a non-empty string`,
      )
    }
  }
  if (!(BOUND_KINDS as readonly string[]).includes(evaluation.kind)) {
    throw new AuthorityBoundError(
      'EXHAUSTION_ISSUE_MALFORMED',
      `kind must be one of ${BOUND_KINDS.join(', ')}`,
    )
  }
  const body: AuthorityExhaustionBody = Object.freeze({
    record_type: AUTHORITY_EXHAUSTION_TYPE,
    bound_id: evaluation.bound_id,
    delegation_id: delegationId,
    kind: evaluation.kind as BoundKind,
    boundary: input.boundary,
    verification_method: input.verification_method,
    found_at: input.found_at,
    reason_code: evaluation.reason_code,
    evidence: Object.freeze(
      evaluation.fulfilments
        .filter(a => a.accepted)
        .map(a => Object.freeze({ attestor: a.attestor, attested_at: a.attested_at })),
    ),
    ...(input.detail !== undefined ? { detail: input.detail } : {}),
  })
  const exhaustionId = computeAuthorityExhaustionIdForWrite(body)
  const unsigned = Object.freeze({ ...body, exhaustion_id: exhaustionId })
  return Object.freeze({
    ...unsigned,
    signature: signAuthorityExhaustion(unsigned, privateKeyHex),
  })
}

export type AuthorityExhaustionFailureCode =
  | 'SCHEMA_INVALID'
  | 'UNSUPPORTED_RECORD_TYPE'
  | 'ID_MISMATCH'
  | 'KEY_UNRESOLVED'
  | 'SIGNATURE_INVALID'

export interface AuthorityExhaustionVerification {
  /** `valid` or `invalid` only. This function answers a question about ONE record's bytes
   *  and its signer, which is genuinely two sided, so it does not borrow the lifecycle
   *  vocabulary. What the record means for a grant's state is `evaluateBound`'s question,
   *  and a verified record is evidence toward it, never a substitute for it. */
  readonly status: 'valid' | 'invalid'
  readonly failures: readonly AuthorityExhaustionFailureCode[]
}

/**
 * Verify an exhaustion record's bytes, identifier and signature.
 *
 * A `valid` answer here means: the record recomputes its own identifier, and the key
 * resolved for its `boundary` at its `found_at` signed it. It does NOT mean the bound is
 * exhausted. It means the named boundary said so, at that time, over those bytes. Treating
 * the two as the same thing is the substitution draft-03's own security considerations warn
 * about for receipts generally, verbatim: "Verifiers MUST treat receipts as evidence of what
 * was attested, not as proof of what is true."
 *
 * Proposed.
 */
export function verifyAuthorityExhaustion(
  record: AuthorityExhaustion,
  resolveVerificationKey: (
    boundary: string,
    verificationMethod: string,
    foundAt: string,
  ) => string | null,
): AuthorityExhaustionVerification {
  const failures: AuthorityExhaustionFailureCode[] = []
  const invalid = (): AuthorityExhaustionVerification =>
    Object.freeze({ status: 'invalid' as const, failures: Object.freeze([...failures]) })

  if (record === null || typeof record !== 'object') {
    failures.push('SCHEMA_INVALID')
    return invalid()
  }
  if (record.record_type !== AUTHORITY_EXHAUSTION_TYPE) {
    failures.push('UNSUPPORTED_RECORD_TYPE')
    return invalid()
  }
  for (const field of [
    'bound_id',
    'delegation_id',
    'boundary',
    'verification_method',
    'found_at',
    'reason_code',
    'exhaustion_id',
    'signature',
  ] as const) {
    if (typeof record[field] !== 'string' || record[field].length === 0) {
      failures.push('SCHEMA_INVALID')
      return invalid()
    }
  }
  if (!Array.isArray(record.evidence) || !(BOUND_KINDS as readonly string[]).includes(record.kind)) {
    failures.push('SCHEMA_INVALID')
    return invalid()
  }

  const { exhaustion_id: claimedId, signature: _signature, ...body } = record
  if (computeAuthorityExhaustionId(body as AuthorityExhaustionBody) !== claimedId) {
    failures.push('ID_MISMATCH')
    return invalid()
  }

  const publicKey = resolveVerificationKey(
    record.boundary,
    record.verification_method,
    record.found_at,
  )
  if (typeof publicKey !== 'string' || publicKey.length === 0) {
    failures.push('KEY_UNRESOLVED')
    return invalid()
  }
  if (!verifyAuthorityExhaustionSignature(record, publicKey)) {
    failures.push('SIGNATURE_INVALID')
    return invalid()
  }
  return Object.freeze({ status: 'valid' as const, failures: Object.freeze([]) })
}
