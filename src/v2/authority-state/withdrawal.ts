// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. Withdrawal, or correction, of a recorded revocation.
// See ./types.ts for the specification position. Concept source:
// aeoess/agent-authority-lifecycle, invariant candidate CAND-02 (later evidence does not
// rewrite earlier evidence) and invariant L3 (reauthorization creates new authority).
// Proposed.
//
// THE ONE SENTENCE THIS FILE EXISTS FOR. A corrected false revocation is a separate record,
// not a resurrection. Draft-03 section 3.5 states "Revocation is irreversible", and nothing
// below relaxes that: an accepted withdrawal leaves the revocation held, leaves it
// verifying byte for byte, and leaves every chain verdict exactly where it was. What the
// withdrawal changes is what a verifier can REPORT, which had no representation at all.
//
// Continuity after a correction still needs a fresh grant from a principal who currently
// holds authority. This module mints no grant and no authority of any kind.

import type { AuthorityRevocationV1 } from '../authority-revocation/types.js'
import { AuthorityStateError } from './marker.js'
import {
  REVOCATION_WITHDRAWAL_RECORD_TYPE,
  REVOCATION_WITHDRAWAL_VERSION,
  WITHDRAWAL_STANDINGS,
  type CorrectedRevocationView,
  type RevocationWithdrawalV0,
  type WithdrawalEvaluation,
  type WithdrawalStanding,
  type WithdrawalStandingResolver,
} from './types.js'

const ID = /^sha256:[0-9a-f]{64}$/

export function isWithdrawalStanding(value: unknown): value is WithdrawalStanding {
  return typeof value === 'string' && (WITHDRAWAL_STANDINGS as readonly string[]).includes(value)
}

export interface RevocationWithdrawalInput {
  readonly revocation_id: string
  readonly delegation_id: string
  readonly withdrawn_by: string
  readonly withdrawn_at: string
  readonly reason_code: string
  readonly detail?: string
}

/**
 * Build a `RevocationWithdrawalV0`.
 *
 * A shape constructor and nothing more. It does not sign, does not canonicalize, and does
 * not compute an identifier, because minting the signed form of a record type is a
 * conformance-vocabulary decision reserved to the maintainer and this module is not making
 * it. `record_type` carries the `proposed:` namespace for the same reason.
 *
 * An absent `detail` is absent, never `null`: the key is not present at all, matching how
 * the revocation record treats its own optional detail.
 */
export function revocationWithdrawal(input: RevocationWithdrawalInput): RevocationWithdrawalV0 {
  if (input === null || typeof input !== 'object') {
    throw new AuthorityStateError('WITHDRAWAL_MALFORMED', 'a withdrawal input must be an object')
  }
  for (const field of ['revocation_id', 'delegation_id'] as const) {
    if (typeof input[field] !== 'string' || !ID.test(input[field])) {
      throw new AuthorityStateError(
        'WITHDRAWAL_ID_NONCANONICAL',
        `${field} must be sha256:<64 lowercase hex>`,
      )
    }
  }
  for (const field of ['withdrawn_by', 'withdrawn_at', 'reason_code'] as const) {
    if (typeof input[field] !== 'string' || input[field].length === 0) {
      throw new AuthorityStateError(
        'WITHDRAWAL_FIELD_REQUIRED',
        `${field} must be a non-empty string`,
      )
    }
  }
  if (input.detail !== undefined && (typeof input.detail !== 'string' || input.detail.length === 0)) {
    throw new AuthorityStateError(
      'WITHDRAWAL_DETAIL_INVALID',
      'detail must be a non-empty string when present',
    )
  }
  const record: {
    record_type: typeof REVOCATION_WITHDRAWAL_RECORD_TYPE
    version: typeof REVOCATION_WITHDRAWAL_VERSION
    revocation_id: string
    delegation_id: string
    withdrawn_by: string
    withdrawn_at: string
    reason_code: string
    detail?: string
  } = {
    record_type: REVOCATION_WITHDRAWAL_RECORD_TYPE,
    version: REVOCATION_WITHDRAWAL_VERSION,
    revocation_id: input.revocation_id,
    delegation_id: input.delegation_id,
    withdrawn_by: input.withdrawn_by,
    withdrawn_at: input.withdrawn_at,
    reason_code: input.reason_code,
  }
  if (input.detail !== undefined) record.detail = input.detail
  return Object.freeze(record)
}

/** A standing resolver that accepts a withdrawal only from the party the revocation itself
 *  names as revoker.
 *
 *  Supplied because it is the rule the forcing fixture chose and it needs to be runnable.
 *  IT IS A CHOICE, NOT A RULE READ FROM ANY TEXT. Draft-03 section 3.5 names the issuer as
 *  the party who may revoke; nothing in draft-03 or in the proposed text says who may
 *  withdraw a revocation, and the concept document's own `Lifecycle standing` entry says
 *  the party who may change an artifact "is not always the issuer". A deployment whose
 *  authority model gives a security function, a successor or a quorum standing to correct a
 *  publication error should pass its own resolver instead of this one. */
export const withdrawalSignerIsRevoker: WithdrawalStandingResolver = (withdrawal, revocation) =>
  withdrawal.withdrawn_by === revocation.revoker ? 'has_standing' : 'no_standing'

function malformed(withdrawal: unknown): boolean {
  const w = withdrawal as Partial<RevocationWithdrawalV0> | null
  if (w === null || typeof w !== 'object') return true
  if (w.record_type !== REVOCATION_WITHDRAWAL_RECORD_TYPE) return true
  if (w.version !== REVOCATION_WITHDRAWAL_VERSION) return true
  if (typeof w.revocation_id !== 'string' || !ID.test(w.revocation_id)) return true
  if (typeof w.delegation_id !== 'string' || !ID.test(w.delegation_id)) return true
  for (const field of ['withdrawn_by', 'withdrawn_at', 'reason_code'] as const) {
    const value = w[field]
    if (typeof value !== 'string' || value.length === 0) return true
  }
  return false
}

/**
 * Decide whether one withdrawal record is accepted against a set of held revocations.
 *
 * Four questions, kept separate on purpose, each with its own code:
 *
 *  1. Is the record a well-formed withdrawal? `WITHDRAWAL_SCHEMA_INVALID`.
 *  2. Does it name a revocation the held set actually contains?
 *     `WITHDRAWAL_NAMES_NO_HELD_REVOCATION`.
 *  3. Does that revocation revoke the delegation this record names?
 *     `WITHDRAWAL_TARGET_MISMATCH`.
 *  4. May this party withdraw it? Asked of the injected resolver, never of the record.
 *     `WITHDRAWAL_SIGNER_WITHOUT_STANDING` when the resolver establishes they may not, and
 *     `WITHDRAWAL_STANDING_NOT_ESTABLISHED` when it cannot establish either way.
 *
 * The last split is the wording rule, executable: a standing question the verifier could
 * not answer is not established, and that is not the same finding as a party established to
 * lack standing. Both refuse the withdrawal, and a caller reporting the refusal has to be
 * able to say which one happened.
 *
 * AUTHENTICATION IS THE CALLER'S. This function never checks a signature, because a
 * withdrawal has no signed form in this SDK, on purpose; see `RevocationWithdrawalV0`.
 * Whoever calls it is the party asserting the record is genuine, exactly as whoever calls
 * `insertVerifiedRevocation` asserts the revocation was verified.
 *
 * NOTHING HERE REMOVES A REVOCATION, on any path. An accepted withdrawal is a record about
 * a record. The held set handed in is not mutated and no store is touched.
 */
export function evaluateRevocationWithdrawal(
  withdrawal: RevocationWithdrawalV0,
  heldRevocations: readonly AuthorityRevocationV1[],
  resolveStanding: WithdrawalStandingResolver,
): WithdrawalEvaluation {
  if (malformed(withdrawal)) {
    return Object.freeze({
      accepted: false,
      reason_code: 'WITHDRAWAL_SCHEMA_INVALID' as const,
      standing: null,
      withdrawal,
    })
  }

  const target = (heldRevocations ?? []).find(r => r?.revocation_id === withdrawal.revocation_id)
  if (target === undefined) {
    return Object.freeze({
      accepted: false,
      reason_code: 'WITHDRAWAL_NAMES_NO_HELD_REVOCATION' as const,
      standing: null,
      withdrawal,
    })
  }
  if (target.delegation_id !== withdrawal.delegation_id) {
    return Object.freeze({
      accepted: false,
      reason_code: 'WITHDRAWAL_TARGET_MISMATCH' as const,
      standing: null,
      withdrawal,
    })
  }

  let standing: WithdrawalStanding
  try {
    standing = resolveStanding(withdrawal, target)
  } catch {
    standing = 'unknown'
  }
  if (!isWithdrawalStanding(standing)) standing = 'unknown'

  if (standing === 'has_standing') {
    return Object.freeze({
      accepted: true,
      reason_code: 'WITHDRAWAL_ACCEPTED' as const,
      standing,
      withdrawal,
    })
  }
  return Object.freeze({
    accepted: false,
    reason_code:
      standing === 'no_standing'
        ? ('WITHDRAWAL_SIGNER_WITHOUT_STANDING' as const)
        : ('WITHDRAWAL_STANDING_NOT_ESTABLISHED' as const),
    standing,
    withdrawal,
  })
}

/**
 * The current position of one revocation together with every withdrawal referencing it.
 *
 * This is the field that did not exist. A verifier that must report "revoked, and the
 * revoker later said this was recorded in error" had nowhere to put the second half, in
 * either reference SDK or in the proposed text, so it could only report the first half and
 * drop the rest.
 *
 * `revocation` is present and unchanged whether or not anything was accepted. Accepted
 * withdrawals are listed, refused ones are listed with their codes, and neither list makes
 * the revocation ineffective: a later finding is a new record that references the earlier
 * one and states its own effect, never an edit of it and never its removal.
 *
 * Withdrawals naming a different revocation are not silently dropped. They are evaluated,
 * refused `WITHDRAWAL_NAMES_NO_HELD_REVOCATION`, and appear in `refused`.
 */
export function correctedRevocationView(
  revocation: AuthorityRevocationV1,
  withdrawals: readonly RevocationWithdrawalV0[],
  resolveStanding: WithdrawalStandingResolver,
): CorrectedRevocationView {
  const held = [revocation]
  const evaluations = (withdrawals ?? []).map(w =>
    evaluateRevocationWithdrawal(w, held, resolveStanding),
  )
  return Object.freeze({
    revocation,
    accepted: Object.freeze(evaluations.filter(e => e.accepted)),
    refused: Object.freeze(evaluations.filter(e => !e.accepted)),
  })
}
