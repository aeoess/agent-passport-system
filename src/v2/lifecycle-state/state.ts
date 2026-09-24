// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. Validating constructors for the lifecycle state vocabulary.
// See ./types.ts for the specification position: nothing here is required by
// draft-pidlisnyi-aps-03, and nothing here changes any existing exported behaviour.

import {
  ESTABLISHMENT_GAPS,
  ESTABLISHED_NEGATIVE_SHAPES,
  LIFECYCLE_VERDICTS,
  BOUNDARY_OUTCOMES,
  type BoundaryOutcome,
  type EstablishedNegativeResolution,
  type EstablishedNegativeShape,
  type EstablishmentGap,
  type LifecycleStateResult,
  type LifecycleVerdict,
  type OutstandingCause,
} from './types.js'

/** Thrown when a caller asks for a `LifecycleStateResult` the vocabulary does not allow.
 *  A shape rule broken at construction is a programming error, not a verdict. */
export class LifecycleStateError extends Error {
  readonly code: string

  constructor(code: string, message: string) {
    super(message)
    this.name = 'LifecycleStateError'
    this.code = code
  }
}

export function isLifecycleVerdict(value: unknown): value is LifecycleVerdict {
  return typeof value === 'string' && (LIFECYCLE_VERDICTS as readonly string[]).includes(value)
}

export function isBoundaryOutcome(value: unknown): value is BoundaryOutcome {
  return typeof value === 'string' && (BOUNDARY_OUTCOMES as readonly string[]).includes(value)
}

export function isEstablishmentGap(value: unknown): value is EstablishmentGap {
  return typeof value === 'string' && (ESTABLISHMENT_GAPS as readonly string[]).includes(value)
}

export function isEstablishedNegativeShape(value: unknown): value is EstablishedNegativeShape {
  return (
    typeof value === 'string' && (ESTABLISHED_NEGATIVE_SHAPES as readonly string[]).includes(value)
  )
}

/** What `lifecycleState` accepts. Same members as `LifecycleStateResult`, and the
 *  constructor is what turns it into one. */
export interface LifecycleStateInput {
  readonly verdict: LifecycleVerdict
  readonly reason_code: string
  readonly missing?: readonly EstablishmentGap[]
  readonly applied_default?: string
  readonly outstanding?: readonly OutstandingCause[]
}

const REASON_CODE_PATTERN = /^[A-Z][A-Z0-9_]*$/

function assertCause(cause: OutstandingCause, index: number): void {
  if (cause === null || typeof cause !== 'object') {
    throw new LifecycleStateError('OUTSTANDING_MALFORMED', `outstanding[${index}] is not an object`)
  }
  for (const field of ['id', 'kind', 'reason_code'] as const) {
    if (typeof cause[field] !== 'string' || cause[field].length === 0) {
      throw new LifecycleStateError(
        'OUTSTANDING_MALFORMED',
        `outstanding[${index}].${field} must be a non-empty string`,
      )
    }
  }
}

/** Build a `LifecycleStateResult`, enforcing the vocabulary's shape rules.
 *
 *  Rules, each with the reason it exists:
 *
 *  1. `verdict` is one of the six. There is no seventh. "Unexecutable" in particular is an
 *     EXECUTION OUTCOME, not a verdict: the artifact stays valid and what fails is the
 *     attempt to carry out the invocation, so it belongs in an execution record under a
 *     `referent_unresolvable` reason, not here.
 *  2. `reason_code` is required and SCREAMING_SNAKE_CASE. Two findings that share a verdict
 *     name must be told apart by their codes.
 *  3. `missing` is present with at least one member exactly when the verdict is
 *     `not_established`, and absent otherwise. A denial on an unestablished state has to
 *     record which of source, freshness or coverage was missing, and a verdict the verifier
 *     DID reach has no gap to report.
 *  4. `outstanding` is present with at least one member exactly when the verdict is
 *     `suspended` or `restricted`, and absent otherwise. Causes compose, so the verdict
 *     carries the set that remains rather than a flag.
 *  5. `applied_default` may not appear on `not_established`. If a declared default applied,
 *     the verifier reached a conclusion and the verdict is that conclusion.
 *
 *  Concept source: aeoess/agent-authority-lifecycle, invariant candidates v2 sections 2.2,
 *  2.3, 2.4 and 3, and candidates BROAD-L7 and CAND-05. All proposed. */
export function lifecycleState(input: LifecycleStateInput): LifecycleStateResult {
  if (!isLifecycleVerdict(input?.verdict)) {
    throw new LifecycleStateError(
      'VERDICT_UNKNOWN',
      `verdict must be one of ${LIFECYCLE_VERDICTS.join(', ')}`,
    )
  }
  if (typeof input.reason_code !== 'string' || !REASON_CODE_PATTERN.test(input.reason_code)) {
    throw new LifecycleStateError(
      'REASON_CODE_INVALID',
      'reason_code must be a non-empty SCREAMING_SNAKE_CASE string',
    )
  }

  const wantsMissing = input.verdict === 'not_established'
  const missing = input.missing
  if (wantsMissing) {
    if (!Array.isArray(missing) || missing.length === 0) {
      throw new LifecycleStateError(
        'MISSING_REQUIRED',
        'a not_established verdict must name at least one missing establishment limb',
      )
    }
    for (const gap of missing) {
      if (!isEstablishmentGap(gap)) {
        throw new LifecycleStateError(
          'MISSING_UNKNOWN',
          `missing must contain only ${ESTABLISHMENT_GAPS.join(', ')}`,
        )
      }
    }
  } else if (missing !== undefined) {
    throw new LifecycleStateError(
      'MISSING_NOT_ALLOWED',
      `missing is only meaningful on not_established, not on ${input.verdict}`,
    )
  }

  const wantsOutstanding = input.verdict === 'suspended' || input.verdict === 'restricted'
  const outstanding = input.outstanding
  if (wantsOutstanding) {
    if (!Array.isArray(outstanding) || outstanding.length === 0) {
      throw new LifecycleStateError(
        'OUTSTANDING_REQUIRED',
        `a ${input.verdict} verdict must name at least one outstanding cause`,
      )
    }
    outstanding.forEach(assertCause)
  } else if (outstanding !== undefined) {
    throw new LifecycleStateError(
      'OUTSTANDING_NOT_ALLOWED',
      `outstanding is only meaningful on suspended or restricted, not on ${input.verdict}`,
    )
  }

  if (input.applied_default !== undefined) {
    if (typeof input.applied_default !== 'string' || input.applied_default.length === 0) {
      throw new LifecycleStateError(
        'APPLIED_DEFAULT_INVALID',
        'applied_default must be a non-empty string when present',
      )
    }
    if (wantsMissing) {
      throw new LifecycleStateError(
        'APPLIED_DEFAULT_NOT_ALLOWED',
        'applied_default cannot appear on not_established: a default that applied is a conclusion',
      )
    }
  }

  const result: {
    verdict: LifecycleVerdict
    reason_code: string
    missing?: readonly EstablishmentGap[]
    applied_default?: string
    outstanding?: readonly OutstandingCause[]
  } = { verdict: input.verdict, reason_code: input.reason_code }
  if (missing !== undefined) result.missing = Object.freeze([...missing])
  if (input.applied_default !== undefined) result.applied_default = input.applied_default
  if (outstanding !== undefined) {
    result.outstanding = Object.freeze(outstanding.map(c => Object.freeze({ ...c })))
  }
  return Object.freeze(result)
}

/** Build the evidential `not_established` (use A) with its mandatory limbs.
 *
 *  Reach for this only when the verifier CANNOT REACH a conclusion. For a negative the
 *  verifier HAS reached, call `resolveEstablishedNegative` instead and report what it
 *  gives you. */
export function notEstablished(
  missing: readonly EstablishmentGap[],
  reasonCode: string,
): LifecycleStateResult {
  return lifecycleState({ verdict: 'not_established', reason_code: reasonCode, missing })
}

const ESTABLISHED_NEGATIVE_RESOLUTIONS: {
  readonly [K in EstablishedNegativeShape]: Extract<EstablishedNegativeResolution, { shape: K }>
} = Object.freeze({
  enabling_condition_not_yet_occurred: Object.freeze({
    shape: 'enabling_condition_not_yet_occurred',
    subject: 'artifact',
    verdict: 'not_yet_effective',
    reason_code: 'ENABLING_CONDITION_NOT_YET_OCCURRED',
  } as const),
  composition_not_satisfied: Object.freeze({
    shape: 'composition_not_satisfied',
    subject: 'boundary',
    outcome: 'denied',
    reason_code: 'COMPOSITION_NOT_SATISFIED',
  } as const),
  pinned_referent_mismatch: Object.freeze({
    shape: 'pinned_referent_mismatch',
    subject: 'boundary',
    outcome: 'denied',
    reason_code: 'PINNED_REFERENT_MISMATCH',
  } as const),
})

/** Map an established negative (use B) to the subject and output it actually belongs to.
 *
 *  None of the three resolves to `not_established`. Two of them are not artifact verdicts
 *  at all: a composition rule that is not satisfied and a pinned referent that is
 *  established to have changed both deny the ACTION at a boundary, and neither makes any
 *  artifact invalid.
 *
 *  Concept source: aeoess/agent-authority-lifecycle, invariant candidates v2 section 3.
 *  Proposed. */
export function resolveEstablishedNegative(
  shape: EstablishedNegativeShape,
): EstablishedNegativeResolution {
  if (!isEstablishedNegativeShape(shape)) {
    throw new LifecycleStateError(
      'ESTABLISHED_NEGATIVE_UNKNOWN',
      `shape must be one of ${ESTABLISHED_NEGATIVE_SHAPES.join(', ')}`,
    )
  }
  return ESTABLISHED_NEGATIVE_RESOLUTIONS[shape]
}
