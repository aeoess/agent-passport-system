// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. The marker constructor and the comparison, and nothing else.
// See ./types.ts for the specification position. Concept source:
// aeoess/agent-authority-lifecycle, invariant candidate CAND-08. Proposed.

import {
  MONOTONICITY_OUTCOMES,
  STATE_MARKER_SCOPES,
  UNPLACEABLE_DISPOSITIONS,
  type MonotonicityOutcome,
  type StateMarker,
  type StateMarkerScope,
  type UnplaceableDisposition,
} from './types.js'

/** Thrown when a caller asks for a marker the vocabulary does not allow. A shape rule
 *  broken at construction is a programming error, not a verdict. Mirrors
 *  `LifecycleStateError` in src/v2/lifecycle-state/. */
export class AuthorityStateError extends Error {
  readonly code: string

  constructor(code: string, message: string) {
    super(message)
    this.name = 'AuthorityStateError'
    this.code = code
  }
}

/** Canonical unsigned decimal integer. Same pattern the authority vector's spend
 *  quantities use: no sign, no leading zero, no separators. */
const DECIMAL = /^(0|[1-9][0-9]*)$/

export function isStateMarkerScope(value: unknown): value is StateMarkerScope {
  return typeof value === 'string' && (STATE_MARKER_SCOPES as readonly string[]).includes(value)
}

export function isMonotonicityOutcome(value: unknown): value is MonotonicityOutcome {
  return typeof value === 'string' && (MONOTONICITY_OUTCOMES as readonly string[]).includes(value)
}

export function isUnplaceableDisposition(value: unknown): value is UnplaceableDisposition {
  return typeof value === 'string' && (UNPLACEABLE_DISPOSITIONS as readonly string[]).includes(value)
}

export interface StateMarkerInput {
  readonly value: string
  readonly scope: StateMarkerScope
  readonly scope_ref?: string
}

/**
 * Build a `StateMarker`, enforcing its shape rules.
 *
 * 1. `value` is a canonical unsigned decimal integer, as a string. A number would lose
 *    exactness past 2^53 - 1 and would admit `1.0`, `1e3` and `-1`, none of which orders
 *    the way a generation counter has to.
 * 2. `scope` is one of the four. There is no fifth and there is no default: which thing a
 *    generation is counted within is the choice the proposed text does not make, so it has
 *    to be stated rather than assumed.
 * 3. `scope_ref` is present and non-empty exactly when `scope` is not `global`. A
 *    per-delegation marker that does not say which delegation cannot be compared against
 *    anything.
 *
 * Proposed. Concept source: aeoess/agent-authority-lifecycle, `Authority epoch`.
 */
export function stateMarker(input: StateMarkerInput): StateMarker {
  if (input === null || typeof input !== 'object') {
    throw new AuthorityStateError('MARKER_MALFORMED', 'a state marker input must be an object')
  }
  if (typeof input.value !== 'string' || !DECIMAL.test(input.value)) {
    throw new AuthorityStateError(
      'MARKER_VALUE_NONCANONICAL',
      'value must be a canonical unsigned decimal integer string',
    )
  }
  if (!isStateMarkerScope(input.scope)) {
    throw new AuthorityStateError(
      'MARKER_SCOPE_UNKNOWN',
      `scope must be one of ${STATE_MARKER_SCOPES.join(', ')}`,
    )
  }
  if (input.scope === 'global') {
    if (input.scope_ref !== undefined) {
      throw new AuthorityStateError(
        'MARKER_SCOPE_REF_NOT_ALLOWED',
        'a global marker names no scope_ref',
      )
    }
    return Object.freeze({ value: input.value, scope: input.scope })
  }
  if (typeof input.scope_ref !== 'string' || input.scope_ref.length === 0) {
    throw new AuthorityStateError(
      'MARKER_SCOPE_REF_REQUIRED',
      `a ${input.scope} marker must name the scope_ref it is counted within`,
    )
  }
  return Object.freeze({ value: input.value, scope: input.scope, scope_ref: input.scope_ref })
}

/** Whether two markers are counted in the same thing and can therefore be ordered. */
export function sameScope(a: StateMarker, b: StateMarker): boolean {
  return a.scope === b.scope && (a.scope_ref ?? null) === (b.scope_ref ?? null)
}

/**
 * Place a presented marker against what a verifier has established.
 *
 * | established | presented          | outcome       |
 * |-------------|--------------------|---------------|
 * | `null`      | any                | `unplaceable` |
 * | any         | `null`             | `unplaceable` |
 * | any         | a different scope  | `unplaceable` |
 * | m           | >= m               | `forward`     |
 * | m           | < m                | `regressed`   |
 *
 * Equal is `forward`, not a third thing: a view that has not moved has not gone backwards.
 *
 * `unplaceable` is where the honesty of the whole module sits. It is returned for a first
 * read and for a cross-scope comparison, it is NOT a verdict, and nothing downstream turns
 * it into one on its own. The proposed text gives a verifier with no prior observation
 * nothing to compare against and does not say whether such a read is trusted or refused.
 *
 * Comparison is integer, through BigInt, never lexical: "10" is after "9".
 *
 * Never throws for a malformed marker. A marker this function cannot read is one it cannot
 * place, which is `unplaceable`, and throwing on the read path of a state comparison would
 * turn a data problem into a crash in a verifier.
 */
export function compareStateMarker(
  established: StateMarker | null | undefined,
  presented: StateMarker | null | undefined,
): MonotonicityOutcome {
  if (!established || !presented) return 'unplaceable'
  if (typeof established.value !== 'string' || !DECIMAL.test(established.value)) return 'unplaceable'
  if (typeof presented.value !== 'string' || !DECIMAL.test(presented.value)) return 'unplaceable'
  if (!sameScope(established, presented)) return 'unplaceable'
  return BigInt(presented.value) >= BigInt(established.value) ? 'forward' : 'regressed'
}

/**
 * The high-water mark a verifier holds after reading a presented view.
 *
 * It only ever moves forward. A regressed view does not lower it, an unplaceable view does
 * not replace it, and a verifier that had none adopts the presented one. This is the
 * "monotonicity against what the verifier has established" limb of CAND-08, which is
 * weaker than a rule against global truth and is the honest strength available: a verifier
 * that has never seen the newer state cannot detect a regression and is not at fault.
 */
export function advanceHighWaterMark(
  established: StateMarker | null | undefined,
  presented: StateMarker | null | undefined,
): StateMarker | null {
  if (!presented) return established ?? null
  if (!established) return presented
  return compareStateMarker(established, presented) === 'forward' ? presented : established
}
