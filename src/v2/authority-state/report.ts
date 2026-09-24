// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. Reporting a chain result, a lifecycle verdict, the monotonicity finding
// and any correction records TOGETHER, without any of them rewriting another.
// See ./types.ts for the specification position. Proposed.

import type { AuthorityValidationResult } from '../authority-delegation/types.js'
import { mapAuthorityValidationToLifecycle } from '../lifecycle-state/map.js'
import type { LifecycleMappingOptions } from '../lifecycle-state/map.js'
import type { CompositeAuthorityResult, LifecycleStateResult } from '../lifecycle-state/types.js'
import type { CorrectedRevocationView, MonotonicityOutcome, StateMarker } from './types.js'

/** A chain result, the lifecycle vocabulary's reading of it, how the state view placed, and
 *  the correction records that reference any revocation behind it.
 *
 *  Four fields, four separate claims, none merged into another. `chain` is byte for byte
 *  what `verifyAuthorityDelegationChain` returned and a caller that reads only that field
 *  sees exactly today's behaviour. */
export interface AuthorityStateReport<TChain> extends CompositeAuthorityResult<TChain> {
  /** How the presented state view placed against the verifier's established mark, or
   *  `undefined` when no state comparison ran. */
  readonly monotonicity?: MonotonicityOutcome
  /** The mark the verifier holds after this read. */
  readonly highWaterMarkAfter?: StateMarker | null
  /** Revocations behind this result together with the withdrawals referencing them. Empty
   *  or absent when none was submitted. A non-empty `accepted` list NEVER implies the chain
   *  result would have been different. */
  readonly corrections?: readonly CorrectedRevocationView[]
}

export interface AuthorityStateReportInput<TChain> {
  readonly chain: TChain
  readonly lifecycle?: LifecycleStateResult
  readonly monotonicity?: MonotonicityOutcome
  readonly highWaterMarkAfter?: StateMarker | null
  readonly corrections?: readonly CorrectedRevocationView[]
}

/**
 * Assemble the report.
 *
 * A pure structural constructor. It computes no verdict, consults no record and cannot
 * change one: every field is what its own module already concluded. That is the shape of
 * the doctrine it encodes. A later finding is a new record that references an earlier one
 * and states its own effect, so the correction sits BESIDE the chain result rather than
 * inside it, and a reader can present both and their relation.
 */
export function authorityStateReport<TChain>(
  input: AuthorityStateReportInput<TChain>,
): AuthorityStateReport<TChain> {
  const report: {
    chain: TChain
    lifecycle?: LifecycleStateResult
    monotonicity?: MonotonicityOutcome
    highWaterMarkAfter?: StateMarker | null
    corrections?: readonly CorrectedRevocationView[]
  } = { chain: input.chain }
  if (input.lifecycle !== undefined) report.lifecycle = input.lifecycle
  if (input.monotonicity !== undefined) report.monotonicity = input.monotonicity
  if (input.highWaterMarkAfter !== undefined) report.highWaterMarkAfter = input.highWaterMarkAfter
  if (input.corrections !== undefined) report.corrections = Object.freeze([...input.corrections])
  return Object.freeze(report)
}

/**
 * The common case, in one call: take a chain result, express it in the lifecycle vocabulary
 * and attach the state findings.
 *
 * Convenience over `mapAuthorityValidationToLifecycle` plus `authorityStateReport`, with no
 * behaviour of its own. Read-only: the chain result is not mutated and is carried through
 * unchanged.
 *
 * The property worth stating: for a chain whose root is revoked, the lifecycle verdict is
 * `invalid` with reason `REVOKED` whether or not `corrections` carries an accepted
 * withdrawal. An accepted correction does not move the verdict one step toward valid. It is
 * reported, and reporting it is the whole of its effect here.
 */
export function reportAuthorityState(
  chain: AuthorityValidationResult,
  input: Omit<AuthorityStateReportInput<AuthorityValidationResult>, 'chain' | 'lifecycle'> & {
    readonly lifecycleOptions?: LifecycleMappingOptions
  } = {},
): AuthorityStateReport<AuthorityValidationResult> {
  return authorityStateReport({
    chain,
    lifecycle: mapAuthorityValidationToLifecycle(chain, input.lifecycleOptions ?? {}),
    monotonicity: input.monotonicity,
    highWaterMarkAfter: input.highWaterMarkAfter,
    corrections: input.corrections,
  })
}
