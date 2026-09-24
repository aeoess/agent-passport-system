// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. Resolving revocation state under a retained high-water mark.
// See ./types.ts for the specification position. Concept source:
// aeoess/agent-authority-lifecycle, invariant candidate CAND-08 and invariants L7 and L11.
// Proposed.
//
// WHAT THIS DOES NOT TOUCH. `AuthorityChainVerificationOptions` is unchanged. The existing
// `createAuthorityRevocationResolver` is unchanged, and its one-argument shape is the shape
// this module produces too: everything new closes over its own state and hands the chain
// verifier back the same callable it already takes. That was the alternative to widening
// the resolver signature, and widening it would have been a breaking change to an exported
// API for the sake of a proposed feature.

import type { AuthorityDelegationV1, RevocationResolution } from '../authority-delegation/types.js'
import { verifyAuthorityRevocation } from '../authority-revocation/verify.js'
import type { AuthorityRevocationVerificationOptions } from '../authority-revocation/verify.js'
import { advanceHighWaterMark, compareStateMarker } from './marker.js'
import type {
  MonotonicityOutcome,
  RetainedAuthorityState,
  StateMarker,
  UnplaceableDisposition,
} from './types.js'

/**
 * What the records a verifier RETAINED say about one delegation.
 *
 * Two answers only.
 *
 *  - `revoked`, when one retained record verifies against this delegation under
 *    `verifyAuthorityRevocation`. The record is re-verified here rather than trusted: a
 *    record that reached the retained set by some other route cannot assert a revocation,
 *    which is the same discipline `createAuthorityRevocationResolver` applies to a stored
 *    record.
 *  - `unknown`, for everything else.
 *
 * NEVER `active`. A retained record set is not a store: it says nothing about the
 * delegations it does not mention, so its silence is ignorance and not a finding. That is
 * L7 ("a revocation answer that is unavailable or stale is indeterminate. It does not
 * become active"), and it is why the two-verifier split in `RetainedAuthorityState` has
 * any content at all. A verifier that kept the records answers `revoked`. A verifier that
 * kept only the number answers `unknown`, which the chain verifier turns into
 * `indeterminate` with `REVOCATION_UNKNOWN`. Those are different verifiers and reporting
 * the same thing for both would be the error.
 *
 * Never throws. A retained set that cannot be read is one that establishes nothing.
 */
export function resolveUnderRetainedState(
  delegation: AuthorityDelegationV1,
  retained: RetainedAuthorityState,
  options: AuthorityRevocationVerificationOptions,
): RevocationResolution {
  try {
    const records = retained?.records ?? []
    for (const record of records) {
      if (verifyAuthorityRevocation(record, delegation, options).state === 'valid') return 'revoked'
    }
    return 'unknown'
  } catch {
    return 'unknown'
  }
}

export interface MonotonicRevocationResolverOptions {
  /** The resolver for the state view actually presented, typically
   *  `createAuthorityRevocationResolver(store, options)`. Consulted only when the presented
   *  view is not behind what the verifier has established. */
  readonly presented: (delegation: AuthorityDelegationV1) => RevocationResolution
  /** The marker the presented view carries, or `null` when it carries none. */
  readonly presentedMarker: StateMarker | null
  /** What this verifier has established: the records it kept and the newest marker it saw. */
  readonly retained: RetainedAuthorityState
  /** Key resolution for re-verifying retained records. */
  readonly verification: AuthorityRevocationVerificationOptions
  /** REQUIRED, with no default. What to do when the presented view cannot be placed
   *  against an established mark, which happens on a first read and on a cross-scope
   *  comparison.
   *
   *  `read_presented` reads the view as current. `refuse` answers `unknown` for every
   *  delegation, which the chain verifier turns into `indeterminate`. Both are defensible,
   *  the outcomes differ, and neither the proposed text nor draft-03 chooses between them,
   *  so this module does not choose either. The absence of a default is the point. */
  readonly onUnplaceable: UnplaceableDisposition
}

export interface MonotonicRevocationResolver {
  /** The one-argument callable `verifyAuthorityDelegationChain` already takes. Pass it
   *  straight through as `resolveRevocation`. */
  readonly resolve: (delegation: AuthorityDelegationV1) => RevocationResolution
  /** How the presented view placed against the established mark. Reported so a caller can
   *  say WHY it answered as it did, rather than only what it answered. */
  readonly monotonicity: MonotonicityOutcome
  /** The mark the verifier holds after this read. Only ever moves forward. */
  readonly highWaterMarkAfter: StateMarker | null
}

/**
 * Compose a presented state view, an established high-water mark and a retained record set
 * into the resolver the chain verifier already takes.
 *
 * | monotonicity  | what `resolve` consults                                             |
 * |---------------|---------------------------------------------------------------------|
 * | `forward`     | the presented view, normally                                         |
 * | `regressed`   | the retained records ONLY: `revoked` or `unknown`, never `active`     |
 * | `unplaceable` | the presented view, or nothing, per `onUnplaceable`                   |
 *
 * The regressed row is CAND-08: a restore, a snapshot mount or a lagging replica presents
 * state from before a revocation, and this refuses to read it as current rather than
 * resolving the disagreement by recency of write. What it does NOT do is claim a revocation
 * it cannot establish. A verifier that retained the record reports `revoked`; one that
 * retained only the mark reports `unknown`, and `unknown` is not established, not false.
 *
 * Nothing here changes the chain verdict directly. The chain verifier decides that, from
 * the answer this resolver gives it, exactly as it does today.
 *
 * Pure: no clock, no network, no randomness, no I/O. The marker and the record set are
 * caller supplied, and `presented` is a caller-supplied callback.
 */
export function createMonotonicRevocationResolver(
  options: MonotonicRevocationResolverOptions,
): MonotonicRevocationResolver {
  const monotonicity = compareStateMarker(options.retained?.highWaterMark ?? null, options.presentedMarker)
  const highWaterMarkAfter = advanceHighWaterMark(
    options.retained?.highWaterMark ?? null,
    options.presentedMarker,
  )

  const resolve = (delegation: AuthorityDelegationV1): RevocationResolution => {
    if (monotonicity === 'regressed') {
      return resolveUnderRetainedState(delegation, options.retained, options.verification)
    }
    if (monotonicity === 'unplaceable' && options.onUnplaceable === 'refuse') return 'unknown'
    try {
      return options.presented(delegation)
    } catch {
      return 'unknown'
    }
  }

  return Object.freeze({ resolve, monotonicity, highWaterMarkAfter })
}
