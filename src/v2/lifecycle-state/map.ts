// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. Expressing an existing chain-verification result in the lifecycle
// vocabulary.
//
// This is a READ-ONLY view. It takes an `AuthorityValidationResult` that
// `verifyAuthorityDelegationChain` already produced and says what that result looks like
// in the six-value vocabulary. It never mutates the input, it is never called from the
// verification path, and a caller that does not import it sees no change whatever. The
// draft-03 four-value result stays a four-value result, and this is reported ALONGSIDE it.
// See ./types.ts `CompositeAuthorityResult`.
//
// What this mapping CANNOT produce, and why: `suspended` and `restricted` never appear,
// because draft-03 chain verification has no concept of a suspension or restriction cause
// and the module that owns cause sets is a separate proposed surface. The `freshness` limb
// never appears either, because chain verification takes a revocation resolver that answers
// active, revoked or unknown with no declared bound attached, and the module that owns
// multi-source status observation owns freshness. A mapping that invented either would be
// claiming a finding the verifier never made.

import type {
  AuthorityFailure,
  AuthorityValidationResult,
} from '../authority-delegation/types.js'
import { lifecycleState } from './state.js'
import type { EstablishmentGap, LifecycleStateResult } from './types.js'

export interface LifecycleMappingOptions {
  /** draft-03 chain verification reports a delegation whose `time.not_before` has not been
   *  reached as `invalid` with failure code `NOT_YET_VALID`. One reading of the six-value
   *  vocabulary calls that a validly issued grant whose enabling date has not arrived,
   *  whose remedy is to wait, which would be `not_yet_effective` rather than `invalid`.
   *
   *  **Default `false`: the mapping keeps the chain's own reading.** The concept document
   *  has not decided this one. The `activation-not-established` fixture puts a grant time
   *  facet and an activation-condition date at the same instant and records the split as a
   *  finding about the proposed text rather than asserting either answer: "the text does
   *  not say whether a waiting grant should be invalid, not yet effective, or something
   *  else." This module is the shared base several other proposed lifecycle surfaces build
   *  on, so it does not embed a contested reading as a default. Settling it belongs to the
   *  activation-condition surface, which is where a condition distinct from the time facet
   *  gets a representation at all.
   *
   *  Set `true` to take the CAND-04 reading. It then applies ONLY when `NOT_YET_VALID` is
   *  the sole failure code in the result. A result carrying it alongside any other failure
   *  still maps to `invalid` on that other failure, because something more than the date is
   *  wrong.
   *
   *  Concept source: aeoess/agent-authority-lifecycle, invariant candidate CAND-04.
   *  Proposed. */
  readonly notYetValidAsNotYetEffective?: boolean
}

/** Which establishment limb a chain failure code leaves missing.
 *
 *  Only codes chain verification can reach on an indeterminate or unsupported state appear.
 *  Everything unlisted falls back to `source`, which is the honest default: the verifier
 *  had no usable answer it accepts, and it is not claiming a freshness bound it was never
 *  given or coverage it was never told about. */
const GAPS_BY_CODE: Readonly<Record<string, readonly EstablishmentGap[]>> = Object.freeze({
  // The resolver answered `unknown`: no accepted source produced a usable determinate answer.
  REVOCATION_UNKNOWN: Object.freeze(['source'] as const),
  KEY_RESOLUTION_FAILED: Object.freeze(['source'] as const),
  KEY_NOT_FOUND: Object.freeze(['source'] as const),
  KEY_AMBIGUOUS: Object.freeze(['source'] as const),
  KEY_UNREACHABLE: Object.freeze(['source'] as const),
  KEY_MATERIAL_MALFORMED: Object.freeze(['source'] as const),
  KEY_SCHEME_UNSUPPORTED: Object.freeze(['source'] as const),
  // A ceiling this implementation imposes: it declined to judge the whole record, so what
  // the answer does not cover is the record itself.
  RESOURCE_LIMIT: Object.freeze(['coverage'] as const),
  UNSUPPORTED_VERSION: Object.freeze(['source'] as const),
  UNSUPPORTED_RECORD_TYPE: Object.freeze(['source'] as const),
  UNSUPPORTED_PROFILE: Object.freeze(['source'] as const),
})

const DEFAULT_GAPS: readonly EstablishmentGap[] = Object.freeze(['source'] as const)

/** The first failure is the one reported, matching how the chain result is read elsewhere
 *  in this SDK and in the conformance fixtures. */
function firstFailure(failures: readonly AuthorityFailure[]): AuthorityFailure | undefined {
  return failures.length > 0 ? failures[0] : undefined
}

/**
 * Express an `AuthorityValidationResult` in the six-value lifecycle vocabulary.
 *
 * | chain state     | lifecycle verdict                                             |
 * |-----------------|---------------------------------------------------------------|
 * | `valid`         | `valid`, reason `CHAIN_VALID`                                  |
 * | `invalid`       | `invalid`, reason = the first failure code. `NOT_YET_VALID`     |
 * |                 | included, unless the caller opts into the CAND-04 reading       |
 * | `indeterminate` | `not_established`, reason = the first failure code, `missing`  |
 * |                 | from that code                                                 |
 * | `unsupported`   | `not_established`, reason = the first failure code, `missing`  |
 * |                 | `['source']`                                                   |
 *
 * `unsupported` mapping to `not_established` is a judgment call worth naming. Draft-03
 * keeps `unsupported` as its own value, and this vocabulary has no member for it. A
 * verifier that declines to judge a record it does not recognise has not reached a
 * conclusion about the artifact, which is the evidential sense of not established, and the
 * missing limb is source: the record is unrecognised. The original chain result is
 * unchanged and still says `unsupported`, so nothing is lost by reporting both.
 *
 * Reported alongside the chain result, never in place of it.
 * Proposed. Concept source: aeoess/agent-authority-lifecycle.
 */
export function mapAuthorityValidationToLifecycle(
  result: AuthorityValidationResult,
  options: LifecycleMappingOptions = {},
): LifecycleStateResult {
  const notYetValidAsNotYetEffective = options.notYetValidAsNotYetEffective === true
  const failures = result.failures ?? []

  switch (result.state) {
    case 'valid':
      return lifecycleState({ verdict: 'valid', reason_code: 'CHAIN_VALID' })

    case 'invalid': {
      const onlyNotYetValid =
        failures.length > 0 && failures.every(f => f.code === 'NOT_YET_VALID')
      if (notYetValidAsNotYetEffective && onlyNotYetValid) {
        return lifecycleState({
          verdict: 'not_yet_effective',
          reason_code: 'NOT_BEFORE_UNREACHED',
        })
      }
      const named = failures.find(f => f.code !== 'NOT_YET_VALID') ?? firstFailure(failures)
      return lifecycleState({
        verdict: 'invalid',
        reason_code: named?.code ?? 'CHAIN_INVALID',
      })
    }

    case 'indeterminate': {
      const named = firstFailure(failures)
      const code = named?.code ?? 'CHAIN_INDETERMINATE'
      return lifecycleState({
        verdict: 'not_established',
        reason_code: code,
        missing: GAPS_BY_CODE[code] ?? DEFAULT_GAPS,
      })
    }

    case 'unsupported': {
      const named = firstFailure(failures)
      const code = named?.code ?? 'CHAIN_UNSUPPORTED'
      return lifecycleState({
        verdict: 'not_established',
        reason_code: code,
        missing: GAPS_BY_CODE[code] ?? DEFAULT_GAPS,
      })
    }

    default:
      // An unrecognised state is itself something this mapping cannot establish. It does
      // not become `invalid`, and it does not throw: the chain result the caller already
      // holds is untouched and still says whatever it said.
      return lifecycleState({
        verdict: 'not_established',
        reason_code: 'CHAIN_STATE_UNRECOGNISED',
        missing: DEFAULT_GAPS,
      })
  }
}
