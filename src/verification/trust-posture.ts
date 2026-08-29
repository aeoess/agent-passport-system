// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// The trust posture every execution gate shares
// ══════════════════════════════════════════════════════════════════
// A passport signature verifies under the public key the passport itself
// carries. On its own it establishes that whoever holds that key wrote the
// passport, capabilities included, and nothing at all about who vouches for
// the holder. A gate that admits on that basis is admitting a self-issued
// claim of authority.
//
// The relying-party middleware was hardened to require a stated posture and
// the five ADAPTER gates were not, so the same hole stayed open in five more
// places: an attacker's self-signed passport declaring `admin:everything`,
// carrying a delegation they issued to themselves, ran the tool and got a
// success receipt. That divergence is the reason this module exists. There is
// now ONE implementation of the rule, and a gate added later inherits it
// instead of reimplementing it and forgetting a case.
//
// The rule, in full:
//
//   trustedIssuers non-empty   the passport MUST carry a valid issuer
//                              countersignature from one of them
//   allowSelfSigned: true      self-signed credentials are accepted, and the
//                              result carries the verifier's warning saying so
//   neither, or an empty list  DENY with UNTRUSTED_ISSUER
//
// An empty trusted-issuer list is an empty list, not a wildcard. Wildcard
// trust is a real posture for a closed network or a development gate, and it
// is available, but it has to be asked for by name.

import { verifyPassport } from './verify.js'
import type { SignedPassport } from '../types/passport.js'
import type { CoreVerifyClockOptions } from '../types/policy.js'

/** Why a passport failed the posture check. */
export type TrustPostureFailure =
  /** Signature, validity window, or a demanded issuer countersignature failed. */
  | 'PASSPORT_INVALID'
  /** The passport is sound, but the gate holds no trust anchor for it and the
   *  caller did not say self-signed credentials are acceptable. */
  | 'UNTRUSTED_ISSUER'

export interface TrustPostureOptions {
  /** Trust anchors: issuer public keys whose countersignature this gate
   *  accepts. A NON-EMPTY list requires a valid countersignature from one of
   *  them, and `allowSelfSigned` does not override that. An empty list, or
   *  omitting the option, means the gate holds no anchors; it does not mean
   *  "trust anyone". */
  trustedIssuers?: string[]
  /** Explicit wildcard trust: admit a passport whose only authority is its own
   *  signature. Required to admit a self-signed credential; the result then
   *  carries the verifier's self-signed warning so an operator can see the
   *  basis on which the request was let through. Default false. Ignored when
   *  `trustedIssuers` is non-empty. */
  allowSelfSigned?: boolean
  /** Uniform clock-skew option, threaded into verifyPassport. */
  clock?: CoreVerifyClockOptions
}

export interface TrustPostureResult {
  /** True iff the passport verified AND the gate had a stated basis for
   *  accepting whoever stands behind it. */
  ok: boolean
  failure?: TrustPostureFailure
  /** Human-readable detail for a deny reason or an audit log. Names the
   *  failing check; never carries key material. */
  detail?: string
  errors: string[]
  warnings: string[]
}

/**
 * Run the shared execution-gate posture check on a presented passport.
 *
 * Pure and offline. Callers turn `ok: false` into whatever their transport
 * calls a denial, and should surface `detail` so an operator can tell an
 * untrusted issuer apart from a broken signature.
 */
export function checkPassportTrustPosture(
  passport: SignedPassport,
  opts: TrustPostureOptions = {},
): TrustPostureResult {
  const anchors = opts.trustedIssuers ?? []

  const result = verifyPassport(passport, {
    trustedIssuers: anchors,
    clock: opts.clock,
  })
  const warnings = result.warnings ?? []

  if (!result.valid) {
    return {
      ok: false,
      failure: 'PASSPORT_INVALID',
      detail: `Passport invalid: ${result.errors.join(', ')}`,
      errors: result.errors,
      warnings,
    }
  }

  // verifyPassport enforces the countersignature only when anchors were
  // supplied; with none, its verdict is signature and validity window alone.
  // Admitting on that basis is a decision the caller has to have made.
  if (anchors.length === 0 && opts.allowSelfSigned !== true) {
    return {
      ok: false,
      failure: 'UNTRUSTED_ISSUER',
      detail:
        'Untrusted issuer: this gate holds no trust anchors. Supply trustedIssuers, or set allowSelfSigned to accept self-signed passports.',
      errors: result.errors,
      warnings,
    }
  }

  return { ok: true, errors: result.errors, warnings }
}
