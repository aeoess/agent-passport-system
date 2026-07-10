// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// APS Composition Check Receipt v0: the stateless ANCHOR verifier.
//
// It verifies the SIGNED REFERENCE only. It evaluates NO policy, runs NO check, computes
// NO aggregate, and has NO notion of what "unsafe" means. It checks: (1) signature under
// a trusted attestor key, (2) binding to the expected (chain, action, context), (3) the
// attestor is trusted for every named policy_profile_id (string identity only), (4)
// freshness against a caller-supplied now_ms (no clock read), (5) well-formedness (profile
// tag, every result in the fixed enum, one result per check), and (6) SURFACES independence
// corroborated from the trust context. It returns the per-check results verbatim and NEVER
// an aggregate "safe". Verifying a signature is not verifying composition-safety; this is an
// anchor verifier, named honestly.

import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import { verify as edVerify } from '../../crypto/keys.js'
import {
  COMPOSITION_CHECK_PROFILE,
  COMPOSITION_CHECK_TAG,
  COMPOSITION_CHECK_RESULTS,
} from './types.js'
import type {
  CompositionCheckReceipt,
  CompositionCheckVerificationContext,
  CompositionCheckVerifyResult,
  CompositionCheckResult,
} from './types.js'

const VALID_RESULTS = new Set<string>(COMPOSITION_CHECK_RESULTS)

/**
 * The exact bytes an attestor signs: the domain-separation tag, then strict RFC 8785 JCS
 * of the receipt with its `signature` field removed. Exported so an independent attestor
 * can reproduce the signing convention byte for byte. This is an envelope helper: it does
 * no policy evaluation and carries no detection logic.
 */
export function compositionCheckSigningPayload(
  receipt: Omit<CompositionCheckReceipt, 'signature'> & { signature?: string },
): string {
  const copy: Record<string, unknown> = { ...receipt }
  delete copy.signature
  return `${COMPOSITION_CHECK_TAG}.${canonicalizeJCS(copy)}`
}

function sigOk(payload: string, sig: string | undefined, pubkey: string | undefined): boolean {
  if (!sig || !pubkey) return false
  try {
    return edVerify(payload, sig, pubkey)
  } catch {
    return false
  }
}

/**
 * Verify a CompositionCheckReceipt against a caller-supplied trust context. Returns the
 * anchor verdict, the failed checks, the surfaced per-check results, and a corroborated
 * independence flag. It NEVER returns "safe": downstream decides whether the named profiles
 * and the independence class meet its risk bar.
 */
export function verifyCompositionCheck(
  receipt: CompositionCheckReceipt,
  ctx: CompositionCheckVerificationContext,
): CompositionCheckVerifyResult {
  const violations: string[] = []

  const attestor = ctx.trusted_attestors?.[receipt.attestor_key_id]

  // 1. signature valid under attestor_key_id (only a trusted key carries a public key here).
  const payload = compositionCheckSigningPayload(receipt)
  if (!sigOk(payload, receipt.signature, attestor?.publicKey)) violations.push('signature')

  // 2. bound to THIS chain_hash / action_ref / context_hash.
  if (receipt.chain_hash !== ctx.expected_chain_hash) violations.push('chain_binding')
  if (receipt.action_ref !== ctx.expected_action_ref) violations.push('action_binding')
  if (receipt.context_hash !== ctx.expected_context_hash) violations.push('context_binding')

  // 3. attestor recognized AND trusted for EVERY named policy profile (string identity only).
  if (!attestor) {
    violations.push('attestor_not_trusted')
  } else {
    const covered = new Set(attestor.profiles ?? [])
    const uncovered = (receipt.policy_profile_ids ?? []).filter((p) => !covered.has(p))
    if (uncovered.length > 0) violations.push('attestor_not_trusted_for_profiles')
  }

  // 4. freshness: issued_at <= now <= expires_at. now_ms is caller-supplied; no clock read.
  //    Fail CLOSED on a non-finite now_ms (undefined/NaN from a loose caller): comparisons
  //    against it would silently be false and let an expired receipt through.
  const issuedMs = Date.parse(receipt.issued_at)
  const expiresMs = Date.parse(receipt.expires_at)
  const nowFinite = Number.isFinite(ctx.now_ms)
  const tsFinite = Number.isFinite(issuedMs) && Number.isFinite(expiresMs)
  if (!nowFinite) violations.push('now_malformed')
  if (!tsFinite) violations.push('timestamp_malformed')
  if (nowFinite && tsFinite) {
    if (ctx.now_ms < issuedMs) violations.push('not_yet_valid')
    else if (ctx.now_ms > expiresMs) violations.push('expired')
  }

  // 5. well-formedness: correct profile tag, every result from the fixed enum, one result
  //    per check. The VALUES (pass/fail/...) are never aggregated, only validated as members.
  if (receipt.profile !== COMPOSITION_CHECK_PROFILE) violations.push('profile_mismatch')
  const results = receipt.result_per_check ?? []
  if (!Array.isArray(results) || !results.every((r) => VALID_RESULTS.has(r as string))) {
    violations.push('result_enum')
  }
  if ((receipt.checks_run?.length ?? 0) !== results.length) {
    violations.push('result_count_mismatch')
  }

  // 6. independence: SURFACE it, corroborated from the trust context AND gated on the
  //    receipt itself anchor-verifying. A self-declared 'independent_registered' the context
  //    does not back is downgraded; and an independent attestor on a receipt that FAILS the
  //    anchor (expired, tampered, mis-bound) is not a usable second anchor either, so a
  //    consumer reading this flag alone cannot be misled. Downgraded here, never upgraded.
  //    (attestor_independence_class is still echoed below as the raw claimed class.)
  const anchorOk = violations.length === 0
  const claimedIndependent = receipt.attestor_independence_class === 'independent_registered'
  const contextIndependent = !!attestor && attestor.registered_by_operator === false
  const independence_is_second_anchor = anchorOk && claimedIndependent && contextIndependent

  return {
    profile: COMPOSITION_CHECK_PROFILE,
    anchor_verified: anchorOk,
    violations,
    policy_profile_ids: receipt.policy_profile_ids ?? [],
    checks_run: receipt.checks_run ?? [],
    result_per_check: results as CompositionCheckResult[],
    attestor_key_id: receipt.attestor_key_id,
    attestor_independence_class: receipt.attestor_independence_class,
    independence_is_second_anchor,
    issued_at: receipt.issued_at,
    expires_at: receipt.expires_at,
  }
}
