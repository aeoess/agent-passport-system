// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
/**
 * @fileoverview Audience-binding verification primitives.
 *
 * ── PROOF BOX ──────────────────────────────────────────────────────────────
 * What a passing audience check PROVES:
 *   The issuer named this relying party (by its `recipientId`) among the
 *   intended recipients of the proof. A proof minted for recipient A is
 *   rejected when checked against recipient B.
 *
 * What it does NOT prove:
 *   - It does NOT prove the proof is otherwise valid. Audience is one facet;
 *     the signature, freshness, scope, and revocation checks are separate and
 *     must all pass independently.
 *   - It does NOT prevent a NAMED recipient from misusing what it legitimately
 *     received. Audience binding restricts WHO may present a proof, not what a
 *     legitimate holder does with it afterward.
 *   - It is NOT an assurance scalar. The status is a mechanical fact about
 *     recipient-identifier membership, derived by the verifier from its own
 *     policy, never read from the proof.
 * ───────────────────────────────────────────────────────────────────────────
 *
 * The membership algorithm reuses the array-normalize + `includes` pattern
 * already established by jwtSvidToDidInput in src/adapters/oauth-rfc8693, and
 * the `expectedAudience`/`recipientId` naming so request-level and proof-level
 * audience reads consistently across the SDK.
 */

import { AUDIENCE_BINDING_PROFILE } from './types.js'
import type {
  AudienceBinding,
  AudienceCheckResult,
  AudiencePolicy,
} from './types.js'

/**
 * A proof object that may carry an additive `aud` binding. Both V2Delegation
 * and BilateralReceipt structurally satisfy this once their optional `aud`
 * slot is populated; this interface keeps the primitive decoupled from either
 * concrete proof type.
 */
export interface AudienceBearer {
  aud?: AudienceBinding
}

/**
 * Normalize an audience value to a recipient-id array, mirroring the OAuth
 * adapter's `Array.isArray(claims.aud) ? claims.aud : [claims.aud]` shape.
 * Returns null when the binding is malformed (absent recipients, empty set,
 * or a non-string member). Callers treat null as `audience_malformed`.
 */
export function normalizeRecipients(aud: AudienceBinding | undefined | null): string[] | null {
  if (aud === undefined || aud === null) return null
  if (typeof aud !== 'object') return null
  if (aud.profile !== AUDIENCE_BINDING_PROFILE) return null
  if (!Array.isArray(aud.recipients)) return null
  if (aud.recipients.length === 0) return null
  for (const r of aud.recipients) {
    if (typeof r !== 'string' || r.length === 0) return null
  }
  return aud.recipients
}

/**
 * Membership test: is `recipientId` among the proof's named recipients? Reuses
 * the same normalize-then-`includes` membership check as the OAuth adapter's
 * expectedAudience path. Returns false for a malformed or absent binding.
 */
export function matchAudience(
  aud: AudienceBinding | undefined,
  recipientId: string,
): boolean {
  const recipients = normalizeRecipients(aud)
  if (recipients === null) return false
  return recipients.includes(recipientId)
}

/**
 * Evaluate the audience facet of a proof against a relying-party policy.
 *
 * Returns a four-valued result consistent with the Belnap ConstraintStatus
 * lattice. The mapping:
 *   - bound + member            → pass  / audience_match
 *   - bound + not a member      → fail  / audience_mismatch
 *   - bound + malformed         → fail  / audience_malformed
 *   - unbound + required        → fail  / audience_required_absent
 *   - unbound + not required    → not_applicable / audience_unbound
 *   - no recipientId in policy  → unknown / audience_unknown
 *
 * Fail-closed: any malformed binding is a failure, never a silent pass.
 */
export function checkAudience(
  proof: AudienceBearer,
  policy: AudiencePolicy,
): AudienceCheckResult {
  // Without a relying-party identity there is nothing to check membership
  // against. Report unknown rather than guessing.
  if (typeof policy.recipientId !== 'string' || policy.recipientId.length === 0) {
    return {
      status: 'unknown',
      reason: 'audience_unknown',
      message: 'No recipientId in policy; audience membership cannot be evaluated.',
    }
  }

  // Optional chaining and the null check below keep this fail-closed on
  // untrusted JSON: a null proof, or an explicit `aud: null` (which a JSON
  // body can carry), is treated as unbound rather than throwing a TypeError.
  const aud = proof?.aud

  // Unbound proof.
  if (aud === undefined || aud === null) {
    if (policy.requireAudience === true) {
      return {
        status: 'fail',
        reason: 'audience_required_absent',
        checkedAgainst: policy.recipientId,
        message: 'Policy requires an audience binding but the proof has none.',
      }
    }
    return {
      status: 'not_applicable',
      reason: 'audience_unbound',
      checkedAgainst: policy.recipientId,
      message: 'Proof is audience-unbound and the policy does not require binding.',
    }
  }

  // Bound proof: normalize and check membership.
  const recipients = normalizeRecipients(aud)
  if (recipients === null) {
    return {
      status: 'fail',
      reason: 'audience_malformed',
      checkedAgainst: policy.recipientId,
      message: 'Audience binding is present but malformed (empty or ill-formed recipients).',
    }
  }

  if (recipients.includes(policy.recipientId)) {
    return {
      status: 'pass',
      reason: 'audience_match',
      recipients,
      checkedAgainst: policy.recipientId,
      message: 'Relying party is a named recipient of this proof.',
    }
  }

  return {
    status: 'fail',
    reason: 'audience_mismatch',
    recipients,
    checkedAgainst: policy.recipientId,
    message: 'Relying party is not among the named recipients of this proof.',
  }
}

/**
 * Construct an audience binding for the given recipient(s). A convenience
 * builder so issuers attach a well-formed, versioned slot. Throws on an empty
 * recipient set so a meaningless binding is never minted.
 */
export function bindAudience(recipients: string | string[]): AudienceBinding {
  const list = Array.isArray(recipients) ? recipients : [recipients]
  if (list.length === 0) {
    throw new Error('refusing to bind an empty audience')
  }
  for (const r of list) {
    if (typeof r !== 'string' || r.length === 0) {
      throw new Error('audience recipient identifiers must be non-empty strings')
    }
  }
  return { profile: AUDIENCE_BINDING_PROFILE, recipients: list }
}
