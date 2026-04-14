// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Provisional Statement — verifyPromotion
// ══════════════════════════════════════════════════════════════════

import { verify } from '../../crypto/keys.js'
import type {
  ProvisionalStatement,
  PromotionPolicy,
  PromotionVerifyResult,
} from './types.js'
import { verifyAuthorSignature } from './create.js'
import { promotionSigningPayload } from './promote.js'

/** Verify that a statement's PromotionEvent cryptographically satisfies
 *  the given PromotionPolicy. Checks:
 *    - status is "promoted"
 *    - author_signature still verifies (no post-promotion tampering)
 *    - promotion.policy_reference matches policy.id
 *    - promoter is one of policy.required_signers
 *    - promoter_signature verifies against the promoter DID
 *    - threshold is satisfied (a single event counts as one signer)
 *    - promoted_at is within max_time_to_promote of created_at
 *    - kind is signature-based (not dead_man_elapsed) */
export function verifyPromotion(
  statement: ProvisionalStatement,
  policy: PromotionPolicy,
): PromotionVerifyResult {
  const errors: string[] = []

  if (statement.status !== 'promoted') {
    errors.push(`Status is "${statement.status}", expected "promoted"`)
  }
  const promotion = statement.promotion
  if (!promotion) {
    errors.push('No promotion event attached')
    return { valid: false, errors }
  }

  // Author signature still intact (guards against post-promotion tampering).
  if (!verifyAuthorSignature(statement)) {
    errors.push('Author signature invalid — statement tampered with')
  }

  if (promotion.kind === 'dead_man_elapsed') {
    errors.push('dead_man_elapsed is not a binding promotion kind')
  }

  if (promotion.policy_reference !== policy.id) {
    errors.push(
      `policy_reference "${promotion.policy_reference}" does not match policy "${policy.id}"`,
    )
  }

  // Promoter must be one of the declared required signers.
  const promoterAuthorized = policy.required_signers.includes(promotion.promoter)
  if (!promoterAuthorized) {
    errors.push(`Promoter "${promotion.promoter}" is not in policy.required_signers`)
  }

  // m-of-n: a single PromotionEvent contributes exactly one signature.
  if (policy.threshold > 1) {
    errors.push(
      `Threshold ${policy.threshold} not satisfied — only one signature present`,
    )
  }
  if (policy.threshold < 1) {
    errors.push(`Policy threshold must be >= 1 (got ${policy.threshold})`)
  }

  // Signature check.
  const payload = promotionSigningPayload({
    statement_id: statement.id,
    kind: promotion.kind,
    promoted_at: promotion.promoted_at,
    promoter: promotion.promoter,
    policy_reference: promotion.policy_reference,
  })
  if (!promotion.promoter_signature) {
    errors.push('Missing promoter signature')
  } else if (!verify(payload, promotion.promoter_signature, promotion.promoter)) {
    errors.push('Promoter signature invalid')
  }

  // Temporal bound — conservative on both sides.
  const createdLatest = statement.created_at.wallClockLatest
  const promotedEarliest = promotion.promoted_at.wallClockEarliest
  const elapsed = promotedEarliest - createdLatest
  if (elapsed > policy.max_time_to_promote) {
    errors.push(
      `Promotion exceeded max_time_to_promote (${elapsed}ms > ${policy.max_time_to_promote}ms)`,
    )
  }

  // Dead-man deadline — a statement must not be promoted after its
  // dead-man expiry, because the expiry means withdrawal.
  if (statement.dead_man_expires_at) {
    if (promotedEarliest > statement.dead_man_expires_at.wallClockLatest) {
      errors.push('Promotion after dead_man_expires_at — statement already auto-withdrawn')
    }
  }

  return { valid: errors.length === 0, errors }
}
