// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Provisional Statement — promoteStatement, processDeadMan
// ══════════════════════════════════════════════════════════════════

import { canonicalize } from '../../core/canonical.js'
import { createHybridTimestamp } from '../../core/time.js'
import type { HybridTimestamp } from '../../types/time.js'
import type {
  ProvisionalStatement,
  PromotionEvent,
  PromotionPolicy,
  PromotionKind,
  PrincipalDID,
  AgentDID,
} from './types.js'
import { verifyPromotion } from './verify.js'

/** Canonical payload a promoter signs. Verifiers reconstruct this to
 *  check PromotionEvent.promoter_signature. */
export function promotionSigningPayload(opts: {
  statement_id: string
  kind: PromotionKind
  promoted_at: HybridTimestamp
  promoter: PrincipalDID | AgentDID
  policy_reference: string
}): string {
  return canonicalize({
    statement_id: opts.statement_id,
    kind: opts.kind,
    promoted_at: opts.promoted_at,
    promoter: opts.promoter,
    policy_reference: opts.policy_reference,
  })
}

/** Promote a provisional statement into binding status. The caller
 *  provides a PromotionEvent that must satisfy the PromotionPolicy
 *  (see verifyPromotion). Dead-man elapsed events do NOT promote —
 *  use processDeadMan for that path, which sets status to "withdrawn". */
export function promoteStatement(
  statement: ProvisionalStatement,
  promotion_event: PromotionEvent,
  policy: PromotionPolicy,
): ProvisionalStatement {
  if (statement.status === 'promoted') {
    throw new Error('Statement already promoted')
  }
  if (statement.status === 'withdrawn') {
    throw new Error('Cannot promote a withdrawn statement')
  }
  if (promotion_event.kind === 'dead_man_elapsed') {
    throw new Error('dead_man_elapsed does not promote — use processDeadMan (auto-withdraw)')
  }

  const candidate: ProvisionalStatement = {
    ...statement,
    status: 'promoted',
    promotion: promotion_event,
  }

  const result = verifyPromotion(candidate, policy)
  if (!result.valid) {
    throw new Error(`Promotion rejected: ${result.errors.join('; ')}`)
  }
  return candidate
}

/** If the dead-man deadline has elapsed on a still-provisional
 *  statement, transition it to "withdrawn". Absence of confirmation is
 *  not consent. Idempotent on already-terminal statements. */
export function processDeadMan(
  statement: ProvisionalStatement,
  opts: { now?: number; gatewayId?: string } = {},
): ProvisionalStatement {
  if (statement.status !== 'provisional') return statement
  if (!statement.dead_man_expires_at) return statement

  const now = opts.now ?? Date.now()
  // Conservative: only fire if we are definitely past the latest bound.
  if (now <= statement.dead_man_expires_at.wallClockLatest) return statement

  const event: PromotionEvent = {
    kind: 'dead_man_elapsed',
    promoted_at: createHybridTimestamp(opts.gatewayId ?? statement.dead_man_expires_at.gatewayId),
    promoter: 'system:dead_man',
    promoter_signature: '',
    policy_reference: 'dead_man_timer',
  }

  return { ...statement, status: 'withdrawn', promotion: event }
}
