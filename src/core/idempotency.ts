// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Commerce Idempotency Key
// ══════════════════════════════════════════════════════════════════
// Content-addressed hash for commerce dedup. Deliberately EXCLUDES
// timestamp so that identical retry attempts produce the same key.
//
// Contrast with computeActionRef() which INCLUDES timestamp —
// action_ref is for receipt identity, idempotency key is for dedup.
// ══════════════════════════════════════════════════════════════════

import { canonicalHash } from './canonical.js'

export function computeIdempotencyKey(params: {
  agentId: string
  scope: string
  target: string
  amount?: { amount: number; currency: string }
}): string {
  return canonicalHash({
    agentId: params.agentId,
    scope: params.scope,
    target: params.target,
    ...(params.amount && { amount: params.amount }),
  })
}
