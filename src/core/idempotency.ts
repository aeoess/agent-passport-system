// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Commerce Idempotency Key
// ══════════════════════════════════════════════════════════════════
// Content-addressed hash for commerce dedup. Deliberately EXCLUDES
// timestamp so that identical retry attempts produce the same key.
//
// Contrast with computeActionRef() which INCLUDES timestamp —
// action_ref is for receipt identity, idempotency key is for dedup.
//
// NOTE: this computes a key only. It provides NO replay or double-spend
// protection on its own. The key is a no-op unless the caller pairs it with a
// store that records issued keys and rejects a repeat (the dedup store lives in
// the gateway, not this stateless SDK). Treating an action as deduplicated on
// the strength of key generation alone is the same trap as reading a spend
// counter that nothing writes.
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
