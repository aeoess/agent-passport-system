// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// action_ref — Content-Addressed Request Identity
// ══════════════════════════════════════════════════════════════════
// Thread claim (A2A#1672, xsa520/desiorac):
//   action_ref     = request identity = SHA-256(canonical(agentId + actionType + scope + timestamp))
//   compoundDigest = decision identity (evaluated) — already on PolicyReceipt
//
// Two receipts with the same action_ref describe the same request.
// Two receipts with the same compound_digest describe the same evaluated
// decision. Equivalence for cross-verifier replay is over compound_digest,
// invariant to verification method.
//
// Timestamps are normalized to ISO 8601 second-precision UTC so that two
// systems independently hashing the same request within the same second
// produce the same action_ref.
// ══════════════════════════════════════════════════════════════════

import { canonicalHash, normalizeTimestamp } from './canonical.js'
import type { ActionIntent } from '../types/policy.js'

/**
 * Compute the content-addressed request identity for an ActionIntent.
 *
 * Inputs hashed: agentId, action.type, action.scopeRequired, normalized timestamp.
 * Timestamp defaults to intent.createdAt; falls back to current time.
 *
 * Returns: lowercase hex SHA-256 digest.
 */
export function computeActionRef(intent: Pick<ActionIntent, 'agentId' | 'action' | 'createdAt'>): string {
  const ts = intent.createdAt ?? new Date().toISOString()
  return canonicalHash({
    agentId: intent.agentId,
    actionType: intent.action.type,
    scopeRequired: intent.action.scopeRequired,
    timestamp: normalizeTimestamp(ts),
  })
}

/**
 * Two receipts with the same action_ref describe the same request.
 * Simple equality check — provided as a named predicate so the semantic
 * intent is explicit at the call site.
 */
export function actionRefsMatch(a: string, b: string): boolean {
  return typeof a === 'string' && typeof b === 'string' && a.length > 0 && a === b
}
