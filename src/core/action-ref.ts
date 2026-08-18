// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
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

import { normalizeTimestamp } from './canonical.js'
import { canonicalHashJCS } from './canonical-jcs.js'
import type { ActionIntent } from '../types/policy.js'

/**
 * Intent shape accepted by computeActionRef. Identical to the ActionIntent
 * pick except that scopeRequired additionally admits a readonly string array,
 * the form draft-pidlisnyi-aps-03 §4.1 defines for the native preimage.
 * ActionIntent itself still types scopeRequired as a single string; widening
 * that type is outside this module (see types/policy.ts).
 */
export type ActionRefIntent =
  Omit<Pick<ActionIntent, 'agentId' | 'action' | 'createdAt'>, 'action'> & {
    action: Omit<ActionIntent['action'], 'scopeRequired'> & {
      scopeRequired: ActionIntent['action']['scopeRequired'] | readonly string[]
    }
  }

/** Raised when scopeRequired carries two elements that are equal after NFC
 *  normalization. draft-pidlisnyi-aps-03 §4.1 defines scope_required as a
 *  duplicate-free array, so a duplicated array has no canonical form and is
 *  rejected rather than deduplicated: an equality key must not map distinct
 *  inputs onto one value silently. Subclasses the built-in Error so any
 *  existing handler that catches Error (or `catch (e)`) still catches it and
 *  fails closed. */
export class DuplicateScopeRequiredError extends Error {
  readonly code = 'ERR_DUPLICATE_SCOPE_REQUIRED'
  /** Stable machine-readable category, shared across the APS SDKs. */
  readonly category = 'invalid_scope_required'
  /** Specific failure within the category. */
  readonly reason = 'duplicate_scope_required'
  constructor(message: string) {
    super(message)
    this.name = 'DuplicateScopeRequiredError'
  }
}

/**
 * Compare two strings by Unicode code point, per §4.1's sort requirement.
 * The JS default sort compares UTF-16 code units, which orders astral-plane
 * characters (surrogate pairs, lead units 0xD800..0xDBFF) BEFORE code points
 * in U+E000..U+FFFF; code-point order puts them after. Iterates codePointAt
 * so surrogate pairs compare as their true code points.
 */
function compareCodePoints(a: string, b: string): number {
  let i = 0
  let j = 0
  while (i < a.length && j < b.length) {
    const ca = a.codePointAt(i) as number
    const cb = b.codePointAt(j) as number
    if (ca !== cb) return ca - cb
    i += ca > 0xffff ? 2 : 1
    j += cb > 0xffff ? 2 : 1
  }
  return (a.length - i) - (b.length - j)
}

/**
 * Canonicalize scopeRequired per draft-pidlisnyi-aps-03 §4.1 before hashing:
 * NFC-normalize each scope string, reject duplicates, then sort the array by
 * Unicode code point. Operates on a copy; never mutates the caller's array.
 * The single-string form (the current ActionIntent type) is NFC-normalized;
 * null/undefined and any non-conforming shape (non-string elements) pass
 * through unchanged so the strict-JCS null-preservation contract and legacy
 * behavior for out-of-spec input both hold.
 *
 * §4.1 defines scope_required as a duplicate-free array. Duplicates are
 * detected AFTER normalization, so two spellings that collide only under NFC
 * (U+00E9 and "e" + U+0301) reject as well. Rejection rather than dedupe:
 * silently collapsing ["a","a"] to ["a"] would map two distinct inputs onto
 * one identity with no error, and would change the identity previously
 * computed for the duplicated input. Valid arrays are byte-unchanged.
 */
function canonicalizeScopeRequired(scope: unknown): unknown {
  if (typeof scope === 'string') return scope.normalize('NFC')
  if (Array.isArray(scope) && scope.every((s) => typeof s === 'string')) {
    const normalized = (scope as string[]).map((s) => s.normalize('NFC'))
    const seen = new Set<string>()
    for (const s of normalized) {
      if (seen.has(s)) {
        throw new DuplicateScopeRequiredError(
          'computeActionRef: scope_required contains duplicate elements after NFC ' +
            `normalization (duplicate_scope_required): ${JSON.stringify(s)}`,
        )
      }
      seen.add(s)
    }
    return normalized.sort(compareCodePoints)
  }
  return scope
}

/**
 * Compute the content-addressed request identity for an ActionIntent.
 *
 * Inputs hashed: agentId, action.type, action.scopeRequired, normalized timestamp.
 * Timestamp defaults to intent.createdAt; falls back to current time.
 *
 * scopeRequired is canonicalized per draft-pidlisnyi-aps-03 §4.1 before
 * hashing: each scope string is NFC-normalized and, when scopeRequired is an
 * array, the array is sorted by Unicode code point. No case folding; scopes
 * that differ only in case stay distinct.
 *
 * Throws DuplicateScopeRequiredError when an array scopeRequired holds two
 * elements equal after NFC normalization. The throw happens inside
 * canonicalization, before the digest is computed, so a duplicated array can
 * never present as an identity mismatch downstream: there is no action_ref to
 * compare in the first place.
 *
 * Canonicalization follows RFC 8785 JCS strictly, per draft-pidlisnyi-aps-01
 * §4.1: null-valued keys are preserved (not stripped) so that two APS engines
 * independently hashing the same request produce the same action_ref. As of
 * #101 an `undefined` member is rejected rather than coerced to null, because
 * undefined is not a JSON value; a caller that means the JSON null passes an
 * explicit null. This is the APS-native form. Cross-ecosystem byte-parity with
 * independent implementations (x402, AgentGraph CTEF, Nobulex) is provided by
 * a separate primitive, computeExternalActionRefV1 in external-action-ref.js,
 * which uses an intentionally different preimage; see that file and
 * docs/specs/action-ref-v1.md.
 *
 * Returns: lowercase hex SHA-256 digest.
 */
export function computeActionRef(intent: ActionRefIntent): string {
  const ts = intent.createdAt ?? new Date().toISOString()
  return canonicalHashJCS({
    agentId: intent.agentId,
    actionType: intent.action.type,
    scopeRequired: canonicalizeScopeRequired(intent.action.scopeRequired),
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
