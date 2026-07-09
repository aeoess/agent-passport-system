// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Payment Rails — canonical V2Delegation scope resolution
// ══════════════════════════════════════════════════════════════════
// Centralized field-name resolution shared across all binding-adapter
// rails (AP2, x402, Stripe-Issuing, ACP, MPP). A delegation that
// satisfies any one rail's spend cap MUST satisfy all of them; this
// module is the single source of truth that guarantees that
// invariant. Per-rail duplicate logic is forbidden — every rail
// reaches the cap through `resolveSpendLimitCents()`.
//
// Why three sources? Real-world V2Delegation objects arrive in three
// idiomatic shapes:
//
//   1. Numeric explicit:    scope.resource_limits.spend_limit_cents
//   2. AP2-mandate alias:   scope.resource_limits['commerce.spend_limit']
//   3. String constraint:   scope.constraints.spend_limit_cents (CSV-friendly)
//
// (1) is preferred and canonical. (2) exists because AP2 mandates
// historically used a dotted-key namespace and we need to honor
// delegations built around that convention without forcing a
// migration. (3) exists because some delegation issuance paths
// (form fields, CLI flags, JSON Schema with stringly typed values)
// emit numbers as strings and we'd rather parse them once at the
// boundary than fail silently.
//
// Resolution returns `null` for absent / malformed; callers MUST
// treat null as "no cap configured, deny by default" — never as
// "unlimited spend permitted." This is a financial-grade invariant.
// ══════════════════════════════════════════════════════════════════

import type { V2Delegation } from '../types.js'

/**
 * Resolve the spend cap (in minor currency units, typically cents)
 * a V2Delegation imposes on the calling rail.
 *
 * Resolution order — first match wins:
 *   1. `scope.resource_limits[canonicalKey]` if a finite non-negative number
 *   2. `scope.resource_limits['commerce.spend_limit']` if a finite non-negative number
 *      (skipped when canonicalKey already equals 'commerce.spend_limit')
 *   3. `Number(scope.constraints.spend_limit_cents)` if the string parses
 *      to a finite non-negative number
 *
 * Returns `null` when no cap is found OR all sources contain
 * malformed values. Callers MUST NOT treat null as unlimited.
 *
 * @param delegation  V2Delegation to inspect
 * @param opts.canonicalKey  Override the primary resource_limits key.
 *   Defaults to `'spend_limit_cents'`. AP2 passes `'commerce.spend_limit'`.
 */
export function resolveSpendLimitCents(
  delegation: V2Delegation,
  opts: { canonicalKey?: string } = {},
): number | null {
  const limits = delegation.scope?.resource_limits ?? {}
  const constraints = delegation.scope?.constraints ?? {}
  const canonicalKey = opts.canonicalKey ?? 'spend_limit_cents'

  // (1) canonical numeric key
  const v1 = limits[canonicalKey]
  if (_isUsableNumber(v1)) return v1 as number

  // (2) AP2 alias 'commerce.spend_limit' (skip if canonical IS that key)
  if (canonicalKey !== 'commerce.spend_limit') {
    const v2 = limits['commerce.spend_limit']
    if (_isUsableNumber(v2)) return v2 as number
  }

  // (3) string fallback in constraints
  const v3 = constraints.spend_limit_cents
  if (typeof v3 === 'string' && v3.length > 0) {
    const parsed = Number(v3)
    if (_isUsableNumber(parsed)) return parsed
  }

  return null
}

function _isUsableNumber(v: unknown): boolean {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0
}
