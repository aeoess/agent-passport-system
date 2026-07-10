// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Verification source, builder and validator
// ══════════════════════════════════════════════════════════════════
// Two single-purpose helpers. buildVerificationSource constructs a record
// and refuses to construct an invalid one. validateVerificationSource
// checks a record somebody else constructed. There is no aggregation, no
// scoring, and no analytics here: judging acquisition posture is relying-
// party policy and stays outside the protocol surface.
// ══════════════════════════════════════════════════════════════════

import type { VerificationSource, VerificationSourceValidation } from './types.js'

export type { VerificationSource, VerificationSourceValidation } from './types.js'

/**
 * Validate a VerificationSource. Fail closed.
 *
 * Rules, all mechanical:
 *   - verified_at_ms must be a finite number greater than zero.
 *   - 'resolver' requires resolver_origin, an https:// origin string.
 *   - 'pinned' requires BOTH pin_populated_at_ms (finite, > 0, not later
 *     than verified_at_ms) and pin_populated_via. A pin that cannot say
 *     what populated it carries no usable posture, so it is invalid
 *     rather than silently treated as fresh.
 *   - 'inline' must not carry resolver_origin or the pin fields; method-
 *     mismatched fields are a malformed record, not extra detail.
 *   - pin_populated_via on a non-pinned method is invalid, likewise
 *     resolver_origin on a non-resolver method.
 */
export function validateVerificationSource(source: VerificationSource): VerificationSourceValidation {
  const reasons: string[] = []

  if (typeof source.verified_at_ms !== 'number' || !Number.isFinite(source.verified_at_ms) || source.verified_at_ms <= 0) {
    reasons.push('verified_at_ms must be a finite epoch-millisecond number greater than zero')
  }

  if (source.method !== 'inline' && source.method !== 'pinned' && source.method !== 'resolver') {
    reasons.push('method must be one of inline, pinned, resolver')
    return { valid: false, reasons }
  }

  if (source.method === 'resolver') {
    if (typeof source.resolver_origin !== 'string' || !source.resolver_origin.startsWith('https://')) {
      reasons.push('resolver method requires resolver_origin, an https:// origin')
    }
    if (source.pin_populated_at_ms !== undefined || source.pin_populated_via !== undefined) {
      reasons.push('pin population fields are only valid on a pinned source')
    }
  }

  if (source.method === 'pinned') {
    if (typeof source.pin_populated_at_ms !== 'number' || !Number.isFinite(source.pin_populated_at_ms) || source.pin_populated_at_ms <= 0) {
      reasons.push('pinned method requires pin_populated_at_ms, a finite epoch-millisecond number greater than zero')
    } else if (typeof source.verified_at_ms === 'number' && source.pin_populated_at_ms > source.verified_at_ms) {
      reasons.push('pin_populated_at_ms must not be later than verified_at_ms')
    }
    if (source.pin_populated_via !== 'inline' && source.pin_populated_via !== 'resolver') {
      reasons.push('pinned method requires pin_populated_via, the method that populated the pin (inline or resolver)')
    }
    if (source.resolver_origin !== undefined) {
      reasons.push('resolver_origin is only valid on a resolver source')
    }
  }

  if (source.method === 'inline') {
    if (source.resolver_origin !== undefined) {
      reasons.push('resolver_origin is only valid on a resolver source')
    }
    if (source.pin_populated_at_ms !== undefined || source.pin_populated_via !== undefined) {
      reasons.push('pin population fields are only valid on a pinned source')
    }
  }

  return { valid: reasons.length === 0, reasons }
}

/**
 * Construct a VerificationSource, refusing invalid combinations. The
 * returned object carries ONLY the keys appropriate to the method, so a
 * record built here never introduces explicitly-undefined keys into a
 * canonicalization path.
 */
export function buildVerificationSource(input: {
  method: 'inline' | 'pinned' | 'resolver'
  verified_at_ms: number
  resolver_origin?: string
  pin_populated_at_ms?: number
  pin_populated_via?: 'inline' | 'resolver'
}): VerificationSource {
  const source: VerificationSource = {
    method: input.method,
    verified_at_ms: input.verified_at_ms,
    ...(input.resolver_origin !== undefined ? { resolver_origin: input.resolver_origin } : {}),
    ...(input.pin_populated_at_ms !== undefined ? { pin_populated_at_ms: input.pin_populated_at_ms } : {}),
    ...(input.pin_populated_via !== undefined ? { pin_populated_via: input.pin_populated_via } : {}),
  }
  const check = validateVerificationSource(source)
  if (!check.valid) {
    throw new Error(`buildVerificationSource: ${check.reasons.join('; ')}`)
  }
  return source
}
