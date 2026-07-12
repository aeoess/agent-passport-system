// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// isRecord — shared non-object input guard for bare verifiers
// ══════════════════════════════════════════════════════════════════
// Exported verifiers take attacker-deliverable input (a JSON literal a
// relying party feeds straight in). The JSON literal `null`, or a bare
// `undefined`, would make a verifier throw a TypeError on its first
// property access or destructuring rather than returning its normal
// reject verdict. A verifier that throws instead of rejecting is a
// denial-of-service and fail-open hazard: the caller's `catch` path is
// not the verifier's `{ valid: false }` path.
//
// This is the single predicate every affected entry uses to fold
// null / undefined / primitives / arrays into that verifier's EXISTING
// reject shape. It intentionally excludes arrays: an array is never a
// well-formed receipt/passport/delegation object.
// ══════════════════════════════════════════════════════════════════

/** True iff `v` is a non-null, non-array object (a plain record). */
export function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}
