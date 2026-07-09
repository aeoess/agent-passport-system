// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Conformance runner - canonicalization vectors + receipt golden corpus
// ══════════════════════════════════════════════════════════════════
// A general-purpose conformance runner for the two cross-implementation
// byte anchors the protocol ships:
//
//   1. CANONICALIZATION vectors - the RFC 8785 JCS and legacy variant
//      expectations (specs/test-vectors-canonicalization.json, mirrored by
//      getTestVectors()). A conformant implementation MUST produce the
//      exact expected_jcs and expected_legacy strings AND the exact
//      sha256_jcs / sha256_legacy digests. A SINGLE-BYTE divergence fails.
//
//   2. RECEIPT golden corpus - the golden valid receipt verifies clean
//      and every negative is rejected for its stated reason, by the
//      shipped crypto + context verifier. (Consumed at merge; see the
//      runner CLI for the on-disk fixture path.)
//
// The runner is the engine; the CLI (scripts/aps-conformance.mjs) and the
// CI workflow are thin wrappers. Report field names mirror
// ConformanceSuiteResult from src/conformance/suite.ts
// (passed/failed/total/categories/tests/summary/durationMs) so existing
// tooling reads it without a new schema.
//
// SCOPE OF CLAIM (dogfooded):
//   Proves: this implementation's canonicalizer produces byte-identical
//     output to the pinned vectors, and the cited receipt verifier agrees
//     with the golden corpus.
//   Does NOT prove: that a different implementation is correct (it must
//     run its own canonicalizer against the same vectors), nor anything
//     about a real-world action a receipt describes.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS, getTestVectors } from '../../core/canonical-jcs.js'
import type { CanonicalizationTestVector } from '../../core/canonical-jcs.js'
import { canonicalize } from '../../core/canonical.js'

// ── Result shape, mirroring ConformanceSuiteResult ──────────────────

export interface ConformanceCheck {
  id: string
  category: string
  name: string
  spec?: string
  passed: boolean
  /** First divergence detail when failed. Non-authoritative on pass. */
  detail?: string
  durationMs: number
}

export interface ConformanceRunnerResult {
  passed: number
  failed: number
  total: number
  categories: Record<string, { passed: number; failed: number }>
  tests: ConformanceCheck[]
  summary: string
  durationMs: number
  /** True iff every check passed. Convenience for an exit code. */
  allPass: boolean
}

function sha256hex(input: string): string {
  return createHash('sha256').update(input, 'utf-8').digest('hex')
}

/** Index of the first byte (UTF-8 code unit) where two strings diverge,
 *  or -1 when identical. Used to make a single-byte divergence legible. */
function firstDivergence(a: string, b: string): number {
  const n = Math.min(a.length, b.length)
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return i
  }
  return a.length === b.length ? -1 : n
}

function divergenceDetail(label: string, expected: string, actual: string): string {
  const at = firstDivergence(expected, actual)
  if (at === -1) return `${label}: lengths differ but no byte diverged (unreachable)`
  const window = 12
  const eSlice = expected.slice(Math.max(0, at - window), at + window)
  const aSlice = actual.slice(Math.max(0, at - window), at + window)
  return (
    `${label}: first divergence at byte ${at}. ` +
    `expected …${JSON.stringify(eSlice)}…, got …${JSON.stringify(aSlice)}…`
  )
}

function run(
  id: string,
  category: string,
  name: string,
  spec: string,
  fn: () => string | null,
): ConformanceCheck {
  const start = Date.now()
  try {
    const detail = fn()
    return detail === null
      ? { id, category, name, spec, passed: true, durationMs: Date.now() - start }
      : { id, category, name, spec, passed: false, detail, durationMs: Date.now() - start }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e)
    return { id, category, name, spec, passed: false, detail: msg, durationMs: Date.now() - start }
  }
}

/**
 * Check one canonicalization vector. Returns null on full agreement, or a
 * human-readable divergence string naming the first divergent byte. Both
 * the JCS and legacy variants and both digests are checked: a single-byte
 * divergence in any one of the four fails.
 */
export function checkCanonicalizationVector(v: CanonicalizationTestVector): string | null {
  const actualJcs = canonicalizeJCS(v.input)
  if (actualJcs !== v.expected_jcs) {
    return divergenceDetail(`${v.id} jcs`, v.expected_jcs, actualJcs)
  }
  const actualLegacy = canonicalize(v.input)
  if (actualLegacy !== v.expected_legacy) {
    return divergenceDetail(`${v.id} legacy`, v.expected_legacy, actualLegacy)
  }
  const actualJcsHash = sha256hex(actualJcs)
  if (actualJcsHash !== v.sha256_jcs) {
    return `${v.id} sha256_jcs: expected ${v.sha256_jcs}, got ${actualJcsHash}`
  }
  const actualLegacyHash = sha256hex(actualLegacy)
  if (actualLegacyHash !== v.sha256_legacy) {
    return `${v.id} sha256_legacy: expected ${v.sha256_legacy}, got ${actualLegacyHash}`
  }
  return null
}

/**
 * Run the canonicalization conformance vectors against this
 * implementation's canonicalizers. `externalVectors` lets a caller load a
 * pinned JSON corpus (e.g. specs/test-vectors-canonicalization.json) and
 * assert it is byte-identical to the code mirror getTestVectors(), so a
 * drift between the two surfaces is itself a conformance failure.
 */
export function runCanonicalizationConformance(
  externalVectors?: CanonicalizationTestVector[],
): ConformanceRunnerResult {
  const start = Date.now()
  const checks: ConformanceCheck[] = []
  const codeVectors = getTestVectors()

  // When an external corpus is supplied, first assert it matches the code
  // mirror field-for-field. This catches a vectors-file edit that was not
  // mirrored into getTestVectors() (or vice versa).
  if (externalVectors !== undefined) {
    checks.push(
      run(
        'CANON-MIRROR',
        'canonicalization',
        'code mirror getTestVectors() is a byte-identical subset of the external corpus',
        'specs/test-vectors-canonicalization.json',
        () => {
          // The frozen code mirror is the shipped subset. The on-disk corpus
          // may extend it (e.g. nested-attestation vectors) but every shared
          // vector MUST be byte-identical, so neither surface can drift.
          if (externalVectors.length < codeVectors.length) {
            return `corpus smaller than code mirror: external ${externalVectors.length}, code ${codeVectors.length}`
          }
          const extById = new Map(externalVectors.map((v) => [v.id, v]))
          for (const code of codeVectors) {
            const ext = extById.get(code.id)
            if (ext === undefined) return `code-mirror vector ${code.id} absent from external corpus`
            for (const field of [
              'expected_jcs',
              'expected_legacy',
              'sha256_jcs',
              'sha256_legacy',
            ] as const) {
              if (ext[field] !== code[field]) {
                return divergenceDetail(`${code.id} ${field}`, code[field], ext[field])
              }
            }
          }
          return null
        },
      ),
    )
  }

  // The vectors actually exercised are the external corpus when supplied
  // (the cross-impl byte anchor), else the code mirror.
  const vectors = externalVectors ?? codeVectors
  for (const v of vectors) {
    checks.push(
      run(
        v.id,
        'canonicalization',
        v.description,
        'RFC 8785 JCS + legacy variant',
        () => checkCanonicalizationVector(v),
      ),
    )
  }

  return summarize(checks, Date.now() - start)
}

/** Fold a check list into the report shape. */
export function summarize(checks: ConformanceCheck[], durationMs: number): ConformanceRunnerResult {
  const categories: Record<string, { passed: number; failed: number }> = {}
  let passed = 0
  let failed = 0
  for (const c of checks) {
    const cat = (categories[c.category] ??= { passed: 0, failed: 0 })
    if (c.passed) {
      passed++
      cat.passed++
    } else {
      failed++
      cat.failed++
    }
  }
  const total = checks.length
  const allPass = failed === 0
  const summary = allPass
    ? `conformance: ${passed}/${total} checks passed`
    : `conformance: ${failed}/${total} checks FAILED (${passed} passed)`
  return { passed, failed, total, categories, tests: checks, summary, durationMs, allPass }
}
