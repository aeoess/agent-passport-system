// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Conformance runner tests
// ══════════════════════════════════════════════════════════════════
// Pins: the runner agrees with the pinned canonicalization vectors,
// asserts the code mirror is a byte-identical subset of the on-disk corpus,
// and FAILS on a single-byte divergence in any of the four expectation
// fields (expected_jcs, expected_legacy, sha256_jcs, sha256_legacy).
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  runCanonicalizationConformance,
  checkCanonicalizationVector,
} from '../../../src/v2/offline-verifier/conformance-runner.js'
import { getTestVectors } from '../../../src/core/canonical-jcs.js'
import type { CanonicalizationTestVector } from '../../../src/core/canonical-jcs.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const VECTORS_PATH = join(__dirname, '..', '..', '..', 'specs', 'test-vectors-canonicalization.json')

function loadDiskVectors(): CanonicalizationTestVector[] {
  return JSON.parse(readFileSync(VECTORS_PATH, 'utf-8')) as CanonicalizationTestVector[]
}

describe('conformance runner: canonicalization vectors', () => {
  it('passes every code-mirror vector', () => {
    const report = runCanonicalizationConformance()
    assert.equal(report.allPass, true, report.summary)
    assert.equal(report.failed, 0)
    assert.ok(report.total >= 10, 'at least the 10 shipped vectors run')
  })

  it('passes the on-disk corpus and confirms it matches the code mirror', () => {
    const disk = loadDiskVectors()
    const report = runCanonicalizationConformance(disk)
    assert.equal(report.allPass, true, report.summary)
    // The mirror check is present and passed.
    const mirror = report.tests.find((t) => t.id === 'CANON-MIRROR')
    assert.ok(mirror, 'mirror check is run when an external corpus is supplied')
    assert.equal(mirror!.passed, true)
  })

  it('code mirror getTestVectors() is a byte-identical subset of the on-disk corpus', () => {
    const disk = loadDiskVectors()
    const code = getTestVectors()
    // The frozen code mirror is the shipped subset; the on-disk corpus may
    // extend it with additional vectors (e.g. nested-attestation cases).
    // Every code-mirror vector MUST appear in the corpus byte-identical.
    assert.ok(disk.length >= code.length)
    const diskById = new Map(disk.map((v) => [v.id, v]))
    for (const c of code) {
      const d = diskById.get(c.id)
      assert.ok(d, `code vector ${c.id} present in on-disk corpus`)
      assert.equal(d!.expected_jcs, c.expected_jcs, `${c.id} expected_jcs`)
      assert.equal(d!.expected_legacy, c.expected_legacy, `${c.id} expected_legacy`)
      assert.equal(d!.sha256_jcs, c.sha256_jcs, `${c.id} sha256_jcs`)
      assert.equal(d!.sha256_legacy, c.sha256_legacy, `${c.id} sha256_legacy`)
    }
  })

  it('fails on a single-byte divergence in expected_jcs', () => {
    const disk = loadDiskVectors()
    const corrupted = JSON.parse(JSON.stringify(disk)) as CanonicalizationTestVector[]
    // cv-002 is the null-divergence case. Flip one byte of its JCS
    // expectation so the implementation's output no longer matches.
    const idx = corrupted.findIndex((v) => v.id === 'cv-002')
    assert.ok(idx >= 0)
    corrupted[idx].expected_jcs = corrupted[idx].expected_jcs.replace('null', 'NULL')
    const report = runCanonicalizationConformance(corrupted)
    assert.equal(report.allPass, false)
    assert.ok(report.failed >= 1)
    // The mirror check also catches it (corpus drifted from code mirror).
    const mirror = report.tests.find((t) => t.id === 'CANON-MIRROR')
    assert.equal(mirror!.passed, false)
  })

  it('fails on a single-byte divergence in a pinned sha256 digest', () => {
    const disk = loadDiskVectors()
    const corrupted = JSON.parse(JSON.stringify(disk)) as CanonicalizationTestVector[]
    const idx = corrupted.findIndex((v) => v.id === 'cv-009')
    assert.ok(idx >= 0)
    const orig = corrupted[idx].sha256_jcs
    // Flip the last hex nibble of the pinned digest.
    const lastChar = orig.slice(-1)
    corrupted[idx].sha256_jcs = orig.slice(0, -1) + (lastChar === '0' ? '1' : '0')
    const report = runCanonicalizationConformance(corrupted)
    assert.equal(report.allPass, false)
  })

  it('checkCanonicalizationVector returns null on agreement, a detail string on divergence', () => {
    const code = getTestVectors()
    const v = code.find((x) => x.id === 'cv-004')
    assert.ok(v)
    assert.equal(checkCanonicalizationVector(v!), null)
    const broken: CanonicalizationTestVector = { ...v!, expected_legacy: '{"BROKEN":true}' }
    const detail = checkCanonicalizationVector(broken)
    assert.ok(typeof detail === 'string' && detail.includes('cv-004 legacy'))
  })

  it('report field names mirror ConformanceSuiteResult', () => {
    const report = runCanonicalizationConformance()
    for (const field of ['passed', 'failed', 'total', 'categories', 'tests', 'summary', 'durationMs']) {
      assert.ok(field in report, `report has ${field}`)
    }
  })
})
