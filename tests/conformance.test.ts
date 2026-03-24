// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { runConformanceSuite } from '../src/index.js'

describe('Conformance Suite', () => {
  it('all conformance tests pass', () => {
    const result = runConformanceSuite()
    console.log(result.summary)
    assert.equal(result.failed, 0, `${result.failed} conformance tests failed:\n${
      result.tests.filter(t => !t.passed).map(t => `  ${t.id} ${t.name}: ${t.error}`).join('\n')
    }`)
    assert.ok(result.total >= 20, `Expected at least 20 tests, got ${result.total}`)
  })

  it('returns structured categories', () => {
    const result = runConformanceSuite()
    assert.ok(result.categories['Identity'], 'Identity category exists')
    assert.ok(result.categories['DID Resolution'], 'DID Resolution category exists')
    assert.ok(result.categories['Entity Verification'], 'Entity Verification category exists')
    assert.ok(result.categories['Data Lifecycle'], 'Data Lifecycle category exists')
  })

  it('summary is human-readable', () => {
    const result = runConformanceSuite()
    assert.ok(result.summary.includes('APS Conformance Suite'))
    assert.ok(result.summary.includes('passed'))
    assert.ok(result.summary.includes('By category'))
  })
})
