// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Build B — cross-language verification against specs/fixtures/build-b/*.json.
//
// Each fixture pins expected canonical output (6-digit decimal strings
// for weights, 64-char hex for profile hashes). The TS implementation
// must reproduce the expected bytes exactly; the Python test
// tests/v2/test_attribution_weights_cross_language.py does the same.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import {
  computeComputeAxisWeights,
  computeDataAxisWeights,
  hashWeightProfile,
} from '../../src/index.js'

const FIXTURE_DIR = '/Users/tima/aeoess_web/specs/fixtures/build-b'

function loadFixtures(): Array<{ name: string; data: any }> {
  return readdirSync(FIXTURE_DIR)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((name) => ({
      name,
      data: JSON.parse(readFileSync(join(FIXTURE_DIR, name), 'utf8')),
    }))
}

describe('Build B cross-language fixtures — TS implementation matches pinned expected output', () => {
  const fixtures = loadFixtures()
  assert.equal(fixtures.length, 10, `expected 10 fixtures, found ${fixtures.length}`)

  for (const { name, data } of fixtures) {
    it(`${name}: ${data.description}`, () => {
      if (data.kind === 'd_axis') {
        const actual = computeDataAxisWeights(data.input.sources, {
          action_timestamp: data.input.action_timestamp,
        })
        assert.deepEqual(actual, data.expected.weights)
      } else if (data.kind === 'c_axis') {
        const actual = computeComputeAxisWeights(data.input.providers)
        assert.deepEqual(actual, data.expected.weights)
      } else if (data.kind === 'profile_hash') {
        const actual = hashWeightProfile(data.input.profile)
        assert.equal(actual, data.expected.hash)
      } else {
        assert.fail(`unknown fixture kind: ${data.kind}`)
      }
    })
  }
})
