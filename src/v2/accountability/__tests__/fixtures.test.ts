// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Fixture cross-verification — every checked-in fixture must verify clean.
// Cross-implementation byte-match anchor: other SDKs validate against
// THESE files. Any change to construct/* that breaks fixture signatures
// fails this test loud.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { verifyActionReceipt } from '../verify/action.js'
import { verifyAuthorityBoundaryReceipt } from '../verify/authority-boundary.js'
import { verifyCustodyReceipt } from '../verify/custody.js'
import { verifyContestabilityReceipt } from '../verify/contestability.js'
import { verifyAPSBundle } from '../verify/bundle.js'

import type { ActionReceipt } from '../types/action.js'
import type { AuthorityBoundaryReceipt } from '../types/authority-boundary.js'
import type { CustodyReceipt } from '../types/custody.js'
import type { ContestabilityReceipt } from '../types/contestability.js'
import type { APSBundle } from '../types/bundle.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURES_DIR = join(__dirname, '..', 'fixtures')

function loadFixture<T>(name: string): T {
  return JSON.parse(readFileSync(join(FIXTURES_DIR, name), 'utf8')) as T
}

describe('accountability fixtures', () => {
  it('action.fixture.json verifies clean', () => {
    const r = loadFixture<ActionReceipt>('action.fixture.json')
    const v = verifyActionReceipt(r)
    assert.equal(v.valid, true, JSON.stringify(v))
  })

  it('authority-boundary.fixture.json verifies clean', () => {
    const r = loadFixture<AuthorityBoundaryReceipt>('authority-boundary.fixture.json')
    const v = verifyAuthorityBoundaryReceipt(r)
    assert.equal(v.valid, true, JSON.stringify(v))
  })

  it('custody.fixture.json verifies clean', () => {
    const r = loadFixture<CustodyReceipt>('custody.fixture.json')
    const v = verifyCustodyReceipt(r)
    assert.equal(v.valid, true, JSON.stringify(v))
  })

  it('contestability.fixture.json verifies clean', () => {
    const r = loadFixture<ContestabilityReceipt>('contestability.fixture.json')
    const v = verifyContestabilityReceipt(r)
    assert.equal(v.valid, true, JSON.stringify(v))
  })

  it('bundle.fixture.json verifies clean', () => {
    const r = loadFixture<APSBundle>('bundle.fixture.json')
    const v = verifyAPSBundle(r)
    assert.equal(v.valid, true, JSON.stringify(v))
  })
})
