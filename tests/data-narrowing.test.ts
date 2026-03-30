// ══════════════════════════════════════════════════════════════════
// Data Narrowing Invariant — Tests
// ══════════════════════════════════════════════════════════════════
// GPT "Context-Bypass Attack": data can only narrow, never widen.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  assertDataNarrowsOnly, applyDataConstraints,
  isValidNarrowing, NARROWING_ORDER,
} from '../src/core/data-narrowing.js'
import type { FacetSnapshot } from '../src/core/data-narrowing.js'

describe('Data Narrowing — Status Ordering', () => {
  it('fail is most restrictive (0)', () => {
    assert.strictEqual(NARROWING_ORDER['fail'], 0)
  })

  it('pass is least restrictive (3)', () => {
    assert.strictEqual(NARROWING_ORDER['pass'], 3)
  })

  it('ordering: fail < unknown < not_applicable < pass', () => {
    assert.ok(NARROWING_ORDER['fail'] < NARROWING_ORDER['unknown'])
    assert.ok(NARROWING_ORDER['unknown'] < NARROWING_ORDER['not_applicable'])
    assert.ok(NARROWING_ORDER['not_applicable'] < NARROWING_ORDER['pass'])
  })
})

describe('Data Narrowing — isValidNarrowing', () => {
  it('same status is valid', () => {
    assert.ok(isValidNarrowing('pass', 'pass'))
    assert.ok(isValidNarrowing('fail', 'fail'))
  })

  it('narrowing (pass → fail) is valid', () => {
    assert.ok(isValidNarrowing('pass', 'fail'))
    assert.ok(isValidNarrowing('pass', 'unknown'))
  })

  it('widening (fail → pass) is invalid', () => {
    assert.ok(!isValidNarrowing('fail', 'pass'))
    assert.ok(!isValidNarrowing('unknown', 'pass'))
  })
})

describe('Data Narrowing — assertDataNarrowsOnly', () => {
  it('passes when data only narrows constraints', () => {
    const before: FacetSnapshot[] = [
      { facet: 'scope', status: 'pass' },
      { facet: 'spend', status: 'pass' },
    ]
    const after: FacetSnapshot[] = [
      { facet: 'scope', status: 'fail' },  // narrowed
      { facet: 'spend', status: 'pass' },   // unchanged
    ]
    const result = assertDataNarrowsOnly(before, after)
    assert.ok(result.valid)
    assert.strictEqual(result.violations.length, 0)
  })

  it('detects widening attempt (fail → pass)', () => {
    const before: FacetSnapshot[] = [
      { facet: 'scope', status: 'fail' },
    ]
    const after: FacetSnapshot[] = [
      { facet: 'scope', status: 'pass' },  // WIDENING — violation
    ]
    const result = assertDataNarrowsOnly(before, after)
    assert.ok(!result.valid)
    assert.strictEqual(result.violations.length, 1)
    assert.strictEqual(result.violations[0].facet, 'scope')
    assert.strictEqual(result.violations[0].before, 'fail')
    assert.strictEqual(result.violations[0].after, 'pass')
  })

  it('detects multiple widening attempts', () => {
    const before: FacetSnapshot[] = [
      { facet: 'scope', status: 'fail' },
      { facet: 'spend', status: 'unknown' },
      { facet: 'time', status: 'pass' },
    ]
    const after: FacetSnapshot[] = [
      { facet: 'scope', status: 'pass' },    // WIDENING
      { facet: 'spend', status: 'pass' },     // WIDENING
      { facet: 'time', status: 'pass' },      // unchanged — ok
    ]
    const result = assertDataNarrowsOnly(before, after)
    assert.ok(!result.valid)
    assert.strictEqual(result.violations.length, 2)
  })

  it('passes when unchanged', () => {
    const snap: FacetSnapshot[] = [
      { facet: 'scope', status: 'pass' },
      { facet: 'spend', status: 'pass' },
    ]
    const result = assertDataNarrowsOnly(snap, snap)
    assert.ok(result.valid)
  })
})

describe('Data Narrowing — applyDataConstraints', () => {
  it('applies narrowing influence (pass → fail)', () => {
    const current: FacetSnapshot[] = [
      { facet: 'scope', status: 'pass' },
      { facet: 'spend', status: 'pass' },
    ]
    const influence: FacetSnapshot[] = [
      { facet: 'scope', status: 'fail' },  // narrowing — accepted
    ]
    const { result, rejected } = applyDataConstraints(current, influence)
    assert.strictEqual(rejected.length, 0)
    const scope = result.find(f => f.facet === 'scope')!
    assert.strictEqual(scope.status, 'fail', 'Scope should be narrowed to fail')
  })

  it('rejects widening influence (fail → pass)', () => {
    const current: FacetSnapshot[] = [
      { facet: 'scope', status: 'fail' },
    ]
    const influence: FacetSnapshot[] = [
      { facet: 'scope', status: 'pass' },  // widening — rejected
    ]
    const { result, rejected } = applyDataConstraints(current, influence)
    assert.strictEqual(rejected.length, 1)
    assert.strictEqual(rejected[0].facet, 'scope')
    const scope = result.find(f => f.facet === 'scope')!
    assert.strictEqual(scope.status, 'fail', 'Original should be preserved')
  })

  it('accepts new restrictive facets from data', () => {
    const current: FacetSnapshot[] = [
      { facet: 'scope', status: 'pass' },
    ]
    const influence: FacetSnapshot[] = [
      { facet: 'data', status: 'fail' },  // new facet, restrictive — accepted
    ]
    const { result, rejected } = applyDataConstraints(current, influence)
    assert.strictEqual(rejected.length, 0)
    assert.ok(result.find(f => f.facet === 'data'), 'New restrictive facet should be added')
  })

  it('ignores new permissive facets from data', () => {
    const current: FacetSnapshot[] = [
      { facet: 'scope', status: 'pass' },
    ]
    const influence: FacetSnapshot[] = [
      { facet: 'data', status: 'pass' },  // new facet, permissive — ignored
    ]
    const { result, rejected } = applyDataConstraints(current, influence)
    assert.ok(!result.find(f => f.facet === 'data'), 'New permissive facet should not be added')
  })

  it('mixed: some narrowed, some rejected', () => {
    const current: FacetSnapshot[] = [
      { facet: 'scope', status: 'pass' },
      { facet: 'spend', status: 'fail' },
      { facet: 'time', status: 'unknown' },
    ]
    const influence: FacetSnapshot[] = [
      { facet: 'scope', status: 'fail' },     // narrowing — ok
      { facet: 'spend', status: 'pass' },      // widening — rejected
      { facet: 'time', status: 'fail' },       // narrowing — ok
    ]
    const { result, rejected } = applyDataConstraints(current, influence)
    assert.strictEqual(rejected.length, 1)
    assert.strictEqual(rejected[0].facet, 'spend')
    assert.strictEqual(result.find(f => f.facet === 'scope')!.status, 'fail')
    assert.strictEqual(result.find(f => f.facet === 'spend')!.status, 'fail') // preserved
    assert.strictEqual(result.find(f => f.facet === 'time')!.status, 'fail')  // narrowed
  })
})
