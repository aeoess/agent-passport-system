// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Tier-2 binding-adapter conformance harness: test surface
// ══════════════════════════════════════════════════════════════════
// Pins the cross-rail invariants for the five binding adapters
// (AP2, x402, Stripe-Issuing, ACP, MPP). Loads per-rail fixtures
// from src/v2/payment-rails/conformance/binding-fixtures/, runs
// runBindingConformance(BUILTIN_BINDING_ADAPTERS, fixtures), and
// asserts each invariant for each scenario explicitly so a future
// regression points at the specific failed assertion rather than a
// generic harness failure.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  BUILTIN_BINDING_ADAPTERS,
  runBindingConformance,
} from '../../../src/v2/payment-rails/conformance/binding-harness.js'
import type {
  BindingFixtureSet,
  BindingRailName,
} from '../../../src/v2/payment-rails/conformance/binding-harness.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_DIR = join(
  __dirname,
  '..',
  '..',
  '..',
  'src',
  'v2',
  'payment-rails',
  'conformance',
  'binding-fixtures',
)

const RAILS: BindingRailName[] = ['ap2', 'x402', 'stripe-issuing', 'acp', 'mpp']

function loadFixture(rail: BindingRailName): BindingFixtureSet {
  const raw = readFileSync(join(FIXTURE_DIR, `${rail}.fixture.json`), 'utf8')
  return JSON.parse(raw) as BindingFixtureSet
}

const FIXTURES: Record<BindingRailName, BindingFixtureSet> = {
  ap2: loadFixture('ap2'),
  x402: loadFixture('x402'),
  'stripe-issuing': loadFixture('stripe-issuing'),
  acp: loadFixture('acp'),
  mpp: loadFixture('mpp'),
}

// One harness run shared across the explicit per-scenario assertions
// below. The harness never throws in non-strict mode; failures land
// in the report so the test surface can pin each scenario.
const REPORT = runBindingConformance(BUILTIN_BINDING_ADAPTERS, FIXTURES)

// ── Top-level shape ──────────────────────────────────────────────

describe('Tier-2 binding-adapter conformance: report shape', () => {
  it('schema_version is consensus 1.0.0 across all five rail fixtures', () => {
    assert.equal(REPORT.schema_version, '1.0.0')
  })

  it('produces a structured report with all_pass=true and zero failures', () => {
    assert.equal(REPORT.failed, 0, JSON.stringify(REPORT.scenarios.filter((s) => !s.pass), null, 2))
    assert.equal(REPORT.all_pass, true)
  })

  it('total scenario count is 5*9 per-rail + 5 cross-rail = 50', () => {
    // Per rail: 5 conformance + 3 denial + 1 determinism = 9. Five rails = 45.
    // Plus the 5 cross-rail byte-parity scenarios (one per shared CONF id).
    assert.equal(REPORT.total, 50)
    assert.equal(REPORT.passed, 50)
  })
})

// ── (a) Field-name resolution invariant ──────────────────────────

describe('Tier-2 invariant (a): field-name resolution byte-parity', () => {
  for (const rail of RAILS) {
    for (const scn of FIXTURES[rail].conformance) {
      it(`[${rail}] ${scn.id}: ${scn.description}`, () => {
        const r = REPORT.scenarios.find(
          (x) =>
            x.rail_name === rail &&
            x.scenario_id === scn.id &&
            x.invariant === 'field_name_resolution',
        )
        assert.ok(r, `no field_name_resolution report for [${rail}/${scn.id}]`)
        assert.equal(
          r.pass,
          true,
          `expected pass=true, got detail='${r.detail ?? ''}'`,
        )
      })
    }
  }
})

// ── (b) Denial vocabulary round-trip ─────────────────────────────

describe('Tier-2 invariant (b): denial vocabulary round-trip', () => {
  for (const rail of RAILS) {
    for (const scn of FIXTURES[rail].denials) {
      it(`[${rail}] ${scn.id}: ${scn.description}`, () => {
        const r = REPORT.scenarios.find(
          (x) =>
            x.rail_name === rail &&
            x.scenario_id === scn.id &&
            x.invariant === 'denial_round_trip',
        )
        assert.ok(r, `no denial_round_trip report for [${rail}/${scn.id}]`)
        assert.equal(
          r.pass,
          true,
          `expected pass=true, got detail='${r.detail ?? ''}'`,
        )
      })
    }
  }
})

// ── (c) Resolver determinism ─────────────────────────────────────

describe('Tier-2 invariant (c): resolver determinism', () => {
  for (const rail of RAILS) {
    for (const scn of FIXTURES[rail].determinism) {
      it(`[${rail}] ${scn.id}: ${scn.description}`, () => {
        const r = REPORT.scenarios.find(
          (x) =>
            x.rail_name === rail &&
            x.scenario_id === scn.id &&
            x.invariant === 'resolver_determinism',
        )
        assert.ok(r, `no resolver_determinism report for [${rail}/${scn.id}]`)
        assert.equal(
          r.pass,
          true,
          `expected pass=true, got detail='${r.detail ?? ''}'`,
        )
      })
    }
  }
})

// ── Cross-rail byte-parity (folds invariant a across rails) ──────

describe('Tier-2 cross-rail byte-parity', () => {
  // The shared conformance ids that EVERY rail's fixture publishes.
  // The harness uses set intersection across rail fixtures.
  const sharedIds = ['BIND-CONF-01', 'BIND-CONF-02', 'BIND-CONF-03', 'BIND-CONF-04', 'BIND-CONF-05']

  for (const id of sharedIds) {
    it(`${id} resolves byte-identical across all 5 rails`, () => {
      const r = REPORT.scenarios.find(
        (x) => x.scenario_id === id && x.invariant === 'cross_rail_byte_parity',
      )
      assert.ok(r, `no cross_rail_byte_parity report for ${id}`)
      assert.equal(r.pass, true, `byte divergence: detail='${r.detail ?? ''}'`)
    })
  }
})

// ── Strict mode throws on first failure ──────────────────────────

describe('Tier-2 binding-harness strict mode', () => {
  it('strict=true on the standard fixture set does not throw', () => {
    assert.doesNotThrow(() => {
      runBindingConformance(BUILTIN_BINDING_ADAPTERS, FIXTURES, { strict: true })
    })
  })

  it('strict=true throws when the expected cap diverges from what the rail resolves', () => {
    const broken: BindingFixtureSet = {
      ...FIXTURES.ap2,
      conformance: [
        {
          id: 'BIND-BROKEN-01',
          description: 'expected cap intentionally wrong',
          delegation: FIXTURES.ap2.conformance[0].delegation,
          // The fixture's delegation resolves to 50000; expecting 1 forces a fail.
          expected_cap_minor_units: 1,
        },
      ],
    }
    assert.throws(() => {
      runBindingConformance(
        BUILTIN_BINDING_ADAPTERS,
        { ...FIXTURES, ap2: broken },
        { strict: true },
      )
    }, /field_name_resolution/)
  })
})
