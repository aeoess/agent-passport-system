// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Conformance harness — runs all standard scenarios against the
// Nano reference adapter from src/v2/payment-rails/nano.ts and
// against the canonical fixtures under conformance/fixtures/.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  createDefaultGovernanceHooks,
  createNanoRail,
} from '../../../../src/v2/payment-rails/index.js'
import {
  HARNESS_FIXED_NOW,
  runConformance,
  STANDARD_SCENARIOS,
} from '../../../../src/v2/payment-rails/conformance/index.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_DIR = join(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  'src',
  'v2',
  'payment-rails',
  'conformance',
  'fixtures',
)

function makeRail() {
  return createNanoRail({
    receivingAddress:
      'nano_3test1f1xt7r3y6a7z9k1c0nv8d4yhfk93rcd6b1pmce8wkqf6kpunkfxnwd',
    fetchHistory: async () => [],
    fetchBlockInfo: async () => ({ confirmed: 'true', amount: '0' }),
  })
}

describe('conformance — Nano reference adapter passes the standard suite', () => {
  it('runs all 10 standard scenarios with 0 failures', async () => {
    const rail = makeRail()
    const hooks = createDefaultGovernanceHooks()
    const report = await runConformance(rail, hooks, { now: HARNESS_FIXED_NOW })

    assert.equal(report.total, 10, 'expected 10 scenarios')
    assert.equal(report.rail_name, 'nano')
    assert.equal(report.rail_currency, 'XNO')

    const failures = report.scenarios.filter((s) => !s.pass)
    if (failures.length > 0) {
      const detail = failures
        .map((f) => `  ${f.id}: ${f.reason ?? '(no reason)'}`)
        .join('\n')
      assert.fail(`expected 10/10 pass, got ${report.failed} failures:\n${detail}`)
    }
    assert.equal(report.passed, 10)
    assert.equal(report.failed, 0)
    assert.equal(report.all_pass, true)
  })

  it('every scenario in STANDARD_SCENARIOS has a unique SCN-XXX id', () => {
    const ids = STANDARD_SCENARIOS.map((s) => s.id)
    const unique = new Set(ids)
    assert.equal(unique.size, ids.length, 'duplicate scenario id detected')
    for (const id of ids) {
      assert.match(id, /^SCN-\d{3}$/, `bad scenario id format: ${id}`)
    }
  })

  it('report includes per-scenario duration_ms and description', async () => {
    const rail = makeRail()
    const hooks = createDefaultGovernanceHooks()
    const report = await runConformance(rail, hooks, { now: HARNESS_FIXED_NOW })

    for (const s of report.scenarios) {
      assert.equal(typeof s.duration_ms, 'number', `${s.id} missing duration_ms`)
      assert.ok(s.duration_ms >= 0, `${s.id} negative duration`)
      assert.ok(s.description.length > 0, `${s.id} missing description`)
    }
  })
})

// ── Byte-parity: pinned fixtures match what the reference impl emits ──

describe('conformance fixtures — byte-parity against reference impl', () => {
  it('every SCN-XXX scenario in STANDARD_SCENARIOS has a fixture file', () => {
    const files = readdirSync(FIXTURE_DIR).filter((f) =>
      /^SCN-\d{3}\.fixture\.json$/.test(f),
    )
    const expected = STANDARD_SCENARIOS.map((s) => `${s.id}.fixture.json`).sort()
    assert.deepEqual(files.sort(), expected)
  })

  it('META.json declares schema_version and lists all scenarios', () => {
    const meta = JSON.parse(readFileSync(join(FIXTURE_DIR, 'META.json'), 'utf8')) as {
      schema_version: string
      scenarios: Array<{ id: string; description: string }>
    }
    assert.equal(typeof meta.schema_version, 'string')
    assert.match(meta.schema_version, /^\d+\.\d+\.\d+$/)
    assert.equal(meta.scenarios.length, STANDARD_SCENARIOS.length)
    const fixtureIds = meta.scenarios.map((s) => s.id).sort()
    const harnessIds = STANDARD_SCENARIOS.map((s) => s.id).sort()
    assert.deepEqual(fixtureIds, harnessIds)
  })

  it('emit_receipt fixtures (SCN-006, SCN-007, SCN-010) reproduce signed bytes', async () => {
    const { emitReceipt, verifyPaymentReceipt } = await import(
      '../../../../src/v2/payment-rails/index.js'
    )
    for (const id of ['SCN-006', 'SCN-007', 'SCN-010']) {
      const fx = JSON.parse(
        readFileSync(join(FIXTURE_DIR, `${id}.fixture.json`), 'utf8'),
      ) as {
        input: Parameters<typeof emitReceipt>[0]
        issuer_private_key_hex: string
        expected: Parameters<typeof verifyPaymentReceipt>[0]
      }
      const reproduced = emitReceipt(fx.input, fx.issuer_private_key_hex)
      assert.deepEqual(
        reproduced,
        fx.expected,
        `${id}: emitReceipt output drifted from fixture`,
      )
      const v = verifyPaymentReceipt(fx.expected)
      assert.equal(v.valid, true, `${id}: pinned fixture failed verify (${v.reason})`)
    }
  })

  it('emit_denial fixture (SCN-008) reproduces signed bytes', async () => {
    const { emitDenial, verifyPaymentDenial } = await import(
      '../../../../src/v2/payment-rails/index.js'
    )
    const fx = JSON.parse(
      readFileSync(join(FIXTURE_DIR, 'SCN-008.fixture.json'), 'utf8'),
    ) as {
      input: Parameters<typeof emitDenial>[0]
      issuer_private_key_hex: string
      expected: Parameters<typeof verifyPaymentDenial>[0]
    }
    const reproduced = emitDenial(fx.input, fx.issuer_private_key_hex)
    assert.deepEqual(reproduced, fx.expected, 'SCN-008: emitDenial output drifted')
    const v = verifyPaymentDenial(fx.expected)
    assert.equal(v.valid, true, `SCN-008: pinned fixture failed verify (${v.reason})`)
  })
})
