// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// A content address may not depend on the machine that computed it.
// ══════════════════════════════════════════════════════════════════
// `normalizeTimestamp` parsed with `new Date(ts)`, which reads a zone-less
// value in the LOCAL zone. Its only caller is the legacy `computeActionRef`,
// whose output goes inside signed bytes and keys the idempotency reservation.
// So one intent carrying `2026-04-05T03:39:31` produced one action_ref in UTC
// and a different one nine hours away in Asia/Tokyo: two writers could reserve
// the same action twice, or one could fail to match its own earlier
// reservation.
//
// The rule: an explicit offset or Z is required. Date-only, impossible dates
// and hour 24 are refused too, all of which `new Date` accepted, rolling
// 2026-02-30 forward into March. Lowercase `t` and `z` stay accepted, because
// RFC 3339 section 5.6 permits them and `parseRfc3339` takes them; this
// function does not get to be stricter than the parser the rest of the SDK
// verifies against.
//
// Nothing that already produced an address changes its address. The expected
// values in `IDENTITY` were captured from the previous implementation before
// it was changed, and are pinned here as literals.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { normalizeTimestamp } from '../src/core/canonical.js'
import { computeActionRef } from '../src/core/action-ref.js'

/** Run `fn` with TZ set, restoring whatever was there before. */
function underZone<T>(tz: string, fn: () => T): T {
  const previous = process.env.TZ
  process.env.TZ = tz
  try {
    return fn()
  } finally {
    if (previous === undefined) delete process.env.TZ
    else process.env.TZ = previous
  }
}

const ZONES = ['UTC', 'Asia/Tokyo', 'America/Los_Angeles']

describe('the action_ref timestamp does not depend on the machine', () => {
  it('a zone-less value is refused in every zone', () => {
    // Before: UTC gave 2026-04-05T03:39:31Z and Asia/Tokyo gave
    // 2026-04-04T18:39:31Z for this exact input.
    for (const tz of ZONES) {
      underZone(tz, () => {
        assert.throws(
          () => normalizeTimestamp('2026-04-05T03:39:31'),
          /invalid timestamp/,
          `zone-less value accepted under TZ=${tz}`,
        )
      })
    }
  })

  it('an explicit offset gives one output in every zone', () => {
    const outputs = ZONES.map(tz => underZone(tz, () => normalizeTimestamp('2026-04-05T12:39:31+09:00')))
    assert.deepEqual(new Set(outputs).size, 1, `zone-dependent output: ${outputs.join(' vs ')}`)
    assert.equal(outputs[0], '2026-04-05T03:39:31Z')
  })

  it('one instant written three ways gives one action_ref', () => {
    const forTimestamp = (createdAt: string) => computeActionRef({
      agentId: 'ag_1',
      action: { type: 'read', target: 'db', scopeRequired: ['data:read'] },
      createdAt,
    } as never)
    const z = forTimestamp('2026-04-05T03:39:31Z')
    assert.equal(forTimestamp('2026-04-05T12:39:31+09:00'), z)
    assert.equal(forTimestamp('2026-04-04T22:39:31-05:00'), z)
    assert.equal(forTimestamp('2026-04-05T03:39:31+00:00'), z)
    // And it is stable across zones, which is the property that was broken.
    for (const tz of ZONES) {
      assert.equal(underZone(tz, () => forTimestamp('2026-04-05T12:39:31+09:00')), z)
    }
  })
})

describe('what normalizeTimestamp refuses', () => {
  const REFUSED: [string, string][] = [
    ['zone-less', '2026-04-05T03:39:31'],
    ['date only', '2026-04-05'],
    ['impossible day of month', '2026-02-30T00:00:00Z'],
    ['hour 24', '2026-04-05T24:00:00Z'],
    ['empty string', ''],
    ['whitespace padded', '  2026-04-05T03:39:31Z  '],
    ['trailing space', '2026-04-05T03:39:31Z '],
    ['not a date', 'not-a-date'],
    ['space separator', '2026-04-05 03:39:31Z'],
    ['single-digit hour', '2026-04-05T3:39:31Z'],
    ['offset without colon', '2026-04-05T03:39:31+0900'],
    ['leap second', '2026-12-31T23:59:60Z'],
  ]
  for (const [label, ts] of REFUSED) {
    it(`refuses ${label}`, () => {
      assert.throws(() => normalizeTimestamp(ts), /normalizeTimestamp: invalid timestamp/)
    })
  }

  it('refuses a non-string, without constructing a Date from it', () => {
    for (const bad of [null, undefined, 12345, {}, []]) {
      assert.throws(() => normalizeTimestamp(bad as never), /invalid timestamp/)
    }
  })

  it('names the rule rather than only the input', () => {
    assert.throws(() => normalizeTimestamp('2026-04-05T03:39:31'), /explicit offset or Z/)
  })
})

describe('every input that produced an address still produces the same one', () => {
  // Captured from the previous implementation under TZ=UTC and TZ=Asia/Tokyo
  // before the change; identical in both, which is why they can be literals.
  const IDENTITY: [string, string][] = [
    ['2026-04-05T03:39:31Z', '2026-04-05T03:39:31Z'],
    ['2026-04-05T03:39:31.987Z', '2026-04-05T03:39:31Z'],
    ['2026-04-05T03:39:31+00:00', '2026-04-05T03:39:31Z'],
    ['2026-04-05T12:39:31+09:00', '2026-04-05T03:39:31Z'],
    ['2026-04-04T22:39:31-05:00', '2026-04-05T03:39:31Z'],
    ['2026-04-05t03:39:31z', '2026-04-05T03:39:31Z'],
  ]
  for (const [input, expected] of IDENTITY) {
    it(`${input} still normalizes to ${expected}`, () => {
      assert.equal(normalizeTimestamp(input), expected)
    })
  }

  it('lowercase t and z stay accepted, matching parseRfc3339', () => {
    // Deliberately NOT aligned with the Python SDK, which refuses these. RFC
    // 3339 section 5.6 permits them and this SDK's ratified parser accepts
    // them; a derivation helper does not get to be stricter than the parser
    // the verifiers use.
    assert.equal(normalizeTimestamp('2026-04-05t03:39:31z'), '2026-04-05T03:39:31Z')
    assert.equal(normalizeTimestamp('2026-04-05T03:39:31z'), '2026-04-05T03:39:31Z')
    assert.equal(normalizeTimestamp('2026-04-05t03:39:31Z'), '2026-04-05T03:39:31Z')
  })

  it('fractional seconds truncate rather than round', () => {
    assert.equal(normalizeTimestamp('2026-04-05T03:39:31.999Z'), '2026-04-05T03:39:31Z')
    assert.equal(normalizeTimestamp('2026-04-05T03:39:31.001Z'), '2026-04-05T03:39:31Z')
    assert.equal(normalizeTimestamp('2026-04-05T03:39:31.123456789Z'), '2026-04-05T03:39:31Z')
  })
})
