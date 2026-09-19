// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { computeExternalActionRefV1 } from '../src/core/external-action-ref.js'

describe('computeExternalActionRefV1 action-ref-v1-jcs-sha256 cross-ecosystem key', () => {
  // Byte-match anchors against independent implementations of the external
  // form: argentum-core (giskard09) and the andysalvo/action-ref-verify
  // vectors. A match proves APS computes the same correlation key as the
  // ecosystem, not just a value that agrees with itself.
  const anchors = [
    {
      name: 'giskard09 argentum-core example',
      input: {
        agentId: 'pioneer-agent-001',
        actionType: 'payment.send',
        scope: 'mycelium:payment',
        timestamp: '2026-05-24T10:30:00.000Z',
      },
      expected: '584bc79bb11ce3af5058b3da84d03f85e4aa464a175bd4f913aeb82a22cef60f',
    },
    {
      name: 'andysalvo 0001-giskard-baseline',
      input: {
        agentId: 'nexus-agent-xa12.onrender.com',
        actionType: 'oracle.signal',
        scope: 'BTC',
        timestamp: '2025-05-18T11:40:31.000Z',
      },
      expected: 'fdd7f810499f06be24355ca8e2bfb8c4b965cc80c838f41fa074683443d89f5a',
    },
    {
      name: 'andysalvo 0006-rfc8785-negative-zero',
      input: {
        agentId: 'test-negative-zero.example.com',
        actionType: 'oracle.signal',
        scope: 'BTC',
        timestamp: '2025-01-01T00:00:00.000Z',
      },
      expected: 'd7a591f6afb04565baca3ef862324b692bfb7be731aa53d98f3814bb3cb6bdb0',
    },
  ]

  for (const a of anchors) {
    it(`byte-matches ${a.name}`, () => {
      assert.equal(computeExternalActionRefV1(a.input), a.expected)
    })
  }

  it('returns 64-char lowercase hex', () => {
    const ref = computeExternalActionRefV1(anchors[0].input)
    assert.match(ref, /^[0-9a-f]{64}$/)
  })

  it('is deterministic across key insertion order (JCS sorts)', () => {
    const a = computeExternalActionRefV1({ agentId: 'x', actionType: 'a', scope: 's', timestamp: '2026-01-01T00:00:00.000Z' })
    const b = computeExternalActionRefV1({ timestamp: '2026-01-01T00:00:00.000Z', scope: 's', actionType: 'a', agentId: 'x' })
    assert.equal(a, b)
  })

  it('accepts a Date and renders it to the canonical millisecond form', () => {
    const fromString = computeExternalActionRefV1({
      agentId: 'nexus-agent-xa12.onrender.com',
      actionType: 'oracle.signal',
      scope: 'BTC',
      timestamp: '2025-05-18T11:40:31.000Z',
    })
    const fromDate = computeExternalActionRefV1({
      agentId: 'nexus-agent-xa12.onrender.com',
      actionType: 'oracle.signal',
      scope: 'BTC',
      timestamp: new Date('2025-05-18T11:40:31.000Z'),
    })
    assert.equal(fromDate, fromString)
  })

  it('rejects a second-precision timestamp rather than coercing it', () => {
    assert.throws(
      () => computeExternalActionRefV1({ agentId: 'a', actionType: 't', scope: 's', timestamp: '2025-05-18T11:40:31Z' }),
      /three fractional digits/,
    )
  })

  it('rejects an extra-precision timestamp', () => {
    assert.throws(
      () => computeExternalActionRefV1({ agentId: 'a', actionType: 't', scope: 's', timestamp: '2025-05-18T11:40:31.000000Z' }),
      /three fractional digits/,
    )
  })

  it('differs from a single-field change (scope is load-bearing)', () => {
    const base = computeExternalActionRefV1({ agentId: 'a', actionType: 't', scope: 's1', timestamp: '2026-01-01T00:00:00.000Z' })
    const other = computeExternalActionRefV1({ agentId: 'a', actionType: 't', scope: 's2', timestamp: '2026-01-01T00:00:00.000Z' })
    assert.notEqual(base, other)
  })
})

describe('computeExternalActionRefV1 draft-03 section 4.2 hardening: calendar validity and field types', () => {
  // Reference vector: {actionType: "commerce_preflight", agentId:
  // "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", scope:
  // "commerce:write"}. Digests below were computed from the UNMODIFIED
  // implementation (before this hardening was applied) and must not change,
  // since the preimage keys and the hashing are untouched by this fix.
  const validBase = {
    actionType: 'commerce_preflight',
    agentId: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    scope: 'commerce:write',
  }

  const shapeRejections = [
    { name: 'month 13', timestamp: '2026-13-01T00:00:00.000Z' },
    { name: 'hour 24', timestamp: '2026-04-08T24:00:00.000Z' },
    { name: 'minute 60 (only seconds admit :60)', timestamp: '2026-04-08T12:60:00.000Z' },
  ]
  for (const c of shapeRejections) {
    it(`rejects a malformed timestamp (${c.name})`, () => {
      assert.throws(
        () => computeExternalActionRefV1({ ...validBase, timestamp: c.timestamp }),
        /three fractional digits/,
      )
    })
  }

  const calendarRejections = [
    { name: 'February 30 does not exist', timestamp: '2026-02-30T00:00:00.000Z' },
    { name: 'February 29 in a non-leap year', timestamp: '2027-02-29T00:00:00.000Z' },
  ]
  for (const c of calendarRejections) {
    it(`rejects a calendar-invalid timestamp (${c.name})`, () => {
      assert.throws(
        () => computeExternalActionRefV1({ ...validBase, timestamp: c.timestamp }),
        /does not exist in that month/,
      )
    })
  }

  it('rejects an array-wrapped timestamp instead of hashing its RegExp-coerced string form', () => {
    assert.throws(
      () =>
        computeExternalActionRefV1({
          ...validBase,
          timestamp: ['2026-04-08T12:00:00.000Z'] as unknown as string,
        }),
      /timestamp must be a string or a Date/,
    )
  })

  it('rejects a numeric timestamp', () => {
    assert.throws(
      () => computeExternalActionRefV1({ ...validBase, timestamp: 1747568431000 as unknown as string }),
      /timestamp must be a string or a Date/,
    )
  })

  it('rejects a Date whose year falls outside the four-digit range (renders with an expanded year)', () => {
    assert.throws(
      () => computeExternalActionRefV1({ ...validBase, timestamp: new Date(Date.UTC(10000, 0, 1)) }),
      /three fractional digits/,
    )
  })

  it('rejects a non-string actionType', () => {
    assert.throws(
      () => computeExternalActionRefV1({ ...validBase, actionType: 123 as unknown as string }),
      /computeExternalActionRefV1: actionType must be a string/,
    )
  })

  it('rejects a null agentId', () => {
    assert.throws(
      () => computeExternalActionRefV1({ ...validBase, agentId: null as unknown as string }),
      /computeExternalActionRefV1: agentId must be a string/,
    )
  })

  it('rejects an array scope', () => {
    assert.throws(
      () =>
        computeExternalActionRefV1({
          ...validBase,
          scope: ['commerce:write'] as unknown as string,
        }),
      /computeExternalActionRefV1: scope must be a string/,
    )
  })

  it('accepts a leap-second timestamp (:60) at 23:59 on the last day of the month (RFC 3339 section 5.7 and Appendix D) and pins its digest', () => {
    const ref = computeExternalActionRefV1({ ...validBase, timestamp: '2016-12-31T23:59:60.000Z' })
    assert.equal(ref, '9987eae85a2037cd2b8cd300d357f33a633e47fb735af5fb6cc742ff41ec69ac')
  })

  it('accepts February 29 in a leap year at the last millisecond of the day', () => {
    const ref = computeExternalActionRefV1({ ...validBase, timestamp: '2028-02-29T23:59:59.999Z' })
    assert.match(ref, /^[0-9a-f]{64}$/)
  })

  it('accepts year 0000 (a leap year under the proleptic Gregorian calendar)', () => {
    const ref = computeExternalActionRefV1({ ...validBase, timestamp: '0000-01-01T00:00:00.000Z' })
    assert.match(ref, /^[0-9a-f]{64}$/)
  })

  it('accepts empty strings for actionType, agentId and scope (no non-empty rule in section 4.2)', () => {
    const ref = computeExternalActionRefV1({
      actionType: '',
      agentId: '',
      scope: '',
      timestamp: '2026-04-08T12:00:00.000Z',
    })
    assert.match(ref, /^[0-9a-f]{64}$/)
  })

  it('pins the accepted digest for the reference commerce_preflight vector, unchanged from the pre-fix implementation', () => {
    const ref = computeExternalActionRefV1({ ...validBase, timestamp: '2026-04-08T12:00:00.000Z' })
    assert.equal(ref, '560f1463cf4d1b4f754a4f536a41df6e6c576dd249c6a887a0c7b1f773145941')
  })
})

describe('computeExternalActionRefV1: second 60 valid only at 23:59 on the last day of a month (RFC 3339 section 5.7, Appendix D)', () => {
  // draft-pidlisnyi-aps-03 section 4.2 timestamp, RFC 3339 section 5.7 and
  // Appendix D: a canonical timestamp whose seconds field is 60 is valid
  // only when the hour is 23, the minute is 59, and the day is the last day
  // of its month in the proleptic Gregorian calendar. Every other :60 is
  // invalid.
  const validBase = {
    actionType: 'commerce_preflight',
    agentId: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    scope: 'commerce:write',
  }

  const acceptedTimestamps = [
    '2016-12-31T23:59:60.000Z',
    '2026-06-30T23:59:60.000Z',
    '2028-02-29T23:59:60.999Z',
    '2027-02-28T23:59:60.000Z',
    '0000-02-29T23:59:60.000Z',
  ]
  for (const timestamp of acceptedTimestamps) {
    it(`accepts second 60 at ${timestamp}`, () => {
      const ref = computeExternalActionRefV1({ ...validBase, timestamp })
      assert.match(ref, /^[0-9a-f]{64}$/)
    })
  }

  const rejectedTimestamps = [
    ['2026-04-08T12:00:60.000Z', 'not the last day of its month (was EX-P11)'],
    ['2026-06-29T23:59:60.000Z', 'not the last day of June'],
    ['2016-12-31T23:58:60.000Z', 'minute 58'],
    ['2016-12-31T22:59:60.000Z', 'hour 22'],
    ['2028-02-28T23:59:60.000Z', 'not the last day of February in a leap year'],
    ['2027-02-29T23:59:60.000Z', 'no such day in a non-leap year'],
  ] as const
  for (const [timestamp, reason] of rejectedTimestamps) {
    it(`rejects second 60 at ${timestamp} (${reason})`, () => {
      assert.throws(
        () => computeExternalActionRefV1({ ...validBase, timestamp }),
        /does not exist in that month|second 60 outside 23:59 on the last day of its month/,
      )
    })
  }
})
