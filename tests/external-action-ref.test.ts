// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  computeExternalActionRefV1,
  parseExternalActionRefV1Preimage,
} from '../src/core/external-action-ref.js'

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
      /computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: actionType must be a string/,
    )
  })

  it('rejects a null agentId', () => {
    assert.throws(
      () => computeExternalActionRefV1({ ...validBase, agentId: null as unknown as string }),
      /computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: agentId must be a string/,
    )
  })

  it('rejects an array scope', () => {
    assert.throws(
      () =>
        computeExternalActionRefV1({
          ...validBase,
          scope: ['commerce:write'] as unknown as string,
        }),
      /computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: scope must be a string/,
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

  // Changed 2026-10-02: an empty scope used to be accepted here together with
  // an empty actionType and agentId. The profile's input domain makes scope
  // non-empty (no "" not-applicable exception), so the empty-scope half of
  // this case moved to the input-domain suite below as a rejection. The
  // empty-actionType and empty-agentId half still holds: the domain adds no
  // non-empty rule for those two fields.
  it('accepts empty strings for actionType and agentId (the non-empty rule is scope only)', () => {
    const ref = computeExternalActionRefV1({
      actionType: '',
      agentId: '',
      scope: 's',
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

describe('computeExternalActionRefV1 input domain: OUT_OF_PROFILE_DOMAIN before any digest', () => {
  // The Domain paragraph of giskard09/argentum-core docs/spec/action-ref.md
  // at commit 6ceecf5442fb9a573fdc87a0559755437a7f379f
  // (with the 2026-07-29, 2026-08-15 and 2026-08-16 entries) and its
  // reference validator _validate_domain: agent_id, action_type and
  // scope are ASCII only, scope is non-empty, and a duplicate preimage key is
  // refused. A preimage outside the domain is refused before any digest
  // exists, never canonicalized by best effort.
  const validBase = {
    actionType: 'commerce_preflight',
    agentId: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    scope: 'commerce:write',
    timestamp: '2026-04-08T12:00:00.000Z',
  }

  const nonAsciiCases = [
    // One per field, and per kind of non-ASCII: Latin-1 supplement, a BMP
    // code point, and an astral-plane code point (a surrogate pair in UTF-16).
    { field: 'agentId', value: 'did:aps:агент-001', why: 'Cyrillic' },
    { field: 'agentId', value: 'did:aps:café', why: 'Latin-1 supplement' },
    { field: 'actionType', value: 'noop.📄', why: 'astral-plane emoji, a surrogate pair' },
    { field: 'actionType', value: 'розрахунок.sign', why: 'Cyrillic' },
    { field: 'scope', value: 'scope:звіт', why: 'Cyrillic' },
    { field: 'scope', value: 'scope:📄', why: 'astral-plane emoji, a surrogate pair' },
  ] as const
  for (const c of nonAsciiCases) {
    it(`rejects a non-ASCII ${c.field} (${c.why}) with OUT_OF_PROFILE_DOMAIN`, () => {
      assert.throws(
        () => computeExternalActionRefV1({ ...validBase, [c.field]: c.value }),
        (error: unknown) => {
          assert.ok(error instanceof Error)
          assert.match(error.message, /^computeExternalActionRefV1: /)
          assert.match(error.message, /OUT_OF_PROFILE_DOMAIN/)
          assert.match(error.message, new RegExp(c.field))
          return true
        },
      )
    })
  }

  it('rejects a lone surrogate in scope (not a valid code point, and above 0x7F either way)', () => {
    assert.throws(
      () => computeExternalActionRefV1({ ...validBase, scope: `scope:${String.fromCharCode(0xd800)}` }),
      /computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: scope/,
    )
  })

  it('rejects an empty scope with OUT_OF_PROFILE_DOMAIN (no "" not-applicable exception)', () => {
    assert.throws(
      () => computeExternalActionRefV1({ ...validBase, scope: '' }),
      (error: unknown) => {
        assert.ok(error instanceof Error)
        assert.match(error.message, /^computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: scope/)
        assert.match(error.message, /non-empty/)
        return true
      },
    )
  })

  it('rejects the preimage before the timestamp is even examined (domain first, no digest)', () => {
    // Both the scope and the timestamp are invalid. The domain failure is the
    // one reported, which is what "stop before any digest" means in practice.
    assert.throws(
      () => computeExternalActionRefV1({ ...validBase, scope: '', timestamp: 'not-a-timestamp' }),
      /OUT_OF_PROFILE_DOMAIN: scope/,
    )
  })

  it('still accepts an in-domain ASCII preimage and returns the digest it returned before', () => {
    // Unchanged from the pre-domain implementation: narrowing acceptance must
    // not move a single accepted digest.
    assert.equal(
      computeExternalActionRefV1(validBase),
      '560f1463cf4d1b4f754a4f536a41df6e6c576dd249c6a887a0c7b1f773145941',
    )
    assert.equal(
      computeExternalActionRefV1({
        agentId: 'pioneer-agent-001',
        actionType: 'payment.send',
        scope: 'mycelium:payment',
        timestamp: '2026-05-24T10:30:00.000Z',
      }),
      '584bc79bb11ce3af5058b3da84d03f85e4aa464a175bd4f913aeb82a22cef60f',
    )
  })

  it('accepts the ASCII extremes: U+0000 and U+007F are in the domain, U+0080 is not', () => {
    // ASCII-only means code point <= 0x7F, not "printable". The boundary is
    // 0x7F accepted, 0x80 rejected. JCS escapes the C0 control itself; that is
    // canonicalization's business, not the domain's.
    const ref = computeExternalActionRefV1({
      ...validBase,
      scope: `a${String.fromCharCode(0x00)}${String.fromCharCode(0x7f)}~`,
    })
    assert.match(ref, /^[0-9a-f]{64}$/)
    assert.throws(
      () => computeExternalActionRefV1({ ...validBase, scope: `a${String.fromCharCode(0x80)}` }),
      /OUT_OF_PROFILE_DOMAIN: scope/,
    )
  })
})

describe('parseExternalActionRefV1Preimage: the serialized entry point', () => {
  const canonicalJson =
    '{"action_type":"payment.send","agent_id":"pioneer-agent-001","scope":"mycelium:payment","timestamp":"2026-05-24T10:30:00.000Z"}'

  it('maps the snake_case preimage to the camelCase input', () => {
    assert.deepEqual(parseExternalActionRefV1Preimage(canonicalJson), {
      actionType: 'payment.send',
      agentId: 'pioneer-agent-001',
      scope: 'mycelium:payment',
      timestamp: '2026-05-24T10:30:00.000Z',
    })
  })

  it('reaches the same digest as the direct call, in any key order', () => {
    const expected = '584bc79bb11ce3af5058b3da84d03f85e4aa464a175bd4f913aeb82a22cef60f'
    assert.equal(computeExternalActionRefV1(parseExternalActionRefV1Preimage(canonicalJson)), expected)
    assert.equal(
      computeExternalActionRefV1(
        parseExternalActionRefV1Preimage(
          '{"timestamp":"2026-05-24T10:30:00.000Z","scope":"mycelium:payment","agent_id":"pioneer-agent-001","action_type":"payment.send"}',
        ),
      ),
      expected,
    )
  })

  it('tolerates insignificant whitespace between tokens', () => {
    assert.equal(
      computeExternalActionRefV1(
        parseExternalActionRefV1Preimage(
          '{\n  "action_type" : "payment.send" ,\n  "agent_id": "pioneer-agent-001",\n  "scope": "mycelium:payment",\n  "timestamp": "2026-05-24T10:30:00.000Z"\n}\n',
        ),
      ),
      '584bc79bb11ce3af5058b3da84d03f85e4aa464a175bd4f913aeb82a22cef60f',
    )
  })

  it('rejects a duplicate preimage key with OUT_OF_PROFILE_DOMAIN', () => {
    assert.throws(
      () =>
        parseExternalActionRefV1Preimage(
          '{"agent_id":"a","action_type":"t","scope":"s","timestamp":"2026-05-24T10:30:00.000Z","agent_id":"b"}',
        ),
      (error: unknown) => {
        assert.ok(error instanceof Error)
        assert.match(error.message, /^parseExternalActionRefV1Preimage: OUT_OF_PROFILE_DOMAIN: duplicate preimage key/)
        assert.match(error.message, /agent_id/)
        return true
      },
    )
  })

  it('rejects an escape-aliased duplicate key (names compared after JSON string decoding)', () => {
    // The two member names are byte-different and decode to the same string,
    // so a parser comparing raw name bytes would accept this document.
    assert.throws(
      () =>
        parseExternalActionRefV1Preimage(
          '{"agent_id":"a","action_type":"t","scope":"s","\\u0073cope":"t","timestamp":"2026-05-24T10:30:00.000Z"}',
        ),
      /OUT_OF_PROFILE_DOMAIN: duplicate preimage key "scope"/,
    )
  })

  it('rejects a duplicate key whose value repeats identically (it is the key, not a disagreement)', () => {
    assert.throws(
      () =>
        parseExternalActionRefV1Preimage(
          '{"agent_id":"a","agent_id":"a","action_type":"t","scope":"s","timestamp":"2026-05-24T10:30:00.000Z"}',
        ),
      /OUT_OF_PROFILE_DOMAIN: duplicate preimage key "agent_id"/,
    )
  })

  it('sees a duplicate key that follows a nested value, past the value skipper', () => {
    assert.throws(
      () =>
        parseExternalActionRefV1Preimage(
          '{"agent_id":{"nested":"{\\"scope\\":1}"},"scope":[1,2,{"a":"}"}],"action_type":"t","timestamp":"2026-05-24T10:30:00.000Z","scope":"s"}',
        ),
      /OUT_OF_PROFILE_DOMAIN: duplicate preimage key "scope"/,
    )
  })

  const nonObjectTopLevels = [
    { name: 'an array', json: '[{"agent_id":"a"}]' },
    { name: 'a string', json: '"did:aps:z6Mk"' },
    { name: 'a number', json: '42' },
    { name: 'a boolean', json: 'true' },
    { name: 'null', json: 'null' },
  ] as const
  for (const c of nonObjectTopLevels) {
    it(`rejects a top level that is ${c.name}`, () => {
      assert.throws(
        () => parseExternalActionRefV1Preimage(c.json),
        /parseExternalActionRefV1Preimage: OUT_OF_PROFILE_DOMAIN: the preimage must be a JSON object/,
      )
    })
  }

  it('rejects malformed JSON rather than guessing at it', () => {
    assert.throws(
      () => parseExternalActionRefV1Preimage('{"agent_id":"a",'),
      /parseExternalActionRefV1Preimage: OUT_OF_PROFILE_DOMAIN: invalid JSON/,
    )
  })

  it('rejects a non-string argument', () => {
    assert.throws(
      () => parseExternalActionRefV1Preimage({ agent_id: 'a' } as unknown as string),
      /parseExternalActionRefV1Preimage: OUT_OF_PROFILE_DOMAIN: expected a JSON string/,
    )
  })

  it('leaves the domain and type checks to computeExternalActionRefV1', () => {
    // The parser answers only what the bytes can answer. A missing field, a
    // non-string value and an out-of-domain value all surface from the helper.
    assert.throws(
      () =>
        computeExternalActionRefV1(
          parseExternalActionRefV1Preimage('{"agent_id":"a","scope":"s","timestamp":"2026-05-24T10:30:00.000Z"}'),
        ),
      /computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: actionType must be a string/,
    )
    assert.throws(
      () =>
        computeExternalActionRefV1(
          parseExternalActionRefV1Preimage('{"agent_id":"a","action_type":"t","scope":"s","timestamp":1781166600123}'),
        ),
      /computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: timestamp must be a string or a Date/,
    )
    assert.throws(
      () =>
        computeExternalActionRefV1(
          parseExternalActionRefV1Preimage(
            '{"agent_id":"a","action_type":"t","scope":"","timestamp":"2026-05-24T10:30:00.000Z"}',
          ),
        ),
      /computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: scope/,
    )
    assert.throws(
      () =>
        computeExternalActionRefV1(
          parseExternalActionRefV1Preimage(
            '{"agent_id":"did:aps:агент","action_type":"t","scope":"s","timestamp":"2026-05-24T10:30:00.000Z"}',
          ),
        ),
      /computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: agentId/,
    )
  })
})

describe('OUT_OF_PROFILE_DOMAIN marks every rejection of an out-of-profile input', () => {
  // One marker for every domain failure. The profile requires a verifier to
  // return OUT_OF_PROFILE_DOMAIN and stop before any digest whenever a
  // preimage falls outside the domain, so a caller that wants to distinguish
  // "this input is not in the profile" from any other error must be able to
  // do it with a single check. The timestamp grammar and calendar rules are
  // part of the domain, not a separate well-formedness layer, so they carry
  // the marker too.
  //
  // Each case below also keeps the original wording after the marker, which
  // is what the per-kind assertions in the describe blocks above pin.
  const base = {
    actionType: 'commerce_preflight',
    agentId: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    scope: 'commerce:write',
    timestamp: '2026-05-24T10:30:00.000Z',
  }

  const computeCases = [
    {
      kind: 'non-string actionType',
      run: () => computeExternalActionRefV1({ ...base, actionType: 123 as unknown as string }),
    },
    {
      kind: 'non-string agentId',
      run: () => computeExternalActionRefV1({ ...base, agentId: null as unknown as string }),
    },
    {
      kind: 'non-string scope',
      run: () => computeExternalActionRefV1({ ...base, scope: ['x'] as unknown as string }),
    },
    {
      kind: 'non-string, non-Date timestamp',
      run: () =>
        computeExternalActionRefV1({ ...base, timestamp: 1781166600123 as unknown as string }),
    },
    {
      kind: 'invalid Date timestamp',
      run: () => computeExternalActionRefV1({ ...base, timestamp: new Date('not a date') }),
    },
    {
      kind: 'Date rendering outside years 0000-9999',
      run: () =>
        computeExternalActionRefV1({ ...base, timestamp: new Date(Date.UTC(10000, 0, 1)) }),
    },
    {
      kind: 'timestamp grammar failure',
      run: () => computeExternalActionRefV1({ ...base, timestamp: '2026-05-24T10:30:00Z' }),
    },
    {
      kind: 'timestamp calendar failure (day not in month)',
      run: () => computeExternalActionRefV1({ ...base, timestamp: '2026-02-30T10:30:00.000Z' }),
    },
    {
      kind: 'timestamp second 60 out of place',
      run: () => computeExternalActionRefV1({ ...base, timestamp: '2026-06-15T23:59:60.000Z' }),
    },
    {
      kind: 'non-ASCII field value',
      run: () => computeExternalActionRefV1({ ...base, scope: 'scope:звіт' }),
    },
    {
      kind: 'empty scope',
      run: () => computeExternalActionRefV1({ ...base, scope: '' }),
    },
  ] as const

  for (const c of computeCases) {
    it(`marks ${c.kind}`, () => {
      assert.throws(c.run, (error: unknown) => {
        assert.ok(error instanceof Error)
        assert.match(error.message, /OUT_OF_PROFILE_DOMAIN/)
        assert.match(error.message, /^computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: /)
        return true
      })
    })
  }

  const parseCases = [
    { kind: 'duplicate preimage key', json: '{"scope":"a","scope":"b"}' },
    { kind: 'escape-aliased duplicate preimage key', json: '{"scope":"a","\\u0073cope":"b"}' },
    { kind: 'non-object top level (array)', json: '["agent_id"]' },
    { kind: 'non-object top level (string)', json: '"agent_id"' },
    { kind: 'non-object top level (null)', json: 'null' },
    { kind: 'malformed JSON', json: '{"agent_id":"a",' },
  ] as const

  for (const c of parseCases) {
    it(`marks ${c.kind}`, () => {
      assert.throws(
        () => parseExternalActionRefV1Preimage(c.json),
        (error: unknown) => {
          assert.ok(error instanceof Error)
          assert.match(error.message, /OUT_OF_PROFILE_DOMAIN/)
          assert.match(error.message, /^parseExternalActionRefV1Preimage: OUT_OF_PROFILE_DOMAIN: /)
          return true
        },
      )
    })
  }

  it('marks a non-string argument to the parser', () => {
    assert.throws(
      () => parseExternalActionRefV1Preimage(42 as unknown as string),
      (error: unknown) => {
        assert.ok(error instanceof Error)
        assert.match(error.message, /^parseExternalActionRefV1Preimage: OUT_OF_PROFILE_DOMAIN: /)
        return true
      },
    )
  })

  it('marks every rejection reachable through the serialized entry point', () => {
    // The adapter the conformance Action drives is
    // computeExternalActionRefV1(parseExternalActionRefV1Preimage(bytes)),
    // so the marker has to hold for that composition and not only for each
    // function in isolation.
    const outOfProfile = [
      '{"agent_id":"a","action_type":"t","scope":"","timestamp":"2026-05-24T10:30:00.000Z"}',
      '{"agent_id":"did:aps:агент","action_type":"t","scope":"s","timestamp":"2026-05-24T10:30:00.000Z"}',
      '{"agent_id":"a","action_type":"t","scope":"s","timestamp":"2026-05-24T10:30:00Z"}',
      '{"agent_id":"a","action_type":"t","scope":"s","timestamp":"2026-02-30T10:30:00.000Z"}',
      '{"agent_id":"a","action_type":"t","scope":"s","timestamp":1781166600123}',
      '{"agent_id":"a","action_type":"t","scope":"s","agent_id":"b","timestamp":"2026-05-24T10:30:00.000Z"}',
      '[]',
    ]
    for (const json of outOfProfile) {
      assert.throws(
        () => computeExternalActionRefV1(parseExternalActionRefV1Preimage(json)),
        (error: unknown) => {
          assert.ok(error instanceof Error, `expected an Error for ${json}`)
          assert.match(error.message, /OUT_OF_PROFILE_DOMAIN/, `unmarked rejection for ${json}`)
          return true
        },
      )
    }
  })
})
