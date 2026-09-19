// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  computeActionRefV2,
  computeActionRefV2FromJson,
  computePayloadRefV1,
  createActionReferenceInputV2,
  parseActionReferenceInputV2,
  type ActionReferenceInputV2,
} from '../src/v2/action-reference/v2.js'

describe('action_ref v2', () => {
  const base = () => createActionReferenceInputV2({
    agent_id: 'did:example:agent',
    action_type: 'mcp:tools/call',
    target: 'https://mcp.example#tool=checkout',
    payload_ref: computePayloadRefV1({ cart: ['sku-1'] }),
    scope_required: ['commerce:write'],
    issued_at: '2026-07-17T00:00:00.000Z',
    nonce: '11'.repeat(16),
  })

  it('is deterministic and domain-shaped', () => {
    assert.match(computeActionRefV2(base()), /^[0-9a-f]{64}$/)
    assert.equal(computeActionRefV2(base()), computeActionRefV2(base()))
  })

  it('binds target, payload, and nonce so same-second calls do not collide', () => {
    const original = base()
    assert.notEqual(computeActionRefV2(original), computeActionRefV2({ ...original, target: 'https://mcp.example#tool=refund' }))
    assert.notEqual(computeActionRefV2(original), computeActionRefV2({ ...original, payload_ref: computePayloadRefV1({ cart: ['sku-2'] }) }))
    assert.notEqual(computeActionRefV2(original), computeActionRefV2({ ...original, nonce: '12'.repeat(16) }))
  })

  it('normalizes and sorts scopes before hashing', () => {
    const first = createActionReferenceInputV2({
      ...base(),
      scope_required: ['repo:write', 'cafe\u0301:read'],
    })
    const second = createActionReferenceInputV2({
      ...base(),
      scope_required: ['caf\u00e9:read', 'repo:write'],
    })
    assert.equal(computeActionRefV2(first), computeActionRefV2(second))
  })
})

describe('action_ref v2 serialized input, strict duplicate-member parsing', () => {
  // A well-formed document, written out as the bytes a peer would send.
  const doc = {
    profile: 'aps-action-ref-v2',
    agent_id: 'did:example:agent',
    action_type: 'mcp:tools/call',
    target: 'https://mcp.example#tool=checkout',
    payload_ref: computePayloadRefV1({ cart: ['sku-1'] }),
    scope_required: ['commerce:write'],
    issued_at: '2026-07-17T00:00:00.000Z',
    nonce: '11'.repeat(16),
  }
  const clean = JSON.stringify(doc)
  // JSON.stringify cannot emit a duplicate member, so the duplicate is spliced
  // in textually. That is the point: the fact only exists in the byte stream.
  const withDuplicate = clean.replace(
    '"agent_id":"did:example:agent"',
    '"agent_id":"did:example:agent","agent_id":"did:example:attacker"',
  )
  // Same member name reached through an escape alias rather than a literal
  // repeat, so this is rejected only if names are compared AFTER decoding.
  const withEscapedDuplicate = clean.replace(
    '"agent_id":"did:example:agent"',
    '"agent_id":"did:example:agent","\\u0061gent_id":"did:example:attacker"',
  )

  it('the duplicate is genuinely present in the raw bytes', () => {
    // Guards the fixture itself: if the splice silently failed, the rejection
    // tests below would pass for the wrong reason.
    assert.notEqual(withDuplicate, clean)
    assert.notEqual(withEscapedDuplicate, clean)
    assert.equal(withDuplicate.match(/"agent_id":/g)?.length, 2)
    // And a permissive parser really does lose it, which is why validation
    // downstream of JSON.parse can never see this.
    assert.equal((JSON.parse(withDuplicate) as { agent_id: string }).agent_id, 'did:example:attacker')
  })

  it('rejects a duplicated member name at parseActionReferenceInputV2', () => {
    assert.throws(() => parseActionReferenceInputV2(withDuplicate), /duplicate object member/)
  })

  it('rejects a duplicated member name at computeActionRefV2FromJson', () => {
    assert.throws(() => computeActionRefV2FromJson(withDuplicate), /duplicate object member/)
  })

  it('rejects an escape-aliased duplicate at both entry points', () => {
    assert.throws(() => parseActionReferenceInputV2(withEscapedDuplicate), /duplicate object member/)
    assert.throws(() => computeActionRefV2FromJson(withEscapedDuplicate), /duplicate object member/)
  })

  it('accepts the same document without the duplicate', () => {
    const parsed = parseActionReferenceInputV2(clean)
    assert.equal(parsed.agent_id, 'did:example:agent')
    assert.match(computeActionRefV2FromJson(clean), /^[0-9a-f]{64}$/)
  })

  it('agrees digest-for-digest with the already-parsed path', () => {
    // Proves the serialized path is the existing path plus parsing, not a
    // second implementation that could drift.
    assert.equal(computeActionRefV2FromJson(clean), computeActionRefV2(parseActionReferenceInputV2(clean)))
    assert.equal(computeActionRefV2FromJson(clean), computeActionRefV2(createActionReferenceInputV2({
      agent_id: doc.agent_id,
      action_type: doc.action_type,
      target: doc.target,
      payload_ref: doc.payload_ref,
      scope_required: doc.scope_required,
      issued_at: doc.issued_at,
      nonce: doc.nonce,
    })))
  })

  it('does not weaken the existing validation it wraps', () => {
    const wrongProfile = clean.replace('"aps-action-ref-v2"', '"aps-action-ref-v1"')
    assert.throws(() => parseActionReferenceInputV2(wrongProfile), /action reference profile/)
    const badNonce = clean.replace(doc.nonce, 'zz'.repeat(16))
    assert.throws(() => parseActionReferenceInputV2(badNonce))
    const extraKey = clean.replace('"profile":', '"unexpected":1,"profile":')
    assert.throws(() => parseActionReferenceInputV2(extraKey))
  })
})

describe('action_ref v2, section 4.1 type coercion rejection', () => {
  // The frozen valid input from the pinned-digest vector below. Also the base
  // for every mutation case: only the field under test is replaced.
  const validInput = {
    profile: 'aps-action-ref-v2',
    agent_id: 'did:key:z6MkA',
    action_type: 'commerce_preflight',
    target: 'https://api.example/payments',
    payload_ref: 'a'.repeat(64),
    scope_required: ['commerce:read'],
    issued_at: '2026-04-08T12:00:00.000Z',
    nonce: 'b'.repeat(32),
  }

  const fieldMessages: Record<'payload_ref' | 'issued_at' | 'nonce', RegExp> = {
    payload_ref: /^Error: payload_ref: expected 64 lowercase hexadecimal characters$/,
    issued_at: /^Error: issued_at: expected canonical UTC milliseconds$/,
    nonce: /^Error: nonce: expected 32 lowercase hexadecimal characters$/,
  }

  for (const field of ['payload_ref', 'issued_at', 'nonce'] as const) {
    const validValue = validInput[field]
    const message = fieldMessages[field]

    const mutations: Record<string, unknown> = {
      'a one-element array holding the valid value': [validValue],
      'a nested array wrapping the valid value': [[validValue]],
      'a number': 12345,
      'null': null,
    }

    for (const [label, malformed] of Object.entries(mutations)) {
      it(`computeActionRefV2 rejects ${field} as ${label}`, () => {
        const candidate = { ...validInput, [field]: malformed } as unknown as ActionReferenceInputV2
        assert.throws(() => computeActionRefV2(candidate), message)
      })
    }

    // Only JSON.stringify-able mutations round-trip through the serialized
    // entry point; the array-wrapped cases cover the coercion this defect
    // was actually about (String(["x"]) === "x").
    for (const label of [
      'a one-element array holding the valid value',
      'a nested array wrapping the valid value',
    ] as const) {
      it(`parseActionReferenceInputV2 rejects ${field} as ${label}`, () => {
        const raw = JSON.stringify({ ...validInput, [field]: mutations[label] })
        assert.throws(() => parseActionReferenceInputV2(raw), message)
      })
    }
  }

  it('the pinned valid-input digest is unchanged (produced by the unmodified code on 2026-09-18)', () => {
    const value: ActionReferenceInputV2 = {
      profile: 'aps-action-ref-v2',
      agent_id: validInput.agent_id,
      action_type: validInput.action_type,
      target: validInput.target,
      payload_ref: validInput.payload_ref,
      scope_required: validInput.scope_required,
      issued_at: validInput.issued_at,
      nonce: validInput.nonce,
    }
    assert.equal(
      computeActionRefV2(value),
      'bf73633f76d1fd2aa81564dbd69d04f6f815d5bb3f27495a480f5984e256a822',
    )
  })
})

describe('action_ref v2, section 4.1 second-60 (leap second) admissibility (draft03-repair)', () => {
  // AR-P01 of the cross-implementation vector file: a complete, already
  // valid ActionReferenceInputV2. Every case below is this object as-is or
  // with only issued_at replaced.
  const base: ActionReferenceInputV2 = {
    profile: 'aps-action-ref-v2',
    agent_id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    action_type: 'commerce_preflight',
    target: 'https://api.example/payments',
    payload_ref: '9e1d86673f6f2401f5504fdac162c3a429dc2b539f9fa2e0d22a588fb3ffabdf',
    scope_required: ['commerce:read', 'commerce:write'],
    issued_at: '2026-04-08T12:00:00.000Z',
    nonce: '00112233445566778899aabbccddeeff',
  }

  it('AR-P01: the base digest is unchanged by the fix', () => {
    assert.equal(
      computeActionRefV2(base),
      '4931f6d13c63a865901de8135ee442cd9ee40a1075e52c72594fa18c713a8382',
    )
  })

  it('AR-P17: second 60 on an actual leap-second date is accepted, digest from the section 4.1 formula', () => {
    const value: ActionReferenceInputV2 = { ...base, issued_at: '2016-12-31T23:59:60.000Z' }
    assert.equal(
      computeActionRefV2(value),
      '970594ab1ede3ececd07231e045f2764fc1b5cefad1017df556f98d41ab5a5eb',
    )
  })

  it('AR-N38 (formerly AR-P18): second 60 not at 23:59 on the last day of the month is rejected (was accepted before RFC 3339 section 5.7 was applied)', () => {
    const value: ActionReferenceInputV2 = { ...base, issued_at: '2026-04-08T12:00:60.000Z' }
    assert.throws(() => computeActionRefV2(value), /^Error: issued_at: invalid calendar timestamp$/)
  })

  it('AR-P17 and AR-N38 (formerly AR-P18) agree through the serialized entry point', () => {
    const ar17: ActionReferenceInputV2 = { ...base, issued_at: '2016-12-31T23:59:60.000Z' }
    const ar18: ActionReferenceInputV2 = { ...base, issued_at: '2026-04-08T12:00:60.000Z' }
    assert.equal(computeActionRefV2FromJson(JSON.stringify(ar17)), computeActionRefV2(ar17))
    assert.throws(() => computeActionRefV2FromJson(JSON.stringify(ar18)), /issued_at: invalid calendar timestamp/)
    assert.throws(() => computeActionRefV2(ar18), /issued_at: invalid calendar timestamp/)
  })

  const rejectionCases: Array<[string, string, RegExp]> = [
    ['second 61, past the leap-second allowance', '2026-04-08T12:00:61.000Z',
      /^Error: issued_at: expected canonical UTC milliseconds$/],
    ['day 30 of February in a non-leap year', '2026-02-30T00:00:00.000Z',
      /^Error: issued_at: invalid calendar timestamp$/],
    ['day 29 of February in a non-leap year', '2027-02-29T00:00:00.000Z',
      /^Error: issued_at: invalid calendar timestamp$/],
    ['hour 24', '2026-04-08T24:00:00.000Z',
      /^Error: issued_at: expected canonical UTC milliseconds$/],
    ['second 60 with no fractional digits', '2026-04-08T12:00:60Z',
      /^Error: issued_at: expected canonical UTC milliseconds$/],
    // RFC 3339 section 5.7 and Appendix D: second 60 is valid only
    // at 23:59 on the last day of its month.
    ['second 60 not on the last day of the month (AR-N38, formerly AR-P18)', '2026-04-08T12:00:60.000Z',
      /^Error: issued_at: invalid calendar timestamp$/],
    ['second 60 on a day that is not the last day of June', '2026-06-29T23:59:60.000Z',
      /^Error: issued_at: invalid calendar timestamp$/],
    ['second 60 at minute 58', '2016-12-31T23:58:60.000Z',
      /^Error: issued_at: invalid calendar timestamp$/],
    ['second 60 at hour 22', '2016-12-31T22:59:60.000Z',
      /^Error: issued_at: invalid calendar timestamp$/],
    ['second 60 on February 28 of a leap year, not the last day', '2028-02-28T23:59:60.000Z',
      /^Error: issued_at: invalid calendar timestamp$/],
    ['second 60 on February 29 of a non-leap year, no such day', '2027-02-29T23:59:60.000Z',
      /^Error: issued_at: invalid calendar timestamp$/],
  ]

  for (const [label, issuedAt, message] of rejectionCases) {
    it(`rejects issued_at: ${label}`, () => {
      const value: ActionReferenceInputV2 = { ...base, issued_at: issuedAt }
      assert.throws(() => computeActionRefV2(value), message)
    })
  }

  const acceptedCases: Array<[string, string]> = [
    ['second 60 on the last day of February in a leap year', '2028-02-29T23:59:60.000Z'],
    ['year 0000, a leap year under the proleptic Gregorian rule', '0000-02-29T00:00:00.000Z'],
    // RFC 3339 section 5.7 and Appendix D: second 60 at 23:59 on
    // the last day of its month.
    ['second 60 on the last day of December (AR-P17 date)', '2016-12-31T23:59:60.000Z'],
    ['second 60 on the last day of June', '2026-06-30T23:59:60.000Z'],
    ['second 60 on the last day of February in a leap year, non-zero milliseconds', '2028-02-29T23:59:60.999Z'],
    ['second 60 on the last day of February in a non-leap year', '2027-02-28T23:59:60.000Z'],
    ['second 60 on the last day of February, year 0000 (leap year)', '0000-02-29T23:59:60.000Z'],
  ]

  for (const [label, issuedAt] of acceptedCases) {
    it(`accepts issued_at: ${label}`, () => {
      const value: ActionReferenceInputV2 = { ...base, issued_at: issuedAt }
      assert.match(computeActionRefV2(value), /^[0-9a-f]{64}$/)
    })
  }
})

describe('action_ref v2, section 4.1 rejects noncharacters (draft section 4.1 lines 813-815, RFC 7493 section 2.1)', () => {
  // Same base as AR-P01 above: a complete, valid ActionReferenceInputV2.
  // Every case below is this object as-is or with only the field under test
  // mutated. Noncharacters are written as JS escapes, never as literal
  // source bytes: BMP noncharacters as \uXXXX, and the two supplementary
  // ones (U+10FFFF, U+1FFFE) as their decoded surrogate pairs.
  const base: ActionReferenceInputV2 = {
    profile: 'aps-action-ref-v2',
    agent_id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    action_type: 'commerce_preflight',
    target: 'https://api.example/payments',
    payload_ref: '9e1d86673f6f2401f5504fdac162c3a429dc2b539f9fa2e0d22a588fb3ffabdf',
    scope_required: ['commerce:read', 'commerce:write'],
    issued_at: '2026-04-08T12:00:00.000Z',
    nonce: '00112233445566778899aabbccddeeff',
  }

  it('AR-N: agent_id with a trailing noncharacter U+FDD0 is rejected', () => {
    const value: ActionReferenceInputV2 = { ...base, agent_id: base.agent_id + '\ufdd0' }
    assert.throws(() => computeActionRefV2(value), /^Error: \$\.agent_id: noncharacter$/)
  })

  it('AR-N: target with a trailing noncharacter U+FFFF is rejected', () => {
    const value: ActionReferenceInputV2 = { ...base, target: base.target + '\uffff' }
    assert.throws(() => computeActionRefV2(value), /^Error: \$\.target: noncharacter$/)
  })

  it('AR-N: scope_required with a noncharacter U+10FFFF, still sorted after commerce:read, is rejected', () => {
    // \udbff\udfff is U+10FFFF decoded as its UTF-16 surrogate pair, written
    // as an explicit JavaScript escape sequence rather than a literal
    // character: the low 16 bits of the code point are FFFF, so it is a
    // noncharacter regardless of the surrogate encoding.
    const scope = 'commerce:write' + '\udbff\udfff'
    const value: ActionReferenceInputV2 = { ...base, scope_required: ['commerce:read', scope] }
    assert.throws(() => computeActionRefV2(value), /^Error: \$\.scope_required\[1\]: noncharacter$/)
  })

  it('PR-N: a payload string with a noncharacter U+1FFFE is rejected', () => {
    // \ud83f\udffe is U+1FFFE decoded: low 16 bits FFFE.
    assert.throws(
      () => computePayloadRefV1({ note: 'x' + '\ud83f\udffe' }),
      /^Error: \$\.note: noncharacter$/,
    )
  })

  it('AJ-N: a JSON-escaped noncharacter U+FFFF in action_type is rejected at the serialized entry point', () => {
    const raw = JSON.stringify(base).replace(
      '"action_type":"commerce_preflight"',
      '"action_type":"commerce_preflight\\uffff"',
    )
    assert.throws(() => computeActionRefV2FromJson(raw), /^Error: \$\.action_type: noncharacter$/)
  })

  it('AC-N: createActionReferenceInputV2 rejects a target with a noncharacter U+FDEF', () => {
    assert.throws(() => createActionReferenceInputV2({
      agent_id: base.agent_id,
      action_type: base.action_type,
      target: 'https://api.example/pay' + '\ufdef',
      payload_ref: base.payload_ref,
      scope_required: base.scope_required,
      issued_at: base.issued_at,
      nonce: base.nonce,
    }), /^Error: \$\.target: noncharacter$/)
  })

  it('AR-P: agent_id with the replacement character U+FFFD (not a noncharacter) is accepted', () => {
    const value: ActionReferenceInputV2 = { ...base, agent_id: base.agent_id + '\ufffd' }
    assert.match(computeActionRefV2(value), /^[0-9a-f]{64}$/)
  })

  it('AR-P: target with U+1F600 is accepted', () => {
    // \ud83d\ude00 is U+1F600 decoded: low 16 bits F600, not FFFE or FFFF.
    const value: ActionReferenceInputV2 = { ...base, target: base.target + '\ud83d\ude00' }
    assert.match(computeActionRefV2(value), /^[0-9a-f]{64}$/)
  })
})
