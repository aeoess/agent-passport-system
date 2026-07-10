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
