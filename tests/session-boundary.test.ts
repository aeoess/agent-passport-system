// HLC session boundary extraction tests.
// Reference: Nanook PDR v2.19 §7.6.3, gap audit §3 row 14 / row 29 / §5 rank 5.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  extractSessions,
  DEFAULT_SESSION_GAP_MS,
} from '../src/index.js'
import type { HybridTimestamp, SessionBoundary } from '../src/index.js'

// ── Fixtures ────────────────────────────────────────────────

/** Build a HybridTimestamp at a deterministic wall-clock midpoint with a
 *  symmetric NTP drift bound. The function is pure: every test stamp is
 *  constructed from explicit numbers, never from Date.now(). */
function stamp(opts: {
  midpointMs: number
  driftMs?: number
  logicalTime?: number
  gatewayId?: string
}): HybridTimestamp {
  const drift = opts.driftMs ?? 50
  return {
    logicalTime: opts.logicalTime ?? 0,
    wallClockEarliest: opts.midpointMs - drift,
    wallClockLatest: opts.midpointMs + drift,
    gatewayId: opts.gatewayId ?? 'gw-test',
  }
}

/** Walk-clock midpoint at minute boundary, drift 50ms by default.
 *  Use minute increments so default 5-minute threshold has clear semantics. */
function minute(n: number, driftMs?: number, logicalTime?: number): HybridTimestamp {
  return stamp({ midpointMs: n * 60_000, driftMs, logicalTime })
}

// ── 1. Empty array ──────────────────────────────────────────

describe('extractSessions — empty input', () => {
  it('returns empty array for empty input', () => {
    assert.deepEqual(extractSessions([]), [])
  })
})

// ── 2. Single stamp ─────────────────────────────────────────

describe('extractSessions — single stamp', () => {
  it('returns one session with start === end and eventCount = 1', () => {
    const s = minute(1)
    const sessions = extractSessions([s])
    assert.equal(sessions.length, 1)
    assert.strictEqual(sessions[0].start, s)
    assert.strictEqual(sessions[0].end, s)
    assert.equal(sessions[0].eventCount, 1)
    assert.equal(sessions[0].gapFromPreviousMs, 0)
  })
})

// ── 3. Two stamps within threshold ──────────────────────────

describe('extractSessions — two stamps within threshold', () => {
  it('groups two stamps 1 minute apart into one session (eventCount=2)', () => {
    const a = minute(1)
    const b = minute(2)
    const sessions = extractSessions([a, b])
    assert.equal(sessions.length, 1)
    assert.strictEqual(sessions[0].start, a)
    assert.strictEqual(sessions[0].end, b)
    assert.equal(sessions[0].eventCount, 2)
    assert.equal(sessions[0].gapFromPreviousMs, 0)
  })
})

// ── 4. Two stamps separated by exactly threshold + 1 ────────

describe('extractSessions — strict greater-than boundary', () => {
  it('two stamps separated by exactly DEFAULT_SESSION_GAP_MS + 1ms split into two sessions', () => {
    // Conservative gap = next.earliest - prev.latest. We need
    //   next.midpoint - 50 - (prev.midpoint + 50) > 300_000
    // → next.midpoint > prev.midpoint + 300_100
    // Set next.midpoint = prev.midpoint + 300_101, so gap = 300_001 (> 300_000).
    const a = stamp({ midpointMs: 1_000_000 })
    const b = stamp({ midpointMs: 1_000_000 + 300_101 })
    const sessions = extractSessions([a, b])
    assert.equal(sessions.length, 2, 'gap of 300_001 ms (> 300_000) splits sessions')
    assert.equal(sessions[0].eventCount, 1)
    assert.equal(sessions[1].eventCount, 1)
    assert.strictEqual(sessions[0].start, a)
    assert.strictEqual(sessions[1].start, b)
  })

  it('two stamps separated by EXACTLY DEFAULT_SESSION_GAP_MS stay in one session', () => {
    // Conservative gap exactly equal to threshold should NOT split.
    // gap = next.earliest - prev.latest = (next.midpoint - 50) - (prev.midpoint + 50)
    //     = next.midpoint - prev.midpoint - 100
    // For gap === 300_000: next.midpoint = prev.midpoint + 300_100
    const a = stamp({ midpointMs: 1_000_000 })
    const b = stamp({ midpointMs: 1_000_000 + 300_100 })
    // Sanity-check the math: the conservative gap should be exactly 300_000
    assert.equal(b.wallClockEarliest - a.wallClockLatest, 300_000, 'sanity: gap is exactly the threshold')
    const sessions = extractSessions([a, b])
    assert.equal(sessions.length, 1, 'gap exactly equal to threshold does NOT split (strict greater-than)')
    assert.equal(sessions[0].eventCount, 2)
  })
})

// ── 5. Three-stamp sequence with one gap in the middle ─────

describe('extractSessions — three stamps, one mid gap', () => {
  it('gap between #1 and #2 produces sessions [1] and [2,3]', () => {
    // a then huge gap then b, c close together
    const a = stamp({ midpointMs: 0 })
    const b = stamp({ midpointMs: 600_000 })  // 10 minutes after a → split
    const c = stamp({ midpointMs: 660_000 })  // 1 minute after b → grouped
    const sessions = extractSessions([a, b, c])
    assert.equal(sessions.length, 2)
    assert.equal(sessions[0].eventCount, 1)
    assert.equal(sessions[1].eventCount, 2)
    assert.strictEqual(sessions[0].start, a)
    assert.strictEqual(sessions[0].end, a)
    assert.strictEqual(sessions[1].start, b)
    assert.strictEqual(sessions[1].end, c)
  })

  it('gap between #2 and #3 produces sessions [1,2] and [3]', () => {
    const a = stamp({ midpointMs: 0 })
    const b = stamp({ midpointMs: 60_000 })   // 1 minute after a → grouped
    const c = stamp({ midpointMs: 660_000 })  // 10 minutes after b → split
    const sessions = extractSessions([a, b, c])
    assert.equal(sessions.length, 2)
    assert.equal(sessions[0].eventCount, 2)
    assert.equal(sessions[1].eventCount, 1)
    assert.strictEqual(sessions[0].start, a)
    assert.strictEqual(sessions[0].end, b)
    assert.strictEqual(sessions[1].start, c)
  })
})

// ── 6. Five-stamp sequence with two gaps → three sessions ──

describe('extractSessions — five stamps, two gaps', () => {
  it('returns three sessions with correct event counts', () => {
    // Sequence: A B  ........  C  ........  D E
    // Sessions: [A,B] [C] [D,E]
    const a = stamp({ midpointMs: 0 })
    const b = stamp({ midpointMs: 60_000 })
    const c = stamp({ midpointMs: 600_000 })  // 9 min gap from b → split
    const d = stamp({ midpointMs: 1_200_000 }) // 10 min gap from c → split
    const e = stamp({ midpointMs: 1_260_000 }) // 1 min after d → grouped
    const sessions = extractSessions([a, b, c, d, e])
    assert.equal(sessions.length, 3)
    assert.equal(sessions[0].eventCount, 2)
    assert.equal(sessions[1].eventCount, 1)
    assert.equal(sessions[2].eventCount, 2)
    assert.strictEqual(sessions[0].start, a)
    assert.strictEqual(sessions[0].end, b)
    assert.strictEqual(sessions[1].start, c)
    assert.strictEqual(sessions[1].end, c)
    assert.strictEqual(sessions[2].start, d)
    assert.strictEqual(sessions[2].end, e)
  })

  it('every stamp separated by more than threshold returns N single-event sessions', () => {
    const sequence = [0, 1, 2, 3, 4].map(i => stamp({ midpointMs: i * 600_000 }))
    const sessions = extractSessions(sequence)
    assert.equal(sessions.length, 5)
    for (const s of sessions) {
      assert.equal(s.eventCount, 1)
    }
  })

  it('all stamps within threshold returns one session covering full range', () => {
    const sequence = [0, 1, 2, 3, 4].map(i => stamp({ midpointMs: i * 60_000 }))
    const sessions = extractSessions(sequence)
    assert.equal(sessions.length, 1)
    assert.equal(sessions[0].eventCount, 5)
    assert.strictEqual(sessions[0].start, sequence[0])
    assert.strictEqual(sessions[0].end, sequence[4])
  })
})

// ── 7. Custom threshold override ────────────────────────────

describe('extractSessions — custom gapThresholdMs', () => {
  it('tighter threshold (60_000 = 1 min) splits stamps that the default (5 min) groups', () => {
    const a = stamp({ midpointMs: 0 })
    const b = stamp({ midpointMs: 120_000 }) // 2 min — under default, over custom

    const defaultSessions = extractSessions([a, b])
    assert.equal(defaultSessions.length, 1, 'default 5-min threshold groups them')

    const customSessions = extractSessions([a, b], { gapThresholdMs: 60_000 })
    assert.equal(customSessions.length, 2, '1-min threshold splits them')
  })

  it('looser threshold (1 hour) groups stamps that the default would split', () => {
    const a = stamp({ midpointMs: 0 })
    const b = stamp({ midpointMs: 600_000 }) // 10 min — over default, under 1 hour

    assert.equal(extractSessions([a, b]).length, 2, 'default splits at 10 min')
    assert.equal(
      extractSessions([a, b], { gapThresholdMs: 3_600_000 }).length,
      1,
      '1-hour threshold groups them',
    )
  })
})

// ── 8. Default threshold regression lock ────────────────────

describe('extractSessions — default threshold', () => {
  it('DEFAULT_SESSION_GAP_MS is 300_000 (5 minutes)', () => {
    assert.equal(DEFAULT_SESSION_GAP_MS, 300_000)
  })
})

// ── 9. gapFromPreviousMs ────────────────────────────────────

describe('extractSessions — gapFromPreviousMs', () => {
  it('first session always has gapFromPreviousMs = 0', () => {
    const a = stamp({ midpointMs: 1_000_000 })
    const b = stamp({ midpointMs: 5_000_000 })
    const sessions = extractSessions([a, b])
    assert.equal(sessions[0].gapFromPreviousMs, 0)
  })

  it('subsequent sessions report the conservative gap from the previous session end', () => {
    // Three sessions: [A], [B], [C]
    // A ends at midpoint=0+50=50
    // B starts at midpoint=600_000, earliest=599_950 → gap = 599_950 - 50 = 599_900
    // B ends at midpoint=600_000, latest=600_050
    // C starts at midpoint=1_200_000, earliest=1_199_950 → gap = 1_199_950 - 600_050 = 599_900
    const a = stamp({ midpointMs: 0 })
    const b = stamp({ midpointMs: 600_000 })
    const c = stamp({ midpointMs: 1_200_000 })
    const sessions = extractSessions([a, b, c])
    assert.equal(sessions.length, 3)
    assert.equal(sessions[0].gapFromPreviousMs, 0)
    assert.equal(sessions[1].gapFromPreviousMs, 599_900)
    assert.equal(sessions[2].gapFromPreviousMs, 599_900)
  })
})

// ── 10. Overlapping wall-clock ranges (negative conservative gap) ──

describe('extractSessions — overlapping wall-clock ranges', () => {
  it('overlapping ranges produce no boundary even when logical ordering differs', () => {
    // Two stamps with overlapping wall-clock ranges:
    //   A: midpoint=1000, latest=1050
    //   B: midpoint=1020, earliest=970
    // Conservative gap = 970 - 1050 = -80 (negative, ranges overlap)
    // → no boundary, even though logically distinct events
    const a: HybridTimestamp = {
      logicalTime: 1,
      wallClockEarliest: 950,
      wallClockLatest: 1050,
      gatewayId: 'gw-1',
    }
    const b: HybridTimestamp = {
      logicalTime: 2,
      wallClockEarliest: 970,
      wallClockLatest: 1070,
      gatewayId: 'gw-1',
    }
    const sessions = extractSessions([a, b])
    assert.equal(sessions.length, 1, 'overlapping ranges = same session')
    assert.equal(sessions[0].eventCount, 2)
  })

  it('overlapping ranges across different gateways still produce no boundary', () => {
    // Negative gap is negative regardless of gatewayId — the conservative
    // wall-clock test does not consult logical ordering.
    const a: HybridTimestamp = {
      logicalTime: 100,
      wallClockEarliest: 0,
      wallClockLatest: 1000,
      gatewayId: 'gw-A',
    }
    const b: HybridTimestamp = {
      logicalTime: 1,
      wallClockEarliest: 500,
      wallClockLatest: 1500,
      gatewayId: 'gw-B',
    }
    const sessions = extractSessions([a, b])
    assert.equal(sessions.length, 1)
    assert.equal(sessions[0].eventCount, 2)
  })
})

// ── 11. Input is not mutated ────────────────────────────────

describe('extractSessions — input immutability', () => {
  it('does not mutate the input array', () => {
    const a = stamp({ midpointMs: 0 })
    const b = stamp({ midpointMs: 60_000 })
    const c = stamp({ midpointMs: 660_000 }) // 10 min gap → split
    const input = [a, b, c]
    const inputSnapshot = [...input]
    const inputLength = input.length

    extractSessions(input)

    assert.equal(input.length, inputLength)
    for (let i = 0; i < inputSnapshot.length; i++) {
      assert.strictEqual(input[i], inputSnapshot[i])
    }
  })

  it('does not mutate any input HybridTimestamp object', () => {
    const a = stamp({ midpointMs: 0 })
    const beforeA = { ...a }
    extractSessions([a])
    assert.deepEqual(a, beforeA)
  })
})

// ── 12. No clock reads (purity check) ──────────────────────

describe('extractSessions — does not consult Date.now()', () => {
  it('a far-past stamp followed by a close stamp groups together', () => {
    // If the function read the wall clock, it might treat these as ancient
    // and split. They should be grouped because the gap between them is small.
    const ancient = stamp({ midpointMs: 1_000_000 }) // 1970-01-01 + ~16 min
    const slightlyLater = stamp({ midpointMs: 1_060_000 }) // 1 min later
    const sessions = extractSessions([ancient, slightlyLater])
    assert.equal(sessions.length, 1)
    assert.equal(sessions[0].eventCount, 2)
  })

  it('a far-future stamp grouped with a close stamp also stays one session', () => {
    const future1 = stamp({ midpointMs: 99_999_999_000 }) // year ~5138
    const future2 = stamp({ midpointMs: 99_999_999_000 + 60_000 })
    const sessions = extractSessions([future1, future2])
    assert.equal(sessions.length, 1)
    assert.equal(sessions[0].eventCount, 2)
  })

  it('mixing past and future stamps splits if their gap exceeds threshold', () => {
    const ancient = stamp({ midpointMs: 0 })
    const future = stamp({ midpointMs: 99_999_999_000 })
    const sessions = extractSessions([ancient, future])
    assert.equal(sessions.length, 2)
  })
})
