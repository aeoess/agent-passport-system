// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// M4 verifier production-hardening tests (additive).
// Explicit negative-path fixtures for every check.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  DEFAULT_CLOCK_SKEW_MS,
  checkClockSkew,
  InMemorySeenSet,
  checkReplay,
  recordRevocationFreshness,
  hashReceiptForChain,
  verifyReceiptSequence,
  buildHardeningScopeOfClaim,
} from '../../src/v2/verifier-hardening/index.js'
import { createSnapshotFreshness, createRotatingFreshness } from '../../src/core/freshness.js'
import type { ActionReceipt } from '../../src/types/passport.js'

const now = new Date('2026-05-31T12:00:00.000Z')
const nowMs = now.getTime()

// ── (a) clock skew ──

describe('M4 clock skew: uniform allowedClockSkewMs', () => {
  const skew = 60_000 // 60s

  it('exp exactly at the lower boundary (now - skew) is accepted', () => {
    const exp = new Date(nowMs - skew) // exp === now - skew → valid (inclusive)
    const r = checkClockSkew({ exp, now, allowedClockSkewMs: skew })
    assert.equal(r.verdict, 'valid')
    assert.equal(r.outsideByMs, 0)
  })

  it('exp one ms past the lower boundary is rejected as expired', () => {
    const exp = new Date(nowMs - skew - 1)
    const r = checkClockSkew({ exp, now, allowedClockSkewMs: skew })
    assert.equal(r.verdict, 'expired')
    assert.equal(r.outsideByMs, 1)
  })

  it('iat exactly at the upper boundary (now + skew) is accepted', () => {
    const iat = new Date(nowMs + skew) // iat === now + skew → valid (inclusive)
    const r = checkClockSkew({ iat, now, allowedClockSkewMs: skew })
    assert.equal(r.verdict, 'valid')
  })

  it('iat one ms past the upper boundary is rejected as not_yet_valid', () => {
    const iat = new Date(nowMs + skew + 1)
    const r = checkClockSkew({ iat, now, allowedClockSkewMs: skew })
    assert.equal(r.verdict, 'not_yet_valid')
    assert.equal(r.outsideByMs, 1)
  })

  it('accepts ISO strings and epoch-ms equally', () => {
    const isoExp = new Date(nowMs - skew).toISOString()
    assert.equal(checkClockSkew({ exp: isoExp, now, allowedClockSkewMs: skew }).verdict, 'valid')
    assert.equal(checkClockSkew({ exp: nowMs - skew, now, allowedClockSkewMs: skew }).verdict, 'valid')
  })

  it('defaults to DEFAULT_CLOCK_SKEW_MS when no skew is supplied', () => {
    const exp = new Date(nowMs - DEFAULT_CLOCK_SKEW_MS) // exactly at default boundary
    assert.equal(checkClockSkew({ exp, now }).verdict, 'valid')
    const expPast = new Date(nowMs - DEFAULT_CLOCK_SKEW_MS - 1)
    assert.equal(checkClockSkew({ exp: expPast, now }).verdict, 'expired')
  })

  it('no timestamps supplied → valid (nothing to reject)', () => {
    assert.equal(checkClockSkew({ now, allowedClockSkewMs: skew }).verdict, 'valid')
  })
})

// ── (b) replay ──

describe('M4 replay: jti / evidence_id single-use', () => {
  it('first submit accepted, second submit of same jti rejected', () => {
    const seen = new InMemorySeenSet()
    const first = checkReplay('jti-abc', seen)
    assert.equal(first.verdict, 'accepted')
    assert.equal(first.id, 'jti-abc')

    const second = checkReplay('jti-abc', seen)
    assert.equal(second.verdict, 'rejected_replay')
    assert.equal(second.id, 'jti-abc')
  })

  it('distinct ids are each accepted once', () => {
    const seen = new InMemorySeenSet()
    assert.equal(checkReplay('evidence-1', seen).verdict, 'accepted')
    assert.equal(checkReplay('evidence-2', seen).verdict, 'accepted')
    assert.equal(seen.size, 2)
  })

  it('missing id is rejected (a MUST-enforce verifier cannot dedupe an id-less receipt)', () => {
    const seen = new InMemorySeenSet()
    assert.equal(checkReplay(undefined, seen).verdict, 'rejected_missing_id')
    assert.equal(checkReplay('', seen).verdict, 'rejected_missing_id')
  })

  it('has() reports membership without recording', () => {
    const seen = new InMemorySeenSet()
    assert.equal(seen.has('x'), false)
    seen.recordIfFirst('x')
    assert.equal(seen.has('x'), true)
  })
})

// ── (c) revocation-freshness, all four results ──

describe('M4 revocation-freshness: fresh / stale / unavailable / skipped', () => {
  const maxStalenessMs = 60_000

  it('fresh: source within typed window and within maxStalenessMs', () => {
    // produced 30s ago, snapshot maxAge 120s, tolerance 60s → fresh
    const freshness = createSnapshotFreshness(new Date(nowMs - 30_000).toISOString(), 120)
    const rec = recordRevocationFreshness({ source: 'crl://example', maxStalenessMs, checkedAt: now, freshness })
    assert.equal(rec.result, 'fresh')
    assert.equal(rec.allowedDespiteStale, false)
    assert.equal(rec.source, 'crl://example')
    assert.equal(rec.maxStalenessMs, maxStalenessMs)
    assert.ok(rec.freshness, 'reuses AttestationFreshness shape')
    assert.equal(rec.freshness?.type, 'snapshot')
  })

  it('stale: source older than maxStalenessMs even if typed-fresh', () => {
    // produced 90s ago, snapshot maxAge 600s (typed-fresh) but tolerance 60s → stale
    const freshness = createSnapshotFreshness(new Date(nowMs - 90_000).toISOString(), 600)
    const rec = recordRevocationFreshness({ source: 'crl://example', maxStalenessMs, checkedAt: now, freshness })
    assert.equal(rec.result, 'stale')
    assert.equal(rec.allowedDespiteStale, false)
  })

  it('stale with allowDespiteStale records the explicit risk acceptance', () => {
    const freshness = createRotatingFreshness(new Date(nowMs - 500_000).toISOString(), 60) // long expired ttl
    const rec = recordRevocationFreshness({
      source: 'crl://example', maxStalenessMs, checkedAt: now, freshness, allowDespiteStale: true,
    })
    assert.equal(rec.result, 'stale')
    assert.equal(rec.allowedDespiteStale, true)
  })

  it('unavailable: source could not be reached', () => {
    const rec = recordRevocationFreshness({ source: 'crl://example', maxStalenessMs, checkedAt: now, unavailable: true })
    assert.equal(rec.result, 'unavailable')
    assert.equal(rec.allowedDespiteStale, false)
  })

  it('unavailable with allowDespiteStale records the override', () => {
    const rec = recordRevocationFreshness({
      source: 'crl://example', maxStalenessMs, checkedAt: now, unavailable: true, allowDespiteStale: true,
    })
    assert.equal(rec.result, 'unavailable')
    assert.equal(rec.allowedDespiteStale, true)
  })

  it('skipped: verifier did not consult a source', () => {
    const rec = recordRevocationFreshness({ source: 'none', maxStalenessMs, checkedAt: now })
    assert.equal(rec.result, 'skipped')
    assert.equal(rec.allowedDespiteStale, false)
    assert.equal(rec.freshness, undefined)
  })

  it('checkedAt is recorded as an ISO timestamp', () => {
    const rec = recordRevocationFreshness({ source: 'none', maxStalenessMs, checkedAt: now })
    assert.equal(rec.checkedAt, now.toISOString())
  })
})

// ── (d) sequence-chaining, detect a deleted receipt ──

function receipt(seq: number, prevHash?: string): ActionReceipt {
  return {
    receiptId: `r-${seq}`,
    version: '2.0',
    timestamp: new Date(nowMs + seq * 1000).toISOString(),
    agentId: 'agent-1',
    delegationId: 'del-1',
    action: { type: 'noop', target: 't', scopeUsed: 's' },
    result: { status: 'success', summary: `step ${seq}` },
    delegationChain: ['root', 'agent-1'],
    sequenceNumber: seq,
    ...(prevHash !== undefined ? { previousReceiptHash: prevHash } : {}),
    signature: `sig-${seq}`,
  }
}

describe('M4 receipt sequence-chaining: gap detection', () => {
  it('continuous counter stream has no gaps', () => {
    const stream = [receipt(1), receipt(2), receipt(3)]
    const r = verifyReceiptSequence(stream)
    assert.equal(r.continuous, true)
    assert.equal(r.gaps.length, 0)
  })

  it('a deleted receipt is detected via a counter gap', () => {
    // r-2 was deleted: stream jumps 1 → 3
    const stream = [receipt(1), receipt(3)]
    const r = verifyReceiptSequence(stream)
    assert.equal(r.continuous, false)
    assert.equal(r.gaps.length, 1)
    assert.equal(r.gaps[0].kind, 'counter_gap')
    assert.equal(r.gaps[0].atIndex, 1)
  })

  it('a duplicate / non-increasing counter is flagged out_of_order', () => {
    const stream = [receipt(2), receipt(2)]
    const r = verifyReceiptSequence(stream)
    assert.equal(r.continuous, false)
    assert.equal(r.gaps[0].kind, 'out_of_order')
  })

  it('continuous hash chain has no gaps', () => {
    const r1 = receipt(1)
    const r2 = receipt(2, hashReceiptForChain(r1))
    const r3 = receipt(3, hashReceiptForChain(r2))
    const r = verifyReceiptSequence([r1, r2, r3])
    assert.equal(r.continuous, true)
  })

  it('a deleted receipt breaks the hash chain', () => {
    const r1 = receipt(1)
    const r2 = receipt(2, hashReceiptForChain(r1))
    const r3 = receipt(3, hashReceiptForChain(r2))
    // delete r2: r3 still points at hash(r2), but predecessor is now r1
    const r = verifyReceiptSequence([r1, r3])
    assert.equal(r.continuous, false)
    assert.ok(r.gaps.some(g => g.kind === 'hash_break'))
  })

  it('hashReceiptForChain is stable and excludes the signature', () => {
    const r1 = receipt(1)
    const r1Resigned: ActionReceipt = { ...r1, signature: 'different-sig' }
    assert.equal(hashReceiptForChain(r1), hashReceiptForChain(r1Resigned))
  })

  it('receipts without either signal are treated as continuous (back-compat)', () => {
    const bare: ActionReceipt = {
      receiptId: 'b1', version: '2.0', timestamp: now.toISOString(), agentId: 'a',
      delegationId: 'd', action: { type: 'noop', target: 't', scopeUsed: 's' },
      result: { status: 'success', summary: 'x' }, delegationChain: ['a'], signature: 's',
    }
    const r = verifyReceiptSequence([bare, { ...bare, receiptId: 'b2' }])
    assert.equal(r.continuous, true)
  })
})

// ── proof box / dogfood ──

describe('M4 proof box: ScopeOfClaim dogfood', () => {
  it('exposes a ScopeOfClaim mirroring the proof box', () => {
    const scope = buildHardeningScopeOfClaim()
    assert.ok(scope.asserts.length > 0)
    assert.ok(scope.does_not_assert.length >= 2)
    assert.equal(scope.self_attested, false)
    assert.equal(scope.capture_mode, 'gateway_observed')
  })
})
