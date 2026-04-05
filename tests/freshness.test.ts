import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  computeEvidenceAge, isEvidenceFresh,
  createSnapshotFreshness, createRotatingFreshness
} from '../src/core/freshness.js'
import type { AttestationFreshness } from '../src/types/passport.js'

const at = (iso: string) => new Date(iso)

describe('AttestationFreshness — typed evidence staleness (A2A#1712)', () => {
  const validAt = '2026-04-05T12:00:00Z'

  it('snapshot with maxAge 3600: fresh at +1800s, stale at +3601s', () => {
    const f = createSnapshotFreshness(validAt, 3600)
    assert.ok(isEvidenceFresh(f, at('2026-04-05T12:30:00Z')))
    assert.ok(!isEvidenceFresh(f, at('2026-04-05T13:00:01Z')))
  })

  it('snapshot with no maxAge defaults to fresh (conservative)', () => {
    const f = createSnapshotFreshness(validAt)
    assert.ok(isEvidenceFresh(f, at('2030-01-01T00:00:00Z')))
  })

  it('rotating with ttl 300: fresh at +200s, stale at +301s', () => {
    const f = createRotatingFreshness(validAt, 300)
    assert.ok(isEvidenceFresh(f, at('2026-04-05T12:03:20Z')))
    assert.ok(!isEvidenceFresh(f, at('2026-04-05T12:05:01Z')))
  })

  it('rotating without ttl is never fresh (ttl required)', () => {
    const f: AttestationFreshness = { type: 'rotating', validAt }
    assert.ok(!isEvidenceFresh(f, at(validAt)))
  })

  it('static is always fresh regardless of age', () => {
    const f: AttestationFreshness = { type: 'static', validAt }
    assert.ok(isEvidenceFresh(f, at('2099-01-01T00:00:00Z')))
  })

  it('computeEvidenceAge returns floored seconds since validAt', () => {
    const f = createSnapshotFreshness(validAt, 9999)
    assert.equal(computeEvidenceAge(f, at('2026-04-05T12:00:30Z')), 30)
    assert.equal(computeEvidenceAge(f, at('2026-04-05T12:01:00Z')), 60)
  })

  it('computeEvidenceAge is non-negative under clock skew (now < validAt)', () => {
    const f = createSnapshotFreshness('2026-04-05T12:00:00Z', 600)
    assert.equal(computeEvidenceAge(f, at('2026-04-05T11:59:30Z')), 0)
  })

  it('round trip: create → age → check after simulated advance', () => {
    const f = createRotatingFreshness(validAt, 100)
    const tPlus50 = at('2026-04-05T12:00:50Z')
    const tPlus150 = at('2026-04-05T12:02:30Z')
    assert.equal(computeEvidenceAge(f, tPlus50), 50)
    assert.ok(isEvidenceFresh(f, tPlus50))
    assert.ok(!isEvidenceFresh(f, tPlus150))
  })

  it('createSnapshotFreshness / createRotatingFreshness return correctly typed records', () => {
    const s = createSnapshotFreshness(validAt, 60)
    assert.equal(s.type, 'snapshot')
    assert.equal(s.maxAge, 60)
    const r = createRotatingFreshness(validAt, 300)
    assert.equal(r.type, 'rotating')
    assert.equal(r.ttl, 300)
  })
})
