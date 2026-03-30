// ══════════════════════════════════════════════════════════════════
// Anchor States — Tests
// ══════════════════════════════════════════════════════════════════
// Consilium Priority 6. Receipt anchor lifecycle + auto-batching.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createAnchorMetadata, markBatched, markAnchored,
  shouldAutoBatch, meetsAnchorRequirement, isValidAnchorTransition,
  DEFAULT_AUTO_BATCH_CONFIG, ANCHOR_STATE_ORDER,
} from '../src/core/anchor-state.js'

describe('Anchor States — Lifecycle', () => {
  it('new receipt starts unanchored', () => {
    const a = createAnchorMetadata()
    assert.strictEqual(a.state, 'unanchored')
  })

  it('critical receipt starts as critical_direct_anchor', () => {
    const a = createAnchorMetadata(true)
    assert.strictEqual(a.state, 'critical_direct_anchor')
  })

  it('transitions unanchored → batched_pending', () => {
    let a = createAnchorMetadata()
    a = markBatched(a, 'batch_001')
    assert.strictEqual(a.state, 'batched_pending')
    assert.strictEqual(a.batchId, 'batch_001')
  })

  it('transitions batched_pending → anchored', () => {
    let a = createAnchorMetadata()
    a = markBatched(a, 'batch_001')
    a = markAnchored(a, 'rekor:abc123', 'sigstore')
    assert.strictEqual(a.state, 'anchored')
    assert.strictEqual(a.anchorRef, 'rekor:abc123')
    assert.strictEqual(a.anchorBackend, 'sigstore')
    assert.ok(a.anchoredAt)
  })

  it('critical_direct_anchor is immutable through batch/anchor', () => {
    let a = createAnchorMetadata(true)
    a = markBatched(a, 'batch_001')
    assert.strictEqual(a.state, 'critical_direct_anchor', 'Should not downgrade')
    a = markAnchored(a, 'ref', 'backend')
    assert.strictEqual(a.state, 'critical_direct_anchor', 'Should not change')
  })

  it('already anchored stays anchored through markBatched', () => {
    let a = createAnchorMetadata()
    a = markBatched(a, 'batch_001')
    a = markAnchored(a, 'ref', 'backend')
    a = markBatched(a, 'batch_002')
    assert.strictEqual(a.state, 'anchored', 'Should not downgrade')
  })
})

describe('Anchor States — Ordering & Requirements', () => {
  it('ordering: unanchored < batched_pending < anchored < critical', () => {
    assert.ok(ANCHOR_STATE_ORDER['unanchored'] < ANCHOR_STATE_ORDER['batched_pending'])
    assert.ok(ANCHOR_STATE_ORDER['batched_pending'] < ANCHOR_STATE_ORDER['anchored'])
    assert.ok(ANCHOR_STATE_ORDER['anchored'] < ANCHOR_STATE_ORDER['critical_direct_anchor'])
  })

  it('meetsAnchorRequirement checks minimum', () => {
    assert.ok(meetsAnchorRequirement('anchored', 'batched_pending'))
    assert.ok(meetsAnchorRequirement('anchored', 'anchored'))
    assert.ok(!meetsAnchorRequirement('unanchored', 'batched_pending'))
    assert.ok(meetsAnchorRequirement('critical_direct_anchor', 'anchored'))
  })

  it('valid transitions only move forward', () => {
    assert.ok(isValidAnchorTransition('unanchored', 'batched_pending'))
    assert.ok(isValidAnchorTransition('batched_pending', 'anchored'))
    assert.ok(isValidAnchorTransition('anchored', 'anchored')) // same = valid
    assert.ok(!isValidAnchorTransition('anchored', 'unanchored'))
    assert.ok(!isValidAnchorTransition('batched_pending', 'unanchored'))
  })
})

describe('Anchor States — Auto-Batch Trigger', () => {
  it('does not trigger on empty pending', () => {
    const r = shouldAutoBatch(0, new Date().toISOString())
    assert.ok(!r.trigger)
  })

  it('triggers on max_receipts', () => {
    const r = shouldAutoBatch(100, new Date().toISOString())
    assert.ok(r.trigger)
    assert.strictEqual(r.reason, 'max_receipts')
  })

  it('triggers on max_interval when enough time elapsed', () => {
    const fiveMinAgo = new Date(Date.now() - 301 * 1000).toISOString()
    const r = shouldAutoBatch(5, fiveMinAgo)
    assert.ok(r.trigger)
    assert.strictEqual(r.reason, 'max_interval')
  })

  it('does not trigger when under both thresholds', () => {
    const r = shouldAutoBatch(10, new Date().toISOString())
    assert.ok(!r.trigger)
  })

  it('triggers on first batch ever with pending receipts', () => {
    const r = shouldAutoBatch(1, null)
    assert.ok(r.trigger)
    assert.strictEqual(r.reason, 'max_interval')
  })

  it('default config has 5 min interval and 100 receipt cap', () => {
    assert.strictEqual(DEFAULT_AUTO_BATCH_CONFIG.maxIntervalSeconds, 300)
    assert.strictEqual(DEFAULT_AUTO_BATCH_CONFIG.maxReceiptsPerBatch, 100)
    assert.ok(DEFAULT_AUTO_BATCH_CONFIG.directAnchorCritical)
  })
})
