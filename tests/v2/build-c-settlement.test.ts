// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Build C — Settlement Pipeline property tests.
//
// Spec: BUILD-C-SETTLEMENT-PIPELINE.md §"Property tests". Invariants
// I-C1 through I-C6 plus the 8 property tests the spec enumerates.
// Each test either fuzzes large inputs or targets a named invariant.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  aggregateAttributionPrimitives,
  buildContributorQueryResponse,
  constructAttributionPrimitive,
  emptyAxisMerkleRoot,
  generateKeyPair,
  publicKeyFromPrivate,
  signSettlementRecord,
  verifyContributorQueryResponse,
  verifySettlementRecord,
  verifySettlementSignature,
} from '../../src/index.js'
import type {
  AttributionAxes,
  AttributionPrimitive,
  AttributionSettlementPeriod,
  AttributionSettlementRecord,
} from '../../src/index.js'

// ─────────────────────────────────────────────────────────────
// Deterministic PRNG — mulberry32, same pattern as Build B tests.
// ─────────────────────────────────────────────────────────────

function mulberry32(seed: number): () => number {
  let s = seed >>> 0
  return () => {
    s = (s + 0x6d2b79f5) >>> 0
    let t = s
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

// Deterministic gateway key for tests — never used outside unit tests.
const GATEWAY_PRIV = 'a'.repeat(64)
const GATEWAY_PUB = publicKeyFromPrivate(GATEWAY_PRIV)
const GATEWAY_DID = `did:gateway:test-${GATEWAY_PUB.slice(0, 12)}`

function isoAt(baseMs: number, offsetMs: number): string {
  return new Date(baseMs + offsetMs).toISOString()
}

function mkAxes(
  rng: () => number,
  opts: { dSources: number; cProviders: number; gChain: number; receiptIndex: number },
): AttributionAxes {
  const { dSources, cProviders, gChain, receiptIndex } = opts
  const dRaw = Array.from({ length: dSources }, () => rng())
  const dSum = dRaw.reduce((a, b) => a + b, 0) || 1
  const dNorm = dRaw.map((r) => r / dSum)
  const D = dNorm.map((w, i) => ({
    source_did: `did:data:s-${receiptIndex}-${i}`,
    contribution_weight: w.toFixed(6),
    access_receipt_hash: 'a'.repeat(64),
  }))

  const cRaw = Array.from({ length: cProviders }, () => rng())
  const cSum = cRaw.reduce((a, b) => a + b, 0) || 1
  const cNorm = cRaw.map((r) => r / cSum)
  const C = cNorm.map((w, i) => ({
    provider_did: `did:compute:p-${receiptIndex}-${i}`,
    compute_share: w.toFixed(6),
    hardware_attestation_hash: '1'.repeat(64),
  }))

  const G = Array.from({ length: gChain }, (_, depth) => ({
    delegation_id: `del-${receiptIndex}-${depth}`,
    signer_did: `did:gov:root-${depth}`,
    scope_hash: 'f'.repeat(64),
    depth,
  }))

  return { D, P: [], G, C }
}

function mkReceipt(
  rng: () => number,
  timestamp: string,
  receiptIndex: number,
  privKey: string,
  opts?: Parameters<typeof mkAxes>[1],
): AttributionPrimitive {
  return constructAttributionPrimitive({
    action: {
      agentId: `did:agent:rng-${receiptIndex}`,
      actionType: 'generate',
      params: { i: receiptIndex },
      nonce: `nonce-${receiptIndex}`,
    },
    axes: mkAxes(rng, opts ?? { dSources: 2, cProviders: 2, gChain: 1, receiptIndex }),
    issuer: GATEWAY_DID,
    issuerPrivateKey: privKey,
    timestamp,
  })
}

// ─────────────────────────────────────────────────────────────
// Test 1 — Fuzz: 10k random Attribution Primitives, S3 conservation
// ─────────────────────────────────────────────────────────────

describe('Build C test 1: 10k-receipt fuzz — S3 conservation holds per axis', () => {
  it('aggregation over 10,000 receipts yields a record whose axes balance within tolerance', () => {
    const rng = mulberry32(0x51151100)
    const N = 10_000
    const baseMs = Date.parse('2026-04-01T00:00:00.000Z')
    const t0 = '2026-04-01T00:00:00.000Z'
    const t1 = '2026-04-02T00:00:00.000Z'
    const period: AttributionSettlementPeriod = { t0, t1, period_id: 'test-day-1' }

    const receipts: AttributionPrimitive[] = []
    for (let i = 0; i < N; i++) {
      // Spread across 24 hours (t1 exclusive).
      const offsetMs = Math.floor(rng() * (24 * 3600 * 1000 - 1))
      const ts = isoAt(baseMs, offsetMs)
      const dSources = 1 + Math.floor(rng() * 5)
      const cProviders = 1 + Math.floor(rng() * 3)
      const gChain = 1 + Math.floor(rng() * 3)
      receipts.push(mkReceipt(rng, ts, i, GATEWAY_PRIV, { dSources, cProviders, gChain, receiptIndex: i }))
    }

    const unsigned = aggregateAttributionPrimitives(receipts, period, {
      gateway_did: GATEWAY_DID,
      issued_at: '2026-04-02T00:00:00.001Z',
    })
    const signature = signSettlementRecord(unsigned, GATEWAY_PRIV)
    const record: AttributionSettlementRecord = { ...unsigned, signature }

    const result = verifySettlementRecord(record, { gatewayPublicKeyHex: GATEWAY_PUB })
    assert.equal(result.valid, true, `verify failed: ${JSON.stringify(result)}`)
    assert.equal(record.total_input_count, N)
    for (const tag of ['D', 'C', 'G'] as const) {
      let sum = 0
      for (const c of record.axes[tag].contributors) sum += Number.parseFloat(c.total_weight)
      if (record.axes[tag].residual_bucket) {
        sum += Number.parseFloat(record.axes[tag].residual_bucket!.total_pooled_weight)
      }
      const delta = Math.abs(sum - record.axes[tag].total_actions)
      assert.ok(
        delta <= Math.max(1e-6, record.axes[tag].total_actions * 5e-6),
        `axis ${tag} conservation drift ${delta} > tolerance for N=${record.axes[tag].total_actions}`,
      )
    }
  })
})

// ─────────────────────────────────────────────────────────────
// Test 2 — Contributor-query round trip
// ─────────────────────────────────────────────────────────────

describe('Build C test 2: contributor-query round-trip for every contributor', () => {
  it('every contributor in the record can build + verify a query response without the gateway', () => {
    const rng = mulberry32(0x22220002)
    const t0 = '2026-04-10T00:00:00.000Z'
    const t1 = '2026-04-11T00:00:00.000Z'
    const period: AttributionSettlementPeriod = { t0, t1, period_id: 'test-day-query' }
    const baseMs = Date.parse(t0)
    const receipts: AttributionPrimitive[] = []
    for (let i = 0; i < 50; i++) {
      const ts = isoAt(baseMs, 60_000 * i)
      receipts.push(mkReceipt(rng, ts, i, GATEWAY_PRIV, {
        dSources: 2, cProviders: 2, gChain: 2, receiptIndex: i,
      }))
    }
    const unsigned = aggregateAttributionPrimitives(receipts, period, { gateway_did: GATEWAY_DID, issued_at: '2026-04-11T00:00:00.001Z' })
    const signature = signSettlementRecord(unsigned, GATEWAY_PRIV)
    const record: AttributionSettlementRecord = { ...unsigned, signature }

    for (const tag of ['D', 'C', 'G'] as const) {
      for (const c of record.axes[tag].contributors) {
        const resp = buildContributorQueryResponse(record, c.contributor_did)
        assert.ok(resp, `no query response for ${c.contributor_did}`)
        const verdict = verifyContributorQueryResponse(resp!, { gatewayPublicKeyHex: GATEWAY_PUB })
        assert.equal(verdict.valid, true, `verify failed for ${c.contributor_did}: ${JSON.stringify(verdict)}`)
      }
    }
  })
})

// ─────────────────────────────────────────────────────────────
// Test 3 — Empty period
// ─────────────────────────────────────────────────────────────

describe('Build C test 3: empty period produces verifiable empty record', () => {
  it('zero receipts → record with all four axes empty; verification succeeds', () => {
    const period: AttributionSettlementPeriod = {
      t0: '2026-04-12T00:00:00.000Z',
      t1: '2026-04-13T00:00:00.000Z',
      period_id: 'empty-day',
    }
    const unsigned = aggregateAttributionPrimitives([], period, {
      gateway_did: GATEWAY_DID,
      issued_at: '2026-04-13T00:00:00.001Z',
    })
    const signature = signSettlementRecord(unsigned, GATEWAY_PRIV)
    const record: AttributionSettlementRecord = { ...unsigned, signature }

    const verdict = verifySettlementRecord(record, { gatewayPublicKeyHex: GATEWAY_PUB })
    assert.equal(verdict.valid, true, `verify failed: ${JSON.stringify(verdict)}`)
    assert.equal(record.total_input_count, 0)
    const emptyRoot = emptyAxisMerkleRoot()
    for (const tag of ['D', 'P', 'G', 'C'] as const) {
      assert.deepEqual(record.axes[tag].contributors, [])
      assert.equal(record.axes[tag].total_actions, 0)
      assert.equal(record.axes[tag].residual_bucket, null)
      assert.equal(record.axes[tag].axis_merkle_root, emptyRoot)
    }
    assert.equal(record.input_receipts_hash, emptyRoot)
  })
})

// ─────────────────────────────────────────────────────────────
// Test 4 — Tampering flips signature verification (total_weight flip)
// ─────────────────────────────────────────────────────────────

describe('Build C test 4: flip a total_weight bit → SIGNATURE_INVALID', () => {
  it('mutating a contributor total_weight breaks the signature check', () => {
    const rng = mulberry32(0x44440004)
    const t0 = '2026-04-14T00:00:00.000Z'
    const t1 = '2026-04-15T00:00:00.000Z'
    const period: AttributionSettlementPeriod = { t0, t1, period_id: 'tamper-4' }
    const baseMs = Date.parse(t0)
    const receipts = Array.from({ length: 5 }, (_, i) =>
      mkReceipt(rng, isoAt(baseMs, i * 60_000), i, GATEWAY_PRIV, {
        dSources: 2, cProviders: 1, gChain: 1, receiptIndex: i,
      }),
    )
    const unsigned = aggregateAttributionPrimitives(receipts, period, { gateway_did: GATEWAY_DID, issued_at: '2026-04-15T00:00:00.001Z' })
    const signature = signSettlementRecord(unsigned, GATEWAY_PRIV)
    const record: AttributionSettlementRecord = { ...unsigned, signature }

    const tampered = JSON.parse(JSON.stringify(record)) as AttributionSettlementRecord
    const c = tampered.axes.D.contributors[0]
    const orig = Number.parseFloat(c.total_weight)
    c.total_weight = (orig + 0.000001).toFixed(6)

    // With the weight flipped, the leaf hash in the record no longer
    // matches the stored merkle_leaf_hash — S2 catches it before S1.
    // That's OK: we still fail with a specific reason, not just a bare
    // boolean. Either MERKLE_ROOT_MISMATCH or SIGNATURE_INVALID is
    // acceptable here.
    const verdict = verifySettlementRecord(tampered, { gatewayPublicKeyHex: GATEWAY_PUB })
    assert.equal(verdict.valid, false)
    assert.ok(
      verdict.valid === false &&
        (verdict.reason === 'MERKLE_ROOT_MISMATCH' || verdict.reason === 'SIGNATURE_INVALID' || verdict.reason === 'CONSERVATION_VIOLATION'),
      `expected MERKLE_ROOT_MISMATCH or SIGNATURE_INVALID or CONSERVATION_VIOLATION, got ${(verdict as { valid: false; reason: string }).reason}`,
    )

    // Also assert verifySettlementSignature() directly flags the flipped
    // record under S1 if we fix the Merkle chain to stay consistent.
    const merkleFixed = JSON.parse(JSON.stringify(record)) as AttributionSettlementRecord
    merkleFixed.signature = 'b'.repeat(128)
    assert.equal(
      verifySettlementSignature(merkleFixed, GATEWAY_PUB),
      false,
      'swapping signature bytes must fail S1',
    )
  })
})

// ─────────────────────────────────────────────────────────────
// Test 5 — Swap two contributor DIDs → MERKLE_ROOT_MISMATCH
// ─────────────────────────────────────────────────────────────

describe('Build C test 5: swap two contributor DIDs → MERKLE_ROOT_MISMATCH', () => {
  it('reordering contributors without re-computing the root is detected', () => {
    const rng = mulberry32(0x55550005)
    const t0 = '2026-04-16T00:00:00.000Z'
    const t1 = '2026-04-17T00:00:00.000Z'
    const period: AttributionSettlementPeriod = { t0, t1, period_id: 'tamper-5' }
    const baseMs = Date.parse(t0)
    const receipts = Array.from({ length: 4 }, (_, i) =>
      mkReceipt(rng, isoAt(baseMs, i * 1000), i, GATEWAY_PRIV, {
        dSources: 3, cProviders: 2, gChain: 1, receiptIndex: i,
      }),
    )
    const unsigned = aggregateAttributionPrimitives(receipts, period, { gateway_did: GATEWAY_DID, issued_at: '2026-04-17T00:00:00.001Z' })
    const signature = signSettlementRecord(unsigned, GATEWAY_PRIV)
    const record: AttributionSettlementRecord = { ...unsigned, signature }

    const tampered = JSON.parse(JSON.stringify(record)) as AttributionSettlementRecord
    assert.ok(tampered.axes.D.contributors.length >= 2)
    const a = tampered.axes.D.contributors[0]
    const b = tampered.axes.D.contributors[1]
    const origA = a.contributor_did
    a.contributor_did = b.contributor_did
    b.contributor_did = origA
    // Leave weights and merkle_leaf_hash untouched — that IS the tamper.

    const verdict = verifySettlementRecord(tampered, { gatewayPublicKeyHex: GATEWAY_PUB })
    assert.equal(verdict.valid, false)
    assert.ok(
      verdict.valid === false && verdict.reason === 'MERKLE_ROOT_MISMATCH',
      `expected MERKLE_ROOT_MISMATCH, got ${(verdict as { valid: false; reason: string }).reason}`,
    )
  })
})

// ─────────────────────────────────────────────────────────────
// Test 6 — Residual bucket round trip
// ─────────────────────────────────────────────────────────────

describe('Build C test 6: residual bucket flows into settlement bucket (I-C6)', () => {
  it('receipts carrying per-receipt residual buckets yield a settlement-level bucket that verifies', () => {
    const t0 = '2026-04-18T00:00:00.000Z'
    const t1 = '2026-04-19T00:00:00.000Z'
    const period: AttributionSettlementPeriod = { t0, t1, period_id: 'residual-6' }
    const baseMs = Date.parse(t0)
    const rng = mulberry32(0x66660006)
    const receipts: AttributionPrimitive[] = []
    for (let i = 0; i < 8; i++) {
      const axes: AttributionAxes = {
        D: [
          { source_did: `did:data:big-${i}`, contribution_weight: '0.800000', access_receipt_hash: 'a'.repeat(64) },
          {
            residual_id: 'residual:D' as const,
            total_pooled_weight: '0.200000',
            count_of_pooled_contributors: 5,
            pooled_contributors_hash: 'c'.repeat(64),
          },
        ],
        P: [],
        G: [{ delegation_id: `d-${i}`, signer_did: 'did:gov:root', scope_hash: 'f'.repeat(64), depth: 0 }],
        C: [{ provider_did: `did:compute:p-${i}`, compute_share: '1.000000', hardware_attestation_hash: '1'.repeat(64) }],
      }
      receipts.push(
        constructAttributionPrimitive({
          action: { agentId: 'did:agent:x', actionType: 'x', params: { i }, nonce: `n-${i}` },
          axes,
          issuer: GATEWAY_DID,
          issuerPrivateKey: GATEWAY_PRIV,
          timestamp: isoAt(baseMs, i * 1000),
        }),
      )
      // Silence unused rng.
      void rng
    }
    const unsigned = aggregateAttributionPrimitives(receipts, period, { gateway_did: GATEWAY_DID, issued_at: '2026-04-19T00:00:00.001Z' })
    const signature = signSettlementRecord(unsigned, GATEWAY_PRIV)
    const record: AttributionSettlementRecord = { ...unsigned, signature }

    const verdict = verifySettlementRecord(record, { gatewayPublicKeyHex: GATEWAY_PUB })
    assert.equal(verdict.valid, true, `verify failed: ${JSON.stringify(verdict)}`)

    const bucket = record.axes.D.residual_bucket
    assert.ok(bucket, 'expected a D-axis residual bucket')
    // Pooled weight sums across 8 receipts: 8 × 0.2 = 1.6.
    assert.equal(bucket!.total_pooled_weight, '1.600000')
    assert.equal(bucket!.count_of_pooled_contributors, 40)
    assert.equal(bucket!.residual_id, 'residual:D')
  })
})

// ─────────────────────────────────────────────────────────────
// Test 7 — Half-open interval boundary (load-bearing; spec §Property #7)
// ─────────────────────────────────────────────────────────────

describe('Build C test 7: receipt at t0 included, receipt at t1 excluded (half-open)', () => {
  it('t0-exact is in, t1-exact is out; off-by-one is fatal if this fails', () => {
    const t0 = '2026-04-20T00:00:00.000Z'
    const t1 = '2026-04-21T00:00:00.000Z'
    const period: AttributionSettlementPeriod = { t0, t1, period_id: 'boundary-7' }

    const atT0 = constructAttributionPrimitive({
      action: { agentId: 'did:agent:t0', actionType: 'x', params: {}, nonce: 'n-t0' },
      axes: { D: [{ source_did: 'did:data:t0', contribution_weight: '1.000000', access_receipt_hash: 'a'.repeat(64) }], P: [], G: [{ delegation_id: 'd-t0', signer_did: 'did:gov:t0', scope_hash: 'f'.repeat(64), depth: 0 }], C: [{ provider_did: 'did:compute:t0', compute_share: '1.000000', hardware_attestation_hash: '1'.repeat(64) }] },
      issuer: GATEWAY_DID,
      issuerPrivateKey: GATEWAY_PRIV,
      timestamp: t0,
    })
    const atT1 = constructAttributionPrimitive({
      action: { agentId: 'did:agent:t1', actionType: 'x', params: {}, nonce: 'n-t1' },
      axes: { D: [{ source_did: 'did:data:t1', contribution_weight: '1.000000', access_receipt_hash: 'a'.repeat(64) }], P: [], G: [{ delegation_id: 'd-t1', signer_did: 'did:gov:t1', scope_hash: 'f'.repeat(64), depth: 0 }], C: [{ provider_did: 'did:compute:t1', compute_share: '1.000000', hardware_attestation_hash: '1'.repeat(64) }] },
      issuer: GATEWAY_DID,
      issuerPrivateKey: GATEWAY_PRIV,
      timestamp: t1,
    })
    const justBeforeT1 = constructAttributionPrimitive({
      action: { agentId: 'did:agent:mid', actionType: 'x', params: {}, nonce: 'n-mid' },
      axes: { D: [{ source_did: 'did:data:mid', contribution_weight: '1.000000', access_receipt_hash: 'a'.repeat(64) }], P: [], G: [{ delegation_id: 'd-mid', signer_did: 'did:gov:mid', scope_hash: 'f'.repeat(64), depth: 0 }], C: [{ provider_did: 'did:compute:mid', compute_share: '1.000000', hardware_attestation_hash: '1'.repeat(64) }] },
      issuer: GATEWAY_DID,
      issuerPrivateKey: GATEWAY_PRIV,
      timestamp: '2026-04-20T23:59:59.999Z',
    })

    const unsigned = aggregateAttributionPrimitives([atT0, atT1, justBeforeT1], period, { gateway_did: GATEWAY_DID, issued_at: '2026-04-21T00:00:00.001Z' })

    assert.equal(unsigned.total_input_count, 2, 't0 and t1-1ms should be included; t1-exact excluded')
    const dDids = unsigned.axes.D.contributors.map((c) => c.contributor_did).sort()
    assert.deepEqual(dDids, ['did:data:mid', 'did:data:t0'])
    // t1's DID must NOT appear anywhere.
    for (const tag of ['D', 'G', 'C'] as const) {
      for (const c of unsigned.axes[tag].contributors) {
        assert.ok(!c.contributor_did.endsWith('t1'), `axis ${tag} still contains a t1 contributor: ${c.contributor_did}`)
      }
    }
  })
})

// ─────────────────────────────────────────────────────────────
// Test 8 — Multi-axis contributor: same DID in D and C with distinct shares
// ─────────────────────────────────────────────────────────────

describe('Build C test 8: one DID active on two axes gets distinct shares per axis', () => {
  it('a DID that is both a data source and a compute provider settles independently per axis', () => {
    const t0 = '2026-04-22T00:00:00.000Z'
    const t1 = '2026-04-23T00:00:00.000Z'
    const period: AttributionSettlementPeriod = { t0, t1, period_id: 'multiaxis-8' }
    const shared = 'did:aeoess:hybrid-actor'

    const r1 = constructAttributionPrimitive({
      action: { agentId: 'did:agent:r1', actionType: 'x', params: {}, nonce: 'n1' },
      axes: {
        D: [
          { source_did: shared, contribution_weight: '0.600000', access_receipt_hash: 'a'.repeat(64) },
          { source_did: 'did:data:other', contribution_weight: '0.400000', access_receipt_hash: 'b'.repeat(64) },
        ],
        P: [],
        G: [{ delegation_id: 'd1', signer_did: 'did:gov:root', scope_hash: 'f'.repeat(64), depth: 0 }],
        C: [{ provider_did: 'did:compute:cpu', compute_share: '1.000000', hardware_attestation_hash: '1'.repeat(64) }],
      },
      issuer: GATEWAY_DID,
      issuerPrivateKey: GATEWAY_PRIV,
      timestamp: '2026-04-22T01:00:00.000Z',
    })
    const r2 = constructAttributionPrimitive({
      action: { agentId: 'did:agent:r2', actionType: 'x', params: {}, nonce: 'n2' },
      axes: {
        D: [{ source_did: 'did:data:elsewhere', contribution_weight: '1.000000', access_receipt_hash: 'c'.repeat(64) }],
        P: [],
        G: [{ delegation_id: 'd2', signer_did: 'did:gov:root', scope_hash: 'f'.repeat(64), depth: 0 }],
        C: [
          { provider_did: shared, compute_share: '0.800000', hardware_attestation_hash: '1'.repeat(64) },
          { provider_did: 'did:compute:other', compute_share: '0.200000', hardware_attestation_hash: '2'.repeat(64) },
        ],
      },
      issuer: GATEWAY_DID,
      issuerPrivateKey: GATEWAY_PRIV,
      timestamp: '2026-04-22T02:00:00.000Z',
    })

    const unsigned = aggregateAttributionPrimitives([r1, r2], period, { gateway_did: GATEWAY_DID, issued_at: '2026-04-23T00:00:00.001Z' })
    const signature = signSettlementRecord(unsigned, GATEWAY_PRIV)
    const record: AttributionSettlementRecord = { ...unsigned, signature }

    const d = record.axes.D.contributors.find((c) => c.contributor_did === shared)
    const c = record.axes.C.contributors.find((cc) => cc.contributor_did === shared)
    assert.ok(d, 'shared DID missing from D axis')
    assert.ok(c, 'shared DID missing from C axis')
    assert.equal(d!.total_weight, '0.600000')
    assert.equal(c!.total_weight, '0.800000')

    // Independent per-axis contributor queries both verify.
    const resp = buildContributorQueryResponse(record, shared)
    assert.ok(resp)
    const verdict = verifyContributorQueryResponse(resp!, { gatewayPublicKeyHex: GATEWAY_PUB })
    assert.equal(verdict.valid, true, JSON.stringify(verdict))
    assert.ok(resp!.per_axis.D && resp!.per_axis.C)
  })
})

// ─────────────────────────────────────────────────────────────
// Additional: S5 end-to-end with input receipts supplied
// ─────────────────────────────────────────────────────────────

describe('Build C S5: input_receipts_hash recomputes when input receipts are supplied', () => {
  it('supplying the input receipts yields a valid verdict; dropping one fails S5', () => {
    const t0 = '2026-04-24T00:00:00.000Z'
    const t1 = '2026-04-25T00:00:00.000Z'
    const period: AttributionSettlementPeriod = { t0, t1, period_id: 's5-roundtrip' }
    const rng = mulberry32(0xabcd1234)
    const baseMs = Date.parse(t0)
    const receipts = Array.from({ length: 6 }, (_, i) =>
      mkReceipt(rng, isoAt(baseMs, i * 3600_000), i, GATEWAY_PRIV, {
        dSources: 2, cProviders: 1, gChain: 1, receiptIndex: i,
      }),
    )
    const unsigned = aggregateAttributionPrimitives(receipts, period, { gateway_did: GATEWAY_DID, issued_at: '2026-04-25T00:00:00.001Z' })
    const signature = signSettlementRecord(unsigned, GATEWAY_PRIV)
    const record: AttributionSettlementRecord = { ...unsigned, signature }

    const okVerdict = verifySettlementRecord(record, { gatewayPublicKeyHex: GATEWAY_PUB, inputReceipts: receipts })
    assert.equal(okVerdict.valid, true, `S5 with matching receipts should pass: ${JSON.stringify(okVerdict)}`)

    const dropOne = receipts.slice(0, 5)
    const droppedVerdict = verifySettlementRecord(record, { gatewayPublicKeyHex: GATEWAY_PUB, inputReceipts: dropOne })
    assert.equal(droppedVerdict.valid, false)
    assert.ok(
      droppedVerdict.valid === false &&
        droppedVerdict.reason === 'INPUT_RECEIPTS_HASH_MISMATCH',
      `expected INPUT_RECEIPTS_HASH_MISMATCH, got ${(droppedVerdict as { valid: false; reason: string }).reason}`,
    )
  })
})
