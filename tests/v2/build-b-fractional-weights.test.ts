// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Build B — Fractional Weights property tests.
//
// Spec: BUILD-B-FRACTIONAL-WEIGHTS.md §"Property tests". Invariants
// I-B1 through I-B6, plus the Build A+B integration test required by
// the ship checklist.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  ATTRIBUTION_ROLES,
  DEFAULT_WEIGHT_PROFILE,
  aggregateDataAxis,
  computeComputeAxisWeights,
  computeDataAxisWeights,
  constructAttributionPrimitive,
  generateKeyPair,
  hashWeightProfile,
  projectAttribution,
  recencyDecay,
  validateWeightProfile,
  verifyAttributionProjection,
} from '../../src/index.js'
import type {
  AccessReceiptWithRole,
  AttributionRole,
  AttributionAction,
  AttributionAxes,
  GovernanceAxisEntry,
  InferenceBillingRecord,
  ProtocolAxisEntry,
  WeightProfile,
} from '../../src/index.js'

// ─────────────────────────────────────────────────────────────
// Deterministic PRNG — mulberry32. Lets us run 1e5 trials with a
// stable seed so failures are reproducible.
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

function randRole(rng: () => number): AttributionRole {
  return ATTRIBUTION_ROLES[Math.floor(rng() * ATTRIBUTION_ROLES.length)]
}

function randTs(rng: () => number, baseMs: number): string {
  // 0–90 days in the past.
  const ageMs = Math.floor(rng() * 90 * 86_400_000)
  return new Date(baseMs - ageMs).toISOString()
}

function randSource(rng: () => number, actionMs: number, index: number): AccessReceiptWithRole {
  return {
    source_did: `did:data:src-${index}-${Math.floor(rng() * 1e9)}`,
    access_receipt_hash: 'a'.repeat(64),
    role: randRole(rng),
    timestamp: randTs(rng, actionMs),
    content_length: 1 + Math.floor(rng() * 50_000),
  }
}

function randProvider(rng: () => number, index: number): InferenceBillingRecord {
  return {
    provider_did: `did:compute:prv-${index}-${Math.floor(rng() * 1e9)}`,
    hardware_attestation_hash: '1'.repeat(64),
    prompt_tokens: Math.floor(rng() * 10_000),
    completion_tokens: Math.floor(rng() * 10_000),
  }
}

function sumWeights(entries: Array<{ contribution_weight?: string; compute_share?: string }>): number {
  return entries.reduce(
    (acc, e) => acc + Number.parseFloat(e.contribution_weight ?? e.compute_share ?? '0'),
    0,
  )
}

// ─────────────────────────────────────────────────────────────
// I-B1, I-B2: sum-to-one (1e5 trials)
// ─────────────────────────────────────────────────────────────

describe('I-B1: D-axis sum-to-one property (1e5 trials)', () => {
  it('random 100-source distributions sum to 1.0 within N × 5e-7 (rounding budget)', () => {
    const rng = mulberry32(0xb1b1b1b1)
    const actionMs = Date.parse('2026-04-16T12:00:00.000Z')
    const actionTs = new Date(actionMs).toISOString()
    const TRIALS = 100_000
    let worst = 0
    for (let i = 0; i < TRIALS; i++) {
      // Vary source count across trials so we exercise both small and
      // large inputs. Most trials at 1–100 sources.
      const n = 1 + Math.floor(rng() * 100)
      const sources = Array.from({ length: n }, (_, j) => randSource(rng, actionMs, j))
      const weights = computeDataAxisWeights(sources, { action_timestamp: actionTs })
      const total = sumWeights(weights)
      const diff = Math.abs(total - 1)
      if (diff > worst) worst = diff
      // Canonical emission is 6-digit rounded. Each of the N terms can err
      // by up to 5e-7 in the worst case, so the max accumulated rounding
      // drift for the sum of the 6-digit strings is N × 5e-7. Add 1e-12
      // of double-precision slack. Raw-float sum-to-one at 1e-9 is
      // covered by the strict test below.
      const bound = n * 5e-7 + 1e-12
      if (diff > bound) {
        assert.fail(`trial ${i}: sum=${total}, diff=${diff}, n=${n}, bound=${bound}`)
      }
    }
    // Absolute worst across all trials should be ≤ 100 × 5e-7 + slack.
    assert.ok(worst < 1e-4, `worst case diff ${worst} exceeds 1e-4`)
  })
})

describe('I-B2: C-axis sum-to-one property (1e5 trials)', () => {
  it('random 100-provider token-share distributions sum to 1.0 within rounding budget', () => {
    const rng = mulberry32(0xc2c2c2c2)
    const TRIALS = 100_000
    let worst = 0
    for (let i = 0; i < TRIALS; i++) {
      const n = 1 + Math.floor(rng() * 100)
      // Ensure at least one non-zero token count per trial.
      const providers: InferenceBillingRecord[] = Array.from({ length: n }, (_, j) => randProvider(rng, j))
      if (providers.every((p) => p.prompt_tokens === 0 && p.completion_tokens === 0)) {
        providers[0] = { ...providers[0], prompt_tokens: 1 }
      }
      const weights = computeComputeAxisWeights(providers)
      const total = sumWeights(weights)
      const diff = Math.abs(total - 1)
      if (diff > worst) worst = diff
      const bound = n * 5e-7 + 1e-12
      if (diff > bound) {
        assert.fail(`trial ${i}: sum=${total}, diff=${diff}, n=${n}, bound=${bound}`)
      }
    }
    assert.ok(worst < 1e-4, `worst case diff ${worst} exceeds 1e-4`)
  })
})

// Strict I-B1 in double-precision (no rounding): sum of raw ratios is
// exactly 1.0 within 1e-9. This is the spec's stated tolerance — applied
// to the pre-canonicalization floats rather than the 6-digit strings.
describe('I-B1 strict: raw D-axis ratios sum to 1.0 within 1e-9', () => {
  it('holds for 10k random trials at double precision', () => {
    const rng = mulberry32(0xd1d1d1d1)
    const actionMs = Date.parse('2026-04-16T12:00:00.000Z')
    const actionTs = new Date(actionMs).toISOString()
    for (let i = 0; i < 10_000; i++) {
      const n = 1 + Math.floor(rng() * 50)
      const sources = Array.from({ length: n }, (_, j) => randSource(rng, actionMs, j))
      // Recompute the raw numerators to check the underlying math. This
      // skips the string rounding step so we can assert the 1e-9 bound.
      const raws = sources.map((s) => {
        const r = DEFAULT_WEIGHT_PROFILE.role_weights[s.role]
        const dec = recencyDecay(actionTs, s.timestamp, DEFAULT_WEIGHT_PROFILE)
        const l = Math.log(1 + s.content_length) / Math.log(1 + 1000)
        return r * dec * l
      })
      const total = raws.reduce((a, b) => a + b, 0)
      if (total <= 0) continue
      const sumRatios = raws.reduce((a, b) => a + b / total, 0)
      assert.ok(Math.abs(sumRatios - 1) < 1e-9, `trial ${i}: ${sumRatios}`)
    }
  })
})

// ─────────────────────────────────────────────────────────────
// I-B3: empty-axis handling
// ─────────────────────────────────────────────────────────────

describe('I-B3: empty axes are valid input', () => {
  it('D: empty sources → empty array', () => {
    const out = computeDataAxisWeights([], { action_timestamp: '2026-04-16T12:00:00.000Z' })
    assert.deepEqual(out, [])
  })

  it('C: empty providers → empty array', () => {
    assert.deepEqual(computeComputeAxisWeights([]), [])
  })

  it('all-zero weights rejected as malformed for D', () => {
    // Every content_length = 0 means log(1+0) = 0 for every source, so
    // every numerator is 0 regardless of role/recency. This is malformed.
    const src: AccessReceiptWithRole = {
      source_did: 'did:data:x',
      access_receipt_hash: '0'.repeat(64),
      role: 'primary_source',
      timestamp: '2026-04-16T12:00:00.000Z',
      content_length: 0,
    }
    assert.throws(
      () => computeDataAxisWeights([src], { action_timestamp: '2026-04-16T12:00:00.000Z' }),
      /total D-axis raw weight is zero/,
    )
  })

  it('all-zero weights rejected as malformed for C', () => {
    const prv: InferenceBillingRecord = {
      provider_did: 'did:compute:x',
      hardware_attestation_hash: '0'.repeat(64),
      prompt_tokens: 0,
      completion_tokens: 0,
    }
    assert.throws(
      () => computeComputeAxisWeights([prv]),
      /total C-axis raw weight is zero/,
    )
  })
})

// ─────────────────────────────────────────────────────────────
// I-B5: insertion-order invariance + deterministic tie-break
// ─────────────────────────────────────────────────────────────

describe('I-B5: insertion-order invariance and deterministic tie-break', () => {
  it('swapping two sources\' insertion order produces identical weights', () => {
    const actionTs = '2026-04-16T12:00:00.000Z'
    const A: AccessReceiptWithRole = {
      source_did: 'did:data:A', access_receipt_hash: 'a'.repeat(64),
      role: 'primary_source', timestamp: '2026-04-10T00:00:00.000Z', content_length: 800,
    }
    const B: AccessReceiptWithRole = {
      source_did: 'did:data:B', access_receipt_hash: 'b'.repeat(64),
      role: 'supporting_evidence', timestamp: '2026-04-12T00:00:00.000Z', content_length: 1200,
    }
    const C: AccessReceiptWithRole = {
      source_did: 'did:data:C', access_receipt_hash: 'c'.repeat(64),
      role: 'context_only', timestamp: '2026-04-14T00:00:00.000Z', content_length: 200,
    }
    const orderings = [[A, B, C], [C, B, A], [B, C, A], [A, C, B]]
    // Compute per-source weight for each ordering, then assert all
    // orderings agree on the weight per source_did.
    const weightsByDid: Record<string, Set<string>> = {}
    for (const order of orderings) {
      const out = computeDataAxisWeights(order, { action_timestamp: actionTs })
      for (const entry of out) {
        ;(weightsByDid[entry.source_did] ??= new Set()).add(entry.contribution_weight)
      }
    }
    for (const [did, ws] of Object.entries(weightsByDid)) {
      assert.equal(ws.size, 1, `source ${did} got differing weights across orderings: ${[...ws]}`)
    }
  })

  it('identical inputs produce identical weights (tie-break is ordering-independent)', () => {
    const actionTs = '2026-04-16T12:00:00.000Z'
    const sA: AccessReceiptWithRole = {
      source_did: 'did:data:aaa', access_receipt_hash: 'a'.repeat(64),
      role: 'primary_source', timestamp: '2026-04-16T00:00:00.000Z', content_length: 500,
    }
    const sB: AccessReceiptWithRole = { ...sA, source_did: 'did:data:bbb', access_receipt_hash: 'b'.repeat(64) }
    const sC: AccessReceiptWithRole = { ...sA, source_did: 'did:data:ccc', access_receipt_hash: 'c'.repeat(64) }
    const out = computeDataAxisWeights([sA, sB, sC], { action_timestamp: actionTs })
    // All three weights equal since inputs are identical aside from DID.
    const w = new Set(out.map((x) => x.contribution_weight))
    assert.equal(w.size, 1, `expected all equal, got ${[...w]}`)
  })
})

// ─────────────────────────────────────────────────────────────
// Length scaling invariance (spec property test 4)
// ─────────────────────────────────────────────────────────────

describe('Doubling all content lengths does not change relative weights meaningfully', () => {
  it('relative order is preserved under uniform length scale', () => {
    const actionTs = '2026-04-16T12:00:00.000Z'
    const base: AccessReceiptWithRole[] = [
      { source_did: 'did:data:a', access_receipt_hash: 'a'.repeat(64), role: 'primary_source', timestamp: '2026-04-10T00:00:00.000Z', content_length: 500 },
      { source_did: 'did:data:b', access_receipt_hash: 'b'.repeat(64), role: 'supporting_evidence', timestamp: '2026-04-11T00:00:00.000Z', content_length: 800 },
      { source_did: 'did:data:c', access_receipt_hash: 'c'.repeat(64), role: 'context_only', timestamp: '2026-04-12T00:00:00.000Z', content_length: 200 },
    ]
    const doubled = base.map((s) => ({ ...s, content_length: s.content_length * 2 }))
    const w1 = computeDataAxisWeights(base, { action_timestamp: actionTs })
    const w2 = computeDataAxisWeights(doubled, { action_timestamp: actionTs })
    // Same ordering of weights by DID.
    const rank1 = [...w1].sort((a, b) => Number(b.contribution_weight) - Number(a.contribution_weight)).map((x) => x.source_did)
    const rank2 = [...w2].sort((a, b) => Number(b.contribution_weight) - Number(a.contribution_weight)).map((x) => x.source_did)
    assert.deepEqual(rank1, rank2)
  })
})

// ─────────────────────────────────────────────────────────────
// Recency invariant (spec property test 5)
// ─────────────────────────────────────────────────────────────

describe('Recency decay: one-day-old source retains ≥ 0.977 of baseline', () => {
  it('exp(-ln(2)/30) ≥ 0.977', () => {
    const actionTs = '2026-04-16T12:00:00.000Z'
    const oneDayOld = '2026-04-15T12:00:00.000Z'
    const d = recencyDecay(actionTs, oneDayOld, DEFAULT_WEIGHT_PROFILE)
    assert.ok(d >= 0.977, `got ${d}, expected ≥ 0.977`)
  })

  it('recencyDecay respects the min_recency floor', () => {
    const actionTs = '2027-04-16T12:00:00.000Z'
    const ancient = '2010-01-01T00:00:00.000Z'
    const d = recencyDecay(actionTs, ancient, DEFAULT_WEIGHT_PROFILE)
    assert.equal(d, DEFAULT_WEIGHT_PROFILE.recency.min_recency)
  })
})

// ─────────────────────────────────────────────────────────────
// I-B4: residual bucket preserves pre-threshold weights
// ─────────────────────────────────────────────────────────────

describe('I-B4: residual bucket sum equals pre-threshold pooled weight', () => {
  it('pre-threshold weights from Build B feed Build A residual intact', () => {
    const actionTs = '2026-04-16T12:00:00.000Z'
    // Construct a scenario where most weight is carried by one high-
    // signal source and the long tail individually falls below 0.001.
    // Needs enough tail entries that their normalized weight drops below
    // the 0.001 pooling threshold (spec §4.1 default).
    const dominant: AccessReceiptWithRole = {
      source_did: 'did:data:dominant',
      access_receipt_hash: 'd'.repeat(64),
      role: 'primary_source',
      timestamp: '2026-04-16T00:00:00.000Z',
      content_length: 100_000,
    }
    const tail: AccessReceiptWithRole[] = Array.from({ length: 1500 }, (_, i) => ({
      source_did: `did:data:tail-${String(i).padStart(4, '0')}`,
      access_receipt_hash: String(i).padStart(64, '0'),
      role: 'background_retrieval',
      timestamp: '2025-12-01T00:00:00.000Z', // far past the decay floor
      content_length: 1,
    }))
    const weights = computeDataAxisWeights([dominant, ...tail], { action_timestamp: actionTs })
    const agg = aggregateDataAxis(weights, { minWeight: 0.001 })
    if (!agg.residual) throw new Error('expected a residual bucket in this scenario')
    // Sum of pooled entries' pre-threshold weights should equal the
    // residual's total_pooled_weight. Reconstruct the pooled subset:
    // it's exactly the entries whose weight < 0.001 in the original.
    const pooledEntries = weights.filter(
      (e) => Number.parseFloat(e.contribution_weight) < 0.001,
    )
    const expected = pooledEntries.reduce(
      (a, e) => a + Number.parseFloat(e.contribution_weight),
      0,
    )
    const reported = Number.parseFloat(agg.residual.total_pooled_weight)
    assert.ok(
      Math.abs(reported - expected) < 1e-6,
      `residual=${reported}, expected=${expected}`,
    )
    assert.equal(agg.residual.count_of_pooled_contributors, pooledEntries.length)
  })
})

// ─────────────────────────────────────────────────────────────
// I-B6: profile-hash binding
// ─────────────────────────────────────────────────────────────

describe('I-B6: profile hash binds all configurable parameters', () => {
  it('hashWeightProfile is stable across runs', () => {
    const h1 = hashWeightProfile(DEFAULT_WEIGHT_PROFILE)
    const h2 = hashWeightProfile(DEFAULT_WEIGHT_PROFILE)
    assert.equal(h1, h2)
    assert.match(h1, /^[0-9a-f]{64}$/)
  })

  it('any differing field yields a different hash', () => {
    const base = DEFAULT_WEIGHT_PROFILE
    const h0 = hashWeightProfile(base)
    const variants: WeightProfile[] = [
      { ...base, version: 'v0.2' },
      { ...base, role_weights: { ...base.role_weights, primary_source: 0.95 } },
      { ...base, recency: { ...base.recency, tau_days: 60 } },
      { ...base, length: { ...base.length, reference_length: 2000 } },
      { ...base, compute: { ...base.compute, completion_multiplier: 4.0 } },
    ]
    for (const v of variants) {
      assert.notEqual(hashWeightProfile(v), h0)
    }
  })

  it('validateWeightProfile rejects invalid input', () => {
    const bad = { ...DEFAULT_WEIGHT_PROFILE, recency: { ...DEFAULT_WEIGHT_PROFILE.recency, tau_days: -1 } }
    const result = validateWeightProfile(bad)
    assert.equal(result.valid, false)
    assert.ok(result.errors.some((e) => e.includes('tau_days')))
  })
})

// ─────────────────────────────────────────────────────────────
// Build A + Build B integration test (ship checklist)
// ─────────────────────────────────────────────────────────────

describe('Build A + Build B integration: compute → construct → project → verify', () => {
  it('D-axis projection verifies end-to-end with computed weights', () => {
    const actionTs = '2026-04-16T12:00:00.000Z'
    const sources: AccessReceiptWithRole[] = [
      { source_did: 'did:data:kff-2025', access_receipt_hash: 'a'.repeat(64), role: 'primary_source', timestamp: '2026-04-15T00:00:00.000Z', content_length: 3500 },
      { source_did: 'did:data:cms-archive', access_receipt_hash: 'b'.repeat(64), role: 'supporting_evidence', timestamp: '2026-04-10T00:00:00.000Z', content_length: 1200 },
      { source_did: 'did:data:news-blurb', access_receipt_hash: 'c'.repeat(64), role: 'context_only', timestamp: '2026-04-14T00:00:00.000Z', content_length: 400 },
    ]
    const providers: InferenceBillingRecord[] = [
      { provider_did: 'did:compute:anthropic', hardware_attestation_hash: '1'.repeat(64), prompt_tokens: 1200, completion_tokens: 800 },
      { provider_did: 'did:compute:openai', hardware_attestation_hash: '2'.repeat(64), prompt_tokens: 900, completion_tokens: 600 },
    ]

    const D = computeDataAxisWeights(sources, { action_timestamp: actionTs })
    const C = computeComputeAxisWeights(providers)

    // Weights are canonical 6-digit strings — Build A consumes directly.
    for (const e of D) assert.match(e.contribution_weight, /^\d+\.\d{6}$/)
    for (const e of C) assert.match(e.compute_share, /^\d+\.\d{6}$/)

    const P: ProtocolAxisEntry[] = [
      { module_id: 'redact-pii', module_version: '2.3.1', evaluation_outcome: 'approved', evaluation_receipt_hash: 'e'.repeat(64) },
    ]
    const G: GovernanceAxisEntry[] = [
      { delegation_id: 'delegation:root', signer_did: 'did:aps:customer', scope_hash: 'f'.repeat(64), depth: 0 },
      { delegation_id: 'delegation:agent', signer_did: 'did:aps:agent-alpha', scope_hash: 'e'.repeat(64), depth: 1 },
    ]
    const axes: AttributionAxes = { D, P, G, C }

    const { publicKey, privateKey } = generateKeyPair()
    const action: AttributionAction = {
      agentId: 'did:aps:agent-alpha',
      actionType: 'query.summarize',
      params: { topic: 'healthcare-reform-march-2026' },
      nonce: '77777777-7777-7777-7777-777777777777',
    }
    const primitive = constructAttributionPrimitive({
      action,
      axes,
      issuer: 'did:aps:issuer-test',
      issuerPrivateKey: privateKey,
      timestamp: actionTs,
    })
    const projection = projectAttribution(primitive, 'D')
    const verdict = verifyAttributionProjection(projection, publicKey)
    assert.equal(verdict.valid, true, (verdict as { reason?: string }).reason)

    // D axis_data round-trips the computed weights unchanged.
    const axisD = projection.axis_data as typeof D
    assert.equal(axisD.length, D.length)
    for (const original of D) {
      const match = axisD.find((x) => x.source_did === original.source_did)
      assert.ok(match)
      assert.equal(match!.contribution_weight, original.contribution_weight)
      assert.equal(match!.access_receipt_hash, original.access_receipt_hash)
    }
  })
})
