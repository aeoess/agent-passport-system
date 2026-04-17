// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Build A + B + C end-to-end integration test.
//
// Construct 1000 Attribution Primitives using Build B weights, aggregate
// via Build C, verify S1-S5, build per-contributor query responses, and
// verify each. This is the integration proof that the three modules
// compose correctly — not a unit test of any single one.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  aggregateAttributionPrimitives,
  buildContributorQueryResponse,
  computeComputeAxisWeights,
  computeDataAxisWeights,
  constructAttributionPrimitive,
  publicKeyFromPrivate,
  signSettlementRecord,
  verifyContributorQueryResponse,
  verifySettlementRecord,
} from '../../src/index.js'
import type {
  AccessReceiptWithRole,
  AttributionAxes,
  AttributionPrimitive,
  AttributionRole,
  AttributionSettlementPeriod,
  AttributionSettlementRecord,
  InferenceBillingRecord,
} from '../../src/index.js'

const ROLES: AttributionRole[] = ['primary_source', 'supporting_evidence', 'context_only', 'background_retrieval']

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

const GATEWAY_PRIV = 'e2e'.padEnd(64, 'f')
const GATEWAY_PUB = publicKeyFromPrivate(GATEWAY_PRIV)
const GATEWAY_DID = `did:aeoess:gateway:e2e-${GATEWAY_PUB.slice(0, 12)}`

describe('Build A + B + C end-to-end: 1000 primitives → aggregate → verify → per-contributor proof', () => {
  it('full pipeline yields a verifiable record and verifiable contributor queries', () => {
    const rng = mulberry32(0xe2e2e2e2)
    const N = 1000
    const t0 = '2026-04-28T00:00:00.000Z'
    const t1 = '2026-04-29T00:00:00.000Z'
    const period: AttributionSettlementPeriod = { t0, t1, period_id: 'e2e-day' }
    const baseMs = Date.parse(t0)
    const periodMs = Date.parse(t1) - baseMs

    // Pool of DIDs so contributors recur across receipts — otherwise we
    // get trivial 1-action-per-contributor aggregates.
    const dataPool = Array.from({ length: 30 }, (_, i) => `did:data:pool-${i}`)
    const computePool = Array.from({ length: 8 }, (_, i) => `did:compute:pool-${i}`)
    const govRoot = 'did:aeoess:root-gateway'

    const receipts: AttributionPrimitive[] = []
    for (let i = 0; i < N; i++) {
      const offsetMs = Math.floor(rng() * (periodMs - 1))
      const ts = new Date(baseMs + offsetMs).toISOString()

      // Build B: produce D-axis weights from 3–6 source records.
      const dCount = 3 + Math.floor(rng() * 4)
      const sources: AccessReceiptWithRole[] = Array.from({ length: dCount }, (_, j) => ({
        source_did: dataPool[Math.floor(rng() * dataPool.length)],
        access_receipt_hash: 'a'.repeat(64),
        role: ROLES[Math.floor(rng() * ROLES.length)],
        timestamp: new Date(baseMs + Math.floor(rng() * periodMs)).toISOString(),
        content_length: 100 + Math.floor(rng() * 50_000),
      }))
      // De-duplicate source_did — Build B expects unique DIDs per receipt.
      const dedupD = new Map<string, AccessReceiptWithRole>()
      for (const s of sources) dedupD.set(s.source_did, s)
      const uniqueSources = [...dedupD.values()]
      const dWeights = computeDataAxisWeights(uniqueSources, { action_timestamp: ts })

      // Build B: C-axis weights.
      const cCount = 1 + Math.floor(rng() * 3)
      const providers: InferenceBillingRecord[] = Array.from({ length: cCount }, () => ({
        provider_did: computePool[Math.floor(rng() * computePool.length)],
        hardware_attestation_hash: '1'.repeat(64),
        prompt_tokens: 100 + Math.floor(rng() * 5000),
        completion_tokens: 50 + Math.floor(rng() * 2000),
      }))
      const dedupC = new Map<string, InferenceBillingRecord>()
      for (const p of providers) {
        const existing = dedupC.get(p.provider_did)
        if (existing) {
          existing.prompt_tokens += p.prompt_tokens
          existing.completion_tokens += p.completion_tokens
        } else {
          dedupC.set(p.provider_did, { ...p })
        }
      }
      const cWeights = computeComputeAxisWeights([...dedupC.values()])

      const axes: AttributionAxes = {
        D: dWeights,
        P: [],
        G: [{ delegation_id: `d-${i}`, signer_did: govRoot, scope_hash: 'f'.repeat(64), depth: 0 }],
        C: cWeights,
      }
      receipts.push(constructAttributionPrimitive({
        action: { agentId: 'did:agent:e2e', actionType: 'generate', params: { i }, nonce: `n-e2e-${i}` },
        axes, issuer: GATEWAY_DID, issuerPrivateKey: GATEWAY_PRIV, timestamp: ts,
      }))
    }

    const unsigned = aggregateAttributionPrimitives(receipts, period, {
      gateway_did: GATEWAY_DID,
      issued_at: '2026-04-29T00:00:00.001Z',
    })
    const signature = signSettlementRecord(unsigned, GATEWAY_PRIV)
    const record: AttributionSettlementRecord = { ...unsigned, signature }

    // S1-S5 with input receipts.
    const verdict = verifySettlementRecord(record, {
      gatewayPublicKeyHex: GATEWAY_PUB,
      inputReceipts: receipts,
    })
    assert.equal(verdict.valid, true, `record failed verification: ${JSON.stringify(verdict)}`)
    assert.equal(record.total_input_count, N)

    // Sanity: both pools collapsed into the aggregate.
    assert.ok(record.axes.D.contributors.length <= dataPool.length)
    assert.ok(record.axes.C.contributors.length <= computePool.length)
    assert.equal(record.axes.G.contributors.length, 1) // all receipts share govRoot

    // Per-contributor queries for every contributor on every axis.
    let queryCount = 0
    for (const tag of ['D', 'C', 'G'] as const) {
      for (const c of record.axes[tag].contributors) {
        const resp = buildContributorQueryResponse(record, c.contributor_did)
        assert.ok(resp, `no query response for ${c.contributor_did}`)
        const vv = verifyContributorQueryResponse(resp!, { gatewayPublicKeyHex: GATEWAY_PUB })
        assert.equal(vv.valid, true, `verify failed for ${c.contributor_did}: ${JSON.stringify(vv)}`)
        queryCount++
      }
    }
    assert.ok(queryCount >= 1, 'expected at least one contributor query response')

    // Contribution counts total matches total_actions for each axis.
    for (const tag of ['D', 'C', 'G'] as const) {
      let total = 0
      for (const c of record.axes[tag].contributors) total += c.contribution_count
      // Each receipt touches axis X exactly once per contributor, so
      // total contribution_count ≥ total_actions (multi-contributor
      // receipts add more) — at minimum it equals total_actions when
      // every receipt has exactly one entry.
      assert.ok(total >= record.axes[tag].total_actions, `axis ${tag}: ${total} < ${record.axes[tag].total_actions}`)
    }
  })
})
