// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Generate cross-language fixtures for Build C. Run with:
//   npx tsx scripts/generate-build-c-fixtures.ts
//
// Writes 5 JSON fixtures to /Users/tima/aeoess_web/specs/fixtures/build-c/.
// Each fixture contains {description, input_receipts, period, expected_record,
// contributor_queries: [{did, response}]}. Python (and TS) verifiers load
// these and assert byte-identical canonical output.
//
// Determinism:
//   - gateway key pair is derived from sha256("build-c-fixture-gateway-key-v1")
//   - per-receipt private keys derived from sha256("build-c-fixture-receipt-" + i)
//     (actually the same gateway key signs everything — gateways sign receipts
//     too in the reference deployment)
//   - all timestamps, action_refs, and nonces are deterministic

import { createHash } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  aggregateAttributionPrimitives,
  buildContributorQueryResponse,
  constructAttributionPrimitive,
  publicKeyFromPrivate,
  signSettlementRecord,
} from '../src/index.js'
import type {
  AttributionAxes,
  AttributionPrimitive,
  AttributionSettlementPeriod,
  AttributionSettlementRecord,
} from '../src/index.js'

const OUT_DIR = '/Users/tima/aeoess_web/specs/fixtures/build-c'
mkdirSync(OUT_DIR, { recursive: true })

// Derive a deterministic 32-byte private key (hex) from a label. The SDK
// ed25519 helper accepts any 32-byte seed, so sha256(label) is a clean
// fixture key. Never used for anything other than fixture generation.
function deterministicKey(label: string): string {
  return createHash('sha256').update(label).digest('hex')
}

const GATEWAY_PRIV = deterministicKey('build-c-fixture-gateway-key-v1')
const GATEWAY_PUB = publicKeyFromPrivate(GATEWAY_PRIV)
const GATEWAY_DID = `did:aeoess:gateway:build-c-fixture-${GATEWAY_PUB.slice(0, 12)}`

function write(name: string, body: unknown): void {
  const path = join(OUT_DIR, `${name}.json`)
  writeFileSync(path, JSON.stringify(body, null, 2) + '\n')
  console.log(`wrote ${path}`)
}

function isoAt(baseMs: number, offsetMs: number): string {
  return new Date(baseMs + offsetMs).toISOString()
}

// ─── Scenario 1: 100-action single-axis ────────────────────────
{
  const t0 = '2026-04-01T00:00:00.000Z'
  const t1 = '2026-04-02T00:00:00.000Z'
  const period: AttributionSettlementPeriod = { t0, t1, period_id: 'fixture-c-01-single-axis' }
  const baseMs = Date.parse(t0)
  const receipts: AttributionPrimitive[] = []
  for (let i = 0; i < 100; i++) {
    // Only 5 unique data sources across 100 receipts — heavy aggregation.
    const didA = `did:data:src-${i % 5}`
    const didB = `did:data:src-${(i + 1) % 5}`
    const axes: AttributionAxes = {
      D: [
        { source_did: didA, contribution_weight: '0.700000', access_receipt_hash: 'a'.repeat(64) },
        { source_did: didB, contribution_weight: '0.300000', access_receipt_hash: 'b'.repeat(64) },
      ],
      P: [],
      G: [{ delegation_id: `d-${i}`, signer_did: 'did:gov:root', scope_hash: 'f'.repeat(64), depth: 0 }],
      C: [{ provider_did: 'did:compute:only', compute_share: '1.000000', hardware_attestation_hash: '1'.repeat(64) }],
    }
    receipts.push(constructAttributionPrimitive({
      action: { agentId: 'did:agent:fixture-01', actionType: 'generate', params: { i }, nonce: `n-01-${i}` },
      axes, issuer: GATEWAY_DID, issuerPrivateKey: GATEWAY_PRIV,
      timestamp: isoAt(baseMs, i * 60_000),
    }))
  }
  const unsigned = aggregateAttributionPrimitives(receipts, period, {
    gateway_did: GATEWAY_DID,
    issued_at: '2026-04-02T00:00:00.001Z',
  })
  const signature = signSettlementRecord(unsigned, GATEWAY_PRIV)
  const record: AttributionSettlementRecord = { ...unsigned, signature }
  const queries = ['did:data:src-0', 'did:data:src-1', 'did:compute:only']
    .map((did) => ({ contributor_did: did, response: buildContributorQueryResponse(record, did) }))
  write('01-single-axis-100-actions', {
    description: '100-action period, 5 recurring D-axis contributors plus one C-axis provider',
    gateway_public_key: GATEWAY_PUB,
    gateway_did: GATEWAY_DID,
    period,
    input_receipts: receipts,
    expected_record: record,
    contributor_queries: queries,
  })
}

// ─── Scenario 2: 1000-action multi-axis ───────────────────────
{
  const t0 = '2026-04-03T00:00:00.000Z'
  const t1 = '2026-04-04T00:00:00.000Z'
  const period: AttributionSettlementPeriod = { t0, t1, period_id: 'fixture-c-02-multi-axis' }
  const baseMs = Date.parse(t0)
  const receipts: AttributionPrimitive[] = []
  for (let i = 0; i < 1000; i++) {
    const sharedDid = 'did:aeoess:hybrid-actor-42'
    const onD = i % 3 === 0
    const onC = i % 3 === 1
    const D = onD
      ? [
          { source_did: sharedDid, contribution_weight: '0.600000', access_receipt_hash: 'a'.repeat(64) },
          { source_did: `did:data:pool-${i % 7}`, contribution_weight: '0.400000', access_receipt_hash: 'b'.repeat(64) },
        ]
      : [{ source_did: `did:data:pool-${i % 7}`, contribution_weight: '1.000000', access_receipt_hash: 'c'.repeat(64) }]
    const C = onC
      ? [
          { provider_did: sharedDid, compute_share: '0.700000', hardware_attestation_hash: '1'.repeat(64) },
          { provider_did: `did:compute:farm-${i % 4}`, compute_share: '0.300000', hardware_attestation_hash: '2'.repeat(64) },
        ]
      : [{ provider_did: `did:compute:farm-${i % 4}`, compute_share: '1.000000', hardware_attestation_hash: '3'.repeat(64) }]
    const axes: AttributionAxes = {
      D, P: [],
      G: [
        { delegation_id: `d-${i}-0`, signer_did: 'did:gov:root', scope_hash: 'f'.repeat(64), depth: 0 },
        { delegation_id: `d-${i}-1`, signer_did: `did:gov:sub-${i % 3}`, scope_hash: 'e'.repeat(64), depth: 1 },
      ],
      C,
    }
    receipts.push(constructAttributionPrimitive({
      action: { agentId: 'did:agent:fixture-02', actionType: 'generate', params: { i }, nonce: `n-02-${i}` },
      axes, issuer: GATEWAY_DID, issuerPrivateKey: GATEWAY_PRIV,
      timestamp: isoAt(baseMs, i * 86_000),
    }))
  }
  const unsigned = aggregateAttributionPrimitives(receipts, period, {
    gateway_did: GATEWAY_DID,
    issued_at: '2026-04-04T00:00:00.001Z',
  })
  const signature = signSettlementRecord(unsigned, GATEWAY_PRIV)
  const record: AttributionSettlementRecord = { ...unsigned, signature }
  const queries = ['did:aeoess:hybrid-actor-42', 'did:data:pool-0', 'did:gov:root']
    .map((did) => ({ contributor_did: did, response: buildContributorQueryResponse(record, did) }))
  write('02-multi-axis-1000-actions', {
    description: '1000-action period, hybrid-actor-42 active on both D and C axes in disjoint action subsets',
    gateway_public_key: GATEWAY_PUB,
    gateway_did: GATEWAY_DID,
    period,
    input_receipts: receipts,
    expected_record: record,
    contributor_queries: queries,
  })
}

// ─── Scenario 3: residual bucket ──────────────────────────────
{
  const t0 = '2026-04-05T00:00:00.000Z'
  const t1 = '2026-04-06T00:00:00.000Z'
  const period: AttributionSettlementPeriod = { t0, t1, period_id: 'fixture-c-03-residual' }
  const baseMs = Date.parse(t0)
  const receipts: AttributionPrimitive[] = []
  for (let i = 0; i < 20; i++) {
    const axes: AttributionAxes = {
      D: [
        { source_did: `did:data:top-${i % 3}`, contribution_weight: '0.850000', access_receipt_hash: 'a'.repeat(64) },
        {
          residual_id: 'residual:D' as const,
          total_pooled_weight: '0.150000',
          count_of_pooled_contributors: 12,
          pooled_contributors_hash: createHash('sha256').update(`pooled-${i}`).digest('hex'),
        },
      ],
      P: [],
      G: [{ delegation_id: `d-${i}`, signer_did: 'did:gov:root', scope_hash: 'f'.repeat(64), depth: 0 }],
      C: [{ provider_did: 'did:compute:big', compute_share: '1.000000', hardware_attestation_hash: '1'.repeat(64) }],
    }
    receipts.push(constructAttributionPrimitive({
      action: { agentId: 'did:agent:fixture-03', actionType: 'generate', params: { i }, nonce: `n-03-${i}` },
      axes, issuer: GATEWAY_DID, issuerPrivateKey: GATEWAY_PRIV,
      timestamp: isoAt(baseMs, i * 3600_000),
    }))
  }
  const unsigned = aggregateAttributionPrimitives(receipts, period, {
    gateway_did: GATEWAY_DID,
    issued_at: '2026-04-06T00:00:00.001Z',
  })
  const signature = signSettlementRecord(unsigned, GATEWAY_PRIV)
  const record: AttributionSettlementRecord = { ...unsigned, signature }
  const queries = ['did:data:top-0', 'did:compute:big']
    .map((did) => ({ contributor_did: did, response: buildContributorQueryResponse(record, did) }))
  write('03-residual-bucket', {
    description: '20-action period with a per-receipt D-axis residual bucket; settlement bucket aggregates',
    gateway_public_key: GATEWAY_PUB,
    gateway_did: GATEWAY_DID,
    period,
    input_receipts: receipts,
    expected_record: record,
    contributor_queries: queries,
  })
}

// ─── Scenario 4: empty period ─────────────────────────────────
{
  const t0 = '2026-04-07T00:00:00.000Z'
  const t1 = '2026-04-08T00:00:00.000Z'
  const period: AttributionSettlementPeriod = { t0, t1, period_id: 'fixture-c-04-empty' }
  const unsigned = aggregateAttributionPrimitives([], period, {
    gateway_did: GATEWAY_DID,
    issued_at: '2026-04-08T00:00:00.001Z',
  })
  const signature = signSettlementRecord(unsigned, GATEWAY_PRIV)
  const record: AttributionSettlementRecord = { ...unsigned, signature }
  write('04-empty-period', {
    description: 'Zero actions over 24h; record has empty axes and empty Merkle roots per I-C5',
    gateway_public_key: GATEWAY_PUB,
    gateway_did: GATEWAY_DID,
    period,
    input_receipts: [],
    expected_record: record,
    contributor_queries: [],
  })
}

// ─── Scenario 5: fragmented — one contributor per action ─────
{
  const t0 = '2026-04-09T00:00:00.000Z'
  const t1 = '2026-04-10T00:00:00.000Z'
  const period: AttributionSettlementPeriod = { t0, t1, period_id: 'fixture-c-05-fragmented' }
  const baseMs = Date.parse(t0)
  const receipts: AttributionPrimitive[] = []
  for (let i = 0; i < 50; i++) {
    const axes: AttributionAxes = {
      D: [{ source_did: `did:data:unique-${i}`, contribution_weight: '1.000000', access_receipt_hash: 'a'.repeat(64) }],
      P: [],
      G: [{ delegation_id: `d-${i}`, signer_did: `did:gov:unique-${i}`, scope_hash: 'f'.repeat(64), depth: 0 }],
      C: [{ provider_did: `did:compute:unique-${i}`, compute_share: '1.000000', hardware_attestation_hash: '1'.repeat(64) }],
    }
    receipts.push(constructAttributionPrimitive({
      action: { agentId: 'did:agent:fixture-05', actionType: 'generate', params: { i }, nonce: `n-05-${i}` },
      axes, issuer: GATEWAY_DID, issuerPrivateKey: GATEWAY_PRIV,
      timestamp: isoAt(baseMs, i * 1_728_000),
    }))
  }
  const unsigned = aggregateAttributionPrimitives(receipts, period, {
    gateway_did: GATEWAY_DID,
    issued_at: '2026-04-10T00:00:00.001Z',
  })
  const signature = signSettlementRecord(unsigned, GATEWAY_PRIV)
  const record: AttributionSettlementRecord = { ...unsigned, signature }
  const queries = ['did:data:unique-0', 'did:data:unique-49', 'did:compute:unique-25']
    .map((did) => ({ contributor_did: did, response: buildContributorQueryResponse(record, did) }))
  write('05-fragmented-one-action-each', {
    description: 'Worst-case fragmentation — 50 unique contributors per axis, one action each',
    gateway_public_key: GATEWAY_PUB,
    gateway_did: GATEWAY_DID,
    period,
    input_receipts: receipts,
    expected_record: record,
    contributor_queries: queries,
  })
}

console.log('\nDone.')
