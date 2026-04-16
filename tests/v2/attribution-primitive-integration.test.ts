// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Attribution Primitive — integration and property-style tests.
//
// Covers: Merkle composition under arbitrary axis orderings, batch
// attribution across many primitives, replay protection via action_ref,
// round-trip invariants across the four projections, §4.1 residual
// aggregation, and the cross-primitive claim that two projections cannot
// cross-verify unless they originate from the same signed receipt.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import {
  ATTRIBUTION_AXIS_TAGS,
  aggregateComputeAxis,
  aggregateDataAxis,
  aggregateProtocolAxis,
  buildMerkleFrame,
  checkProjectionConsistency,
  computeAttributionActionRef,
  constructAttributionPrimitive,
  envelopeBytes,
  generateKeyPair,
  hashAxisLeaf,
  hashNode,
  projectAllAxes,
  projectAttribution,
  projectionPath,
  reconstructRoot,
  toWeightString,
  verifyAttributionProjection,
} from '../../src/index.js'
import type {
  AttributionAction,
  AttributionAxes,
  AttributionPrimitive,
  AttributionProjection,
  ComputeAxisEntry,
  DataAxisEntry,
  GovernanceAxisEntry,
  ProtocolAxisEntry,
} from '../../src/index.js'

// ─────────────────────────────────────────────────────────────
// Generators
// ─────────────────────────────────────────────────────────────

let seed = 0x9e3779b1
function rand(): number {
  seed ^= seed << 13
  seed ^= seed >>> 17
  seed ^= seed << 5
  return (seed >>> 0) / 0xffffffff
}

function randomHash(): string {
  let s = ''
  for (let i = 0; i < 64; i++) s += Math.floor(rand() * 16).toString(16)
  return s
}

function randomWeightsSummingToOne(n: number): string[] {
  const raw: number[] = []
  for (let i = 0; i < n; i++) raw.push(rand() + 0.0001)
  const total = raw.reduce((a, b) => a + b, 0)
  const normalized = raw.map((r) => r / total)
  return normalized.map((w) => toWeightString(Math.floor(w * 1e6) / 1e6))
}

function generateRandomAxes(sizes: { d: number; p: number; g: number; c: number }): AttributionAxes {
  const wD = randomWeightsSummingToOne(sizes.d)
  const D: DataAxisEntry[] = []
  for (let i = 0; i < sizes.d; i++) {
    D.push({
      source_did: `did:data:src-${Math.floor(rand() * 1e9).toString(16)}`,
      contribution_weight: wD[i],
      access_receipt_hash: randomHash(),
    })
  }

  const P: ProtocolAxisEntry[] = []
  for (let i = 0; i < sizes.p; i++) {
    P.push({
      module_id: `module-${Math.floor(rand() * 1e9).toString(16)}`,
      module_version: `${Math.floor(rand() * 10)}.${Math.floor(rand() * 10)}.${Math.floor(rand() * 10)}`,
      evaluation_outcome: 'approved',
      evaluation_receipt_hash: randomHash(),
    })
  }

  const G: GovernanceAxisEntry[] = []
  for (let i = 0; i < sizes.g; i++) {
    G.push({
      delegation_id: `del-${i}-${Math.floor(rand() * 1e6)}`,
      signer_did: `did:aps:signer-${i}`,
      scope_hash: randomHash(),
      depth: i,
    })
  }

  const wC = randomWeightsSummingToOne(sizes.c)
  const C: ComputeAxisEntry[] = []
  for (let i = 0; i < sizes.c; i++) {
    C.push({
      provider_did: `did:compute:provider-${Math.floor(rand() * 1e9).toString(16)}`,
      compute_share: wC[i],
      hardware_attestation_hash: randomHash(),
    })
  }
  return { D, P, G, C }
}

function randomAction(): AttributionAction {
  return {
    agentId: `did:aps:agent-${Math.floor(rand() * 1e6)}`,
    actionType: 'query.arbitrary',
    params: { q: Math.floor(rand() * 1e9) },
    nonce: randomUUID(),
  }
}

function issuerKeys() {
  const { publicKey, privateKey } = generateKeyPair()
  return { issuer: `did:aps:issuer-${Math.floor(rand() * 1e6)}`, publicKey, privateKey }
}

function buildRandomPrimitive(sizes = { d: 3, p: 3, g: 3, c: 3 }) {
  const { issuer, publicKey, privateKey } = issuerKeys()
  const action = randomAction()
  const axes = generateRandomAxes(sizes)
  const primitive = constructAttributionPrimitive({
    action,
    axes,
    issuer,
    issuerPrivateKey: privateKey,
  })
  return { primitive, action, issuer, publicKey, privateKey }
}

// ─────────────────────────────────────────────────────────────
// Merkle composition property
// ─────────────────────────────────────────────────────────────

describe('Merkle composition (property)', () => {
  it('frame.root equals SHA-256(N_content || N_auth_infra) for any axes', () => {
    for (let i = 0; i < 30; i++) {
      const axes = generateRandomAxes({ d: 1 + Math.floor(rand() * 5), p: 1 + Math.floor(rand() * 5), g: 1 + Math.floor(rand() * 5), c: 1 + Math.floor(rand() * 5) })
      const frame = buildMerkleFrame(axes)
      const expected = createHash('sha256').update(Buffer.concat([frame.nodes.N_content, frame.nodes.N_auth_infra])).digest()
      assert.ok(frame.root.equals(expected))
    }
  })

  it('reconstructRoot on each axis always matches frame.root', () => {
    for (let i = 0; i < 30; i++) {
      const axes = generateRandomAxes({ d: 2, p: 2, g: 2, c: 2 })
      const frame = buildMerkleFrame(axes)
      for (const tag of ATTRIBUTION_AXIS_TAGS) {
        const path = projectionPath(frame, tag)
        const leaf = hashAxisLeaf(tag === 'D' ? frame.axes.D : tag === 'P' ? frame.axes.P : tag === 'G' ? frame.axes.G : frame.axes.C)
        const reconstructed = reconstructRoot(leaf, path, tag)
        assert.ok(reconstructed.equals(frame.root))
      }
    }
  })

  it('swapping axis content between two primitives produces different roots', () => {
    const a = generateRandomAxes({ d: 2, p: 2, g: 2, c: 2 })
    const b = generateRandomAxes({ d: 2, p: 2, g: 2, c: 2 })
    const rootA = buildMerkleFrame(a).root.toString('hex')
    const mixed = buildMerkleFrame({ D: b.D, P: a.P, G: a.G, C: a.C }).root.toString('hex')
    assert.notEqual(rootA, mixed)
  })
})

// ─────────────────────────────────────────────────────────────
// Round-trip across all four projections
// ─────────────────────────────────────────────────────────────

describe('round-trip invariants across projections', () => {
  it('each axis projection verifies under the issuer key and pairs cross-verify', () => {
    for (let i = 0; i < 20; i++) {
      const { primitive, publicKey } = buildRandomPrimitive({ d: 3, p: 4, g: 2, c: 3 })
      const projections = projectAllAxes(primitive)
      for (const tag of ATTRIBUTION_AXIS_TAGS) {
        const res = verifyAttributionProjection(projections[tag], publicKey)
        assert.deepEqual(res, { valid: true })
      }
      // All 6 unordered pairs of distinct axes cross-verify
      const tags = ATTRIBUTION_AXIS_TAGS
      for (let a = 0; a < tags.length; a++) {
        for (let b = a + 1; b < tags.length; b++) {
          const r = checkProjectionConsistency(projections[tags[a]], projections[tags[b]])
          assert.deepEqual(r, { same_receipt: true })
        }
      }
    }
  })

  it('mutating any single projection field breaks verification', () => {
    const { primitive, publicKey } = buildRandomPrimitive()
    const p = projectAttribution(primitive, 'D')
    const mutations: AttributionProjection[] = [
      { ...p, action_ref: randomHash() },
      { ...p, merkle_root: randomHash() },
      { ...p, signature: randomHash() + randomHash() },
      { ...p, timestamp: '2026-05-01T00:00:00.000Z' },
      { ...p, issuer: 'did:aps:other' },
    ]
    for (const m of mutations) {
      const res = verifyAttributionProjection(m, publicKey)
      assert.equal(res.valid, false)
    }
  })
})

// ─────────────────────────────────────────────────────────────
// Batch attribution — many primitives verified together
// ─────────────────────────────────────────────────────────────

describe('batch attribution', () => {
  it('verifies 100 projections across 25 primitives from 5 issuers', () => {
    const issuers = Array.from({ length: 5 }, () => issuerKeys())
    const primitives: { primitive: AttributionPrimitive; pub: string }[] = []
    for (let i = 0; i < 25; i++) {
      const iss = issuers[i % 5]
      const primitive = constructAttributionPrimitive({
        action: randomAction(),
        axes: generateRandomAxes({ d: 2, p: 2, g: 2, c: 2 }),
        issuer: iss.issuer,
        issuerPrivateKey: iss.privateKey,
      })
      primitives.push({ primitive, pub: iss.publicKey })
    }
    let verified = 0
    for (const { primitive, pub } of primitives) {
      for (const tag of ATTRIBUTION_AXIS_TAGS) {
        const p = projectAttribution(primitive, tag)
        const res = verifyAttributionProjection(p, pub)
        if (res.valid) verified++
      }
    }
    assert.equal(verified, 25 * 4)
  })

  it('projections from different receipts never cross-verify as same_receipt', () => {
    const { primitive: p1 } = buildRandomPrimitive()
    const { primitive: p2 } = buildRandomPrimitive()
    const a = projectAttribution(p1, 'D')
    const b = projectAttribution(p2, 'D')
    const res = checkProjectionConsistency(a, b)
    assert.equal(res.same_receipt, false)
  })
})

// ─────────────────────────────────────────────────────────────
// Replay protection via action_ref
// ─────────────────────────────────────────────────────────────

describe('replay protection', () => {
  it('the same logical action with a different nonce produces a different action_ref', () => {
    const base: AttributionAction = {
      agentId: 'did:aps:agent',
      actionType: 'infer',
      params: { x: 1 },
      nonce: randomUUID(),
    }
    const a1 = computeAttributionActionRef(base)
    const a2 = computeAttributionActionRef({ ...base, nonce: randomUUID() })
    assert.notEqual(a1, a2)
  })

  it('two issuers signing the same action_ref produce different signatures and cannot cross-verify', () => {
    const action = randomAction()
    const axes = generateRandomAxes({ d: 2, p: 2, g: 2, c: 2 })
    const i1 = issuerKeys()
    const i2 = issuerKeys()
    const p1 = constructAttributionPrimitive({ action, axes, issuer: i1.issuer, issuerPrivateKey: i1.privateKey, timestamp: '2026-04-12T17:42:08.342Z' })
    const p2 = constructAttributionPrimitive({ action, axes, issuer: i2.issuer, issuerPrivateKey: i2.privateKey, timestamp: '2026-04-12T17:42:08.342Z' })
    assert.equal(p1.action_ref, p2.action_ref)
    assert.equal(p1.merkle_root, p2.merkle_root)
    assert.notEqual(p1.signature, p2.signature)
    // Cross-issuer verification fails
    const proj2 = projectAttribution(p2, 'D')
    const res = verifyAttributionProjection(proj2, i1.publicKey)
    assert.equal(res.valid, false)
  })
})

// ─────────────────────────────────────────────────────────────
// Residual aggregation §4.1
// ─────────────────────────────────────────────────────────────

describe('residual aggregation §4.1', () => {
  it('pools sub-threshold data contributors into a residual bucket', () => {
    const entries: DataAxisEntry[] = [
      { source_did: 'did:data:big', contribution_weight: '0.800000', access_receipt_hash: 'a'.repeat(64) },
      { source_did: 'did:data:small1', contribution_weight: '0.000500', access_receipt_hash: 'b'.repeat(64) },
      { source_did: 'did:data:small2', contribution_weight: '0.000400', access_receipt_hash: 'c'.repeat(64) },
    ]
    const result = aggregateDataAxis(entries)
    assert.equal(result.pooledCount, 2)
    assert.ok(result.residual)
    assert.equal(result.residual!.residual_id, 'residual:D')
    assert.equal(result.residual!.count_of_pooled_contributors, 2)
    assert.equal(result.retained.length, 1)
    assert.match(result.residual!.pooled_contributors_hash, /^[0-9a-f]{64}$/)
  })

  it('returns no residual when all contributors meet the threshold', () => {
    const entries: DataAxisEntry[] = [
      { source_did: 'did:data:big1', contribution_weight: '0.500000', access_receipt_hash: 'a'.repeat(64) },
      { source_did: 'did:data:big2', contribution_weight: '0.500000', access_receipt_hash: 'b'.repeat(64) },
    ]
    const result = aggregateDataAxis(entries)
    assert.equal(result.pooledCount, 0)
    assert.equal(result.residual, null)
  })

  it('aggregation is deterministic: pooled hash is order-independent', () => {
    const a: DataAxisEntry[] = [
      { source_did: 'did:data:a', contribution_weight: '0.000100', access_receipt_hash: '1'.repeat(64) },
      { source_did: 'did:data:b', contribution_weight: '0.000200', access_receipt_hash: '2'.repeat(64) },
      { source_did: 'did:data:big', contribution_weight: '0.999700', access_receipt_hash: '3'.repeat(64) },
    ]
    const b: DataAxisEntry[] = [a[2], a[1], a[0]]
    const r1 = aggregateDataAxis(a)
    const r2 = aggregateDataAxis(b)
    assert.equal(r1.residual!.pooled_contributors_hash, r2.residual!.pooled_contributors_hash)
  })

  it('a primitive carrying a residual bucket still verifies end-to-end', () => {
    const entries: DataAxisEntry[] = [
      { source_did: 'did:data:big', contribution_weight: '0.900000', access_receipt_hash: 'a'.repeat(64) },
      { source_did: 'did:data:tiny', contribution_weight: '0.000100', access_receipt_hash: 'b'.repeat(64) },
    ]
    const { retained, residual } = aggregateDataAxis(entries)
    assert.ok(residual)
    const axes: AttributionAxes = {
      D: [...retained, residual!],
      P: [
        { module_id: 'mod', module_version: '1.0.0', evaluation_outcome: 'approved', evaluation_receipt_hash: 'c'.repeat(64) },
      ],
      G: [{ delegation_id: 'd0', signer_did: 'did:aps:r', scope_hash: 'd'.repeat(64), depth: 0 }],
      C: [{ provider_did: 'did:compute:x', compute_share: '1.000000', hardware_attestation_hash: 'e'.repeat(64) }],
    }
    const { publicKey, privateKey } = generateKeyPair()
    const primitive = constructAttributionPrimitive({
      action: randomAction(),
      axes,
      issuer: 'did:aps:issuer',
      issuerPrivateKey: privateKey,
    })
    const proj = projectAttribution(primitive, 'D')
    const res = verifyAttributionProjection(proj, publicKey)
    assert.deepEqual(res, { valid: true })
  })

  it('aggregateProtocolAxis leaves unweighted entries alone', () => {
    const entries: ProtocolAxisEntry[] = [
      { module_id: 'no-weight', module_version: '1.0.0', evaluation_outcome: 'approved', evaluation_receipt_hash: 'a'.repeat(64) },
    ]
    const result = aggregateProtocolAxis(entries)
    assert.equal(result.residual, null)
    assert.equal(result.retained.length, 1)
  })

  it('aggregateComputeAxis pools sub-threshold providers', () => {
    const entries: ComputeAxisEntry[] = [
      { provider_did: 'did:compute:big', compute_share: '0.980000', hardware_attestation_hash: '1'.repeat(64) },
      { provider_did: 'did:compute:tiny', compute_share: '0.000500', hardware_attestation_hash: '2'.repeat(64) },
    ]
    const r = aggregateComputeAxis(entries)
    assert.equal(r.pooledCount, 1)
    assert.equal(r.residual!.residual_id, 'residual:C')
  })
})

// ─────────────────────────────────────────────────────────────
// Envelope stability (cross-language fixture)
// ─────────────────────────────────────────────────────────────

describe('envelope stability', () => {
  it('envelopeBytes is a pure function of its four inputs', () => {
    const env = {
      action_ref: 'a'.repeat(64),
      merkle_root: 'b'.repeat(64),
      issuer: 'did:aps:issuer',
      timestamp: '2026-04-12T17:42:08.342Z',
    }
    const e1 = envelopeBytes(env)
    const e2 = envelopeBytes({ ...env })
    assert.equal(e1, e2)
    // Field order in the envelope object must not affect the canonical
    // output — the canonicalizer sorts keys.
    const e3 = envelopeBytes({
      timestamp: env.timestamp,
      issuer: env.issuer,
      merkle_root: env.merkle_root,
      action_ref: env.action_ref,
    })
    assert.equal(e1, e3)
  })

  it('known-fixture envelope matches expected canonical sha256', () => {
    // Hand-computed fixture. Any change to canonicalization rules would
    // flip this hash — which would also flip TS/Python interoperability.
    const env = {
      action_ref: '0000000000000000000000000000000000000000000000000000000000000001',
      merkle_root: '0000000000000000000000000000000000000000000000000000000000000002',
      issuer: 'did:aps:test',
      timestamp: '2026-04-12T17:42:08.342Z',
    }
    const bytes = envelopeBytes(env)
    const digest = createHash('sha256').update(bytes).digest('hex')
    assert.equal(bytes, '{"action_ref":"0000000000000000000000000000000000000000000000000000000000000001","issuer":"did:aps:test","merkle_root":"0000000000000000000000000000000000000000000000000000000000000002","timestamp":"2026-04-12T17:42:08.342Z"}')
    assert.match(digest, /^[0-9a-f]{64}$/)
  })

  it('hashNode is commutative-negative: order matters', () => {
    const a = createHash('sha256').update('a').digest()
    const b = createHash('sha256').update('b').digest()
    const ab = hashNode(a, b)
    const ba = hashNode(b, a)
    assert.ok(!ab.equals(ba))
  })
})
