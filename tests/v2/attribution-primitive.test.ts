// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Attribution Primitive — unit tests covering construction, signing,
// projection, verification, and the §2.5 canonicalization rules.
//
// Spec reference: ATTRIBUTION-PRIMITIVE-v1.1.md

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import {
  ATTRIBUTION_AXIS_TAGS,
  assertCanonicalTimestamp,
  attributionCanonicalHashHex,
  attributionCanonicalTimestamp,
  buildMerkleFrame,
  checkProjectionConsistency,
  computeAttributionActionRef,
  constructAttributionPrimitive,
  envelopeBytes,
  generateKeyPair,
  hashAxisLeaf,
  normalizeAxes,
  orderGovernanceAxis,
  projectAllAxes,
  projectAttribution,
  projectionPath,
  projectionDataAsD,
  projectionDataAsP,
  projectionDataAsG,
  projectionDataAsC,
  reconstructRoot,
  resignAttributionPrimitive,
  sortDataAxis,
  sortProtocolAxis,
  sortComputeAxis,
  toWeightString,
  verifyAttributionPrimitive,
  verifyAttributionProjection,
} from '../../src/index.js'
import type {
  AttributionAction,
  AttributionAxes,
  AttributionProjection,
  ComputeAxisEntry,
  DataAxisEntry,
  GovernanceAxisEntry,
  ProtocolAxisEntry,
} from '../../src/index.js'

// ─────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────

function demoAxes(): AttributionAxes {
  const D: DataAxisEntry[] = [
    { source_did: 'did:data:kff-2025', contribution_weight: '0.583000', access_receipt_hash: 'a'.repeat(64) },
    { source_did: 'did:data:cms-archive-2025', contribution_weight: '0.417000', access_receipt_hash: 'b'.repeat(64) },
  ]
  const P: ProtocolAxisEntry[] = [
    { module_id: 'redact-pii-v2.3', module_version: '2.3.1', evaluation_outcome: 'approved', evaluation_receipt_hash: 'c'.repeat(64) },
    { module_id: 'cite-verify-v1.7', module_version: '1.7.4', evaluation_outcome: 'approved', evaluation_receipt_hash: 'd'.repeat(64) },
    { module_id: 'factcheck-v3.1', module_version: '3.1.2', evaluation_outcome: 'approved', evaluation_receipt_hash: 'e'.repeat(64) },
  ]
  const G: GovernanceAxisEntry[] = [
    { delegation_id: 'delegation:root-customer-principal', signer_did: 'did:aps:customer', scope_hash: 'f'.repeat(64), depth: 0 },
    { delegation_id: 'delegation:customer-to-agent', signer_did: 'did:aps:customer-agent', scope_hash: 'e'.repeat(63) + 'a', depth: 1 },
    { delegation_id: 'delegation:agent-to-gateway', signer_did: 'did:aps:gateway', scope_hash: 'd'.repeat(63) + 'a', depth: 2 },
  ]
  const C: ComputeAxisEntry[] = [
    { provider_did: 'did:compute:anthropic-inference', compute_share: '0.342000', hardware_attestation_hash: '1'.repeat(64) },
    { provider_did: 'did:compute:openai-inference', compute_share: '0.331000', hardware_attestation_hash: '2'.repeat(64) },
    { provider_did: 'did:compute:google-inference', compute_share: '0.327000', hardware_attestation_hash: '3'.repeat(64) },
  ]
  return { D, P, G, C }
}

function demoAction(overrides: Partial<AttributionAction> = {}): AttributionAction {
  return {
    agentId: overrides.agentId ?? 'did:aps:agent-alpha',
    actionType: overrides.actionType ?? 'query.summarize',
    params: overrides.params ?? { prompt: 'Summarize findings from 2025 policy reports', region: 'us-west' },
    nonce: overrides.nonce ?? '11111111-1111-1111-1111-111111111111',
  }
}

function issuerFixture() {
  const { publicKey, privateKey } = generateKeyPair()
  return {
    issuer: 'did:aps:gateway-test',
    issuerPublicKey: publicKey,
    issuerPrivateKey: privateKey,
  }
}

function buildPrimitive(overrides: Partial<AttributionAxes> = {}) {
  const { issuer, issuerPublicKey, issuerPrivateKey } = issuerFixture()
  const action = demoAction()
  const axes = { ...demoAxes(), ...overrides }
  const primitive = constructAttributionPrimitive({
    action,
    axes,
    issuer,
    issuerPrivateKey,
  })
  return { primitive, action, issuer, issuerPublicKey, issuerPrivateKey }
}

// ─────────────────────────────────────────────────────────────
// Canonicalization + timestamp §2.5
// ─────────────────────────────────────────────────────────────

describe('canonicalization §2.5', () => {
  it('toWeightString forces 6-digit precision', () => {
    assert.equal(toWeightString(0.5), '0.500000')
    assert.equal(toWeightString(1 / 3), '0.333333')
    assert.equal(toWeightString('0.123456'), '0.123456')
  })

  it('rejects weights outside [0, 1]', () => {
    assert.throws(() => toWeightString(-0.01))
    assert.throws(() => toWeightString(1.01))
    assert.throws(() => toWeightString(Number.NaN))
  })

  it('rejects weight strings with wrong precision', () => {
    assert.throws(() => toWeightString('0.5'))
    assert.throws(() => toWeightString('0.33333'))
    assert.throws(() => toWeightString('0.3333333'))
    assert.throws(() => toWeightString('1e-3'))
  })

  it('assertCanonicalTimestamp accepts millisecond precision UTC only', () => {
    assert.doesNotThrow(() => assertCanonicalTimestamp('2026-04-12T17:42:08.342Z'))
    assert.throws(() => assertCanonicalTimestamp('2026-04-12T17:42:08Z'))
    assert.throws(() => assertCanonicalTimestamp('2026-04-12T17:42:08.342+00:00'))
    assert.throws(() => assertCanonicalTimestamp('2026-04-12T17:42:08.342'))
  })

  it('canonicalTimestamp() produces a stamp that round-trips through assertCanonicalTimestamp', () => {
    const s = attributionCanonicalTimestamp()
    assert.doesNotThrow(() => assertCanonicalTimestamp(s))
  })
})

describe('axis ordering §2.5', () => {
  it('sorts D by source_did', () => {
    const unsorted: DataAxisEntry[] = [
      { source_did: 'did:data:z', contribution_weight: '0.100000', access_receipt_hash: 'a'.repeat(64) },
      { source_did: 'did:data:a', contribution_weight: '0.200000', access_receipt_hash: 'b'.repeat(64) },
    ]
    const sorted = sortDataAxis(unsorted) as DataAxisEntry[]
    assert.equal(sorted[0].source_did, 'did:data:a')
  })

  it('sorts P by (module_id, module_version)', () => {
    const unsorted: ProtocolAxisEntry[] = [
      { module_id: 'z-module', module_version: '1.0.0', evaluation_outcome: 'approved', evaluation_receipt_hash: 'a'.repeat(64) },
      { module_id: 'a-module', module_version: '2.0.0', evaluation_outcome: 'approved', evaluation_receipt_hash: 'b'.repeat(64) },
      { module_id: 'a-module', module_version: '1.0.0', evaluation_outcome: 'approved', evaluation_receipt_hash: 'c'.repeat(64) },
    ]
    const sorted = sortProtocolAxis(unsorted) as ProtocolAxisEntry[]
    assert.equal(sorted[0].module_id, 'a-module')
    assert.equal(sorted[0].module_version, '1.0.0')
    assert.equal(sorted[1].module_id, 'a-module')
    assert.equal(sorted[1].module_version, '2.0.0')
  })

  it('sorts C by provider_did', () => {
    const unsorted: ComputeAxisEntry[] = [
      { provider_did: 'did:compute:z', compute_share: '0.500000', hardware_attestation_hash: 'a'.repeat(64) },
      { provider_did: 'did:compute:a', compute_share: '0.500000', hardware_attestation_hash: 'b'.repeat(64) },
    ]
    const sorted = sortComputeAxis(unsorted) as ComputeAxisEntry[]
    assert.equal(sorted[0].provider_did, 'did:compute:a')
  })

  it('orders G by increasing depth', () => {
    const unsorted: GovernanceAxisEntry[] = [
      { delegation_id: 'd2', signer_did: 'did:aps:two', scope_hash: 'a'.repeat(64), depth: 2 },
      { delegation_id: 'd0', signer_did: 'did:aps:zero', scope_hash: 'b'.repeat(64), depth: 0 },
      { delegation_id: 'd1', signer_did: 'did:aps:one', scope_hash: 'c'.repeat(64), depth: 1 },
    ]
    const ordered = orderGovernanceAxis(unsorted)
    assert.deepEqual(ordered.map((g) => g.depth), [0, 1, 2])
  })

  it('rejects duplicate depths in G', () => {
    const bad: GovernanceAxisEntry[] = [
      { delegation_id: 'a', signer_did: 'did:aps:a', scope_hash: 'a'.repeat(64), depth: 0 },
      { delegation_id: 'b', signer_did: 'did:aps:b', scope_hash: 'b'.repeat(64), depth: 0 },
    ]
    assert.throws(() => orderGovernanceAxis(bad))
  })

  it('normalizeAxes is idempotent', () => {
    const axes = demoAxes()
    const once = normalizeAxes(axes)
    const twice = normalizeAxes(once)
    assert.deepEqual(once, twice)
  })
})

// ─────────────────────────────────────────────────────────────
// action_ref §1.2 / §3.4
// ─────────────────────────────────────────────────────────────

describe('computeAttributionActionRef', () => {
  it('produces a 64-hex sha256 digest', () => {
    const ref = computeAttributionActionRef(demoAction())
    assert.match(ref, /^[0-9a-f]{64}$/)
  })

  it('is deterministic for the same action tuple', () => {
    const a1 = computeAttributionActionRef(demoAction())
    const a2 = computeAttributionActionRef(demoAction())
    assert.equal(a1, a2)
  })

  it('distinguishes actions with different nonces', () => {
    const a = computeAttributionActionRef(demoAction({ nonce: 'aaa' }))
    const b = computeAttributionActionRef(demoAction({ nonce: 'bbb' }))
    assert.notEqual(a, b)
  })

  it('distinguishes actions with different params', () => {
    const a = computeAttributionActionRef(demoAction({ params: { x: 1 } }))
    const b = computeAttributionActionRef(demoAction({ params: { x: 2 } }))
    assert.notEqual(a, b)
  })

  it('rejects malformed action tuples', () => {
    assert.throws(() => computeAttributionActionRef({ agentId: '', actionType: 't', params: {}, nonce: 'n' } as AttributionAction))
    assert.throws(() => computeAttributionActionRef({ agentId: 'a', actionType: '', params: {}, nonce: 'n' } as AttributionAction))
    assert.throws(() => computeAttributionActionRef({ agentId: 'a', actionType: 't', params: {}, nonce: '' } as AttributionAction))
  })
})

// ─────────────────────────────────────────────────────────────
// Merkle tree §2.1
// ─────────────────────────────────────────────────────────────

describe('Merkle tree §2.1', () => {
  it('produces a 32-byte root from four axis leaves', () => {
    const frame = buildMerkleFrame(demoAxes())
    assert.equal(frame.root.length, 32)
    assert.equal(frame.leaves.D.length, 32)
    assert.equal(frame.leaves.P.length, 32)
    assert.equal(frame.leaves.G.length, 32)
    assert.equal(frame.leaves.C.length, 32)
  })

  it('pairs content (D,P) and authority-infrastructure (G,C) nodes as specified', () => {
    const frame = buildMerkleFrame(demoAxes())
    const expectedContent = createHash('sha256')
      .update(Buffer.concat([frame.leaves.D, frame.leaves.P]))
      .digest()
    const expectedAuth = createHash('sha256')
      .update(Buffer.concat([frame.leaves.G, frame.leaves.C]))
      .digest()
    const expectedRoot = createHash('sha256')
      .update(Buffer.concat([expectedContent, expectedAuth]))
      .digest()
    assert.ok(frame.nodes.N_content.equals(expectedContent))
    assert.ok(frame.nodes.N_auth_infra.equals(expectedAuth))
    assert.ok(frame.root.equals(expectedRoot))
  })

  it('all four projection paths have length two (balanced tree §2.2)', () => {
    const frame = buildMerkleFrame(demoAxes())
    for (const tag of ATTRIBUTION_AXIS_TAGS) {
      const p = projectionPath(frame, tag)
      assert.equal(p.length, 2)
      assert.match(p[0], /^[0-9a-f]{64}$/)
      assert.match(p[1], /^[0-9a-f]{64}$/)
    }
  })

  it('reconstructRoot recovers the built root for each axis', () => {
    const axes = demoAxes()
    const frame = buildMerkleFrame(axes)
    for (const tag of ATTRIBUTION_AXIS_TAGS) {
      const path = projectionPath(frame, tag)
      const leaf = hashAxisLeaf(
        tag === 'D' ? frame.axes.D : tag === 'P' ? frame.axes.P : tag === 'G' ? frame.axes.G : frame.axes.C,
      )
      const computed = reconstructRoot(leaf, path, tag)
      assert.ok(computed.equals(frame.root), `root mismatch for axis ${tag}`)
    }
  })

  it('reconstructRoot with mismatched path bytes yields a different root', () => {
    const frame = buildMerkleFrame(demoAxes())
    const goodPath = projectionPath(frame, 'D')
    const badPath: [string, string] = [goodPath[0].replace(/^./, '0'), goodPath[1]]
    const leaf = hashAxisLeaf(frame.axes.D)
    const computed = reconstructRoot(leaf, badPath, 'D')
    assert.ok(!computed.equals(frame.root))
  })
})

// ─────────────────────────────────────────────────────────────
// Construction + signing §2.7
// ─────────────────────────────────────────────────────────────

describe('constructAttributionPrimitive', () => {
  it('returns a fully populated primitive with hex sha256 fields', () => {
    const { primitive } = buildPrimitive()
    assert.match(primitive.action_ref, /^[0-9a-f]{64}$/)
    assert.match(primitive.merkle_root, /^[0-9a-f]{64}$/)
    assert.match(primitive.signature, /^[0-9a-f]{128}$/)
    assert.doesNotThrow(() => assertCanonicalTimestamp(primitive.timestamp))
  })

  it('deterministic merkle_root for the same axes, regardless of input ordering', () => {
    const { issuer, issuerPrivateKey } = issuerFixture()
    const action = demoAction()
    const axes1 = demoAxes()
    const axes2: AttributionAxes = {
      D: [...axes1.D].reverse(),
      P: [...axes1.P].reverse(),
      G: [...axes1.G].reverse(),
      C: [...axes1.C].reverse(),
    }
    const p1 = constructAttributionPrimitive({ action, axes: axes1, issuer, issuerPrivateKey, timestamp: '2026-04-12T17:42:08.342Z' })
    const p2 = constructAttributionPrimitive({ action, axes: axes2, issuer, issuerPrivateKey, timestamp: '2026-04-12T17:42:08.342Z' })
    assert.equal(p1.merkle_root, p2.merkle_root)
    assert.equal(p1.signature, p2.signature)
  })

  it('rejects missing issuer or private key', () => {
    const action = demoAction()
    const axes = demoAxes()
    assert.throws(() =>
      constructAttributionPrimitive({ action, axes, issuer: '', issuerPrivateKey: 'x' }),
    )
    assert.throws(() =>
      constructAttributionPrimitive({ action, axes, issuer: 'did:aps:x', issuerPrivateKey: '' }),
    )
  })

  it('rejects a non-canonical timestamp override', () => {
    const { issuer, issuerPrivateKey } = issuerFixture()
    assert.throws(() =>
      constructAttributionPrimitive({
        action: demoAction(),
        axes: demoAxes(),
        issuer,
        issuerPrivateKey,
        timestamp: '2026-04-12T17:42:08Z',
      }),
    )
  })

  it('envelope fields match signature input', () => {
    const { primitive } = buildPrimitive()
    const env = envelopeBytes({
      action_ref: primitive.action_ref,
      merkle_root: primitive.merkle_root,
      issuer: primitive.issuer,
      timestamp: primitive.timestamp,
    })
    const expectedAnchor = attributionCanonicalHashHex({
      action_ref: primitive.action_ref,
      merkle_root: primitive.merkle_root,
      issuer: primitive.issuer,
      timestamp: primitive.timestamp,
    })
    assert.equal(createHash('sha256').update(env).digest('hex'), expectedAnchor)
  })
})

// ─────────────────────────────────────────────────────────────
// Projections §2.2
// ─────────────────────────────────────────────────────────────

describe('projections §2.2', () => {
  it('projectAttribution extracts each axis with a two-hop path', () => {
    const { primitive } = buildPrimitive()
    for (const tag of ATTRIBUTION_AXIS_TAGS) {
      const p = projectAttribution(primitive, tag)
      assert.equal(p.axis_tag, tag)
      assert.equal(p.merkle_path.length, 2)
      assert.equal(p.action_ref, primitive.action_ref)
      assert.equal(p.merkle_root, primitive.merkle_root)
      assert.equal(p.signature, primitive.signature)
    }
  })

  it('projectAllAxes returns four projections with the same envelope fields', () => {
    const { primitive } = buildPrimitive()
    const all = projectAllAxes(primitive)
    const envelopes = new Set<string>()
    for (const tag of ATTRIBUTION_AXIS_TAGS) {
      const p = all[tag]
      envelopes.add(`${p.action_ref}|${p.merkle_root}|${p.signature}|${p.timestamp}`)
    }
    assert.equal(envelopes.size, 1)
  })

  it('axis-cast helpers type-narrow correctly', () => {
    const { primitive } = buildPrimitive()
    const all = projectAllAxes(primitive)
    assert.ok(Array.isArray(projectionDataAsD(all.D)))
    assert.ok(Array.isArray(projectionDataAsP(all.P)))
    assert.ok(Array.isArray(projectionDataAsG(all.G)))
    assert.ok(Array.isArray(projectionDataAsC(all.C)))
    assert.throws(() => projectionDataAsD(all.P))
  })
})

// ─────────────────────────────────────────────────────────────
// Verification §2.3 / §2.6
// ─────────────────────────────────────────────────────────────

describe('verifyAttributionProjection §2.3', () => {
  it('returns valid for a freshly constructed projection under the issuer key', () => {
    const { primitive, issuerPublicKey } = buildPrimitive()
    for (const tag of ATTRIBUTION_AXIS_TAGS) {
      const p = projectAttribution(primitive, tag)
      const res = verifyAttributionProjection(p, issuerPublicKey)
      assert.deepEqual(res, { valid: true })
    }
  })

  it('returns SIGNATURE_INVALID when verified under the wrong public key', () => {
    const { primitive } = buildPrimitive()
    const { publicKey: otherPk } = generateKeyPair()
    const p = projectAttribution(primitive, 'D')
    const res = verifyAttributionProjection(p, otherPk)
    assert.deepEqual(res, { valid: false, reason: 'SIGNATURE_INVALID' })
  })

  it('returns MERKLE_MISMATCH when axis_data is tampered', () => {
    const { primitive, issuerPublicKey } = buildPrimitive()
    const p = projectAttribution(primitive, 'D')
    const tampered: AttributionProjection = {
      ...p,
      axis_data: [{ ...(p.axis_data as DataAxisEntry[])[0], contribution_weight: '0.999999' }],
    }
    const res = verifyAttributionProjection(tampered, issuerPublicKey)
    assert.deepEqual(res, { valid: false, reason: 'MERKLE_MISMATCH' })
  })

  it('returns MERKLE_MISMATCH when the path hashes are tampered', () => {
    const { primitive, issuerPublicKey } = buildPrimitive()
    const p = projectAttribution(primitive, 'P')
    const brokenFirst = p.merkle_path[0].replace(/^./, (c) => (c === '0' ? '1' : '0'))
    const tampered: AttributionProjection = {
      ...p,
      merkle_path: [brokenFirst, p.merkle_path[1]],
    }
    const res = verifyAttributionProjection(tampered, issuerPublicKey)
    assert.deepEqual(res, { valid: false, reason: 'MERKLE_MISMATCH' })
  })

  it('returns SIGNATURE_INVALID when merkle_root and path are both tampered consistently but the signature was over the original root', () => {
    const { primitive, issuerPublicKey } = buildPrimitive()
    const p = projectAttribution(primitive, 'G')
    // Rebuild the tree with different axis content, take the new path + root
    // and graft the old signature: signature verification must fail because
    // the envelope changed.
    const alt: AttributionAxes = {
      ...primitive.axes,
      G: [
        ...primitive.axes.G,
        { delegation_id: 'extra', signer_did: 'did:aps:extra', scope_hash: '9'.repeat(64), depth: 3 },
      ],
    }
    const altFrame = buildMerkleFrame(alt)
    const altPath = projectionPath(altFrame, 'G')
    const tampered: AttributionProjection = {
      ...p,
      axis_data: altFrame.axes.G,
      merkle_path: altPath,
      merkle_root: altFrame.root.toString('hex'),
    }
    const res = verifyAttributionProjection(tampered, issuerPublicKey)
    assert.deepEqual(res, { valid: false, reason: 'SIGNATURE_INVALID' })
  })

  it('returns MALFORMED when the path is not length two', () => {
    const { primitive, issuerPublicKey } = buildPrimitive()
    const p = projectAttribution(primitive, 'C')
    const tampered = { ...p, merkle_path: [p.merkle_path[0]] as unknown as [string, string] }
    const res = verifyAttributionProjection(tampered as AttributionProjection, issuerPublicKey)
    assert.deepEqual(res, { valid: false, reason: 'MALFORMED' })
  })

  it('returns INVALID_AXIS_TAG for an unknown axis', () => {
    const { primitive, issuerPublicKey } = buildPrimitive()
    const p = projectAttribution(primitive, 'D')
    const tampered = { ...p, axis_tag: 'X' as unknown as AttributionProjection['axis_tag'] }
    const res = verifyAttributionProjection(tampered as AttributionProjection, issuerPublicKey)
    assert.deepEqual(res, { valid: false, reason: 'INVALID_AXIS_TAG' })
  })

  it('verifyAttributionPrimitive checks all four axes', () => {
    const { primitive, issuerPublicKey } = buildPrimitive()
    const res = verifyAttributionPrimitive(primitive, issuerPublicKey)
    assert.deepEqual(res, { valid: true })
  })

  it('verifyAttributionPrimitive fails when the signature is mutated', () => {
    const { primitive, issuerPublicKey } = buildPrimitive()
    const corrupt = {
      ...primitive,
      signature: primitive.signature.replace(/^./, (c) => (c === '0' ? '1' : '0')),
    }
    const res = verifyAttributionPrimitive(corrupt, issuerPublicKey)
    assert.equal(res.valid, false)
  })
})

// ─────────────────────────────────────────────────────────────
// Cross-projection consistency §2.4
// ─────────────────────────────────────────────────────────────

describe('checkProjectionConsistency §2.4', () => {
  it('marks projections of the same receipt as SAME_RECEIPT', () => {
    const { primitive } = buildPrimitive()
    const pd = projectAttribution(primitive, 'D')
    const pc = projectAttribution(primitive, 'C')
    const res = checkProjectionConsistency(pd, pc)
    assert.deepEqual(res, { same_receipt: true })
  })

  it('marks projections of different actions as DIFFERENT_ACTIONS', () => {
    const { primitive: p1 } = buildPrimitive()
    const { issuer, issuerPrivateKey } = issuerFixture()
    const p2 = constructAttributionPrimitive({
      action: demoAction({ nonce: 'different-nonce' }),
      axes: demoAxes(),
      issuer,
      issuerPrivateKey,
    })
    const pa = projectAttribution(p1, 'D')
    const pb = projectAttribution(p2, 'D')
    const res = checkProjectionConsistency(pa, pb)
    assert.deepEqual(res, { same_receipt: false, reason: 'DIFFERENT_ACTIONS' })
  })

  it('marks same-action different-receipts as DIFFERENT_RECEIPTS', () => {
    const { issuer, issuerPrivateKey } = issuerFixture()
    const action = demoAction()
    const base = demoAxes()
    const p1 = constructAttributionPrimitive({ action, axes: base, issuer, issuerPrivateKey, timestamp: '2026-04-12T17:42:08.342Z' })
    const altAxes: AttributionAxes = {
      ...base,
      D: [
        ...base.D,
        { source_did: 'did:data:extra', contribution_weight: '0.000500', access_receipt_hash: 'f'.repeat(64) },
      ],
    }
    const p2 = constructAttributionPrimitive({ action, axes: altAxes, issuer, issuerPrivateKey, timestamp: '2026-04-12T17:42:08.342Z' })
    const res = checkProjectionConsistency(projectAttribution(p1, 'D'), projectAttribution(p2, 'D'))
    assert.equal(res.same_receipt, false)
    if (!res.same_receipt) {
      // Different receipts (axes differ) → roots differ → DIFFERENT_RECEIPTS
      assert.equal(res.reason, 'DIFFERENT_RECEIPTS')
    }
  })

  it('marks same-root-different-signature projections as DIFFERENT_SIGNATURES', () => {
    const { primitive } = buildPrimitive()
    const p = projectAttribution(primitive, 'D')
    const tamperedSig = p.signature.replace(/^./, (c) => (c === '0' ? '1' : '0'))
    const p2 = { ...p, signature: tamperedSig }
    const res = checkProjectionConsistency(p, p2)
    assert.deepEqual(res, { same_receipt: false, reason: 'DIFFERENT_SIGNATURES' })
  })

  it('marks same-root-different-issuer projections as METADATA_MISMATCH', () => {
    const { primitive } = buildPrimitive()
    const p = projectAttribution(primitive, 'D')
    const p2 = { ...p, issuer: 'did:aps:other-issuer' }
    const res = checkProjectionConsistency(p, p2)
    assert.deepEqual(res, { same_receipt: false, reason: 'METADATA_MISMATCH' })
  })
})

// ─────────────────────────────────────────────────────────────
// Resigning §2.7
// ─────────────────────────────────────────────────────────────

describe('resignAttributionPrimitive', () => {
  it('produces a verifiable primitive when axes or action are replaced', () => {
    const { primitive, issuer, issuerPublicKey, issuerPrivateKey } = buildPrimitive()
    const axes: AttributionAxes = {
      ...primitive.axes,
      P: primitive.axes.P.map((m, i) => (i === 0 ? { ...(m as ProtocolAxisEntry), weight: '0.100000' } : m)),
    }
    const resigned = resignAttributionPrimitive(primitive, issuerPrivateKey, {
      axes,
      timestamp: '2026-04-12T17:42:09.000Z',
    })
    assert.equal(resigned.issuer, issuer)
    assert.notEqual(resigned.merkle_root, primitive.merkle_root)
    const res = verifyAttributionPrimitive(resigned, issuerPublicKey)
    assert.deepEqual(res, { valid: true })
  })
})
