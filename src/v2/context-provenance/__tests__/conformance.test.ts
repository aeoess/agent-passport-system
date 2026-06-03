// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// CPA v0.1: full VERIFIER CONFORMANCE, both disclosure modes
// ══════════════════════════════════════════════════════════════════
// A matrix of VALID CPAs through verifyCPA, asserting valid:true with the
// correct completeness:
//   full-set  (single leaf, multi leaf, all 8 channels, empty tree) -> PROVEN
//   inclusion (count-only, and disclosed-subset-with-proofs)        -> NOT_PROVEN
// Plus the mutual-binding positive path (a receipt carrying matching
// action_ref + cpa_ref -> valid) and round-trip stability (re-canonicalize,
// re-verify). This is positive conformance; the adversarial fail-closed
// matrix lives in adversarial.test.ts.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

import { publicKeyFromPrivate } from '../../../crypto/keys.js'
import { hexToMultibase } from '../../../core/did.js'
import type { RotatableDIDDocument } from '../../../types/passport.js'
import { canonicalizeJCS } from '../../../core/canonical-jcs.js'

import { buildCPA, computeCpaRef, carryCpaRef, verifyCPA } from '../index.js'
import type {
  ContextItem,
  ContextChannel,
  ContextProvenanceAttestation,
  CpaVerifyResult,
} from '../index.js'

// ── Deterministic key material + DID document ──────────────────────
const PRIV = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
const PUB = publicKeyFromPrivate(PRIV)
const PRODUCER_DID = `did:aps:${hexToMultibase(PUB)}`
const ATTESTED_AT = '2026-06-03T12:00:00Z'

function sha256Hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}
const ACTION_REF = sha256Hex('cpa.conformance.action.001')

function makeDIDDoc(pubHex: string, did: string): RotatableDIDDocument {
  const keyId = `${did}#key-1`
  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
    ],
    id: did,
    controller: did,
    verificationMethod: [
      { id: keyId, type: 'Ed25519VerificationKey2020', controller: did, publicKeyMultibase: hexToMultibase(pubHex) },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
    capabilityDelegation: [keyId],
    rotationLog: [],
    created: '2026-01-01T00:00:00Z',
    updated: '2026-01-01T00:00:00Z',
  } as RotatableDIDDocument
}
const DID_DOC = makeDIDDoc(PUB, PRODUCER_DID)

function item(channel: ContextChannel, ctx_id: string, body: string): ContextItem {
  const bytes = Buffer.from(body, 'utf8')
  return { ctx_id, channel, content_ref: sha256Hex(body), byte_len: bytes.byteLength, content: bytes.toString('base64') }
}

function build(mode: 'full-set' | 'inclusion', items: ContextItem[], disclose?: string[]): ContextProvenanceAttestation {
  return buildCPA({ privateKey: PRIV, action_ref: ACTION_REF, producer_did: PRODUCER_DID, attested_at: ATTESTED_AT, mode, items, disclose })
}

function expectValid(result: CpaVerifyResult, completeness: 'PROVEN' | 'NOT_PROVEN'): void {
  assert.deepEqual(result.reasons, [])
  assert.equal(result.valid, true)
  assert.equal(result.completeness, completeness)
}

// ── Item sets ──────────────────────────────────────────────────────
const SINGLE_LEAF: ContextItem[] = [item('system-config', 'sc-001', 'only system')]
const MULTI_LEAF: ContextItem[] = [
  item('developer', 'dev-005', 'epsilon'),
  item('developer', 'dev-003', 'gamma'),
  item('developer', 'dev-001', 'alpha'),
  item('developer', 'dev-004', 'delta'),
  item('developer', 'dev-002', 'beta'),
]
const ALL_EIGHT: ContextItem[] = [
  item('system-config', 'sc-1', 'sys'),
  item('developer', 'dev-1', 'dev'),
  item('user-socket', 'us-1', 'user'),
  item('retrieval-store', 'rs-1', 'rag'),
  item('tool-result', 'tr-1', 'tool'),
  item('external', 'ext-1', 'ext'),
  item('memory', 'mem-1', 'mem'),
  item('quarantine', 'q-1', 'quar'),
]

// ══════════════════════════════════════════════════════════════════
// FULL-SET conformance -> valid, PROVEN
// ══════════════════════════════════════════════════════════════════
describe('CPA conformance: full-set -> PROVEN', () => {
  it('single-leaf full-set verifies valid + PROVEN', () => {
    expectValid(verifyCPA(build('full-set', SINGLE_LEAF), DID_DOC), 'PROVEN')
  })

  it('multi-leaf single-partition full-set verifies valid + PROVEN', () => {
    const cpa = build('full-set', MULTI_LEAF)
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    assert.equal(dev.leaf_count, 5)
    assert.equal(dev.leaves!.length, 5)
    expectValid(verifyCPA(cpa, DID_DOC), 'PROVEN')
  })

  it('all-eight-channels full-set verifies valid + PROVEN', () => {
    const cpa = build('full-set', ALL_EIGHT)
    assert.equal(cpa.partitions.length, 8)
    // partitions are present in CHANNEL_ORDER, every leaf disclosed.
    assert.deepEqual(cpa.partitions.map(p => p.channel), [
      'system-config', 'developer', 'user-socket', 'retrieval-store',
      'tool-result', 'external', 'memory', 'quarantine',
    ])
    for (const p of cpa.partitions) {
      assert.equal(p.leaf_count, 1)
      assert.equal(p.leaves!.length, 1)
      assert.equal(p.context_profile, undefined)
    }
    expectValid(verifyCPA(cpa, DID_DOC), 'PROVEN')
  })

  it('empty-tree full-set verifies valid + PROVEN (sentinel root)', () => {
    const cpa = build('full-set', [])
    assert.deepEqual(cpa.partitions, [])
    expectValid(verifyCPA(cpa, DID_DOC), 'PROVEN')
  })
})

// ══════════════════════════════════════════════════════════════════
// INCLUSION conformance -> valid, NOT_PROVEN
// ══════════════════════════════════════════════════════════════════
describe('CPA conformance: inclusion -> NOT_PROVEN', () => {
  it('count-only inclusion verifies valid + NOT_PROVEN', () => {
    const cpa = build('inclusion', ALL_EIGHT)
    for (const p of cpa.partitions) {
      assert.ok(p.context_profile)
      assert.equal(p.context_profile!.hidden_leaf_count, p.leaf_count)
      assert.equal(p.leaves, undefined)
      assert.equal(p.inclusion_proofs, undefined)
    }
    expectValid(verifyCPA(cpa, DID_DOC), 'NOT_PROVEN')
  })

  it('disclosed-subset-with-proofs inclusion verifies valid + NOT_PROVEN', () => {
    // Disclose two of the five developer leaves; verifier checks each
    // disclosed leaf carries a proof folding to the declared partition_root.
    const cpa = build('inclusion', MULTI_LEAF, ['dev-002', 'dev-004'])
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    assert.equal(dev.leaf_count, 5)
    assert.equal(dev.leaves!.length, 2)
    assert.equal(dev.inclusion_proofs!.length, 2)
    assert.equal(dev.context_profile!.hidden_leaf_count, 3)
    // disclosed leaves are emitted in ctx_id sort order
    assert.deepEqual(dev.leaves!.map(l => l.ctx_id), ['dev-002', 'dev-004'])
    expectValid(verifyCPA(cpa, DID_DOC), 'NOT_PROVEN')
  })

  it('disclosed-subset across multiple channels verifies valid + NOT_PROVEN', () => {
    const items = [...MULTI_LEAF, item('tool-result', 'tr-001', 'tool one'), item('tool-result', 'tr-002', 'tool two')]
    const cpa = build('inclusion', items, ['dev-001', 'tr-002'])
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    const tr = cpa.partitions.find(p => p.channel === 'tool-result')!
    assert.equal(dev.leaves!.length, 1)
    assert.equal(tr.leaves!.length, 1)
    expectValid(verifyCPA(cpa, DID_DOC), 'NOT_PROVEN')
  })
})

// ══════════════════════════════════════════════════════════════════
// Mutual-binding positive path
// ══════════════════════════════════════════════════════════════════
describe('CPA conformance: mutual binding positive path', () => {
  it('a receipt carrying matching action_ref + cpa_ref verifies valid', () => {
    const cpa = build('full-set', ALL_EIGHT)
    const { cpa_ref } = carryCpaRef(cpa)
    assert.equal(cpa_ref, computeCpaRef(cpa))
    const receipt = { action_ref: ACTION_REF, cpa_ref }
    expectValid(verifyCPA(cpa, DID_DOC, receipt), 'PROVEN')
  })

  it('a receipt carrying only a matching cpa_ref verifies valid', () => {
    const cpa = build('full-set', SINGLE_LEAF)
    expectValid(verifyCPA(cpa, DID_DOC, { cpa_ref: computeCpaRef(cpa) }), 'PROVEN')
  })

  it('a receipt carrying only a matching action_ref verifies valid', () => {
    const cpa = build('inclusion', MULTI_LEAF)
    expectValid(verifyCPA(cpa, DID_DOC, { action_ref: ACTION_REF }), 'NOT_PROVEN')
  })
})

// ══════════════════════════════════════════════════════════════════
// Round-trip stability (re-canonicalize, re-verify)
// ══════════════════════════════════════════════════════════════════
describe('CPA conformance: round-trip stability', () => {
  it('serialize -> JSON.parse -> verify reproduces the same verdict', () => {
    for (const [mode, items, completeness] of [
      ['full-set', ALL_EIGHT, 'PROVEN'],
      ['inclusion', MULTI_LEAF, 'NOT_PROVEN'],
    ] as const) {
      const cpa = build(mode, items)
      const roundTripped = JSON.parse(JSON.stringify(cpa)) as ContextProvenanceAttestation
      // canonical bytes survive a serialize/parse round trip
      assert.equal(canonicalizeJCS(roundTripped), canonicalizeJCS(cpa))
      expectValid(verifyCPA(roundTripped, DID_DOC), completeness)
    }
  })

  it('cpa_ref is stable across a serialize/parse round trip', () => {
    const cpa = build('full-set', ALL_EIGHT)
    const roundTripped = JSON.parse(JSON.stringify(cpa)) as ContextProvenanceAttestation
    assert.equal(computeCpaRef(roundTripped), computeCpaRef(cpa))
  })
})
