// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// CPA v0.1: Phase 0 round-trip tests
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

import { publicKeyFromPrivate } from '../../../crypto/keys.js'
import { hexToMultibase } from '../../../core/did.js'
import type { RotatableDIDDocument } from '../../../types/passport.js'

import {
  buildCPA,
  computeCpaRef,
  verifyCPA,
  CHANNEL_ORDER,
  emptyTreeRoot,
} from '../index.js'
import type { ContextItem, ContextProvenanceAttestation } from '../index.js'
import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { verify } from '../../../crypto/keys.js'

// ── Deterministic key material ─────────────────────────────────────
// Fixed 32-byte seed (64-hex). priv = seed; pub derived from priv.
const PRIV = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
const PUB = publicKeyFromPrivate(PRIV)
const PRODUCER_DID = `did:aps:${hexToMultibase(PUB)}`

const ATTESTED_AT = '2026-06-03T12:00:00Z'

function sha256Hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

/**
 * Minimal RotatableDIDDocument whose single verificationMethod carries
 * PUB as multibase, with the key id in authentication and an empty
 * rotationLog. This is the exact shape isKeyActive checks:
 *   - vm.publicKeyMultibase === hexToMultibase(PUB)
 *   - no retiredAt
 *   - authentication.includes(vm.id)
 * and verifyRotationChain returns true on an empty rotationLog.
 */
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
      {
        id: keyId,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase: hexToMultibase(pubHex),
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
    capabilityDelegation: [keyId],
    rotationLog: [],
    created: '2026-01-01T00:00:00Z',
    updated: '2026-01-01T00:00:00Z',
  }
}

const DID_DOC = makeDIDDoc(PUB, PRODUCER_DID)
const ACTION_REF = sha256Hex('cpa.action.request.001')

function item(channel: ContextItem['channel'], ctx_id: string, body: string): ContextItem {
  const bytes = Buffer.from(body, 'utf8')
  return {
    ctx_id,
    channel,
    content_ref: sha256Hex(body),
    byte_len: bytes.byteLength,
    content: bytes.toString('base64'),
  }
}

// A handful of items across 3+ channels:
//   system-config: single-leaf partition
//   developer:     multi-leaf partition (3 leaves, out of ctx_id order)
//   tool-result:   multi-leaf partition (2 leaves)
function sampleItems(): ContextItem[] {
  return [
    item('system-config', 'sc-001', 'system prompt v3'),
    item('developer', 'dev-003', 'dev instruction gamma'),
    item('developer', 'dev-001', 'dev instruction alpha'),
    item('developer', 'dev-002', 'dev instruction beta'),
    item('tool-result', 'tr-002', 'tool output two'),
    item('tool-result', 'tr-001', 'tool output one'),
  ]
}

// ── (a) full-set build + verify => valid, PROVEN ───────────────────

describe('CPA: full-set round-trip', () => {
  it('builds, signs, and verifies a full-set CPA across 3+ channels (single + multi-leaf)', () => {
    const cpa = buildCPA({
      privateKey: PRIV,
      action_ref: ACTION_REF,
      producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT,
      mode: 'full-set',
      items: sampleItems(),
    })

    assert.equal(cpa.version, 'cpa/0.1')
    assert.equal(cpa.producer_pubkey, PUB)
    assert.equal(cpa.signature.length, 128)
    assert.equal(cpa.mode, 'full-set')

    // present partitions sorted by CHANNEL_ORDER
    const channels = cpa.partitions.map(p => p.channel)
    assert.deepEqual(channels, ['system-config', 'developer', 'tool-result'])

    // single-leaf partition present, multi-leaf present
    const sc = cpa.partitions.find(p => p.channel === 'system-config')!
    assert.equal(sc.leaf_count, 1)
    assert.equal(sc.leaves!.length, 1)
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    assert.equal(dev.leaf_count, 3)
    // full-set partitions carry no context_profile
    assert.equal(sc.context_profile, undefined)
    assert.equal(dev.context_profile, undefined)

    const result = verifyCPA(cpa, DID_DOC)
    assert.deepEqual(result.reasons, [])
    assert.equal(result.valid, true)
    assert.equal(result.completeness, 'PROVEN')
  })

  it('inclusion-mode CPA verifies valid with completeness NOT_PROVEN', () => {
    const cpa = buildCPA({
      privateKey: PRIV,
      action_ref: ACTION_REF,
      producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT,
      mode: 'inclusion',
      items: sampleItems(),
    })
    // Phase 0 inclusion: count-only profiles, hidden_leaf_count = leaf_count
    for (const p of cpa.partitions) {
      assert.ok(p.context_profile, 'inclusion partition must carry context_profile')
      assert.equal(p.context_profile!.hidden_leaf_count, p.leaf_count)
      assert.equal(p.leaves, undefined)
    }
    const result = verifyCPA(cpa, DID_DOC)
    assert.deepEqual(result.reasons, [])
    assert.equal(result.valid, true)
    assert.equal(result.completeness, 'NOT_PROVEN')
  })
})

// ── (b) signature is stable under re-canonicalization ──────────────

describe('CPA: signature stability', () => {
  it('re-canonicalizing the signed object and re-verifying the signature holds', () => {
    const cpa = buildCPA({
      privateKey: PRIV,
      action_ref: ACTION_REF,
      producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT,
      mode: 'full-set',
      items: sampleItems(),
    })
    const bytes = canonicalizeJCS({ ...cpa, signature: '' })
    assert.equal(verify(bytes, cpa.signature, cpa.producer_pubkey), true)

    // Reorder top-level keys; canonical bytes must be identical.
    const reordered = {
      signature: cpa.signature,
      root: cpa.root,
      partitions: cpa.partitions,
      mode: cpa.mode,
      attested_at: cpa.attested_at,
      producer_pubkey: cpa.producer_pubkey,
      producer_did: cpa.producer_did,
      action_ref: cpa.action_ref,
      version: cpa.version,
    } as ContextProvenanceAttestation
    const bytes2 = canonicalizeJCS({ ...reordered, signature: '' })
    assert.equal(bytes2, bytes)
    assert.equal(verify(bytes2, reordered.signature, reordered.producer_pubkey), true)
  })
})

// ── (c) computeCpaRef is deterministic ─────────────────────────────

describe('CPA: cpa_ref determinism', () => {
  it('computeCpaRef returns the same 64-hex on two calls over the same signed object', () => {
    const cpa = buildCPA({
      privateKey: PRIV,
      action_ref: ACTION_REF,
      producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT,
      mode: 'full-set',
      items: sampleItems(),
    })
    const ref1 = computeCpaRef(cpa)
    const ref2 = computeCpaRef(cpa)
    assert.equal(ref1, ref2)
    assert.match(ref1, /^[0-9a-f]{64}$/)
  })
})

// ── (d) empty-tree CPA builds and verifies ─────────────────────────

describe('CPA: empty tree', () => {
  it('builds and verifies a CPA with zero items (empty-tree sentinel root)', () => {
    const cpa = buildCPA({
      privateKey: PRIV,
      action_ref: ACTION_REF,
      producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT,
      mode: 'full-set',
      items: [],
    })
    assert.deepEqual(cpa.partitions, [])
    assert.equal(cpa.root, emptyTreeRoot())

    const result = verifyCPA(cpa, DID_DOC)
    assert.deepEqual(result.reasons, [])
    assert.equal(result.valid, true)
    assert.equal(result.completeness, 'PROVEN')
  })
})

// ── (e) tamper detection ───────────────────────────────────────────

describe('CPA: tamper detection', () => {
  it('a tampered top root yields valid:false', () => {
    const cpa = buildCPA({
      privateKey: PRIV,
      action_ref: ACTION_REF,
      producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT,
      mode: 'full-set',
      items: sampleItems(),
    })
    const last = cpa.root.slice(-1)
    const flipped = last === '0' ? '1' : '0'
    const tampered = { ...cpa, root: cpa.root.slice(0, -1) + flipped } as ContextProvenanceAttestation

    const result = verifyCPA(tampered, DID_DOC)
    assert.equal(result.valid, false)
    // Mutating root breaks the signature (signed bytes include root) AND
    // breaks top-root recompute. Both reasons are fail-closed signals.
    assert.ok(result.reasons.includes('SIGNATURE_INVALID'))
    assert.ok(result.reasons.includes('ROOT_MISMATCH'))
  })

  it('a tampered signature yields valid:false with SIGNATURE_INVALID', () => {
    const cpa = buildCPA({
      privateKey: PRIV,
      action_ref: ACTION_REF,
      producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT,
      mode: 'full-set',
      items: sampleItems(),
    })
    const last = cpa.signature.slice(-1)
    const flipped = last === '0' ? '1' : '0'
    const tampered = { ...cpa, signature: cpa.signature.slice(0, -1) + flipped } as ContextProvenanceAttestation

    const result = verifyCPA(tampered, DID_DOC)
    assert.equal(result.valid, false)
    assert.ok(result.reasons.includes('SIGNATURE_INVALID'))
  })

  it('a tampered leaf content_ref breaks partition_root recompute and the signature', () => {
    const cpa = buildCPA({
      privateKey: PRIV,
      action_ref: ACTION_REF,
      producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT,
      mode: 'full-set',
      items: sampleItems(),
    })
    // Flip a byte of a disclosed leaf's content_ref WITHOUT touching the
    // partition_root: the recompute must catch the divergence.
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    const leaf0 = dev.leaves![0]
    const last = leaf0.content_ref.slice(-1)
    const flipped = last === '0' ? '1' : '0'
    const tamperedLeaf = { ...leaf0, content_ref: leaf0.content_ref.slice(0, -1) + flipped }
    const tamperedDev = { ...dev, leaves: [tamperedLeaf, ...dev.leaves!.slice(1)] }
    const tampered = {
      ...cpa,
      partitions: cpa.partitions.map(p => (p.channel === 'developer' ? tamperedDev : p)),
    } as ContextProvenanceAttestation

    const result = verifyCPA(tampered, DID_DOC)
    assert.equal(result.valid, false)
    assert.ok(result.reasons.includes('SIGNATURE_INVALID'))
    assert.ok(result.reasons.includes('PARTITION_ROOT_MISMATCH'))
  })
})

// ── sanity: CHANNEL_ORDER exported and length 8 ────────────────────

describe('CPA: channel constant', () => {
  it('CHANNEL_ORDER has the 8 frozen channels', () => {
    assert.equal(CHANNEL_ORDER.length, 8)
    assert.equal(CHANNEL_ORDER[0], 'system-config')
    assert.equal(CHANNEL_ORDER[7], 'quarantine')
  })
})
