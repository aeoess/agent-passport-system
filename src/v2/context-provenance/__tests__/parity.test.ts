// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// CPA v0.1: single-implementation PARITY ORACLE
// ══════════════════════════════════════════════════════════════════
// HONESTY CAVEAT (read this before trusting the result):
//
//   Same-language parity over a SHARED JCS primitive proves the Merkle /
//   assembly / verifier logic is independently reproducible and agrees; it
//   does NOT prove the canonicalization is RFC-8785-correct (that is what
//   the section-1 known-answer vectors in known-answer.test.ts are for),
//   and it is NOT a true second-implementation cross-language parity (a Go
//   port is a deferred fast-follow).
//
// What THIS file does: it reimplements the CPA producer INLINE, from the
// frozen TREE-SHAPE.md, WITHOUT importing merkle.ts or cpa.ts. It MAY (and
// does) reuse the shared canonicalizeJCS and the shared sign/
// publicKeyFromPrivate, plus node:crypto directly. For several fixed inputs
// it asserts the independent build is BYTE/HEX-IDENTICAL to the producer's
// buildCPA (root, every partition_root, canonicalizeJCS(signedCpa),
// signature, computeCpaRef), and that the producer's verifyCPA accepts the
// independently-built CPA. Because the JCS primitive is shared, this oracle
// isolates and exercises the Merkle/assembly/binding logic, not the
// canonicalizer. The canonicalizer is gated separately and only by the
// hand-derived known-answer vectors.
// ══════════════════════════════════════════════════════════════════

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

// Shared primitives ONLY (allowed): canonicalizer + signer + pubkey.
import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { sign, publicKeyFromPrivate } from '../../../crypto/keys.js'
import { hexToMultibase } from '../../../core/did.js'
import type { RotatableDIDDocument } from '../../../types/passport.js'

// Producer-under-test (the only allowed import from the module's CPA code).
import { buildCPA, computeCpaRef } from '../cpa.js'
import { verifyCPA } from '../verify.js'
import type {
  ContextItem,
  ContextChannel,
  DisclosureMode,
  ContextProvenanceAttestation,
} from '../types.js'

// ══════════════════════════════════════════════════════════════════
// INDEPENDENT REIMPLEMENTATION (frozen TREE-SHAPE.md; no merkle.ts / cpa.ts)
// ══════════════════════════════════════════════════════════════════

// Frozen domain tags (re-pinned here, NOT imported from merkle.ts).
const REF_LEAF_TAG = 'CPA:v0.1:leaf\n'
const REF_NODE_TAG = 'CPA:v0.1:node\n'
const REF_SIGN_TAG = 'CPA:v0.1:sign\n'
const REF_EMPTY_SENTINEL = 'EMPTY'

// Frozen channel order (re-pinned here, NOT imported from types.ts).
const REF_CHANNEL_ORDER: readonly ContextChannel[] = [
  'system-config',
  'developer',
  'user-socket',
  'retrieval-store',
  'tool-result',
  'external',
  'memory',
  'quarantine',
]

function refUtf8(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

function refSha256(...parts: Uint8Array[]): Uint8Array {
  const h = createHash('sha256')
  for (const p of parts) h.update(p)
  return new Uint8Array(h.digest())
}

function refHex(b: Uint8Array): string {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')
}

// leaf_hash = sha256( utf8(LEAF_TAG) || utf8(JCS({byte_len,channel,content_ref,ctx_id})) )
function refLeafHash(leaf: ContextItem): Uint8Array {
  const preimage = {
    byte_len: leaf.byte_len,
    channel: leaf.channel,
    content_ref: leaf.content_ref,
    ctx_id: leaf.ctx_id,
  }
  return refSha256(refUtf8(REF_LEAF_TAG), refUtf8(canonicalizeJCS(preimage)))
}

// node_hash = sha256( utf8(NODE_TAG) || left32 || right32 ) over RAW bytes.
function refNodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return refSha256(refUtf8(REF_NODE_TAG), left, right)
}

// Bottom-up reduction with RFC-6962 odd promotion (no duplication).
function refReduce(level: Uint8Array[]): Uint8Array {
  if (level.length === 0) throw new Error('ref: empty level')
  let cur = level
  while (cur.length > 1) {
    const next: Uint8Array[] = []
    for (let i = 0; i < cur.length; i += 2) {
      if (i + 1 < cur.length) next.push(refNodeHash(cur[i], cur[i + 1]))
      else next.push(cur[i]) // promote odd node unchanged
    }
    cur = next
  }
  return cur[0]
}

// partition_root over ctx_id-sorted leaves.
function refPartitionRootBytes(leaves: ContextItem[]): Uint8Array {
  if (leaves.length === 0) throw new Error('ref: empty partition')
  const sorted = [...leaves].sort((a, b) =>
    a.ctx_id < b.ctx_id ? -1 : a.ctx_id > b.ctx_id ? 1 : 0,
  )
  return refReduce(sorted.map(refLeafHash))
}

// top root over partition roots in CHANNEL_ORDER, with empty-tree sentinel.
function refTopRootBytes(partitionRoots: Uint8Array[]): Uint8Array {
  if (partitionRoots.length === 0) {
    return refSha256(refUtf8(REF_NODE_TAG), refUtf8(REF_EMPTY_SENTINEL))
  }
  return refReduce(partitionRoots)
}

interface RefBuildInput {
  privateKey: string
  action_ref: string
  producer_did: string
  attested_at: string
  mode: DisclosureMode
  items: ContextItem[]
}

// Independent full-set / count-only inclusion producer (Phase-0 inclusion:
// count-only, no disclosed subset, which is what these fixtures exercise).
function refBuildCPA(input: RefBuildInput): ContextProvenanceAttestation {
  const byChannel = new Map<ContextChannel, ContextItem[]>()
  for (const it of input.items) {
    const b = byChannel.get(it.channel)
    if (b) b.push(it)
    else byChannel.set(it.channel, [it])
  }

  const partitions: ContextProvenanceAttestation['partitions'] = []
  const partitionRootBytes: Uint8Array[] = []

  for (const channel of REF_CHANNEL_ORDER) {
    const leaves = byChannel.get(channel)
    if (!leaves || leaves.length === 0) continue
    const rootBytes = refPartitionRootBytes(leaves)
    partitionRootBytes.push(rootBytes)
    const partition_root = refHex(rootBytes)
    const leaf_count = leaves.length

    if (input.mode === 'full-set') {
      partitions.push({ channel, partition_root, leaf_count, leaves: [...leaves] })
    } else {
      partitions.push({
        channel,
        partition_root,
        leaf_count,
        context_profile: { channel, hidden_leaf_count: leaf_count },
      })
    }
  }

  const root = refHex(refTopRootBytes(partitionRootBytes))
  const producer_pubkey = publicKeyFromPrivate(input.privateKey)

  const unsigned = {
    version: 'cpa/0.1' as const,
    action_ref: input.action_ref,
    producer_did: input.producer_did,
    producer_pubkey,
    attested_at: input.attested_at,
    mode: input.mode,
    partitions,
    root,
    signature: '' as const,
  }
  const signature = sign(canonicalizeJCS(unsigned), input.privateKey)
  return { ...unsigned, signature }
}

// cpa_ref = sha256( utf8(SIGN_TAG) || utf8(JCS(signedCpa)) )
function refComputeCpaRef(signed: ContextProvenanceAttestation): string {
  return refHex(refSha256(refUtf8(REF_SIGN_TAG), refUtf8(canonicalizeJCS(signed))))
}

// ══════════════════════════════════════════════════════════════════
// Fixtures + DID document for verifyCPA acceptance
// ══════════════════════════════════════════════════════════════════

const PRIV = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'
const PUB = publicKeyFromPrivate(PRIV)
const PRODUCER_DID = `did:aps:${hexToMultibase(PUB)}`
const ATTESTED_AT = '2026-06-03T12:00:00Z'

function sha256Hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}
const ACTION_REF = sha256Hex('cpa.parity.action.001')

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

// Named fixtures: single-leaf, multi-leaf, multiple channels, empty tree.
const FIXTURES: Record<string, ContextItem[]> = {
  'single-leaf': [item('system-config', 'sc-001', 'only one')],
  'multi-leaf-one-channel': [
    item('developer', 'dev-003', 'gamma'),
    item('developer', 'dev-001', 'alpha'),
    item('developer', 'dev-002', 'beta'),
  ],
  'multiple-channels': [
    item('system-config', 'sc-001', 'system prompt'),
    item('developer', 'dev-002', 'dev beta'),
    item('developer', 'dev-001', 'dev alpha'),
    item('tool-result', 'tr-001', 'tool one'),
    item('tool-result', 'tr-002', 'tool two'),
    item('external', 'ext-001', 'external blob'),
    item('quarantine', 'q-001', 'quarantined'),
  ],
  'all-eight-channels': [
    item('system-config', 'sc-1', 'a'),
    item('developer', 'dev-1', 'b'),
    item('user-socket', 'us-1', 'c'),
    item('retrieval-store', 'rs-1', 'd'),
    item('tool-result', 'tr-1', 'e'),
    item('external', 'ext-1', 'f'),
    item('memory', 'mem-1', 'g'),
    item('quarantine', 'q-1', 'h'),
  ],
  'empty-tree': [],
}

function assertBytewiseIdentical(
  label: string,
  ref: ContextProvenanceAttestation,
  prod: ContextProvenanceAttestation,
): void {
  // Identical top root.
  assert.equal(ref.root, prod.root, `${label}: root`)
  // Identical per-partition roots, channels, counts (and the partition list
  // is in the same CHANNEL_ORDER, so index-aligned comparison is valid).
  assert.equal(ref.partitions.length, prod.partitions.length, `${label}: partition count`)
  for (let i = 0; i < ref.partitions.length; i++) {
    assert.equal(ref.partitions[i].channel, prod.partitions[i].channel, `${label}: partition[${i}].channel`)
    assert.equal(ref.partitions[i].partition_root, prod.partitions[i].partition_root, `${label}: partition[${i}].partition_root`)
    assert.equal(ref.partitions[i].leaf_count, prod.partitions[i].leaf_count, `${label}: partition[${i}].leaf_count`)
  }
  // Identical canonical bytes of the fully signed object.
  assert.equal(canonicalizeJCS(ref), canonicalizeJCS(prod), `${label}: JCS(signedCpa)`)
  // Identical signature hex (Ed25519 over identical canonical bytes).
  assert.equal(ref.signature, prod.signature, `${label}: signature`)
  // Identical content address; cross-check both computeCpaRef impls too.
  assert.equal(refComputeCpaRef(ref), computeCpaRef(prod), `${label}: cpa_ref ref-vs-prod`)
  assert.equal(computeCpaRef(ref), computeCpaRef(prod), `${label}: cpa_ref prod-of-both`)
}

for (const [label, items] of Object.entries(FIXTURES)) {
  for (const mode of ['full-set', 'inclusion'] as DisclosureMode[]) {
    test(`parity: independent build == producer buildCPA [${label} / ${mode}]`, () => {
      const common = {
        privateKey: PRIV,
        action_ref: ACTION_REF,
        producer_did: PRODUCER_DID,
        attested_at: ATTESTED_AT,
        mode,
        items,
      }
      const ref = refBuildCPA(common)
      const prod = buildCPA(common)
      assertBytewiseIdentical(`${label}/${mode}`, ref, prod)

      // The producer's verifier accepts the INDEPENDENTLY-built CPA.
      const result = verifyCPA(ref, DID_DOC)
      assert.deepEqual(result.reasons, [], `${label}/${mode}: verify reasons`)
      assert.equal(result.valid, true, `${label}/${mode}: verify valid`)
      assert.equal(
        result.completeness,
        mode === 'full-set' ? 'PROVEN' : 'NOT_PROVEN',
        `${label}/${mode}: completeness`,
      )
    })
  }
}

// Explicit empty-tree byte pin: both producers must emit partitions:[] and
// the frozen empty sentinel root.
test('parity: empty tree emits the frozen sentinel root in both builders', () => {
  const common = {
    privateKey: PRIV, action_ref: ACTION_REF, producer_did: PRODUCER_DID,
    attested_at: ATTESTED_AT, mode: 'full-set' as DisclosureMode, items: [] as ContextItem[],
  }
  const ref = refBuildCPA(common)
  const prod = buildCPA(common)
  const sentinel = refHex(refSha256(refUtf8(REF_NODE_TAG), refUtf8(REF_EMPTY_SENTINEL)))
  assert.deepEqual(ref.partitions, [])
  assert.deepEqual(prod.partitions, [])
  assert.equal(ref.root, sentinel)
  assert.equal(prod.root, sentinel)
})
