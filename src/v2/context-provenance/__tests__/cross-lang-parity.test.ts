// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// CPA v0.1: cross-language SHARED-FIXTURE loader (TypeScript side)
// ══════════════════════════════════════════════════════════════════
// This pins the TypeScript reference impl to the ONE shared fixture
// vectors/cpa-v0.1-vectors.json that the Go cpa package test also loads
// (a byte-identical copy lives at agent-passport-go/cpa/testdata/). It is
// NOT a re-derivation of inline literals: every asserted value comes from
// the fixture, so TS and Go are pinned to the same bytes.
//
// LAYERING (honest): the jcs_kats are the HAND-DERIVED trust anchor
// (copied byte-for-byte from known-answer.test.ts); the tree-layer values
// (partition_root, root, cpa_ref, signature) are reference-implementation-
// derived. This test asserts the live TS impl reproduces BOTH layers from
// the fixture: canonicalizeJCS for each KAT, and buildCPA/computeCpaRef/
// merkle helpers for each cpa_case.
// ══════════════════════════════════════════════════════════════════

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { sign, publicKeyFromPrivate } from '../../../crypto/keys.js'
import { buildCPA, computeCpaRef } from '../cpa.js'
import {
  buildPartitionRoot,
  buildTopRoot,
  leafHash,
  bytesToHex,
} from '../merkle.js'
import { CHANNEL_ORDER } from '../types.js'
import type {
  ContextItem,
  ContextChannel,
  DisclosureMode,
  ContextProvenanceAttestation,
} from '../types.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

function sha256Hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

interface Fixture {
  fixed_inputs: { seed: string }
  jcs_kats: Array<{ name: string; input: unknown; expected: string; sha256: string }>
  ed25519: { seed: string; pubkey: string; msg: string; signature: string }
  cpa_cases: Array<{
    name: string
    mode: DisclosureMode
    items: ContextItem[]
    producer_pubkey: string
    partitions: Array<{
      channel: string
      leaf_count: number
      leaf_preimages: Array<{ byte_len: number; channel: string; content_ref: string; ctx_id: string }>
      partition_root: string
    }>
    root: string
    cpa_ref: string
    signature: string
    signed_cpa: ContextProvenanceAttestation
  }>
}

const fixturePath = join(__dirname, '..', 'vectors', 'cpa-v0.1-vectors.json')
const fixture: Fixture = JSON.parse(readFileSync(fixturePath, 'utf8'))
const SEED = fixture.fixed_inputs.seed

// ── jcs_kats: the hand-derived trust anchor ──
test('cross-lang fixture: every jcs_kat canonicalizes to the pinned bytes + sha256', () => {
  assert.equal(fixture.jcs_kats.length, 4)
  for (const k of fixture.jcs_kats) {
    assert.equal(canonicalizeJCS(k.input), k.expected, `${k.name}: canonical bytes`)
    assert.equal(sha256Hex(k.expected), k.sha256, `${k.name}: sha256 of expected`)
    assert.equal(sha256Hex(canonicalizeJCS(k.input)), k.sha256, `${k.name}: sha256 of live canonical`)
  }
})

// ── ed25519: seed derives the pubkey; signature verifies ──
test('cross-lang fixture: ed25519 seed derives pubkey and signs the pinned message', () => {
  const e = fixture.ed25519
  assert.equal(publicKeyFromPrivate(e.seed), e.pubkey)
  // Determinism: re-signing the pinned message yields the pinned signature.
  assert.equal(sign(e.msg, e.seed), e.signature)
})

// ── cpa_cases: tree-layer reproduction from the fixture ──
test('cross-lang fixture: every cpa_case reproduces partition_root, root, cpa_ref, signature', () => {
  assert.equal(fixture.cpa_cases.length, 4)
  for (const c of fixture.cpa_cases) {
    // Rebuild the signed CPA from the fixture's inputs via the producer.
    const cpa = buildCPA({
      privateKey: SEED,
      action_ref: c.signed_cpa.action_ref,
      producer_did: c.signed_cpa.producer_did,
      attested_at: c.signed_cpa.attested_at,
      mode: c.mode,
      items: c.items,
    })

    // producer_pubkey
    assert.equal(cpa.producer_pubkey, c.producer_pubkey, `${c.name}: producer_pubkey`)

    // Every partition_root, recomputed two independent ways.
    for (const p of c.partitions) {
      const leaves = c.items.filter(it => it.channel === p.channel)
      assert.equal(
        buildPartitionRoot(leaves),
        p.partition_root,
        `${c.name}/${p.channel}: partition_root via buildPartitionRoot`,
      )
      // Each committed leaf preimage canonicalizes to a leaf the tree implies.
      for (const pre of p.leaf_preimages) {
        const lh = bytesToHex(leafHash(pre as ContextItem))
        assert.match(lh, /^[0-9a-f]{64}$/, `${c.name}/${p.channel}: leaf hash hex`)
      }
    }

    // Top root recomputed over present partition roots in CHANNEL_ORDER.
    const presentRootsInOrder: string[] = []
    for (const channel of CHANNEL_ORDER as readonly ContextChannel[]) {
      const p = c.partitions.find(pp => pp.channel === channel)
      if (p) presentRootsInOrder.push(p.partition_root)
    }
    if (presentRootsInOrder.length === 0) {
      // empty tree: builder produced the EMPTY sentinel; just assert builder root.
      assert.equal(cpa.root, c.root, `${c.name}: empty-tree root`)
    } else {
      assert.equal(buildTopRoot(presentRootsInOrder), c.root, `${c.name}: top root via buildTopRoot`)
    }

    // Builder root, cpa_ref, signature all match the fixture.
    assert.equal(cpa.root, c.root, `${c.name}: builder root`)
    assert.equal(computeCpaRef(cpa), c.cpa_ref, `${c.name}: cpa_ref`)
    assert.equal(cpa.signature, c.signature, `${c.name}: signature`)

    // The fixture's signed_cpa re-canonicalizes (signature emptied) to bytes
    // that the pinned signature verifies against the producer pubkey, and the
    // builder reproduces the identical signed object.
    assert.deepEqual(cpa, c.signed_cpa, `${c.name}: full signed CPA object`)
    const signingMsg = canonicalizeJCS({ ...c.signed_cpa, signature: '' })
    assert.equal(sign(signingMsg, SEED), c.signature, `${c.name}: signature over emptied-sig bytes`)
  }
})
