// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// CPA v0.1: shared cross-language vector generator
// ══════════════════════════════════════════════════════════════════
// Emits vectors/cpa-v0.1-vectors.json: the SINGLE shared fixture that
// both the TypeScript loader test (cross-lang-parity.test.ts) and the Go
// cpa package test (cpa/cpa_test.go in agent-passport-go) load and must
// reproduce byte/hex-identically.
//
// LAYERING (honest):
//   - jcs_kats are HAND-DERIVED. They are the trust anchor, copied
//     byte-for-byte from known-answer.test.ts (KAV1..KAV4). They are NOT
//     produced by calling canonicalizeJCS here.
//   - The tree-layer values (partition_root, top root, cpa_ref, signature)
//     are REFERENCE-IMPLEMENTATION-DERIVED: computed here by the real
//     buildCPA / computeCpaRef / merkle helpers. Cross-language agreement
//     on the tree layer proves both languages implement the same tree
//     shape over the same hand-anchored JCS bytes. The tree-layer values
//     are NOT hand-derived.
//
// Run: npx tsx src/v2/context-provenance/vectors/generate-vectors.ts
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { writeFileSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { sign, publicKeyFromPrivate } from '../../../crypto/keys.js'
import { buildCPA, computeCpaRef } from '../cpa.js'
import {
  buildPartitionRoot,
  leafPreimage,
} from '../merkle.js'
import {
  CHANNEL_ORDER,
  type ContextItem,
  type DisclosureMode,
  type ContextProvenanceAttestation,
} from '../types.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

function sha256Hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

// ── Fixed inputs (pinned; do not change without re-pinning every output) ──
const SEED = '0000000000000000000000000000000000000000000000000000000000000001'
const PUBKEY = publicKeyFromPrivate(SEED) // 4cb5abf6...ba29 (pinned in known-answer.test.ts)
const ATTESTED_AT = '2026-06-03T00:00:00Z'
const ACTION_REF = '1111111111111111111111111111111111111111111111111111111111111111'
const PRODUCER_DID = 'did:aps:cpa-parity-producer'

// ══════════════════════════════════════════════════════════════════
// jcs_kats: HAND-DERIVED trust anchor, copied byte-for-byte from
// known-answer.test.ts KAV1..KAV4 (NOT produced by canonicalizeJCS here).
// ══════════════════════════════════════════════════════════════════
const KAV1_INPUT = { 'é': 'non-ascii', apple: { b: 2, a: 1 }, Zebra: 'upper', '1key': 'digit-first' }
const KAV1_EXPECTED =
  '{"1key":"digit-first","Zebra":"upper","apple":{"a":1,"b":2},"é":"non-ascii"}'
const KAV1_SHA256 = '347dfed718913d7fdc34a874777cf95d7a4722d47f2ce72aa86e1aa40a8f6b40'

const KAV2_INPUT = { zero: 0, neg: -7, int: 42, dec: 3.5, arr: [3, 1, 2] }
const KAV2_EXPECTED = '{"arr":[3,1,2],"dec":3.5,"int":42,"neg":-7,"zero":0}'
const KAV2_SHA256 = '534b228144a885b47caf14bc5ac3275a2d4ca818f8bb5607d9f3088262fa96e2'

// KAV3 value contains a literal TAB, LF, and U+0001 control char. The string
// literal below is copied from known-answer.test.ts so the control byte is
// preserved exactly.
const KAV3_INPUT = { s: 'a"b\\c\td\ne/fg_ü' }
const KAV3_EXPECTED = '{"s":"a\\"b\\\\c\\td\\ne/f\\u0001g_ü"}'
const KAV3_SHA256 = '6359e665aff8e54d4e09f10ea19c27080fdc12ee1929ee0bb86c32d0e06302aa'

const KAV4_INPUT = { ctx_id: 'sc-001', content_ref: 'aa00', channel: 'system-config', byte_len: 15 }
const KAV4_EXPECTED =
  '{"byte_len":15,"channel":"system-config","content_ref":"aa00","ctx_id":"sc-001"}'
const KAV4_SHA256 = 'abaf17ec1e412bb212629249f6a27fea90adcca658f95f7a2abcce304a18a300'

interface JcsKat {
  name: string
  input: unknown
  expected: string
  sha256: string
}

const jcs_kats: JcsKat[] = [
  { name: 'KAV1', input: KAV1_INPUT, expected: KAV1_EXPECTED, sha256: KAV1_SHA256 },
  { name: 'KAV2', input: KAV2_INPUT, expected: KAV2_EXPECTED, sha256: KAV2_SHA256 },
  { name: 'KAV3', input: KAV3_INPUT, expected: KAV3_EXPECTED, sha256: KAV3_SHA256 },
  { name: 'KAV4', input: KAV4_INPUT, expected: KAV4_EXPECTED, sha256: KAV4_SHA256 },
]

// Self-check: the live canonicalizer MUST already reproduce each hand-derived
// KAT. If it does not, the trust anchor and the reference impl disagree, which
// is a real discrepancy to surface (never a reason to edit the KAT).
for (const k of jcs_kats) {
  const got = canonicalizeJCS(k.input)
  if (got !== k.expected) {
    throw new Error(`KAT ${k.name}: canonicalizeJCS != hand-derived expected\n got: ${got}\nwant: ${k.expected}`)
  }
  if (sha256Hex(k.expected) !== k.sha256) {
    throw new Error(`KAT ${k.name}: sha256(expected) != pinned sha256`)
  }
}

// ══════════════════════════════════════════════════════════════════
// ed25519: fixed-seed signature, reference-impl derived.
// ══════════════════════════════════════════════════════════════════
const ED_MSG = '{"hello":"cpa"}'
const ed25519 = {
  seed: SEED,
  pubkey: PUBKEY,
  msg: ED_MSG,
  signature: sign(ED_MSG, SEED),
}

// ══════════════════════════════════════════════════════════════════
// cpa_cases: reference-implementation-derived tree-layer outputs.
// ══════════════════════════════════════════════════════════════════
interface CpaCase {
  name: string
  description: string
  mode: DisclosureMode
  items: ContextItem[]
  producer_pubkey: string
  partitions: Array<{
    channel: string
    leaf_count: number
    leaf_preimages: Array<Record<string, unknown>>
    partition_root: string
  }>
  root: string
  cpa_ref: string
  signature: string
  signed_cpa: ContextProvenanceAttestation
}

function presentPartitionView(items: ContextItem[]) {
  // Group by channel, take present partitions in CHANNEL_ORDER, and for each
  // emit the committed leaf preimages (4-field objects in ctx_id sort order)
  // plus the partition_root computed by the real merkle helper.
  const byChannel = new Map<string, ContextItem[]>()
  for (const it of items) {
    const b = byChannel.get(it.channel)
    if (b) b.push(it)
    else byChannel.set(it.channel, [it])
  }
  const out: CpaCase['partitions'] = []
  for (const channel of CHANNEL_ORDER) {
    const leaves = byChannel.get(channel)
    if (!leaves || leaves.length === 0) continue
    const sorted = [...leaves].sort((a, b) =>
      a.ctx_id < b.ctx_id ? -1 : a.ctx_id > b.ctx_id ? 1 : 0,
    )
    out.push({
      channel,
      leaf_count: sorted.length,
      leaf_preimages: sorted.map(l => {
        const p = leafPreimage(l)
        // Emit in committed (JCS-sorted) key order for human readability;
        // JCS re-sorts on canonicalize so order here is cosmetic.
        return { byte_len: p.byte_len, channel: p.channel, content_ref: p.content_ref, ctx_id: p.ctx_id }
      }),
      partition_root: buildPartitionRoot(sorted),
    })
  }
  return out
}

function makeCase(name: string, description: string, mode: DisclosureMode, items: ContextItem[]): CpaCase {
  const cpa = buildCPA({
    privateKey: SEED,
    action_ref: ACTION_REF,
    producer_did: PRODUCER_DID,
    attested_at: ATTESTED_AT,
    mode,
    items,
  })
  return {
    name,
    description,
    mode,
    items,
    producer_pubkey: cpa.producer_pubkey,
    partitions: presentPartitionView(items),
    root: cpa.root,
    cpa_ref: computeCpaRef(cpa),
    signature: cpa.signature,
    signed_cpa: cpa,
  }
}

// Case (a): full-set multi-channel, with a single-leaf partition AND a
// 3-leaf partition (exercises odd-promotion in a partition root) across
// >= 3 channels.
const caseA = makeCase(
  'full-set-multi-channel',
  'full-set mode, 3 present channels: system-config single-leaf, developer 3-leaf (odd-promotion), tool-result 2-leaf',
  'full-set',
  [
    { ctx_id: 'sc-001', channel: 'system-config', content_ref: 'aa00', byte_len: 15 },
    { ctx_id: 'dev-001', channel: 'developer', content_ref: 'bb11', byte_len: 11 },
    { ctx_id: 'dev-002', channel: 'developer', content_ref: 'cc22', byte_len: 7 },
    { ctx_id: 'dev-003', channel: 'developer', content_ref: 'dd33', byte_len: 23 },
    { ctx_id: 'tr-001', channel: 'tool-result', content_ref: 'ee44', byte_len: 100 },
    { ctx_id: 'tr-002', channel: 'tool-result', content_ref: 'ff55', byte_len: 64 },
  ],
)

// Case (b): inclusion mode, count-only (no disclosed subset), multi-channel.
const caseB = makeCase(
  'inclusion-count-only-multi-channel',
  'inclusion mode, count-only (no disclosed leaves), 3 present channels',
  'inclusion',
  [
    { ctx_id: 'sc-001', channel: 'system-config', content_ref: 'aa00', byte_len: 15 },
    { ctx_id: 'usr-001', channel: 'user-socket', content_ref: '1234', byte_len: 42 },
    { ctx_id: 'usr-002', channel: 'user-socket', content_ref: '5678', byte_len: 8 },
    { ctx_id: 'ext-001', channel: 'external', content_ref: '9abc', byte_len: 256 },
  ],
)

// Case (c): single-channel single-leaf (root == partition_root == leaf hash).
const caseC = makeCase(
  'single-channel-single-leaf',
  'full-set mode, one channel with exactly one leaf (root == partition_root == leaf hash)',
  'full-set',
  [
    { ctx_id: 'mem-001', channel: 'memory', content_ref: 'face', byte_len: 33 },
  ],
)

// Case (d): empty tree (zero leaves -> partitions=[], root = EMPTY sentinel).
const caseD = makeCase(
  'empty-tree',
  'full-set mode, zero leaves: partitions empty, root is the EMPTY sentinel',
  'full-set',
  [],
)

const cpa_cases = [caseA, caseB, caseC, caseD]

// ══════════════════════════════════════════════════════════════════
// Assemble + write.
// ══════════════════════════════════════════════════════════════════
const fixture = {
  _layering:
    'jcs_kats are HAND-DERIVED (the trust anchor), copied byte-for-byte from ' +
    'known-answer.test.ts KAV1..KAV4. The tree-layer values (partition_root, ' +
    'root, cpa_ref, signature) are REFERENCE-IMPLEMENTATION-DERIVED, computed ' +
    'by the real buildCPA/computeCpaRef/merkle helpers. Cross-language ' +
    'agreement on the tree layer proves both languages implement the same tree ' +
    'shape over the same hand-anchored JCS bytes. The tree-layer values are ' +
    'NOT hand-derived; only the jcs_kats are.',
  version: 'cpa/0.1',
  fixed_inputs: {
    seed: SEED,
    producer_pubkey: PUBKEY,
    attested_at: ATTESTED_AT,
    action_ref: ACTION_REF,
    producer_did: PRODUCER_DID,
  },
  jcs_kats,
  ed25519,
  cpa_cases,
}

const outDir = __dirname
mkdirSync(outDir, { recursive: true })
const outPath = join(outDir, 'cpa-v0.1-vectors.json')
writeFileSync(outPath, JSON.stringify(fixture, null, 2) + '\n', 'utf8')

// eslint-disable-next-line no-console
console.log(`wrote ${outPath}`)
// eslint-disable-next-line no-console
console.log(`  jcs_kats: ${jcs_kats.length}, cpa_cases: ${cpa_cases.length}`)
for (const c of cpa_cases) {
  // eslint-disable-next-line no-console
  console.log(`  ${c.name}: root=${c.root.slice(0, 16)}... cpa_ref=${c.cpa_ref.slice(0, 16)}...`)
}
