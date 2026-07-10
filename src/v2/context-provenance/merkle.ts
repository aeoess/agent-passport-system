// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// CPA v0.1: partitioned-Merkle hashing (FROZEN tree shape)
// ══════════════════════════════════════════════════════════════════
// Three mutually-distinct ASCII domain tags separate the leaf, node, and
// signing pre-images so that a digest computed in one role can never be
// reinterpreted in another (domain-tag confusion). Tags are hashed as
// their raw UTF-8 bytes.
//
// Hashing carries RAW 32-byte digests internally; hex appears only at
// object boundaries (partition_root, root). node_hash concatenates raw
// 32-byte digests, NOT hex strings. The odd-count rule promotes an odd
// node UNCHANGED to the next level (RFC 6962); it is NEVER duplicated,
// which closes CVE-2012-2459 (the Bitcoin Merkle duplicate-leaf
// second-preimage class).
//
// See TREE-SHAPE.md for the frozen-shape narrative.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import type { ContextItem, ContextChannel } from './types.js'

// ── Domain tags (frozen byte values; trailing newline is intentional) ──

/** Leaf pre-image domain tag. */
export const LEAF_TAG = 'CPA:v0.1:leaf\n'
/** Internal-node domain tag. */
export const NODE_TAG = 'CPA:v0.1:node\n'
/** Signing / cpa_ref domain tag (used only for cpa_ref). */
export const SIGN_TAG = 'CPA:v0.1:sign\n'

/** Empty-tree sentinel pre-image. When zero leaves exist in total, the
 *  top root is a fixed, signable constant derived from this sentinel. */
const EMPTY_SENTINEL = 'EMPTY'

// ── Low-level sha256 over raw bytes ──

function sha256(...parts: Uint8Array[]): Uint8Array {
  const h = createHash('sha256')
  for (const p of parts) h.update(p)
  return new Uint8Array(h.digest())
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

// ── Leaf and node hashing (raw 32-byte digests) ──

/**
 * The leaf pre-image: EXACTLY these four fields. content and trust_tier
 * are EXCLUDED so the root is identical whether or not content is later
 * disclosed. JCS sorts keys, so field order here is irrelevant.
 */
export interface LeafPreimage {
  byte_len: number
  channel: ContextChannel
  content_ref: string
  ctx_id: string
}

/** Extract the canonical leaf pre-image from a context item. */
export function leafPreimage(leaf: ContextItem): LeafPreimage {
  return {
    byte_len: leaf.byte_len,
    channel: leaf.channel,
    content_ref: leaf.content_ref,
    ctx_id: leaf.ctx_id,
  }
}

/** leaf_hash = sha256( utf8(LEAF_TAG) || utf8(canonicalizeJCS(preimage)) )
 *  Returns the raw 32-byte digest. */
export function leafHash(leaf: ContextItem): Uint8Array {
  return sha256(utf8(LEAF_TAG), utf8(canonicalizeJCS(leafPreimage(leaf))))
}

/** node_hash = sha256( utf8(NODE_TAG) || left32 || right32 ) over RAW
 *  32-byte digests. Returns the raw 32-byte digest. */
export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(utf8(NODE_TAG), left, right)
}

// ── Tree reduction with RFC 6962 odd-promotion ──

/**
 * Reduce a list of raw 32-byte leaf digests to a single raw 32-byte root
 * using NODE_TAG. Odd node at any level is PROMOTED UNCHANGED to the next
 * level (never duplicated). Single element returns that element. Throws
 * on an empty list (callers handle the empty case explicitly).
 */
function reduce(level: Uint8Array[]): Uint8Array {
  if (level.length === 0) {
    throw new Error('CPA merkle: cannot reduce an empty level')
  }
  let current = level
  while (current.length > 1) {
    const next: Uint8Array[] = []
    for (let i = 0; i < current.length; i += 2) {
      if (i + 1 < current.length) {
        next.push(nodeHash(current[i], current[i + 1]))
      } else {
        // Odd node: promote unchanged (RFC 6962; closes CVE-2012-2459).
        next.push(current[i])
      }
    }
    current = next
  }
  return current[0]
}

/**
 * Build the partition_root (raw 32-byte digest) for one partition's
 * leaves. Leaves are sorted ascending by ctx_id (JS string / code-point
 * order). ctx_id MUST be unique within the partition; a duplicate throws.
 * Single leaf => partition_root = that leaf digest (no node hashing).
 * Throws on an empty leaf list (empty partitions are omitted upstream).
 */
export function buildPartitionRootBytes(leaves: ContextItem[]): Uint8Array {
  if (leaves.length === 0) {
    throw new Error('CPA merkle: a present partition must have at least one leaf')
  }
  const sorted = [...leaves].sort((a, b) =>
    a.ctx_id < b.ctx_id ? -1 : a.ctx_id > b.ctx_id ? 1 : 0,
  )
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i].ctx_id === sorted[i - 1].ctx_id) {
      throw new Error(`CPA merkle: duplicate ctx_id "${sorted[i].ctx_id}" within partition`)
    }
  }
  const digests = sorted.map(leafHash)
  return reduce(digests)
}

/** Hex convenience wrapper around buildPartitionRootBytes. */
export function buildPartitionRoot(leaves: ContextItem[]): string {
  return toHex(buildPartitionRootBytes(leaves))
}

/**
 * Build the top root (raw 32-byte digest) over present partition roots.
 * Input is the ordered list of RAW 32-byte partition_root digests, taken
 * in CHANNEL_ORDER by the caller. Same NODE_TAG odd-promotion rule.
 *   - Zero partitions => EMPTY sentinel: sha256( utf8(NODE_TAG) ||
 *     utf8("EMPTY") ).
 *   - One partition => root = that partition_root.
 */
export function buildTopRootBytes(partitionRootsInChannelOrder: Uint8Array[]): Uint8Array {
  if (partitionRootsInChannelOrder.length === 0) {
    return sha256(utf8(NODE_TAG), utf8(EMPTY_SENTINEL))
  }
  return reduce(partitionRootsInChannelOrder)
}

/** Hex convenience wrapper around buildTopRootBytes. */
export function buildTopRoot(partitionRootsInChannelOrder: string[]): string {
  const bytes = partitionRootsInChannelOrder.map(hexToBytes)
  return toHex(buildTopRootBytes(bytes))
}

/** The frozen empty-tree top root, as 64-hex. Signable sentinel. */
export function emptyTreeRoot(): string {
  return toHex(buildTopRootBytes([]))
}

// ── hex helpers (exported for cpa.ts / verify.ts) ──

export function bytesToHex(bytes: Uint8Array): string {
  return toHex(bytes)
}

export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }
  return out
}

export { utf8 as utf8Bytes }

// ══════════════════════════════════════════════════════════════════
// Phase 1: inclusion proofs (consistent with the FROZEN partition tree)
// ══════════════════════════════════════════════════════════════════
// An inclusion proof is an audit path from a single leaf to the
// partition_root. It is built and verified with the SAME ctx_id sort and
// the SAME RFC-6962 odd-promotion rule that buildPartitionRootBytes /
// reduce use, so a proof folds to exactly the signed partition_root.
//
// Odd-promotion handling (mirrors `reduce`): at each level a node at even
// index i pairs with i+1 as node_hash(level[i], level[i+1]); the target's
// sibling sits to its left (target at odd index) or right (target at even
// index). When the target is the FINAL node at an ODD-length level it has
// no pair and is promoted UNCHANGED to the next level: NO step is recorded
// for that level, exactly as `reduce` pushes current[i] straight through.
// ══════════════════════════════════════════════════════════════════

/** One audit step: the sibling digest (64-hex) and which side it sits on.
 *  side === 'left'  => fold as node_hash(sibling, acc)
 *  side === 'right' => fold as node_hash(acc, sibling) */
export interface InclusionStep {
  sibling: string // 64-hex
  side: 'left' | 'right'
}

/** An inclusion proof for one leaf, identified by its ctx_id. The path is
 *  ordered bottom-up (leaf level first). */
export interface InclusionProof {
  ctx_id: string
  path: InclusionStep[]
}

/**
 * Build an inclusion proof for the leaf whose ctx_id === ctx_id, against
 * the partition formed by `leaves`. Leaves are sorted by ctx_id exactly as
 * buildPartitionRootBytes does. Walks bottom-up, recording the sibling
 * digest (hex) and side at each level, and recording NO step when the
 * target/ancestor is the promoted odd node at a level (it carries straight
 * up, mirroring `reduce`).
 *
 * Throws on an empty partition, a duplicate ctx_id, or a ctx_id not found
 * (these are producer-side invariants; the verifier never calls this).
 */
export function buildInclusionProof(leaves: ContextItem[], ctx_id: string): InclusionProof {
  if (leaves.length === 0) {
    throw new Error('CPA merkle: cannot build an inclusion proof over an empty partition')
  }
  const sorted = [...leaves].sort((a, b) =>
    a.ctx_id < b.ctx_id ? -1 : a.ctx_id > b.ctx_id ? 1 : 0,
  )
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i].ctx_id === sorted[i - 1].ctx_id) {
      throw new Error(`CPA merkle: duplicate ctx_id "${sorted[i].ctx_id}" within partition`)
    }
  }
  let index = sorted.findIndex(l => l.ctx_id === ctx_id)
  if (index < 0) {
    throw new Error(`CPA merkle: ctx_id "${ctx_id}" not found in partition`)
  }

  let current = sorted.map(leafHash)
  const path: InclusionStep[] = []

  while (current.length > 1) {
    const isRightChild = index % 2 === 1
    if (isRightChild) {
      // sibling is to the LEFT at index-1; this pairing always exists.
      path.push({ sibling: toHex(current[index - 1]), side: 'left' })
    } else if (index + 1 < current.length) {
      // sibling is to the RIGHT at index+1.
      path.push({ sibling: toHex(current[index + 1]), side: 'right' })
    } else {
      // Even index AND last node at an odd-length level: promoted
      // unchanged, no sibling. Record NO step (mirrors `reduce`).
    }

    // Build the next level exactly as `reduce` does, tracking the target.
    const next: Uint8Array[] = []
    for (let i = 0; i < current.length; i += 2) {
      if (i + 1 < current.length) {
        next.push(nodeHash(current[i], current[i + 1]))
      } else {
        next.push(current[i])
      }
    }
    index = Math.floor(index / 2)
    current = next
  }

  return { ctx_id, path }
}

/**
 * Verify an inclusion proof: recompute leaf_hash(leaf), fold the path with
 * node_hash respecting each step's side, and compare the hex result to
 * partition_root. Returns false on any structural problem or mismatch
 * (fail-closed; never throws on malformed proof material).
 */
export function verifyInclusionProof(
  leaf: ContextItem,
  proof: InclusionProof,
  partition_root: string,
): boolean {
  if (!proof || typeof proof !== 'object' || !Array.isArray(proof.path)) return false
  if (typeof partition_root !== 'string' || !/^[0-9a-f]{64}$/.test(partition_root)) return false
  if (proof.ctx_id !== leaf.ctx_id) return false

  let acc: Uint8Array
  try {
    acc = leafHash(leaf)
  } catch {
    return false
  }

  for (const step of proof.path) {
    if (!step || typeof step.sibling !== 'string' || !/^[0-9a-f]{64}$/.test(step.sibling)) return false
    if (step.side !== 'left' && step.side !== 'right') return false
    const sib = hexToBytes(step.sibling)
    acc = step.side === 'left' ? nodeHash(sib, acc) : nodeHash(acc, sib)
  }

  return toHex(acc) === partition_root
}
