// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Attribution Settlement — balanced binary Merkle tree over N leaves
// ══════════════════════════════════════════════════════════════════
// Build A's tree was a fixed four-leaf balanced binary tree. Build C
// aggregates over N contributors per axis, so we need an N-leaf tree.
// The construction:
//
//   1. Compute leaf hashes over canonicalized contributor bodies.
//   2. Domain-separate: every leaf is re-hashed as sha256(0x00 || leaf)
//      and every internal node as sha256(0x01 || left || right), so an
//      internal node value can never be reinterpreted as a leaf.
//   3. Adjacent-pair reduction: pair (2i, 2i+1) → internal(left, right).
//   4. If a level has an odd number of nodes, the trailing node is
//      promoted unchanged (NOT duplicated). Duplicating it would let a
//      set like [a,b,c] collide with [a,b,c,c] and forge phantom-
//      duplicate inclusion (CVE-2012-2459 class).
//   5. Recurse until one root remains.
//
// The empty-axis convention (I-C5) uses sha256(canonicalize([])) as the
// axis_merkle_root — handled by the caller.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalize, canonicalizeForWrite } from '../../core/canonical.js'

const LEAF_TAG = Buffer.from([0x00])
const NODE_TAG = Buffer.from([0x01])

/** Path token marking a level where the target was the lone odd node and
 *  was promoted unchanged. It cannot collide with a 64-hex digest, so
 *  {@link verifyMerklePath} disambiguates promotion from a real sibling. */
const PROMOTED_LEVEL = 'promoted'

/** Domain-separated leaf hash: sha256(0x00 || leaf). */
function hashLeafNode(leaf: Buffer): Buffer {
  return createHash('sha256').update(Buffer.concat([LEAF_TAG, leaf])).digest()
}

/** Domain-separated internal node: sha256(0x01 || left || right). */
function hashInternalNode(left: Buffer, right: Buffer): Buffer {
  return createHash('sha256').update(Buffer.concat([NODE_TAG, left, right])).digest()
}

/** sha256(canonicalize(obj)) as raw 32 bytes. */
export function leafHash(obj: unknown): Buffer {
  return createHash('sha256').update(canonicalize(obj)).digest()
}
/** Write-boundary twin of leafHash().
 *
 *  Emits the same bytes as leafHash() for every value it accepts. The only difference
 *  is that an integer-valued number outside the interoperable IEEE 754 range is
 *  refused instead of serialized. Use at signing and new-write boundaries ONLY:
 *  leafHash() stays unrestricted so an artifact signed before this rule keeps
 *  verifying. */
export function leafHashForWrite(obj: unknown): Buffer {
  return createHash('sha256').update(canonicalizeForWrite(obj)).digest()
}

/** Build a balanced binary Merkle tree over arbitrary leaf hashes and
 *  return the root as raw bytes. Leaves and internal nodes are domain-
 *  separated; an odd trailing node is promoted unchanged (never
 *  duplicated) to avoid the CVE-2012-2459 duplicate-leaf collision.
 *  Throws on empty input — the caller is responsible for using the
 *  empty-axis convention in that case. */
export function buildMerkleRoot(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) {
    throw new Error('attribution-settlement: buildMerkleRoot requires at least one leaf')
  }
  let level = leaves.map(hashLeafNode)
  while (level.length > 1) {
    const next: Buffer[] = []
    for (let i = 0; i < level.length; i += 2) {
      next.push(
        i + 1 < level.length
          ? hashInternalNode(level[i], level[i + 1])
          : level[i], // odd node promoted unchanged, never duplicated
      )
    }
    level = next
  }
  return level[0]
}

/** Returns the sibling hashes (bottom-up) required to reconstruct the
 *  root from `leaves[targetIndex]`. The returned hex strings are 32-byte
 *  sha256 digests. Verification also needs the leaf index so the
 *  verifier knows which side of each hashNode the sibling sits on —
 *  {@link verifyMerklePath} takes that argument. */
export function buildContributorMerklePath(
  leaves: Buffer[],
  targetIndex: number,
): string[] {
  if (leaves.length === 0) {
    throw new Error('attribution-settlement: merkle path requires at least one leaf')
  }
  if (targetIndex < 0 || targetIndex >= leaves.length) {
    throw new Error(
      `attribution-settlement: targetIndex ${targetIndex} out of range for ${leaves.length} leaves`,
    )
  }
  const path: string[] = []
  let level = leaves.map(hashLeafNode)
  let idx = targetIndex
  while (level.length > 1) {
    const isRight = idx % 2 === 1
    const siblingIdx = isRight ? idx - 1 : idx + 1
    // Exactly one entry per level keeps the verifier's index arithmetic in
    // sync. When the target is the lone odd node it has no sibling and is
    // promoted unchanged, recorded as PROMOTED_LEVEL rather than a self-
    // duplicate (which would reintroduce the collision).
    path.push(siblingIdx < level.length ? level[siblingIdx].toString('hex') : PROMOTED_LEVEL)
    const next: Buffer[] = []
    for (let i = 0; i < level.length; i += 2) {
      next.push(
        i + 1 < level.length
          ? hashInternalNode(level[i], level[i + 1])
          : level[i],
      )
    }
    level = next
    idx = Math.floor(idx / 2)
  }
  return path
}

/** Reconstruct the Merkle root from (leaf, leafIndex, path) and compare
 *  against `expectedRootHex`. Returns a boolean. Hex comparison is done
 *  lowercase-insensitively. */
export function verifyMerklePath(
  leaf: Buffer,
  leafIndex: number,
  path: string[],
  expectedRootHex: string,
): boolean {
  if (leafIndex < 0) return false
  let acc = hashLeafNode(leaf)
  let idx = leafIndex
  for (const siblingHex of path) {
    if (siblingHex === PROMOTED_LEVEL) {
      // Lone odd node promoted unchanged: nothing to combine at this level.
      idx = Math.floor(idx / 2)
      continue
    }
    if (typeof siblingHex !== 'string' || !/^[0-9a-f]{64}$/i.test(siblingHex)) return false
    const sibling = Buffer.from(siblingHex, 'hex')
    if (sibling.length !== 32) return false
    const isRight = idx % 2 === 1
    acc = isRight ? hashInternalNode(sibling, acc) : hashInternalNode(acc, sibling)
    idx = Math.floor(idx / 2)
  }
  return acc.toString('hex') === expectedRootHex.toLowerCase()
}

/** Convenience: the canonical empty-axis merkle root (I-C5). */
export function emptyAxisMerkleRoot(): string {
  return createHash('sha256').update(canonicalize([])).digest('hex')
}
