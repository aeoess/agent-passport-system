// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Settlement — balanced binary Merkle tree over N leaves
// ══════════════════════════════════════════════════════════════════
// Build A's tree was a fixed four-leaf balanced binary tree. Build C
// aggregates over N contributors per axis, so we need an N-leaf tree.
// The construction:
//
//   1. Compute leaf hashes over canonicalized contributor bodies.
//   2. Adjacent-pair reduction: pair (2i, 2i+1) → hashNode(left, right).
//   3. If a level has an odd number of nodes, the trailing node is
//      duplicated (hashNode(node, node)) — common Bitcoin-style convention.
//   4. Recurse until one root remains.
//
// The empty-axis convention (I-C5) uses sha256(canonicalize([])) as the
// axis_merkle_root — handled by the caller.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalize } from '../../core/canonical.js'
import { hashNode } from '../attribution-primitive/canonical.js'

/** sha256(canonicalize(obj)) as raw 32 bytes. */
export function leafHash(obj: unknown): Buffer {
  return createHash('sha256').update(canonicalize(obj)).digest()
}

/** Build a balanced binary Merkle tree over arbitrary leaf hashes and
 *  return the root as raw bytes. Odd levels duplicate the trailing node
 *  (the standard fold convention). Throws on empty input — the caller is
 *  responsible for using the empty-axis convention in that case. */
export function buildMerkleRoot(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) {
    throw new Error('attribution-settlement: buildMerkleRoot requires at least one leaf')
  }
  let level = leaves.slice()
  while (level.length > 1) {
    const next: Buffer[] = []
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]
      const right = i + 1 < level.length ? level[i + 1] : level[i]
      next.push(hashNode(left, right))
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
  let level = leaves.slice()
  let idx = targetIndex
  while (level.length > 1) {
    const isRight = idx % 2 === 1
    const siblingIdx = isRight ? idx - 1 : idx + 1
    const sibling = siblingIdx < level.length ? level[siblingIdx] : level[idx]
    path.push(sibling.toString('hex'))
    const next: Buffer[] = []
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]
      const right = i + 1 < level.length ? level[i + 1] : level[i]
      next.push(hashNode(left, right))
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
  let acc = leaf
  let idx = leafIndex
  for (const siblingHex of path) {
    if (typeof siblingHex !== 'string' || !/^[0-9a-f]{64}$/i.test(siblingHex)) return false
    const sibling = Buffer.from(siblingHex, 'hex')
    if (sibling.length !== 32) return false
    const isRight = idx % 2 === 1
    acc = isRight ? hashNode(sibling, acc) : hashNode(acc, sibling)
    idx = Math.floor(idx / 2)
  }
  return acc.toString('hex') === expectedRootHex.toLowerCase()
}

/** Convenience: the canonical empty-axis merkle root (I-C5). */
export function emptyAxisMerkleRoot(): string {
  return createHash('sha256').update(canonicalize([])).digest('hex')
}
