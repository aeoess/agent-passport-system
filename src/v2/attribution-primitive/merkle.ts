// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Primitive — balanced four-leaf Merkle tree
// ══════════════════════════════════════════════════════════════════
// Spec §2.1: four leaves in fixed positions. Content pair (D, P) on the
// left, authority-infrastructure pair (G, C) on the right, balanced above.
// All projections share a path length of two.
// ══════════════════════════════════════════════════════════════════

import { hashAxisLeaf, hashNode, normalizeAxes } from './canonical.js'
import type { AttributionAxes, AttributionAxisTag } from './types.js'

export interface MerkleFrame {
  /** Canonically-ordered axes used to derive the leaves. */
  axes: AttributionAxes
  leaves: { D: Buffer; P: Buffer; G: Buffer; C: Buffer }
  nodes: { N_content: Buffer; N_auth_infra: Buffer }
  root: Buffer
}

/** Build the full tree for a set of axes. Callers pass the raw (possibly
 *  unsorted) axes; we normalize before hashing so the caller can't produce
 *  two different canonical representations of the same logical content. */
export function buildMerkleFrame(rawAxes: AttributionAxes): MerkleFrame {
  const axes = normalizeAxes(rawAxes)
  const leafD = hashAxisLeaf(axes.D)
  const leafP = hashAxisLeaf(axes.P)
  const leafG = hashAxisLeaf(axes.G)
  const leafC = hashAxisLeaf(axes.C)
  const nContent = hashNode(leafD, leafP)
  const nAuthInfra = hashNode(leafG, leafC)
  const root = hashNode(nContent, nAuthInfra)
  return {
    axes,
    leaves: { D: leafD, P: leafP, G: leafG, C: leafC },
    nodes: { N_content: nContent, N_auth_infra: nAuthInfra },
    root,
  }
}

/** The sibling path for a projection, in the order §2.2 specifies:
 *  [sibling_leaf_within_pair_hex, sibling_internal_node_hex]. */
export function projectionPath(
  frame: MerkleFrame,
  axis: AttributionAxisTag,
): [string, string] {
  switch (axis) {
    case 'D':
      return [frame.leaves.P.toString('hex'), frame.nodes.N_auth_infra.toString('hex')]
    case 'P':
      return [frame.leaves.D.toString('hex'), frame.nodes.N_auth_infra.toString('hex')]
    case 'G':
      return [frame.leaves.C.toString('hex'), frame.nodes.N_content.toString('hex')]
    case 'C':
      return [frame.leaves.G.toString('hex'), frame.nodes.N_content.toString('hex')]
    default: {
      const exhaustive: never = axis
      throw new Error(`attribution-primitive: unknown axis tag ${String(exhaustive)}`)
    }
  }
}

/** Reconstruct the root from an axis's canonical leaf hash and the two-hop
 *  sibling path. §2.3 algorithm. Returns raw bytes so callers can diff the
 *  buffers; hex comparison is lossy under case normalization. */
export function reconstructRoot(
  axisLeaf: Buffer,
  path: [string, string],
  axis: AttributionAxisTag,
): Buffer {
  const sibling = Buffer.from(path[0], 'hex')
  const siblingInternal = Buffer.from(path[1], 'hex')
  if (sibling.length !== 32 || siblingInternal.length !== 32) {
    throw new Error(
      `attribution-primitive: merkle path hashes must be 32-byte sha256 (got ${sibling.length}, ${siblingInternal.length})`,
    )
  }
  let internal: Buffer
  switch (axis) {
    case 'D':
      internal = hashNode(axisLeaf, sibling) // leaf_D || leaf_P
      return hashNode(internal, siblingInternal) // N_content || N_auth_infra
    case 'P':
      internal = hashNode(sibling, axisLeaf) // leaf_D || leaf_P
      return hashNode(internal, siblingInternal)
    case 'G':
      internal = hashNode(axisLeaf, sibling) // leaf_G || leaf_C
      return hashNode(siblingInternal, internal) // N_content || N_auth_infra
    case 'C':
      internal = hashNode(sibling, axisLeaf) // leaf_G || leaf_C
      return hashNode(siblingInternal, internal)
    default: {
      const exhaustive: never = axis
      throw new Error(`attribution-primitive: unknown axis tag ${String(exhaustive)}`)
    }
  }
}
