// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Primitive — axis projections
// ══════════════════════════════════════════════════════════════════
// Spec §2.2 / §2.3. Each projection extracts one axis's content plus the
// sibling-hash path needed to reconstruct the signed root. The other three
// axes' contents are not recoverable from a single projection (I3, §3.3).
// ══════════════════════════════════════════════════════════════════

import { normalizeAxes } from './canonical.js'
import { buildMerkleFrame, projectionPath } from './merkle.js'
import type {
  AttributionAxes,
  AttributionAxisTag,
  AttributionPrimitive,
  AttributionProjection,
  ComputeAxisItem,
  DataAxisItem,
  GovernanceAxisEntry,
  ProtocolAxisItem,
} from './types.js'

function selectAxis(axes: AttributionAxes, axis: AttributionAxisTag): unknown {
  switch (axis) {
    case 'D':
      return axes.D
    case 'P':
      return axes.P
    case 'G':
      return axes.G
    case 'C':
      return axes.C
  }
}

/** Extract a single axis projection from a primitive. §2.2. The projection
 *  carries a copy of the axis content (no deep clone — callers treating
 *  projections as transport should serialize immediately) plus the two-hop
 *  sibling path to reconstruct the root. */
export function projectAttribution(
  primitive: AttributionPrimitive,
  axis: AttributionAxisTag,
): AttributionProjection {
  if (axis !== 'D' && axis !== 'P' && axis !== 'G' && axis !== 'C') {
    throw new Error(`attribution-primitive: invalid axis tag "${String(axis)}"`)
  }
  // Re-normalize to guarantee the tree we build here matches whatever the
  // original issuer produced. Primitive fields other than axes could have
  // been tampered with after construction — we don't trust primitive inputs
  // to be canonical on their own.
  const normalized = normalizeAxes(primitive.axes)
  const frame = buildMerkleFrame(normalized)
  const path = projectionPath(frame, axis)

  return {
    action_ref: primitive.action_ref,
    axis_tag: axis,
    axis_data: selectAxis(frame.axes, axis),
    merkle_path: path,
    merkle_root: primitive.merkle_root,
    issuer: primitive.issuer,
    timestamp: primitive.timestamp,
    signature: primitive.signature,
  }
}

/** Convenience: extract all four projections in one call. Useful when an
 *  issuer wants to emit projections to four independent settlement queues
 *  in parallel. */
export function projectAllAxes(
  primitive: AttributionPrimitive,
): { D: AttributionProjection; P: AttributionProjection; G: AttributionProjection; C: AttributionProjection } {
  return {
    D: projectAttribution(primitive, 'D'),
    P: projectAttribution(primitive, 'P'),
    G: projectAttribution(primitive, 'G'),
    C: projectAttribution(primitive, 'C'),
  }
}

/** Type-narrowing helpers so callers can pull a projection's axis_data with
 *  the right shape. Throws if the tag doesn't match the expected axis.
 *  (Verification happens separately in verify.ts — these helpers only do
 *  runtime-tag dispatch, no signature checking.) */
export function projectionDataAsD(p: AttributionProjection): DataAxisItem[] {
  if (p.axis_tag !== 'D') throw new Error(`expected axis D projection, got ${p.axis_tag}`)
  return p.axis_data as DataAxisItem[]
}
export function projectionDataAsP(p: AttributionProjection): ProtocolAxisItem[] {
  if (p.axis_tag !== 'P') throw new Error(`expected axis P projection, got ${p.axis_tag}`)
  return p.axis_data as ProtocolAxisItem[]
}
export function projectionDataAsG(p: AttributionProjection): GovernanceAxisEntry[] {
  if (p.axis_tag !== 'G') throw new Error(`expected axis G projection, got ${p.axis_tag}`)
  return p.axis_data as GovernanceAxisEntry[]
}
export function projectionDataAsC(p: AttributionProjection): ComputeAxisItem[] {
  if (p.axis_tag !== 'C') throw new Error(`expected axis C projection, got ${p.axis_tag}`)
  return p.axis_data as ComputeAxisItem[]
}
