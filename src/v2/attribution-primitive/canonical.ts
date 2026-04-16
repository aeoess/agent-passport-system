// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Primitive — canonicalization, ordering, numeric format
// ══════════════════════════════════════════════════════════════════
// Spec §2.5 specifies stricter canonicalization than RFC 8785. This file
// owns the additional constraints so A1 (canonicalization injectivity,
// §3.4) holds for schema-valid inputs.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalize } from '../../core/canonical.js'
import type {
  AttributionAxes,
  AttributionAxisTag,
  AttributionEnvelope,
  ComputeAxisItem,
  DataAxisItem,
  GovernanceAxisEntry,
  ProtocolAxisItem,
  ResidualBucket,
} from './types.js'

const WEIGHT_PATTERN = /^\d+\.\d{6}$/
const ISO_8601_MS_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/

/** Format a numeric weight or decimal-string input as the canonical
 *  6-digit-after-point decimal string required by §2.5. Accepts numbers in
 *  [0, 1] or already-canonical strings. */
export function toWeightString(value: number | string): string {
  if (typeof value === 'string') {
    if (!WEIGHT_PATTERN.test(value)) {
      throw new Error(
        `attribution-primitive: weight string "${value}" must match /^\\d+\\.\\d{6}$/ (§2.5)`,
      )
    }
    return value
  }
  if (!Number.isFinite(value)) {
    throw new Error(`attribution-primitive: weight must be finite, got ${value}`)
  }
  if (value < 0 || value > 1) {
    throw new Error(`attribution-primitive: weight must be in [0, 1], got ${value}`)
  }
  return value.toFixed(6)
}

/** Reject timestamps that a lenient parser would accept but §2.5 forbids.
 *  Forces ISO-8601 UTC with millisecond precision and literal Z suffix. */
export function assertCanonicalTimestamp(ts: string): void {
  if (!ISO_8601_MS_PATTERN.test(ts)) {
    throw new Error(
      `attribution-primitive: timestamp "${ts}" must be ISO-8601 UTC with millisecond precision and trailing Z (§2.5)`,
    )
  }
}

/** Produce the canonical timestamp for "now" or a supplied Date. Spec §2.5
 *  rejects `+00:00` and drops sub-ms precision; toISOString() already emits
 *  the required shape. */
export function canonicalTimestamp(now: Date = new Date()): string {
  const s = now.toISOString()
  assertCanonicalTimestamp(s)
  return s
}

function isResidual(x: unknown): x is ResidualBucket {
  return (
    typeof x === 'object' &&
    x !== null &&
    'residual_id' in (x as object) &&
    typeof (x as ResidualBucket).residual_id === 'string' &&
    (x as ResidualBucket).residual_id.startsWith('residual:')
  )
}

/** Sort an axis to §2.5 ordering so distinct orderings of the same logical
 *  content produce byte-identical canonicalizations.
 *
 *  D: lexicographic by source_did.
 *  P: lexicographic by module_id + '\u0000' + module_version.
 *  C: lexicographic by provider_did.
 *  G: preserved as-is (root-to-leaf by depth).
 *
 *  Residual buckets always sort to the end of their axis so their fixed
 *  identifier does not collide with DID ordering. At most one residual is
 *  permitted per axis; duplicates throw. */
export function sortDataAxis(items: DataAxisItem[]): DataAxisItem[] {
  const residuals = items.filter(isResidual) as ResidualBucket[]
  if (residuals.length > 1) {
    throw new Error('attribution-primitive: at most one residual bucket permitted in axis D')
  }
  const explicit = items.filter((x) => !isResidual(x)) as Exclude<DataAxisItem, ResidualBucket>[]
  explicit.sort((a, b) => (a.source_did < b.source_did ? -1 : a.source_did > b.source_did ? 1 : 0))
  return [...explicit, ...residuals]
}

export function sortProtocolAxis(items: ProtocolAxisItem[]): ProtocolAxisItem[] {
  const residuals = items.filter(isResidual) as ResidualBucket[]
  if (residuals.length > 1) {
    throw new Error('attribution-primitive: at most one residual bucket permitted in axis P')
  }
  const explicit = items.filter((x) => !isResidual(x)) as Exclude<ProtocolAxisItem, ResidualBucket>[]
  explicit.sort((a, b) => {
    const ka = `${a.module_id}\u0000${a.module_version}`
    const kb = `${b.module_id}\u0000${b.module_version}`
    return ka < kb ? -1 : ka > kb ? 1 : 0
  })
  return [...explicit, ...residuals]
}

export function sortComputeAxis(items: ComputeAxisItem[]): ComputeAxisItem[] {
  const residuals = items.filter(isResidual) as ResidualBucket[]
  if (residuals.length > 1) {
    throw new Error('attribution-primitive: at most one residual bucket permitted in axis C')
  }
  const explicit = items.filter((x) => !isResidual(x)) as Exclude<ComputeAxisItem, ResidualBucket>[]
  explicit.sort((a, b) =>
    a.provider_did < b.provider_did ? -1 : a.provider_did > b.provider_did ? 1 : 0,
  )
  return [...explicit, ...residuals]
}

/** Governance axis is ordered by increasing depth (root principal first).
 *  Duplicate depths within the same chain are rejected. */
export function orderGovernanceAxis(items: GovernanceAxisEntry[]): GovernanceAxisEntry[] {
  const ordered = [...items].sort((a, b) => a.depth - b.depth)
  for (let i = 1; i < ordered.length; i++) {
    if (ordered[i].depth === ordered[i - 1].depth) {
      throw new Error(
        `attribution-primitive: governance axis has duplicate depth ${ordered[i].depth}`,
      )
    }
  }
  return ordered
}

/** Normalize all four axes to their canonical ordering. Callers can hand us
 *  unsorted input; the primitive never emits unsorted canonical bytes. */
export function normalizeAxes(axes: AttributionAxes): AttributionAxes {
  return {
    D: sortDataAxis(axes.D),
    P: sortProtocolAxis(axes.P),
    G: orderGovernanceAxis(axes.G),
    C: sortComputeAxis(axes.C),
  }
}

/** SHA-256(canonical(axis_content)) as raw 32 bytes. §2.1. */
export function hashAxisLeaf(axis: unknown): Buffer {
  return createHash('sha256').update(canonicalize(axis)).digest()
}

/** Internal Merkle node: SHA-256(left_bytes || right_bytes). §2.1. */
export function hashNode(left: Buffer, right: Buffer): Buffer {
  return createHash('sha256').update(Buffer.concat([left, right])).digest()
}

/** Hex sha256 of canonicalize(envelope). Used for signing and for deriving
 *  action_ref from the action tuple. */
export function canonicalHashHex(obj: unknown): string {
  return createHash('sha256').update(canonicalize(obj)).digest('hex')
}

/** The canonical envelope §2.3 that Ed25519 signs. Returned as a string so
 *  Python and TypeScript sign/verify exactly the same bytes. */
export function envelopeBytes(env: AttributionEnvelope): string {
  assertCanonicalTimestamp(env.timestamp)
  return canonicalize({
    action_ref: env.action_ref,
    merkle_root: env.merkle_root,
    issuer: env.issuer,
    timestamp: env.timestamp,
  })
}

/** Type-safe enumeration of axis tags, for iteration. */
export const ATTRIBUTION_AXIS_TAGS: ReadonlyArray<AttributionAxisTag> = ['D', 'P', 'G', 'C']
