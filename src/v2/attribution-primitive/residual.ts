// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Primitive — residual-bucket aggregation (§4.1)
// ══════════════════════════════════════════════════════════════════
// Taint-explosion mitigation: contributions with weight < MIN_WEIGHT pool
// into a named per-axis residual bucket. The bucket has its own identifier
// and one entry in the axis. Individual pooled contributors can prove
// inclusion via the bucket's pooled_contributors_hash without the axis
// content enumerating them — keeps receipts bounded even when a long tail
// of sub-threshold contributors participated.
//
// The primitive only covers aggregation. Distribution policy (pre-threshold
// proportional per §4.1 default, or equal-split, or governance-steward) is
// gateway-side — not in this module.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalize } from '../../core/canonical.js'
import { toWeightString } from './canonical.js'
import type {
  ComputeAxisEntry,
  ComputeAxisItem,
  DataAxisEntry,
  DataAxisItem,
  ProtocolAxisEntry,
  ProtocolAxisItem,
  ResidualBucket,
} from './types.js'

export const DEFAULT_MIN_WEIGHT = 0.001

function isResidual(x: unknown): x is ResidualBucket {
  return (
    typeof x === 'object' &&
    x !== null &&
    'residual_id' in (x as object) &&
    typeof (x as ResidualBucket).residual_id === 'string' &&
    (x as ResidualBucket).residual_id.startsWith('residual:')
  )
}

function weightNumber(w: string): number {
  const n = Number.parseFloat(w)
  if (!Number.isFinite(n)) throw new Error(`attribution-primitive: invalid weight string "${w}"`)
  return n
}

/** Merkle commitment over the pooled contributor list, sorted
 *  lexicographically by DID. §4.1. Returned as hex sha256.
 *
 *  This is a content-addressed commitment — NOT a structural Merkle tree
 *  with inclusion paths. The inclusion-proof variant (which would require
 *  emitting sibling paths per pooled contributor) is deployment policy.
 *  For the reference implementation we commit to the canonicalized list. */
function pooledContributorsHash(entries: ReadonlyArray<{ did: string; weight: string }>): string {
  const sorted = [...entries].sort((a, b) => (a.did < b.did ? -1 : a.did > b.did ? 1 : 0))
  return createHash('sha256').update(canonicalize(sorted)).digest('hex')
}

export interface AggregateOptions {
  /** Threshold below which contributions pool into the residual bucket.
   *  Default 0.001 per spec §4.1. */
  minWeight?: number
}

export interface AggregationResult<T> {
  /** Entries retained (weight >= minWeight), with canonical weight strings. */
  retained: T[]
  /** Residual bucket summarizing the pooled contributors, or null if none
   *  were pooled. */
  residual: ResidualBucket | null
  /** Number of contributors that were pooled into the residual. */
  pooledCount: number
}

/** Apply the §4.1 threshold to a list of data-axis contributors. Returns
 *  the retained entries plus a residual bucket (or null). Input entries
 *  that are already ResidualBucket objects are preserved in `retained`
 *  untouched. */
export function aggregateDataAxis(
  entries: DataAxisItem[],
  opts: AggregateOptions = {},
): AggregationResult<DataAxisItem> {
  const minWeight = opts.minWeight ?? DEFAULT_MIN_WEIGHT
  const retained: DataAxisItem[] = []
  const pooled: { did: string; weight: string }[] = []
  let totalPooled = 0

  for (const e of entries) {
    if (isResidual(e)) {
      retained.push(e)
      continue
    }
    const canonicalWeight = toWeightString(e.contribution_weight)
    const w = weightNumber(canonicalWeight)
    if (w < minWeight) {
      pooled.push({ did: (e as DataAxisEntry).source_did, weight: canonicalWeight })
      totalPooled += w
    } else {
      retained.push({ ...(e as DataAxisEntry), contribution_weight: canonicalWeight })
    }
  }

  if (pooled.length === 0) return { retained, residual: null, pooledCount: 0 }

  const residual: ResidualBucket = {
    residual_id: 'residual:D',
    total_pooled_weight: toWeightString(totalPooled),
    count_of_pooled_contributors: pooled.length,
    pooled_contributors_hash: pooledContributorsHash(pooled),
  }
  return { retained, residual, pooledCount: pooled.length }
}

/** Aggregate axis P entries by their optional `weight` field. Entries
 *  without a weight are retained unconditionally (the §4.1 threshold only
 *  applies when the issuer has chosen to emit per-module weights). */
export function aggregateProtocolAxis(
  entries: ProtocolAxisItem[],
  opts: AggregateOptions = {},
): AggregationResult<ProtocolAxisItem> {
  const minWeight = opts.minWeight ?? DEFAULT_MIN_WEIGHT
  const retained: ProtocolAxisItem[] = []
  const pooled: { did: string; weight: string }[] = []
  let totalPooled = 0

  for (const e of entries) {
    if (isResidual(e)) {
      retained.push(e)
      continue
    }
    const entry = e as ProtocolAxisEntry
    if (entry.weight === undefined) {
      retained.push(entry)
      continue
    }
    const canonicalWeight = toWeightString(entry.weight)
    const w = weightNumber(canonicalWeight)
    if (w < minWeight) {
      pooled.push({ did: `${entry.module_id}@${entry.module_version}`, weight: canonicalWeight })
      totalPooled += w
    } else {
      retained.push({ ...entry, weight: canonicalWeight })
    }
  }

  if (pooled.length === 0) return { retained, residual: null, pooledCount: 0 }

  const residual: ResidualBucket = {
    residual_id: 'residual:P',
    total_pooled_weight: toWeightString(totalPooled),
    count_of_pooled_contributors: pooled.length,
    pooled_contributors_hash: pooledContributorsHash(pooled),
  }
  return { retained, residual, pooledCount: pooled.length }
}

/** Aggregate axis C entries by compute_share. Mirrors axis D. */
export function aggregateComputeAxis(
  entries: ComputeAxisItem[],
  opts: AggregateOptions = {},
): AggregationResult<ComputeAxisItem> {
  const minWeight = opts.minWeight ?? DEFAULT_MIN_WEIGHT
  const retained: ComputeAxisItem[] = []
  const pooled: { did: string; weight: string }[] = []
  let totalPooled = 0

  for (const e of entries) {
    if (isResidual(e)) {
      retained.push(e)
      continue
    }
    const entry = e as ComputeAxisEntry
    const canonicalWeight = toWeightString(entry.compute_share)
    const w = weightNumber(canonicalWeight)
    if (w < minWeight) {
      pooled.push({ did: entry.provider_did, weight: canonicalWeight })
      totalPooled += w
    } else {
      retained.push({ ...entry, compute_share: canonicalWeight })
    }
  }

  if (pooled.length === 0) return { retained, residual: null, pooledCount: 0 }

  const residual: ResidualBucket = {
    residual_id: 'residual:C',
    total_pooled_weight: toWeightString(totalPooled),
    count_of_pooled_contributors: pooled.length,
    pooled_contributors_hash: pooledContributorsHash(pooled),
  }
  return { retained, residual, pooledCount: pooled.length }
}
