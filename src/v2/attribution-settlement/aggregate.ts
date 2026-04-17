// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Settlement — aggregation (Build C)
// ══════════════════════════════════════════════════════════════════
// Spec: BUILD-C-SETTLEMENT-PIPELINE.md §"The aggregation".
//
// Given a stream of Attribution Primitives whose timestamps fall within
// [t0, t1) (half-open; I-C5 / property test #7), compute:
//
//   - per-axis per-contributor total_weight (sum of signed weights)
//   - per-axis residual bucket aggregation
//   - per-axis balanced-Merkle axis_merkle_root
//   - input_receipts_hash (Merkle commitment over sorted action_refs)
//
// Axis weight sourcing:
//   D  contribution_weight (Build B normalized; sums to ~1 per receipt)
//   C  compute_share        (Build B normalized; sums to ~1 per receipt)
//   P  weight if present on every explicit entry; equal-split (1/|P|)
//      otherwise. Mixed-weight receipts fall back to the weights they
//      carry and omit unweighted entries — documented in the handoff.
//   G  equal-split (1/|G|) — governance axis has no weight field in
//      Build A. Equal-split preserves I-C2 conservation (Σ weights per
//      receipt = 1) without inventing economic meaning the spec declines
//      to define.
//
// Residual buckets are treated as a single virtual contributor per axis;
// their `total_pooled_weight` sums across the period (I-C6).
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalize } from '../../core/canonical.js'
import {
  assertCanonicalTimestamp,
} from '../attribution-primitive/canonical.js'
import type {
  AttributionAxisTag,
  AttributionPrimitive,
  ComputeAxisEntry,
  ComputeAxisItem,
  DataAxisEntry,
  DataAxisItem,
  GovernanceAxisEntry,
  ProtocolAxisEntry,
  ProtocolAxisItem,
  ResidualBucket,
} from '../attribution-primitive/types.js'
import { buildMerkleRoot, emptyAxisMerkleRoot, leafHash } from './merkle.js'
import type {
  SettlementAxisIndex,
  SettlementContributor,
  SettlementPeriod,
  SettlementRecord,
  SettlementResidualBucket,
} from './types.js'

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
  if (!Number.isFinite(n)) throw new Error(`attribution-settlement: invalid weight string "${w}"`)
  return n
}

function contributorLeafBody(c: SettlementContributor): {
  contributor_did: string
  total_weight: string
  contribution_count: number
} {
  return {
    contributor_did: c.contributor_did,
    total_weight: c.total_weight,
    contribution_count: c.contribution_count,
  }
}

/** Canonical per-contributor leaf hash — hex sha256 of the canonical
 *  body (contributor_did, total_weight, contribution_count). Exposed so
 *  contributor-query verifiers recompute the same bytes. */
export function contributorLeafHashHex(c: SettlementContributor): string {
  return createHash('sha256').update(canonicalize(contributorLeafBody(c))).digest('hex')
}

/** Residual-bucket leaf hash for the per-axis tree. Canonicalizes the
 *  full bucket object. */
export function residualLeafHashHex(r: SettlementResidualBucket): string {
  return createHash('sha256').update(canonicalize(r)).digest('hex')
}

interface AxisAccum {
  /** did → running weight sum + count */
  map: Map<string, { total: number; count: number }>
  /** pooled weight across all receipts' residuals on this axis */
  pooledWeight: number
  pooledMemberCount: number
  /** per-receipt pooled_contributors_hash values, lex-sorted before
   *  committing (I-C6): the settlement bucket's commitment is an
   *  aggregate over the set of per-receipt bucket commitments. */
  perReceiptResidualHashes: string[]
  /** Count of receipts that contributed to this axis (total_actions X). */
  totalActions: number
}

function emptyAccum(): AxisAccum {
  return {
    map: new Map(),
    pooledWeight: 0,
    pooledMemberCount: 0,
    perReceiptResidualHashes: [],
    totalActions: 0,
  }
}

function addContributor(accum: AxisAccum, did: string, weight: number): void {
  const cur = accum.map.get(did)
  if (cur) {
    cur.total += weight
    cur.count += 1
  } else {
    accum.map.set(did, { total: weight, count: 1 })
  }
}

function accumulateResidual(accum: AxisAccum, bucket: ResidualBucket): void {
  accum.pooledWeight += weightNumber(bucket.total_pooled_weight)
  accum.pooledMemberCount += bucket.count_of_pooled_contributors
  accum.perReceiptResidualHashes.push(bucket.pooled_contributors_hash)
}

function pooledWeightOfReceipt(residuals: ResidualBucket[]): number {
  let w = 0
  for (const r of residuals) w += weightNumber(r.total_pooled_weight)
  return w
}

function processDataAxis(items: DataAxisItem[], accum: AxisAccum): void {
  if (items.length === 0) return
  accum.totalActions += 1
  for (const item of items) {
    if (isResidual(item)) {
      accumulateResidual(accum, item)
    } else {
      const e = item as DataAxisEntry
      addContributor(accum, e.source_did, weightNumber(e.contribution_weight))
    }
  }
}

function processComputeAxis(items: ComputeAxisItem[], accum: AxisAccum): void {
  if (items.length === 0) return
  accum.totalActions += 1
  for (const item of items) {
    if (isResidual(item)) {
      accumulateResidual(accum, item)
    } else {
      const e = item as ComputeAxisEntry
      addContributor(accum, e.provider_did, weightNumber(e.compute_share))
    }
  }
}

function protocolEntryDid(e: ProtocolAxisEntry): string {
  return `${e.module_id}@${e.module_version}`
}

function processProtocolAxis(items: ProtocolAxisItem[], accum: AxisAccum): void {
  if (items.length === 0) return
  accum.totalActions += 1
  const explicit = items.filter((x) => !isResidual(x)) as ProtocolAxisEntry[]
  const residuals = items.filter((x) => isResidual(x)) as ResidualBucket[]
  for (const r of residuals) accumulateResidual(accum, r)

  const anyWeighted = explicit.some((e) => e.weight !== undefined)
  if (anyWeighted) {
    for (const e of explicit) {
      if (e.weight === undefined) continue
      addContributor(accum, protocolEntryDid(e), weightNumber(e.weight))
    }
  } else if (explicit.length > 0) {
    const budget = Math.max(0, 1 - pooledWeightOfReceipt(residuals))
    const w = budget / explicit.length
    for (const e of explicit) {
      addContributor(accum, protocolEntryDid(e), w)
    }
  }
}

function processGovernanceAxis(items: GovernanceAxisEntry[], accum: AxisAccum): void {
  if (items.length === 0) return
  accum.totalActions += 1
  const w = 1 / items.length
  for (const e of items) {
    addContributor(accum, e.signer_did, w)
  }
}

/** 6-digit decimal form for settlement weights. Unlike Build A's
 *  `toWeightString`, settlement weights can exceed 1.0 (they accumulate
 *  over many actions); the 6-digit precision is preserved. Rejects
 *  non-finite or negative values. */
export function formatSettlementWeight(v: number): string {
  if (!Number.isFinite(v)) {
    throw new Error(`attribution-settlement: weight must be finite, got ${v}`)
  }
  if (v < 0) {
    throw new Error(`attribution-settlement: weight must be non-negative, got ${v}`)
  }
  return v.toFixed(6)
}

function finalizeAxis(
  axis: AttributionAxisTag,
  accum: AxisAccum,
  period: SettlementPeriod,
): SettlementAxisIndex {
  const dids = [...accum.map.keys()].sort()
  const contributors: SettlementContributor[] = dids.map((did) => {
    const { total, count } = accum.map.get(did)!
    const totalStr = formatSettlementWeight(total)
    const leafBody = {
      contributor_did: did,
      total_weight: totalStr,
      contribution_count: count,
    }
    const merkle_leaf_hash = createHash('sha256')
      .update(canonicalize(leafBody))
      .digest('hex')
    return {
      contributor_did: did,
      total_weight: totalStr,
      contribution_count: count,
      merkle_leaf_hash,
    }
  })

  let residual_bucket: SettlementResidualBucket | null = null
  if (accum.pooledMemberCount > 0 || accum.perReceiptResidualHashes.length > 0) {
    if (axis === 'G') {
      throw new Error('attribution-settlement: governance axis cannot carry a residual bucket')
    }
    const sortedPerReceiptHashes = [...accum.perReceiptResidualHashes].sort()
    const pooled_contributors_hash = createHash('sha256')
      .update(canonicalize(sortedPerReceiptHashes))
      .digest('hex')
    const residual_id = (`residual:${axis}` as SettlementResidualBucket['residual_id'])
    residual_bucket = {
      residual_id,
      total_pooled_weight: formatSettlementWeight(accum.pooledWeight),
      count_of_pooled_contributors: accum.pooledMemberCount,
      pooled_contributors_hash,
    }
  }

  const leafHashes: Buffer[] = contributors.map((c) => Buffer.from(c.merkle_leaf_hash, 'hex'))
  if (residual_bucket) {
    leafHashes.push(Buffer.from(residualLeafHashHex(residual_bucket), 'hex'))
  }
  const axis_merkle_root =
    leafHashes.length === 0 ? emptyAxisMerkleRoot() : buildMerkleRoot(leafHashes).toString('hex')

  return {
    axis,
    period,
    total_actions: accum.totalActions,
    contributors,
    residual_bucket,
    axis_merkle_root,
  }
}

function assertPeriod(period: SettlementPeriod): void {
  if (!period || typeof period !== 'object') {
    throw new Error('attribution-settlement: period required')
  }
  assertCanonicalTimestamp(period.t0)
  assertCanonicalTimestamp(period.t1)
  if (Date.parse(period.t0) >= Date.parse(period.t1)) {
    throw new Error('attribution-settlement: period.t0 must be strictly before period.t1')
  }
  if (typeof period.period_id !== 'string' || period.period_id.length === 0) {
    throw new Error('attribution-settlement: period.period_id required')
  }
}

export interface AggregateOptions {
  /** Gateway DID that will sign the settlement record. */
  gateway_did: string
  /** Override issued_at (tests, replayed audits). Must be canonical. */
  issued_at?: string
  /** When false, throws on any receipt whose timestamp is outside
   *  [t0, t1). Default is true — out-of-period receipts are silently
   *  dropped so a caller can hand us an uncurated batch. */
  skipOutOfPeriod?: boolean
}

/** Compute the unsigned settlement record for `receipts` over `period`.
 *  Half-open interval [t0, t1) — receipts at exactly t1 are excluded.
 *  Returns the record minus its `signature` field; callers pass the
 *  result to `signSettlementRecord` to produce the signed record. */
export function aggregateAttributionPrimitives(
  receipts: AttributionPrimitive[],
  period: SettlementPeriod,
  options: AggregateOptions,
): Omit<SettlementRecord, 'signature'> {
  if (!Array.isArray(receipts)) {
    throw new Error('attribution-settlement: receipts must be an array')
  }
  if (!options || typeof options.gateway_did !== 'string' || options.gateway_did.length === 0) {
    throw new Error('attribution-settlement: options.gateway_did required')
  }
  assertPeriod(period)

  const t0 = Date.parse(period.t0)
  const t1 = Date.parse(period.t1)
  const skipOut = options.skipOutOfPeriod !== false

  const accums: Record<AttributionAxisTag, AxisAccum> = {
    D: emptyAccum(),
    P: emptyAccum(),
    G: emptyAccum(),
    C: emptyAccum(),
  }

  const inPeriod: AttributionPrimitive[] = []
  for (const r of receipts) {
    assertCanonicalTimestamp(r.timestamp)
    const ts = Date.parse(r.timestamp)
    if (ts < t0 || ts >= t1) {
      if (!skipOut) {
        throw new Error(
          `attribution-settlement: receipt ${r.action_ref} timestamp ${r.timestamp} outside period [${period.t0}, ${period.t1})`,
        )
      }
      continue
    }
    inPeriod.push(r)
  }

  for (const r of inPeriod) {
    processDataAxis(r.axes.D, accums.D)
    processProtocolAxis(r.axes.P, accums.P)
    processGovernanceAxis(r.axes.G, accums.G)
    processComputeAxis(r.axes.C, accums.C)
  }

  // Deep-clone period per axis so the shared-reference DAG doesn't trip
  // core/canonical.ts's cycle detector (which treats any revisit as a
  // cycle — a separate latent bug, worked around here). JSON-safe clone
  // is fine: period is three plain strings.
  const clonePeriod = (): SettlementPeriod => ({
    t0: period.t0,
    t1: period.t1,
    period_id: period.period_id,
  })
  const axes: SettlementRecord['axes'] = {
    D: finalizeAxis('D', accums.D, clonePeriod()),
    P: finalizeAxis('P', accums.P, clonePeriod()),
    G: finalizeAxis('G', accums.G, clonePeriod()),
    C: finalizeAxis('C', accums.C, clonePeriod()),
  }

  const sortedActionRefs = inPeriod.map((r) => r.action_ref).sort()
  const actionRefLeaves = sortedActionRefs.map((ref) => leafHash(ref))
  const input_receipts_hash =
    actionRefLeaves.length === 0
      ? emptyAxisMerkleRoot()
      : buildMerkleRoot(actionRefLeaves).toString('hex')

  const issued_at = options.issued_at ?? new Date().toISOString()
  assertCanonicalTimestamp(issued_at)

  return {
    schema: 'aps.settlement.v1',
    period,
    gateway_did: options.gateway_did,
    axes,
    input_receipts_hash,
    total_input_count: inPeriod.length,
    issued_at,
  }
}
