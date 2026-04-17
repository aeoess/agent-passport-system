// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Module 40: Data Source Attribution — SDK primitive ("the pixel")
// ══════════════════════════════════════════════════════════════════════
// SDK retains:
//   • Merkle commitment primitives + signed report shape
//   • computeDataSourceAttribution / verifyDataSourceAttribution
//   • Two attribution models the schema needs to be self-contained:
//       'equal'  — uniform per source (schema baseline)
//       'custom' — caller supplies a weight per source
//
// MOVED to @aeoess/gateway src/sdk-migrated/core/attribution-models.ts
// (2026-04-17): the policy-bearing weighted models — access_weighted
// and recency_weighted with their hardcoded constants (e.g. 1-day
// half-life). Those constants are gateway product policy: the choice
// of half-life is a tuning decision per pricing surface, not a
// protocol primitive.
//
// To use a weighted model, callers run the gateway helper to compute
// the weights and then call computeDataSourceAttribution with
// model='custom' and the resulting customWeights map.
// ══════════════════════════════════════════════════════════════════════

import crypto from 'crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type { DataAccessReceipt } from '../types/data-source.js'
import type {
  DataAttributionModel,
  DataSourceAttributionEntry,
  DataSourceAttributionReport,
} from '../types/data-contribution.js'

// ── Hash Primitives ──

function sha256(data: string): string {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex')
}

function buildMerkleRoot(ids: string[]): string {
  if (ids.length === 0) return sha256('empty')
  let hashes = ids.map(id => sha256(id))
  while (hashes.length > 1) {
    const next: string[] = []
    for (let i = 0; i < hashes.length; i += 2) {
      const left = hashes[i]
      const right = i + 1 < hashes.length ? hashes[i + 1] : left
      next.push(sha256(left + right))
    }
    hashes = next
  }
  return hashes[0]
}

// ── Weight Computation ──
// SDK only knows two models: 'equal' (uniform) and 'custom' (caller
// supplies weights). access_weighted / recency_weighted moved to the
// gateway's attribution-models.ts. Calling those models here throws.

const WEIGHTED_MOVED_MSG =
  "attribution model %s requires gateway policy and moved to " +
  "@aeoess/gateway src/sdk-migrated/core/attribution-models.ts. " +
  "Use the gateway helper to compute weights, then call " +
  "computeDataSourceAttribution with model='custom' and the resulting customWeights."

function computeWeights(
  grouped: Map<string, DataAccessReceipt[]>,
  model: DataAttributionModel,
  customWeights?: Map<string, number>,
): Map<string, number> {
  const weights = new Map<string, number>()

  switch (model) {
    case 'equal': {
      const w = grouped.size > 0 ? 1 / grouped.size : 0
      for (const sourceId of grouped.keys()) weights.set(sourceId, w)
      break
    }
    case 'custom': {
      if (!customWeights) throw new Error('Custom model requires customWeights map')
      let total = 0
      for (const w of customWeights.values()) total += w
      for (const [sourceId] of grouped) {
        const w = customWeights.get(sourceId) ?? 0
        weights.set(sourceId, total > 0 ? w / total : 0)
      }
      break
    }
    case 'access_weighted':
    case 'recency_weighted':
      throw new Error(WEIGHTED_MOVED_MSG.replace('%s', `'${model}'`))
    default:
      throw new Error(`Unknown attribution model: ${model}`)
  }

  return weights
}

// ── Compensation from Terms ──

function computeSourceCompensation(
  receipts: DataAccessReceipt[],
  _weight: number,
): { amount: number; currency: string; model: string } {
  if (receipts.length === 0) return { amount: 0, currency: 'usd', model: 'none' }
  const terms = receipts[0].termsAtAccessTime
  const comp = terms.compensation
  switch (comp.type) {
    case 'none':
    case 'attribution_only':
    case 'negotiate':
      return { amount: 0, currency: 'usd', model: comp.type }
    case 'per_access':
      return { amount: comp.amount * receipts.length, currency: comp.currency, model: 'per_access' }
    case 'revenue_share':
      return { amount: 0, currency: 'usd', model: 'revenue_share' }
    case 'pool':
      return { amount: 0, currency: 'usd', model: 'pool' }
    default:
      return { amount: 0, currency: 'usd', model: 'none' }
  }
}

// ══════════════════════════════════════════════════════════════════════
// MAIN FUNCTION: computeDataSourceAttribution
// ══════════════════════════════════════════════════════════════════════
// The inverse of computeCollaborationAttribution. SDK schema-level
// implementation: model is 'equal' or 'custom'. Default is 'equal' —
// the baseline anyone can compute without taking on gateway policy.
// ══════════════════════════════════════════════════════════════════════

export function computeDataSourceAttribution(opts: {
  outputArtifactId: string
  outputType: 'decision' | 'content' | 'model' | 'action'
  accessReceipts: DataAccessReceipt[]
  sourceDescriptors?: Map<string, string>
  /** SDK supports 'equal' or 'custom'. Weighted models live in gateway. */
  model?: DataAttributionModel
  customWeights?: Map<string, number>
  generatorPublicKey: string
  generatorPrivateKey: string
}): DataSourceAttributionReport {
  const model = opts.model ?? 'equal'

  const grouped = new Map<string, DataAccessReceipt[]>()
  for (const receipt of opts.accessReceipts) {
    const list = grouped.get(receipt.sourceReceiptId) || []
    list.push(receipt)
    grouped.set(receipt.sourceReceiptId, list)
  }

  const weights = computeWeights(grouped, model, opts.customWeights)

  const allReceiptIds: string[] = []
  const sources: DataSourceAttributionEntry[] = []
  let totalCompensation = 0
  let currency = 'usd'

  for (const [sourceId, receipts] of grouped) {
    const weight = weights.get(sourceId) || 0
    const percentage = Math.round(weight * 10000) / 100
    const receiptIds = receipts.map(r => r.accessReceiptId)
    allReceiptIds.push(...receiptIds)
    const comp = computeSourceCompensation(receipts, weight)
    totalCompensation += comp.amount
    currency = comp.currency

    sources.push({
      sourceReceiptId: sourceId,
      sourceDescriptor: opts.sourceDescriptors?.get(sourceId) || '',
      accessReceiptIds: receiptIds,
      accessCount: receipts.length,
      weight: Math.round(weight * 10000) / 10000,
      percentage,
      compensationOwed: comp.amount,
      currency: comp.currency,
      compensationModel: comp.model,
    })
  }

  sources.sort((a, b) => b.percentage - a.percentage)

  allReceiptIds.sort()
  const merkleRoot = buildMerkleRoot(allReceiptIds)
  const entriesHash = sha256(canonicalize(sources))

  const report: Omit<DataSourceAttributionReport, 'signature'> = {
    reportId: 'dsar_' + crypto.randomUUID(),
    outputArtifactId: opts.outputArtifactId,
    outputType: opts.outputType,
    sources,
    attributionModel: model,
    totalSources: sources.length,
    totalAccessEvents: allReceiptIds.length,
    totalCompensation: Math.round(totalCompensation * 100) / 100,
    currency,
    merkleRoot,
    entriesHash,
    generatedAt: new Date().toISOString(),
    generatedBy: opts.generatorPublicKey,
  }

  const signature = sign(canonicalize(report), opts.generatorPrivateKey)
  return { ...report, signature }
}

// ══════════════════════════════════════════════════════════════════════
// VERIFY — pure
// ══════════════════════════════════════════════════════════════════════

export function verifyDataSourceAttribution(
  report: DataSourceAttributionReport,
  publicKey: string,
): { valid: boolean; errors: string[] } {
  const errors: string[] = []

  const { signature, ...unsigned } = report
  if (!verify(canonicalize(unsigned), signature, publicKey)) {
    errors.push('Invalid attribution report signature')
  }

  const expectedHash = sha256(canonicalize(report.sources))
  if (report.entriesHash !== expectedHash) {
    errors.push('Entries hash mismatch — sources may have been tampered')
  }

  const allReceiptIds = report.sources.flatMap(s => s.accessReceiptIds).sort()
  const expectedMerkle = buildMerkleRoot(allReceiptIds)
  if (report.merkleRoot !== expectedMerkle) {
    errors.push('Merkle root mismatch — receipt IDs may have been modified')
  }

  const totalPct = report.sources.reduce((s, e) => s + e.percentage, 0)
  if (Math.abs(totalPct - 100) > 0.1) {
    errors.push(`Percentages sum to ${totalPct}, expected ~100`)
  }

  if (report.totalSources !== report.sources.length) {
    errors.push('Total sources count mismatch')
  }

  const totalEvents = report.sources.reduce((s, e) => s + e.accessCount, 0)
  if (report.totalAccessEvents !== totalEvents) {
    errors.push('Total access events mismatch')
  }

  return { valid: errors.length === 0, errors }
}
