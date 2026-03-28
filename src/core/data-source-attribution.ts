// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Module 40: Data Source Attribution — "The Pixel"
// ══════════════════════════════════════════════════════════════════════
// AppsFlyer answers: "which ad caused this install?"
// This answers: "which data source caused this output?"
//
// Three attribution models, customer picks:
//   equal     — every source gets equal share
//   access_weighted — more accesses = higher contribution
//   recency_weighted — more recent = higher contribution
//
// The weights are configurable, not hardcoded gospel.
// The Merkle tree makes it auditable. The signature makes it legal.
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
// Each model produces raw weights. Normalization happens after.

function computeWeights(
  grouped: Map<string, DataAccessReceipt[]>,
  model: DataAttributionModel,
  customWeights?: Map<string, number>,
): Map<string, number> {
  const weights = new Map<string, number>()

  switch (model) {
    case 'equal': {
      const w = 1 / grouped.size
      for (const sourceId of grouped.keys()) weights.set(sourceId, w)
      break
    }
    case 'access_weighted': {
      let total = 0
      for (const receipts of grouped.values()) total += receipts.length
      for (const [sourceId, receipts] of grouped) {
        weights.set(sourceId, total > 0 ? receipts.length / total : 0)
      }
      break
    }
    case 'recency_weighted': {
      // More recent access = higher weight. Uses exponential decay.
      const now = Date.now()
      const halfLifeMs = 24 * 60 * 60 * 1000 // 1 day half-life
      let totalDecay = 0
      const decays = new Map<string, number>()
      for (const [sourceId, receipts] of grouped) {
        const mostRecent = Math.max(...receipts.map(r => new Date(r.timestamp).getTime()))
        const age = now - mostRecent
        const decay = Math.pow(2, -age / halfLifeMs)
        decays.set(sourceId, decay)
        totalDecay += decay
      }
      for (const [sourceId, decay] of decays) {
        weights.set(sourceId, totalDecay > 0 ? decay / totalDecay : 0)
      }
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
  }

  return weights
}

// ── Compensation from Terms ──

function computeSourceCompensation(
  receipts: DataAccessReceipt[],
  weight: number,
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
      // Revenue share: percentage × weight (caller supplies revenue externally)
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
// The inverse of computeCollaborationAttribution.
// Given an output and the access receipts that fed it,
// compute fractional contribution per data source.
// ══════════════════════════════════════════════════════════════════════

export function computeDataSourceAttribution(opts: {
  outputArtifactId: string
  outputType: 'decision' | 'content' | 'model' | 'action'
  accessReceipts: DataAccessReceipt[]
  sourceDescriptors?: Map<string, string> // sourceReceiptId → human name
  model?: DataAttributionModel
  customWeights?: Map<string, number>
  generatorPublicKey: string
  generatorPrivateKey: string
}): DataSourceAttributionReport {
  const model = opts.model || 'access_weighted'

  // Group receipts by source
  const grouped = new Map<string, DataAccessReceipt[]>()
  for (const receipt of opts.accessReceipts) {
    const list = grouped.get(receipt.sourceReceiptId) || []
    list.push(receipt)
    grouped.set(receipt.sourceReceiptId, list)
  }

  // Compute weights
  const weights = computeWeights(grouped, model, opts.customWeights)

  // Build attribution entries
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

  // Sort by percentage descending
  sources.sort((a, b) => b.percentage - a.percentage)

  // Cryptographic commitment — sort for determinism across compute/verify
  allReceiptIds.sort()
  const merkleRoot = buildMerkleRoot(allReceiptIds)
  const entriesHash = sha256(canonicalize(sources))

  // Build unsigned report
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

  // Sign
  const signature = sign(canonicalize(report), opts.generatorPrivateKey)
  return { ...report, signature }
}

// ══════════════════════════════════════════════════════════════════════
// VERIFY: Check report integrity
// ══════════════════════════════════════════════════════════════════════

export function verifyDataSourceAttribution(
  report: DataSourceAttributionReport,
  publicKey: string,
): { valid: boolean; errors: string[] } {
  const errors: string[] = []

  // Verify signature
  const { signature, ...unsigned } = report
  if (!verify(canonicalize(unsigned), signature, publicKey)) {
    errors.push('Invalid attribution report signature')
  }

  // Verify entries hash
  const expectedHash = sha256(canonicalize(report.sources))
  if (report.entriesHash !== expectedHash) {
    errors.push('Entries hash mismatch — sources may have been tampered')
  }

  // Verify Merkle root — sort for determinism matching compute step
  const allReceiptIds = report.sources.flatMap(s => s.accessReceiptIds).sort()
  const expectedMerkle = buildMerkleRoot(allReceiptIds)
  if (report.merkleRoot !== expectedMerkle) {
    errors.push('Merkle root mismatch — receipt IDs may have been modified')
  }

  // Verify percentages sum to ~100
  const totalPct = report.sources.reduce((s, e) => s + e.percentage, 0)
  if (Math.abs(totalPct - 100) > 0.1) {
    errors.push(`Percentages sum to ${totalPct}, expected ~100`)
  }

  // Verify source count
  if (report.totalSources !== report.sources.length) {
    errors.push('Total sources count mismatch')
  }

  // Verify access event count
  const totalEvents = report.sources.reduce((s, e) => s + e.accessCount, 0)
  if (report.totalAccessEvents !== totalEvents) {
    errors.push('Total access events mismatch')
  }

  return { valid: errors.length === 0, errors }
}
