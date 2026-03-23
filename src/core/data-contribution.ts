// ══════════════════════════════════════════════════════════════════════
// Module 38: Data Contribution Ledger
// ══════════════════════════════════════════════════════════════════════
// Aggregation layer on top of Module 36A (Data Source Registration).
// Tracks who accessed what data, how many times, and what's owed.
//
// Key principle: receipts are the evidence, the ledger is the index.
// The ledger doesn't replace 36A — it aggregates 36A receipts into
// queryable contribution records with compensation accrual.
// ══════════════════════════════════════════════════════════════════════

import crypto from 'crypto'
import {
  DataAccessReceipt, DataTerms,
} from '../types/data-source.js'
import {
  ContributionRecord, ContributionQuery, SourceMetrics,
  AgentDataFootprint, CompensationAccrual,
} from '../types/data-contribution.js'

// ── Ledger State ──
// In-memory for now. Production would use a persistent store.

export interface ContributionLedger {
  records: Map<string, ContributionRecord>  // contributionId → record
  index: {
    bySource: Map<string, Set<string>>     // sourceReceiptId → contributionIds
    byAgent: Map<string, Set<string>>      // agentId → contributionIds
    byPrincipal: Map<string, Set<string>>  // principalId → contributionIds
  }
}

export function createContributionLedger(): ContributionLedger {
  return {
    records: new Map(),
    index: {
      bySource: new Map(),
      byAgent: new Map(),
      byPrincipal: new Map(),
    },
  }
}

// ── Compensation Computation ──

function computeCompensation(terms: DataTerms, accessCount: number): CompensationAccrual {
  const model = terms.compensation
  const base: CompensationAccrual = {
    model: model.type,
    totalOwed: 0,
    currency: 'usd',
    accessesBilled: accessCount,
    lastComputedAt: new Date().toISOString(),
  }

  switch (model.type) {
    case 'none':
    case 'attribution_only':
    case 'negotiate':
      return base
    case 'per_access':
      return { ...base, totalOwed: model.amount * accessCount, currency: model.currency }
    case 'revenue_share':
      // Revenue share requires external revenue data — track percentage only
      return { ...base, model: 'revenue_share', totalOwed: 0 }
    case 'pool':
      return { ...base, model: 'pool' }
    default:
      return base
  }
}

// ── Record a Contribution ──
// Takes a DataAccessReceipt from Module 36A and updates the ledger.

function ledgerKey(receipt: DataAccessReceipt): string {
  return `${receipt.sourceReceiptId}:${receipt.agentId}:${receipt.principalId}`
}

function addToIndex(index: Map<string, Set<string>>, key: string, id: string): void {
  if (!index.has(key)) index.set(key, new Set())
  index.get(key)!.add(id)
}

export function recordContribution(
  ledger: ContributionLedger,
  receipt: DataAccessReceipt,
  sourceDescriptor: string = '',
): ContributionRecord {
  ledgerKey(receipt) // validate receipt structure
  const existing = Array.from(ledger.records.values()).find(
    r => r.sourceReceiptId === receipt.sourceReceiptId
      && r.agentId === receipt.agentId
      && r.principalId === receipt.principalId,
  )

  if (existing) {
    // Update existing contribution record
    existing.accessCount += 1
    existing.lastAccessAt = receipt.timestamp
    if (!existing.purposes.includes(receipt.declaredPurpose)) {
      existing.purposes.push(receipt.declaredPurpose)
    }

    if (!existing.accessMethods.includes(receipt.accessMethod)) {
      existing.accessMethods.push(receipt.accessMethod)
    }
    existing.receiptIds.push(receipt.accessReceiptId)
    existing.compensationAccrued = computeCompensation(
      receipt.termsAtAccessTime, existing.accessCount,
    )
    return existing
  }

  // Create new contribution record
  const record: ContributionRecord = {
    contributionId: 'dcr_' + crypto.randomUUID(),
    sourceReceiptId: receipt.sourceReceiptId,
    sourceDescriptor,
    agentId: receipt.agentId,
    agentPublicKey: receipt.agentPublicKey,
    principalId: receipt.principalId,
    accessCount: 1,
    firstAccessAt: receipt.timestamp,
    lastAccessAt: receipt.timestamp,
    purposes: [receipt.declaredPurpose],
    accessMethods: [receipt.accessMethod],
    compensationAccrued: computeCompensation(receipt.termsAtAccessTime, 1),
    receiptIds: [receipt.accessReceiptId],
  }

  ledger.records.set(record.contributionId, record)
  addToIndex(ledger.index.bySource, receipt.sourceReceiptId, record.contributionId)
  addToIndex(ledger.index.byAgent, receipt.agentId, record.contributionId)
  addToIndex(ledger.index.byPrincipal, receipt.principalId, record.contributionId)

  return record
}

// ── Query Contributions ──

export function queryContributions(
  ledger: ContributionLedger,
  query: ContributionQuery,
): ContributionRecord[] {
  let candidates: ContributionRecord[]

  // Use index for fast lookup when possible
  if (query.sourceReceiptId && ledger.index.bySource.has(query.sourceReceiptId)) {
    const ids = ledger.index.bySource.get(query.sourceReceiptId)!
    candidates = Array.from(ids).map(id => ledger.records.get(id)!).filter(Boolean)
  } else if (query.agentId && ledger.index.byAgent.has(query.agentId)) {
    const ids = ledger.index.byAgent.get(query.agentId)!
    candidates = Array.from(ids).map(id => ledger.records.get(id)!).filter(Boolean)
  } else if (query.principalId && ledger.index.byPrincipal.has(query.principalId)) {
    const ids = ledger.index.byPrincipal.get(query.principalId)!
    candidates = Array.from(ids).map(id => ledger.records.get(id)!).filter(Boolean)
  } else {
    candidates = Array.from(ledger.records.values())
  }

  return candidates.filter(r => {
    if (query.sourceReceiptId && r.sourceReceiptId !== query.sourceReceiptId) return false
    if (query.agentId && r.agentId !== query.agentId) return false
    if (query.principalId && r.principalId !== query.principalId) return false
    if (query.purpose && !r.purposes.includes(query.purpose)) return false
    if (query.after && r.lastAccessAt < query.after) return false
    if (query.before && r.firstAccessAt > query.before) return false
    if (query.minAccessCount && r.accessCount < query.minAccessCount) return false
    return true
  })
}

// ── Source Metrics ──
// "Show me how many agents used our dataset this month and what's owed"

export function getSourceMetrics(
  ledger: ContributionLedger,
  sourceReceiptId: string,
): SourceMetrics | null {
  const records = queryContributions(ledger, { sourceReceiptId })
  if (records.length === 0) return null

  const uniqueAgents = new Set(records.map(r => r.agentId))
  const uniquePrincipals = new Set(records.map(r => r.principalId))
  const purposeBreakdown: Record<string, number> = {}
  let totalAccesses = 0
  let totalOwed = 0
  let currency = 'usd'

  for (const r of records) {
    totalAccesses += r.accessCount
    totalOwed += r.compensationAccrued.totalOwed
    currency = r.compensationAccrued.currency || currency
    for (const p of r.purposes) {
      purposeBreakdown[p] = (purposeBreakdown[p] || 0) + r.accessCount
    }
  }

  const topAgents = records
    .sort((a, b) => b.accessCount - a.accessCount)
    .slice(0, 10)
    .map(r => ({ agentId: r.agentId, accessCount: r.accessCount }))

  return {
    sourceReceiptId,
    sourceDescriptor: records[0]?.sourceDescriptor || '',
    totalAccesses,
    uniqueAgents: uniqueAgents.size,
    uniquePrincipals: uniquePrincipals.size,
    purposeBreakdown,
    compensationOwed: {
      model: records[0]?.compensationAccrued.model || 'none',
      totalOwed,
      currency,
      accessesBilled: totalAccesses,
      lastComputedAt: new Date().toISOString(),
    },
    firstAccess: records.reduce((min, r) => r.firstAccessAt < min ? r.firstAccessAt : min, records[0].firstAccessAt),
    lastAccess: records.reduce((max, r) => r.lastAccessAt > max ? r.lastAccessAt : max, records[0].lastAccessAt),
    topAgents,
  }
}

// ── Agent Data Footprint ──
// "Show me every data source this agent has touched"

export function getAgentDataFootprint(
  ledger: ContributionLedger,
  agentId: string,
): AgentDataFootprint | null {
  const records = queryContributions(ledger, { agentId })
  if (records.length === 0) return null

  let totalAccesses = 0
  let totalComp = 0
  let currency = 'usd'

  const sources = records.map(r => {
    totalAccesses += r.accessCount
    totalComp += r.compensationAccrued.totalOwed
    currency = r.compensationAccrued.currency || currency
    const status = r.compensationAccrued.model === 'none' ? 'none' as const
      : r.compensationAccrued.model === 'attribution_only' ? 'attribution_only' as const
      : r.compensationAccrued.totalOwed > 0 ? 'accruing' as const : 'none' as const
    return {
      sourceReceiptId: r.sourceReceiptId,
      sourceDescriptor: r.sourceDescriptor,
      accessCount: r.accessCount,
      purposes: r.purposes,
      lastAccess: r.lastAccessAt,
      compensationStatus: status,
    }
  })

  return {
    agentId,
    agentPublicKey: records[0].agentPublicKey,
    principalId: records[0].principalId,
    sourcesAccessed: sources,
    totalSources: records.length,
    totalAccesses,
    totalCompensationAccrued: totalComp,
    currency,
  }
}
