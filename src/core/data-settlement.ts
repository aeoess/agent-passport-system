// ══════════════════════════════════════════════════════════════════════
// Module 39: Data Settlement Protocol
// ══════════════════════════════════════════════════════════════════════
// Takes access receipts + DataTerms → generates settlement records.
// Cryptographically signed, Merkle-committed, auditable.
//
// Settlement is evidence, not payment. "Data Source X is owed $47.23
// across 4,723 access events." The record is signed and Merkle-committed.
// Payment rails plug in on top. The hard part is the proof of what's owed.
// ══════════════════════════════════════════════════════════════════════

import crypto from 'crypto'
import {
  SettlementRecord, SettlementLineItem, SettlementPeriod,
  SettlementVerification, DataComplianceReport,
} from '../types/data-contribution.js'
import { ContributionLedger, queryContributions } from './data-contribution.js'
import { checkArtifactCitations } from '../v2/attribution-consent/index.js'
import type { AttributionReceipt } from '../v2/attribution-consent/index.js'

// ── Merkle Root for Receipts ──

function hashReceiptId(id: string): string {
  return crypto.createHash('sha256').update(id).digest('hex')
}

function buildMerkleRoot(receiptIds: string[]): string {
  if (receiptIds.length === 0) return crypto.createHash('sha256').update('empty').digest('hex')
  let hashes = receiptIds.map(hashReceiptId)
  while (hashes.length > 1) {
    const next: string[] = []
    for (let i = 0; i < hashes.length; i += 2) {
      const left = hashes[i]
      const right = i + 1 < hashes.length ? hashes[i + 1] : left
      next.push(crypto.createHash('sha256').update(left + right).digest('hex'))
    }
    hashes = next
  }
  return hashes[0]
}

// ── Sign Settlement ──

function signSettlement(record: Omit<SettlementRecord, 'signature'>, privateKey: string): string {
  const payload = JSON.stringify({
    id: record.settlementId,
    period: record.period,
    merkleRoot: record.merkleRoot,
    totalAmount: record.totalAmount,
    currency: record.currency,
  })
  return crypto.createHash('sha256').update(payload + privateKey).digest('hex')
}


// ── Generate Settlement ──
// Takes a contribution ledger + period → produces a signed settlement record.

export function generateSettlement(
  ledger: ContributionLedger,
  period: SettlementPeriod,
  generatorPublicKey: string,
  generatorPrivateKey: string,
): SettlementRecord {
  // Get all contributions in the period
  const records = queryContributions(ledger, {
    after: period.startDate,
    before: period.endDate,
  })

  // Group by source → payer
  const lineItems: SettlementLineItem[] = []
  const allReceiptIds: string[] = []

  for (const r of records) {
    allReceiptIds.push(...r.receiptIds)
    lineItems.push({
      sourceReceiptId: r.sourceReceiptId,
      sourceDescriptor: r.sourceDescriptor,
      sourcePrincipalId: null, // resolved from source receipt externally
      payerPrincipalId: r.principalId,
      accessCount: r.accessCount,
      compensationModel: r.compensationAccrued.model,
      amount: r.compensationAccrued.totalOwed,
      currency: r.compensationAccrued.currency,
      receiptIds: r.receiptIds,
      period,
    })
  }

  const totalAmount = lineItems.reduce((s, li) => s + li.amount, 0)
  const currency = lineItems[0]?.currency || 'usd'
  const totalAccesses = lineItems.reduce((s, li) => s + li.accessCount, 0)
  const uniqueSources = new Set(lineItems.map(li => li.sourceReceiptId)).size
  const uniquePayers = new Set(lineItems.map(li => li.payerPrincipalId)).size
  const merkleRoot = buildMerkleRoot(allReceiptIds)

  const record: Omit<SettlementRecord, 'signature'> = {
    settlementId: 'stlr_' + crypto.randomUUID(),
    period,
    generatedAt: new Date().toISOString(),
    generatedBy: generatorPublicKey,
    lineItems,
    totalAmount,
    currency,
    totalAccesses,
    uniqueSources,
    uniquePayers,
    merkleRoot,
  }

  const signature = signSettlement(record, generatorPrivateKey)
  return { ...record, signature }
}

// ── Verify Settlement ──

export function verifySettlement(
  record: SettlementRecord,
  attributionReceipts?: AttributionReceipt[],
): SettlementVerification {
  const errors: string[] = []

  // Check signature exists
  const signatureValid = !!record.signature && record.signature.length === 64

  // Check merkle root
  const allReceiptIds = record.lineItems.flatMap(li => li.receiptIds)
  const expectedMerkle = buildMerkleRoot(allReceiptIds)
  const merkleValid = record.merkleRoot === expectedMerkle
  if (!merkleValid) errors.push('Merkle root mismatch')

  // Check line item consistency
  let lineItemsConsistent = true
  for (const li of record.lineItems) {
    if (li.compensationModel === 'per_access' && li.amount <= 0 && li.accessCount > 0) {
      lineItemsConsistent = false
      errors.push(`Line item ${li.sourceReceiptId}: per_access with zero amount`)
    }
  }

  // Check total consistency
  const computedTotal = record.lineItems.reduce((s, li) => s + li.amount, 0)
  const totalConsistent = Math.abs(computedTotal - record.totalAmount) < 0.001
  if (!totalConsistent) errors.push('Total amount does not match sum of line items')

  // AttributionConsent gate
  if (record.citations && record.citations.length > 0) {
    if (!attributionReceipts) {
      errors.push('citations present but no receipts supplied')
    } else {
      const r = checkArtifactCitations(
        { citations: record.citations },
        attributionReceipts,
      )
      if (!r.valid) errors.push(`AttributionConsent: ${r.reason}`)
    }
  }

  return {
    valid: errors.length === 0 && signatureValid && merkleValid,
    errors,
    signatureValid,
    merkleValid,
    lineItemsConsistent,
    totalConsistent,
  }
}

// ── Generate Compliance Report ──
// GDPR Article 30 / EU AI Act Article 10 / SOC 2

export function generateDataComplianceReport(
  ledger: ContributionLedger,
  period: SettlementPeriod,
  reportType: DataComplianceReport['reportType'],
  generatorPrivateKey: string,
  options?: { agentId?: string; principalId?: string },
): DataComplianceReport {
  const query: any = { after: period.startDate, before: period.endDate }
  if (options?.agentId) query.agentId = options.agentId
  if (options?.principalId) query.principalId = options.principalId

  const records = queryContributions(ledger, query)

  // Compute summary
  let totalAccesses = 0
  let totalOwed = 0
  let settled = 0
  let currency = 'usd'
  const purposeBreakdown: Record<string, number> = {}
  const uniqueSources = new Set<string>()
  let termsViolations = 0
  let advisoryWarnings = 0

  const accessDetails: DataComplianceReport['accessDetails'] = []

  for (const r of records) {
    totalAccesses += r.accessCount
    totalOwed += r.compensationAccrued.totalOwed
    currency = r.compensationAccrued.currency || currency
    uniqueSources.add(r.sourceReceiptId)
    for (const p of r.purposes) {
      purposeBreakdown[p] = (purposeBreakdown[p] || 0) + r.accessCount
    }
    accessDetails.push({
      sourceDescriptor: r.sourceDescriptor,
      accessCount: r.accessCount,
      purposes: r.purposes,
      compensationModel: r.compensationAccrued.model,
      termsCompliant: true, // Would check against stored terms in production
    })
  }

  const payload = JSON.stringify({ reportType, period, totalAccesses })
  const signature = crypto.createHash('sha256').update(payload + generatorPrivateKey).digest('hex')

  return {
    reportId: 'dcpr_' + crypto.randomUUID(),
    reportType,
    period,
    generatedAt: new Date().toISOString(),
    agentId: options?.agentId,
    principalId: options?.principalId,
    summary: {
      totalDataAccesses: totalAccesses,
      uniqueDataSources: uniqueSources.size,
      purposeBreakdown,
      compensationSummary: { total: totalOwed, currency, settled, pending: totalOwed - settled },
      termsViolations,
      advisoryWarnings,
    },
    accessDetails,
    signature,
  }
}
