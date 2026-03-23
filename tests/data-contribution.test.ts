import { describe, it } from 'node:test'
import assert from 'node:assert'
import {
  createContributionLedger,
  recordContribution,
  queryContributions,
  getSourceMetrics,
  getAgentDataFootprint,
} from '../src/core/data-contribution.js'
import {
  generateSettlement,
  verifySettlement,
  generateDataComplianceReport,
} from '../src/core/data-settlement.js'
import type { DataAccessReceipt, DataTerms } from '../src/types/data-source.js'

// ── Test Helpers ──

const TERMS_PER_ACCESS: DataTerms = {
  allowedPurposes: ['read', 'analyze', 'summarize'],
  requireAttribution: true,
  requireNotification: false,
  compensation: { type: 'per_access', amount: 0.01, currency: 'usd' },
  derivativePolicy: 'attribution_required',
  auditVisibility: 'source_and_principal',
  revocable: false,
}

const TERMS_FREE: DataTerms = {
  allowedPurposes: ['read', 'analyze'],
  requireAttribution: false,
  requireNotification: false,
  compensation: { type: 'none' },
  derivativePolicy: 'unrestricted',
  auditVisibility: 'public',
  revocable: false,
}

let receiptCounter = 0
function mockReceipt(overrides: Partial<DataAccessReceipt> = {}): DataAccessReceipt {
  receiptCounter++
  return {
    accessReceiptId: `dacr_test_${receiptCounter}`,
    sourceReceiptId: 'srcr_dataset_001',
    sourceMode: 'self_attested',

    dataHash: 'abc123',
    agentId: 'agent_research_bot',
    agentPublicKey: 'pubkey_agent_001',
    principalId: 'principal_tima',
    executionFrameId: `frame_${receiptCounter}`,
    accessScope: 'data:read',
    accessMethod: 'api_call',
    declaredPurpose: 'analyze',
    termsAtAccessTime: TERMS_PER_ACCESS,
    timestamp: new Date().toISOString(),
    gatewayId: 'gw_001',
    gatewayPublicKey: 'gw_pubkey',
    gatewaySignature: 'gw_sig',
    ...overrides,
  } as DataAccessReceipt
}

// ══════════════════════════════════════
// Module 38: Data Contribution Ledger
// ══════════════════════════════════════

describe('Data Contribution Ledger — Recording', () => {
  it('creates new contribution record from first receipt', () => {
    const ledger = createContributionLedger()
    const receipt = mockReceipt()
    const record = recordContribution(ledger, receipt, 'Test Dataset')
    assert.ok(record.contributionId.startsWith('dcr_'))
    assert.strictEqual(record.accessCount, 1)
    assert.strictEqual(record.sourceReceiptId, 'srcr_dataset_001')
    assert.deepStrictEqual(record.purposes, ['analyze'])
  })

  it('aggregates multiple receipts into same contribution record', () => {
    const ledger = createContributionLedger()
    const r1 = mockReceipt({ declaredPurpose: 'analyze' })
    const r2 = mockReceipt({ declaredPurpose: 'summarize' })
    recordContribution(ledger, r1, 'Test Dataset')
    const record = recordContribution(ledger, r2, 'Test Dataset')
    assert.strictEqual(record.accessCount, 2)
    assert.deepStrictEqual(record.purposes, ['analyze', 'summarize'])
    assert.strictEqual(record.receiptIds.length, 2)
  })

  it('computes per_access compensation correctly', () => {
    const ledger = createContributionLedger()
    for (let i = 0; i < 100; i++) recordContribution(ledger, mockReceipt(), 'Dataset')
    const records = queryContributions(ledger, { sourceReceiptId: 'srcr_dataset_001' })
    assert.strictEqual(records[0].compensationAccrued.totalOwed, 1.0) // 100 * $0.01
    assert.strictEqual(records[0].compensationAccrued.currency, 'usd')
  })

  it('creates separate records for different agents', () => {
    const ledger = createContributionLedger()
    recordContribution(ledger, mockReceipt({ agentId: 'agent_A' }), 'Dataset')
    recordContribution(ledger, mockReceipt({ agentId: 'agent_B' }), 'Dataset')
    assert.strictEqual(ledger.records.size, 2)
  })

  it('indexes by source, agent, and principal', () => {
    const ledger = createContributionLedger()
    recordContribution(ledger, mockReceipt(), 'Dataset')
    assert.ok(ledger.index.bySource.has('srcr_dataset_001'))
    assert.ok(ledger.index.byAgent.has('agent_research_bot'))
    assert.ok(ledger.index.byPrincipal.has('principal_tima'))
  })
})

describe('Data Contribution Ledger — Querying', () => {
  it('queries by source receipt ID', () => {
    const ledger = createContributionLedger()
    recordContribution(ledger, mockReceipt({ sourceReceiptId: 'src_A' }), 'A')
    recordContribution(ledger, mockReceipt({ sourceReceiptId: 'src_B' }), 'B')
    const results = queryContributions(ledger, { sourceReceiptId: 'src_A' })
    assert.strictEqual(results.length, 1)
    assert.strictEqual(results[0].sourceDescriptor, 'A')
  })

  it('queries by agent ID', () => {
    const ledger = createContributionLedger()
    recordContribution(ledger, mockReceipt({ agentId: 'bot_1', sourceReceiptId: 'x1' }), 'X')
    recordContribution(ledger, mockReceipt({ agentId: 'bot_2', sourceReceiptId: 'x2' }), 'Y')
    const results = queryContributions(ledger, { agentId: 'bot_1' })
    assert.strictEqual(results.length, 1)
  })

  it('queries by purpose', () => {
    const ledger = createContributionLedger()
    recordContribution(ledger, mockReceipt({ declaredPurpose: 'train', sourceReceiptId: 's1' }), 'T')
    recordContribution(ledger, mockReceipt({ declaredPurpose: 'read', sourceReceiptId: 's2' }), 'R')
    const results = queryContributions(ledger, { purpose: 'train' })
    assert.strictEqual(results.length, 1)
  })

  it('queries with min access count filter', () => {
    const ledger = createContributionLedger()
    for (let i = 0; i < 5; i++) recordContribution(ledger, mockReceipt({ sourceReceiptId: 'heavy' }), 'H')
    recordContribution(ledger, mockReceipt({ sourceReceiptId: 'light', agentId: 'other' }), 'L')
    const results = queryContributions(ledger, { minAccessCount: 3 })
    assert.strictEqual(results.length, 1)
    assert.strictEqual(results[0].sourceDescriptor, 'H')
  })
})

describe('Data Contribution Ledger — Source Metrics', () => {
  it('computes source metrics across multiple agents', () => {
    const ledger = createContributionLedger()
    for (let i = 0; i < 10; i++) recordContribution(ledger, mockReceipt({ agentId: 'a1', sourceReceiptId: 'src_main' }), 'Main')
    for (let i = 0; i < 5; i++) recordContribution(ledger, mockReceipt({ agentId: 'a2', sourceReceiptId: 'src_main' }), 'Main')
    const metrics = getSourceMetrics(ledger, 'src_main')!
    assert.strictEqual(metrics.totalAccesses, 15)
    assert.strictEqual(metrics.uniqueAgents, 2)
    assert.ok(Math.abs(metrics.compensationOwed.totalOwed - 0.15) < 0.001) // 15 * $0.01
    assert.strictEqual(metrics.topAgents.length, 2)
    assert.strictEqual(metrics.topAgents[0].accessCount, 10) // a1 has more
  })

  it('returns null for unknown source', () => {
    const ledger = createContributionLedger()
    assert.strictEqual(getSourceMetrics(ledger, 'nonexistent'), null)
  })
})

describe('Data Contribution Ledger — Agent Footprint', () => {
  it('tracks all sources an agent accessed', () => {
    const ledger = createContributionLedger()
    recordContribution(ledger, mockReceipt({ sourceReceiptId: 'ds_1' }), 'Dataset 1')
    recordContribution(ledger, mockReceipt({ sourceReceiptId: 'ds_2' }), 'Dataset 2')
    recordContribution(ledger, mockReceipt({ sourceReceiptId: 'ds_3' }), 'Dataset 3')
    const footprint = getAgentDataFootprint(ledger, 'agent_research_bot')!
    assert.strictEqual(footprint.totalSources, 3)
    assert.strictEqual(footprint.totalAccesses, 3)
    assert.strictEqual(footprint.totalCompensationAccrued, 0.03)
  })
})

// ══════════════════════════════════════
// Module 39: Data Settlement Protocol
// ══════════════════════════════════════

describe('Data Settlement — Generation', () => {
  it('generates a signed settlement record', () => {
    const ledger = createContributionLedger()
    for (let i = 0; i < 50; i++) recordContribution(ledger, mockReceipt(), 'Dataset')
    const period = { startDate: '2026-01-01', endDate: '2026-12-31', periodLabel: '2026' }
    const settlement = generateSettlement(ledger, period, 'gen_pub', 'gen_priv')
    assert.ok(settlement.settlementId.startsWith('stlr_'))
    assert.strictEqual(settlement.totalAccesses, 50)
    assert.strictEqual(settlement.totalAmount, 0.50) // 50 * $0.01
    assert.strictEqual(settlement.uniqueSources, 1)
    assert.ok(settlement.merkleRoot.length === 64)
    assert.ok(settlement.signature.length === 64)
  })

  it('handles multiple sources in one settlement', () => {
    const ledger = createContributionLedger()
    for (let i = 0; i < 20; i++) recordContribution(ledger, mockReceipt({ sourceReceiptId: 'src_A', agentId: 'a1' }), 'A')
    for (let i = 0; i < 30; i++) recordContribution(ledger, mockReceipt({ sourceReceiptId: 'src_B', agentId: 'a2' }), 'B')
    const period = { startDate: '2026-01-01', endDate: '2026-12-31', periodLabel: '2026' }
    const settlement = generateSettlement(ledger, period, 'gen_pub', 'gen_priv')
    assert.strictEqual(settlement.lineItems.length, 2)
    assert.strictEqual(settlement.totalAccesses, 50)
    assert.strictEqual(settlement.uniqueSources, 2)
    assert.strictEqual(settlement.uniquePayers, 1) // same principal
  })
})

describe('Data Settlement — Verification', () => {
  it('verifies a valid settlement record', () => {
    const ledger = createContributionLedger()
    for (let i = 0; i < 10; i++) recordContribution(ledger, mockReceipt(), 'Dataset')
    const period = { startDate: '2026-01-01', endDate: '2026-12-31', periodLabel: '2026' }
    const settlement = generateSettlement(ledger, period, 'gen_pub', 'gen_priv')
    const result = verifySettlement(settlement)
    assert.strictEqual(result.valid, true)
    assert.strictEqual(result.signatureValid, true)
    assert.strictEqual(result.merkleValid, true)
    assert.strictEqual(result.lineItemsConsistent, true)
    assert.strictEqual(result.totalConsistent, true)
    assert.strictEqual(result.errors.length, 0)
  })

  it('[ADVERSARIAL] detects tampered merkle root', () => {
    const ledger = createContributionLedger()
    for (let i = 0; i < 10; i++) recordContribution(ledger, mockReceipt(), 'Dataset')
    const period = { startDate: '2026-01-01', endDate: '2026-12-31', periodLabel: '2026' }
    const settlement = generateSettlement(ledger, period, 'gen_pub', 'gen_priv')
    settlement.merkleRoot = 'tampered_' + settlement.merkleRoot.slice(9)
    const result = verifySettlement(settlement)
    assert.strictEqual(result.valid, false)
    assert.strictEqual(result.merkleValid, false)
  })

  it('[ADVERSARIAL] detects tampered total amount', () => {
    const ledger = createContributionLedger()
    for (let i = 0; i < 10; i++) recordContribution(ledger, mockReceipt(), 'Dataset')
    const period = { startDate: '2026-01-01', endDate: '2026-12-31', periodLabel: '2026' }
    const settlement = generateSettlement(ledger, period, 'gen_pub', 'gen_priv')
    settlement.totalAmount = 999.99
    const result = verifySettlement(settlement)
    assert.strictEqual(result.totalConsistent, false)
  })
})

describe('Data Compliance Report', () => {
  it('generates GDPR Article 30 report', () => {
    const ledger = createContributionLedger()
    for (let i = 0; i < 25; i++) recordContribution(ledger, mockReceipt({ sourceReceiptId: 'ds_1' }), 'Customer DB')
    for (let i = 0; i < 10; i++) recordContribution(ledger, mockReceipt({ sourceReceiptId: 'ds_2', declaredPurpose: 'train', agentId: 'trainer' }), 'Training Set')
    const period = { startDate: '2026-01-01', endDate: '2026-03-31', periodLabel: '2026-Q1' }
    const report = generateDataComplianceReport(ledger, period, 'gdpr_article30', 'priv_key')
    assert.ok(report.reportId.startsWith('dcpr_'))
    assert.strictEqual(report.reportType, 'gdpr_article30')
    assert.strictEqual(report.summary.totalDataAccesses, 35)
    assert.strictEqual(report.summary.uniqueDataSources, 2)
    assert.ok(report.summary.purposeBreakdown['analyze'] >= 25)
    assert.strictEqual(report.summary.compensationSummary.total, 0.35)
    assert.strictEqual(report.accessDetails.length, 2)
    assert.ok(report.signature.length === 64)
  })

  it('filters compliance report by agent', () => {
    const ledger = createContributionLedger()
    recordContribution(ledger, mockReceipt({ agentId: 'a1', sourceReceiptId: 'x1' }), 'X')
    recordContribution(ledger, mockReceipt({ agentId: 'a2', sourceReceiptId: 'x2' }), 'Y')
    const period = { startDate: '2026-01-01', endDate: '2026-12-31', periodLabel: '2026' }
    const report = generateDataComplianceReport(ledger, period, 'euai_article10', 'key', { agentId: 'a1' })
    assert.strictEqual(report.summary.totalDataAccesses, 1)
    assert.strictEqual(report.agentId, 'a1')
  })

  it('handles free (no compensation) data terms', () => {
    const ledger = createContributionLedger()
    recordContribution(ledger, mockReceipt({ termsAtAccessTime: TERMS_FREE, sourceReceiptId: 'free_ds' }), 'Free')
    const period = { startDate: '2026-01-01', endDate: '2026-12-31', periodLabel: '2026' }
    const report = generateDataComplianceReport(ledger, period, 'general', 'key')
    assert.strictEqual(report.summary.compensationSummary.total, 0)
  })
})
