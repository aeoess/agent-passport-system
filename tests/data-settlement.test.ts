// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import {
  createContributionLedger,
  recordContribution,
} from '../src/core/data-contribution.js'
import {
  generateSettlement,
  verifySettlement,
  generateDataComplianceReport,
} from '../src/core/data-settlement.js'
import type { DataAccessReceipt } from '../src/types/data-source.js'
import type { ContributionLedger } from '../src/core/data-contribution.js'

function makeAccessReceipt(
  sourceReceiptId: string,
  agentId: string,
  perAccessAmount?: number,
  timestamp?: string,
): DataAccessReceipt {
  return {
    accessReceiptId: 'dacr_' + Math.random().toString(36).slice(2, 10),
    sourceReceiptId,
    sourceMode: 'gateway_verified',
    dataHash: 'hash_' + Math.random().toString(36).slice(2, 8),
    agentId,
    agentPublicKey: 'agent_pub_' + agentId,
    principalId: 'principal_1',
    executionFrameId: 'frame_1',
    accessScope: 'read',
    accessMethod: 'api_call',
    declaredPurpose: 'inference:decision_support',
    termsAtAccessTime: {
      allowedPurposes: ['inference:decision_support'],
      requireAttribution: true,
      requireNotification: false,
      compensation: perAccessAmount
        ? { type: 'per_access', amount: perAccessAmount, currency: 'usd' }
        : { type: 'attribution_only' },
      derivativePolicy: 'attribution_required',
      auditVisibility: 'source_and_principal',
      revocable: true,
    },
    timestamp: timestamp || new Date().toISOString(),
    gatewayId: 'gateway_1',
    gatewayPublicKey: 'gw_pub',
    gatewaySignature: 'gw_sig',
  }
}

describe('Module 39: Data Settlement Protocol', () => {
  let keys: { publicKey: string; privateKey: string }
  let ledger: ContributionLedger

  beforeEach(() => {
    keys = generateKeyPair()
    ledger = createContributionLedger()
  })

  describe('generateSettlement', () => {
    it('generates settlement from single source contributions', () => {
      const r1 = makeAccessReceipt('src_A', 'agent_1', 0.10)
      const r2 = makeAccessReceipt('src_A', 'agent_1', 0.10)
      recordContribution(ledger, r1, 'NYT Dataset')
      recordContribution(ledger, r2, 'NYT Dataset')
      const period = {
        startDate: '2026-01-01T00:00:00Z',
        endDate: '2026-12-31T23:59:59Z',
        periodLabel: '2026',
      }
      const settlement = generateSettlement(ledger, period, keys.publicKey, keys.privateKey)
      assert.ok(settlement.settlementId.startsWith('stlr_'))
      assert.equal(settlement.lineItems.length, 1)
      assert.equal(settlement.totalAmount, 0.20)
      assert.equal(settlement.totalAccesses, 2)
      assert.ok(settlement.signature.length > 0)
      assert.ok(settlement.merkleRoot.length === 64)
    })

    it('generates settlement from multiple sources', () => {
      recordContribution(ledger, makeAccessReceipt('src_A', 'agent_1', 0.10), 'Source A')
      recordContribution(ledger, makeAccessReceipt('src_B', 'agent_1', 0.05), 'Source B')
      recordContribution(ledger, makeAccessReceipt('src_C', 'agent_1', 0.25), 'Source C')
      const period = { startDate: '2026-01-01T00:00:00Z', endDate: '2026-12-31T23:59:59Z', periodLabel: '2026' }
      const settlement = generateSettlement(ledger, period, keys.publicKey, keys.privateKey)
      assert.equal(settlement.lineItems.length, 3)
      assert.equal(settlement.uniqueSources, 3)
      assert.equal(settlement.totalAmount, 0.40) // 0.10 + 0.05 + 0.25
    })

    it('attribution_only model produces zero compensation', () => {
      recordContribution(ledger, makeAccessReceipt('src_free', 'agent_1'), 'Free Source')
      const period = { startDate: '2026-01-01T00:00:00Z', endDate: '2026-12-31T23:59:59Z', periodLabel: '2026' }
      const settlement = generateSettlement(ledger, period, keys.publicKey, keys.privateKey)
      assert.equal(settlement.totalAmount, 0)
      assert.equal(settlement.lineItems[0].compensationModel, 'attribution_only')
    })

    it('empty period produces empty settlement', () => {
      recordContribution(ledger, makeAccessReceipt('src_A', 'agent_1', 0.10, '2025-06-01T00:00:00Z'), 'Old Source')
      const period = { startDate: '2026-01-01T00:00:00Z', endDate: '2026-12-31T23:59:59Z', periodLabel: '2026' }
      const settlement = generateSettlement(ledger, period, keys.publicKey, keys.privateKey)
      // Receipt is outside period
      assert.equal(settlement.lineItems.length, 0)
      assert.equal(settlement.totalAmount, 0)
    })
  })

  describe('verifySettlement', () => {
    it('valid settlement passes verification', () => {
      recordContribution(ledger, makeAccessReceipt('src_A', 'agent_1', 0.10), 'Source A')
      recordContribution(ledger, makeAccessReceipt('src_B', 'agent_1', 0.05), 'Source B')
      const period = { startDate: '2026-01-01T00:00:00Z', endDate: '2026-12-31T23:59:59Z', periodLabel: '2026' }
      const settlement = generateSettlement(ledger, period, keys.publicKey, keys.privateKey)
      const result = verifySettlement(settlement)
      assert.equal(result.valid, true)
      assert.equal(result.signatureValid, true)
      assert.equal(result.merkleValid, true)
      assert.equal(result.lineItemsConsistent, true)
      assert.equal(result.totalConsistent, true)
    })

    it('tampered total amount is detected', () => {
      recordContribution(ledger, makeAccessReceipt('src_A', 'agent_1', 0.10), 'Source A')
      const period = { startDate: '2026-01-01T00:00:00Z', endDate: '2026-12-31T23:59:59Z', periodLabel: '2026' }
      const settlement = generateSettlement(ledger, period, keys.publicKey, keys.privateKey)
      settlement.totalAmount = 999.99
      const result = verifySettlement(settlement)
      assert.equal(result.totalConsistent, false)
      assert.ok(result.errors.some(e => e.includes('Total amount')))
    })
  })

  describe('generateDataComplianceReport', () => {
    it('generates GDPR Article 30 report', () => {
      recordContribution(ledger, makeAccessReceipt('src_A', 'agent_1', 0.10), 'EU Dataset')
      recordContribution(ledger, makeAccessReceipt('src_A', 'agent_1', 0.10), 'EU Dataset')
      const period = { startDate: '2026-01-01T00:00:00Z', endDate: '2026-12-31T23:59:59Z', periodLabel: '2026' }
      const report = generateDataComplianceReport(ledger, period, 'gdpr_article30', keys.privateKey)
      assert.ok(report.reportId.startsWith('dcpr_'))
      assert.equal(report.reportType, 'gdpr_article30')
      assert.equal(report.summary.totalDataAccesses, 2)
      assert.equal(report.summary.uniqueDataSources, 1)
      assert.ok(report.signature.length > 0)
    })

    it('generates EU AI Act Article 10 report', () => {
      recordContribution(ledger, makeAccessReceipt('src_A', 'agent_1', 0.10), 'Training Data')
      const period = { startDate: '2026-01-01T00:00:00Z', endDate: '2026-12-31T23:59:59Z', periodLabel: '2026' }
      const report = generateDataComplianceReport(ledger, period, 'euai_article10', keys.privateKey)
      assert.equal(report.reportType, 'euai_article10')
      assert.equal(report.accessDetails.length, 1)
      assert.equal(report.accessDetails[0].sourceDescriptor, 'Training Data')
    })

    it('filters by agentId', () => {
      recordContribution(ledger, makeAccessReceipt('src_A', 'agent_1', 0.10), 'Source A')
      recordContribution(ledger, makeAccessReceipt('src_B', 'agent_2', 0.05), 'Source B')
      const period = { startDate: '2026-01-01T00:00:00Z', endDate: '2026-12-31T23:59:59Z', periodLabel: '2026' }
      const report = generateDataComplianceReport(ledger, period, 'general', keys.privateKey, { agentId: 'agent_1' })
      assert.equal(report.summary.totalDataAccesses, 1)
      assert.equal(report.agentId, 'agent_1')
    })
  })
})
