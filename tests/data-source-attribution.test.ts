// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import {
  computeDataSourceAttribution,
  verifyDataSourceAttribution,
} from '../src/core/data-source-attribution.js'
import type { DataAccessReceipt } from '../src/types/data-source.js'

// ── Test Helpers ──

function makeReceipt(
  sourceReceiptId: string,
  agentId: string,
  timestamp?: string,
  perAccessAmount?: number,
): DataAccessReceipt {
  return {
    accessReceiptId: 'dacr_' + Math.random().toString(36).slice(2, 10),
    sourceReceiptId,
    sourceMode: 'gateway_verified',
    dataHash: 'abc123',
    agentId,
    agentPublicKey: 'agent_pub_key',
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

describe('Module 40: Data Source Attribution — The Pixel', () => {
  let keys: { publicKey: string; privateKey: string }

  beforeEach(() => {
    keys = generateKeyPair()
  })

  describe('computeDataSourceAttribution', () => {
    it('equal model: 3 sources → 33.33% each', () => {
      const receipts = [
        makeReceipt('src_A', 'agent_1'),
        makeReceipt('src_B', 'agent_1'),
        makeReceipt('src_C', 'agent_1'),
      ]
      const report = computeDataSourceAttribution({
        outputArtifactId: 'output_1',
        outputType: 'decision',
        accessReceipts: receipts,
        model: 'equal',
        generatorPublicKey: keys.publicKey,
        generatorPrivateKey: keys.privateKey,
      })
      assert.equal(report.totalSources, 3)
      assert.equal(report.sources.length, 3)
      for (const s of report.sources) {
        assert.ok(Math.abs(s.percentage - 33.33) < 0.1)
      }
    })

    it('access_weighted: more accesses → higher weight', () => {
      const receipts = [
        makeReceipt('src_A', 'agent_1'),
        makeReceipt('src_A', 'agent_1'),
        makeReceipt('src_A', 'agent_1'),
        makeReceipt('src_B', 'agent_1'),
      ]
      const report = computeDataSourceAttribution({
        outputArtifactId: 'output_2',
        outputType: 'content',
        accessReceipts: receipts,
        model: 'access_weighted',
        generatorPublicKey: keys.publicKey,
        generatorPrivateKey: keys.privateKey,
      })
      assert.equal(report.totalSources, 2)
      assert.equal(report.totalAccessEvents, 4)
      const srcA = report.sources.find(s => s.sourceReceiptId === 'src_A')!
      const srcB = report.sources.find(s => s.sourceReceiptId === 'src_B')!
      assert.equal(srcA.percentage, 75)
      assert.equal(srcB.percentage, 25)
    })

    it('recency_weighted: recent access gets higher weight', () => {
      const now = new Date()
      const hourAgo = new Date(now.getTime() - 3600000)
      const dayAgo = new Date(now.getTime() - 86400000)
      const receipts = [
        makeReceipt('src_recent', 'agent_1', now.toISOString()),
        makeReceipt('src_old', 'agent_1', dayAgo.toISOString()),
      ]
      const report = computeDataSourceAttribution({
        outputArtifactId: 'output_3',
        outputType: 'content',
        accessReceipts: receipts,
        model: 'recency_weighted',
        generatorPublicKey: keys.publicKey,
        generatorPrivateKey: keys.privateKey,
      })
      const recent = report.sources.find(s => s.sourceReceiptId === 'src_recent')!
      const old = report.sources.find(s => s.sourceReceiptId === 'src_old')!
      assert.ok(recent.percentage > old.percentage, 'Recent source should have higher %')
      assert.ok(recent.percentage > 60, 'Recent should be >60%')
    })

    it('custom weights: caller provides explicit weights', () => {
      const receipts = [
        makeReceipt('src_A', 'agent_1'),
        makeReceipt('src_B', 'agent_1'),
      ]
      const report = computeDataSourceAttribution({
        outputArtifactId: 'output_4',
        outputType: 'decision',
        accessReceipts: receipts,
        model: 'custom',
        customWeights: new Map([['src_A', 70], ['src_B', 30]]),
        generatorPublicKey: keys.publicKey,
        generatorPrivateKey: keys.privateKey,
      })
      const srcA = report.sources.find(s => s.sourceReceiptId === 'src_A')!
      const srcB = report.sources.find(s => s.sourceReceiptId === 'src_B')!
      assert.equal(srcA.percentage, 70)
      assert.equal(srcB.percentage, 30)
    })

    it('per_access compensation is computed correctly', () => {
      const receipts = [
        makeReceipt('src_A', 'agent_1', undefined, 0.10),
        makeReceipt('src_A', 'agent_1', undefined, 0.10),
        makeReceipt('src_B', 'agent_1', undefined, 0.05),
      ]
      const report = computeDataSourceAttribution({
        outputArtifactId: 'output_5',
        outputType: 'action',
        accessReceipts: receipts,
        model: 'access_weighted',
        generatorPublicKey: keys.publicKey,
        generatorPrivateKey: keys.privateKey,
      })
      const srcA = report.sources.find(s => s.sourceReceiptId === 'src_A')!
      const srcB = report.sources.find(s => s.sourceReceiptId === 'src_B')!
      assert.equal(srcA.compensationOwed, 0.20) // 2 × $0.10
      assert.equal(srcB.compensationOwed, 0.05) // 1 × $0.05
      assert.equal(report.totalCompensation, 0.25)
    })

    it('single source → 100%', () => {
      const receipts = [makeReceipt('src_only', 'agent_1')]
      const report = computeDataSourceAttribution({
        outputArtifactId: 'output_6',
        outputType: 'content',
        accessReceipts: receipts,
        model: 'equal',
        generatorPublicKey: keys.publicKey,
        generatorPrivateKey: keys.privateKey,
      })
      assert.equal(report.totalSources, 1)
      assert.equal(report.sources[0].percentage, 100)
    })

    it('source descriptors are included in report', () => {
      const receipts = [
        makeReceipt('src_A', 'agent_1'),
        makeReceipt('src_B', 'agent_1'),
      ]
      const descriptors = new Map([['src_A', 'NYT Article'], ['src_B', 'Reuters Feed']])
      const report = computeDataSourceAttribution({
        outputArtifactId: 'output_7',
        outputType: 'content',
        accessReceipts: receipts,
        sourceDescriptors: descriptors,
        model: 'equal',
        generatorPublicKey: keys.publicKey,
        generatorPrivateKey: keys.privateKey,
      })
      const srcA = report.sources.find(s => s.sourceReceiptId === 'src_A')!
      assert.equal(srcA.sourceDescriptor, 'NYT Article')
    })

    it('report has valid merkle root and entries hash', () => {
      const receipts = [
        makeReceipt('src_A', 'agent_1'),
        makeReceipt('src_B', 'agent_1'),
        makeReceipt('src_C', 'agent_1'),
      ]
      const report = computeDataSourceAttribution({
        outputArtifactId: 'output_8',
        outputType: 'decision',
        accessReceipts: receipts,
        model: 'equal',
        generatorPublicKey: keys.publicKey,
        generatorPrivateKey: keys.privateKey,
      })
      assert.ok(report.merkleRoot.length === 64)
      assert.ok(report.entriesHash.length === 64)
      assert.ok(report.signature.length > 0)
    })

    it('default model is access_weighted', () => {
      const receipts = [
        makeReceipt('src_A', 'agent_1'),
        makeReceipt('src_A', 'agent_1'),
        makeReceipt('src_B', 'agent_1'),
      ]
      const report = computeDataSourceAttribution({
        outputArtifactId: 'output_9',
        outputType: 'content',
        accessReceipts: receipts,
        generatorPublicKey: keys.publicKey,
        generatorPrivateKey: keys.privateKey,
      })
      assert.equal(report.attributionModel, 'access_weighted')
    })
  })

  describe('verifyDataSourceAttribution', () => {
    it('valid report passes verification', () => {
      const receipts = [
        makeReceipt('src_A', 'agent_1'),
        makeReceipt('src_B', 'agent_1'),
      ]
      const report = computeDataSourceAttribution({
        outputArtifactId: 'output_v1',
        outputType: 'decision',
        accessReceipts: receipts,
        model: 'equal',
        generatorPublicKey: keys.publicKey,
        generatorPrivateKey: keys.privateKey,
      })
      const result = verifyDataSourceAttribution(report, keys.publicKey)
      assert.equal(result.valid, true)
      assert.equal(result.errors.length, 0)
    })

    it('tampered entries hash is detected', () => {
      const receipts = [
        makeReceipt('src_A', 'agent_1'),
        makeReceipt('src_B', 'agent_1'),
      ]
      const report = computeDataSourceAttribution({
        outputArtifactId: 'output_v2',
        outputType: 'decision',
        accessReceipts: receipts,
        model: 'equal',
        generatorPublicKey: keys.publicKey,
        generatorPrivateKey: keys.privateKey,
      })
      // Tamper with a source percentage
      report.sources[0].percentage = 99
      const result = verifyDataSourceAttribution(report, keys.publicKey)
      assert.equal(result.valid, false)
      assert.ok(result.errors.some(e => e.includes('hash mismatch') || e.includes('signature')))
    })

    it('wrong public key fails verification', () => {
      const receipts = [makeReceipt('src_A', 'agent_1')]
      const report = computeDataSourceAttribution({
        outputArtifactId: 'output_v3',
        outputType: 'content',
        accessReceipts: receipts,
        model: 'equal',
        generatorPublicKey: keys.publicKey,
        generatorPrivateKey: keys.privateKey,
      })
      const otherKeys = generateKeyPair()
      const result = verifyDataSourceAttribution(report, otherKeys.publicKey)
      assert.equal(result.valid, false)
      assert.ok(result.errors.some(e => e.includes('signature')))
    })

    it('tampered merkle root is detected', () => {
      const receipts = [
        makeReceipt('src_A', 'agent_1'),
        makeReceipt('src_B', 'agent_1'),
      ]
      const report = computeDataSourceAttribution({
        outputArtifactId: 'output_v4',
        outputType: 'action',
        accessReceipts: receipts,
        model: 'equal',
        generatorPublicKey: keys.publicKey,
        generatorPrivateKey: keys.privateKey,
      })
      report.merkleRoot = 'tampered_root_hash_value_that_is_definitely_wrong_padding_64ch'
      const result = verifyDataSourceAttribution(report, keys.publicKey)
      assert.equal(result.valid, false)
      assert.ok(result.errors.some(e => e.includes('Merkle') || e.includes('signature')))
    })
  })
})
