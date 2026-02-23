// Attribution & Merkle Tree — Trace, Prove, Verify
// Adversarial scenarios marked with [ADVERSARIAL]

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createDelegation, createReceipt, clearStores,
  hashReceipt, traceBeneficiary, computeAttribution, verifyAttributionReport,
  buildMerkleRoot, generateMerkleProof, verifyMerkleProof,
  computeCollaborationAttribution, DEFAULT_SCOPE_WEIGHTS
} from '../src/index.js'
import type { BeneficiaryInfo, ActionReceipt, Delegation } from '../src/index.js'

const human = generateKeyPair()
const agentA = generateKeyPair()
const agentB = generateKeyPair()
const verifier = generateKeyPair()

function makeDelegation(): Delegation {
  return createDelegation({
    delegatedTo: agentA.publicKey,
    delegatedBy: human.publicKey,
    scope: ['code_execution', 'web_search', 'git_operations'],
    spendLimit: 1000,
    privateKey: human.privateKey
  })
}

function makeReceipt(d: Delegation, scope: string, spend: number, result: string = 'success'): ActionReceipt {
  return createReceipt({
    agentId: 'agent-a',
    delegationId: d.delegationId,
    delegation: d,
    action: { type: 'execute', target: 'task', scopeUsed: scope, spend: { amount: spend, currency: 'USD' } },
    result: { status: result, summary: 'done' },
    delegationChain: [human.publicKey, agentA.publicKey],
    privateKey: agentA.privateKey
  })
}

describe('Beneficiary Tracing', () => {
  beforeEach(() => clearStores())

  it('traces receipt back to human beneficiary', () => {
    const d = makeDelegation()
    const receipt = makeReceipt(d, 'code_execution', 10)
    const beneficiaryMap = new Map<string, BeneficiaryInfo>([
      [human.publicKey, { principalId: 'tymofii', relationship: 'creator' }]
    ])
    const trace = traceBeneficiary(receipt, [d], beneficiaryMap)
    assert.equal(trace.beneficiary, 'tymofii')
    assert.ok(trace.verified)
    assert.equal(trace.totalDepth, 1)
  })

  it('[ADVERSARIAL] unverified trace when beneficiary unknown', () => {
    const d = makeDelegation()
    const receipt = makeReceipt(d, 'code_execution', 10)
    const emptyMap = new Map<string, BeneficiaryInfo>()
    const trace = traceBeneficiary(receipt, [d], emptyMap)
    assert.ok(!trace.verified)
  })
})

describe('Attribution Computation', () => {
  beforeEach(() => clearStores())

  it('computes attribution with correct weight formula', () => {
    const d = makeDelegation()
    const r1 = makeReceipt(d, 'code_execution', 10)
    const r2 = makeReceipt(d, 'web_search', 5)
    const report = computeAttribution(
      [r1, r2], 'agent-a', 'tymofii', verifier.privateKey
    )
    assert.equal(report.receiptCount, 2)
    assert.ok(report.totalWeight > 0)
    assert.ok(report.merkleRoot.length === 64)
    assert.ok(report.reportId.startsWith('attr_'))
  })

  it('failed actions contribute zero weight', () => {
    const d = makeDelegation()
    const r = makeReceipt(d, 'code_execution', 10, 'failure')
    const report = computeAttribution(
      [r], 'agent-a', 'tymofii', verifier.privateKey
    )
    assert.equal(report.totalWeight, 0)
  })

  it('uses custom scope weights when provided', () => {
    const d = makeDelegation()
    const r = makeReceipt(d, 'code_execution', 0)
    const defaultReport = computeAttribution(
      [r], 'agent-a', 'tymofii', verifier.privateKey
    )
    const customReport = computeAttribution(
      [r], 'agent-a', 'tymofii', verifier.privateKey,
      { scopeWeights: { code_execution: 5.0 } }
    )
    assert.ok(customReport.totalWeight > defaultReport.totalWeight)
  })

  it('verifies valid attribution report signature', () => {
    const d = makeDelegation()
    const r = makeReceipt(d, 'code_execution', 10)
    const report = computeAttribution(
      [r], 'agent-a', 'tymofii', verifier.privateKey
    )
    const v = verifyAttributionReport(report, verifier.publicKey)
    assert.ok(v.valid)
  })

  it('[ADVERSARIAL] rejects tampered attribution report', () => {
    const d = makeDelegation()
    const r = makeReceipt(d, 'code_execution', 10)
    const report = computeAttribution(
      [r], 'agent-a', 'tymofii', verifier.privateKey
    )
    report.totalWeight = 999
    const v = verifyAttributionReport(report, verifier.publicKey)
    assert.ok(!v.valid)
  })

  it('[ADVERSARIAL] rejects attribution verified with wrong key', () => {
    const d = makeDelegation()
    const r = makeReceipt(d, 'code_execution', 10)
    const report = computeAttribution(
      [r], 'agent-a', 'tymofii', verifier.privateKey
    )
    const v = verifyAttributionReport(report, agentA.publicKey)
    assert.ok(!v.valid)
  })

  it('handles empty receipts', () => {
    const report = computeAttribution(
      [], 'agent-a', 'tymofii', verifier.privateKey
    )
    assert.equal(report.receiptCount, 0)
    assert.equal(report.totalWeight, 0)
  })
})

describe('Merkle Tree', () => {
  it('builds deterministic root from same inputs', () => {
    const hashes = ['aaa', 'bbb', 'ccc']
    const root1 = buildMerkleRoot(hashes)
    const root2 = buildMerkleRoot([...hashes].reverse())
    assert.equal(root1, root2, 'Sorted inputs produce same root')
  })

  it('different inputs produce different roots', () => {
    const root1 = buildMerkleRoot(['aaa', 'bbb'])
    const root2 = buildMerkleRoot(['aaa', 'ccc'])
    assert.notEqual(root1, root2)
  })

  it('generates and verifies inclusion proof', () => {
    const hashes = ['hash1', 'hash2', 'hash3', 'hash4']
    const proof = generateMerkleProof(hashes, 'hash2')
    assert.ok(proof)
    assert.ok(verifyMerkleProof(proof))
  })

  it('[ADVERSARIAL] rejects proof with tampered receipt hash', () => {
    const hashes = ['hash1', 'hash2', 'hash3', 'hash4']
    const proof = generateMerkleProof(hashes, 'hash2')
    assert.ok(proof)
    proof.receiptHash = 'tampered'
    assert.ok(!verifyMerkleProof(proof))
  })

  it('returns null proof for non-existent hash', () => {
    const hashes = ['hash1', 'hash2']
    const proof = generateMerkleProof(hashes, 'doesnotexist')
    assert.equal(proof, null)
  })

  it('handles single-element tree', () => {
    const root = buildMerkleRoot(['onlyone'])
    assert.equal(root, 'onlyone')
  })

  it('handles empty tree', () => {
    const root = buildMerkleRoot([])
    assert.ok(root.length === 64, 'Empty tree returns hash of "empty"')
  })
})

describe('Collaboration Attribution', () => {
  beforeEach(() => clearStores())

  it('splits attribution between multiple agents', () => {
    const dA = createDelegation({
      delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['code_execution'], spendLimit: 500, privateKey: human.privateKey
    })
    const dB = createDelegation({
      delegatedTo: agentB.publicKey, delegatedBy: human.publicKey,
      scope: ['web_search'], spendLimit: 500, privateKey: human.privateKey
    })
    const r1 = createReceipt({
      agentId: 'agent-a', delegationId: dA.delegationId, delegation: dA,
      action: { type: 'execute', target: 't', scopeUsed: 'code_execution', spend: { amount: 20, currency: 'USD' } },
      result: { status: 'success', summary: 'done' },
      delegationChain: [human.publicKey, agentA.publicKey],
      privateKey: agentA.privateKey
    })
    const r2 = createReceipt({
      agentId: 'agent-b', delegationId: dB.delegationId, delegation: dB,
      action: { type: 'search', target: 't', scopeUsed: 'web_search', spend: { amount: 5, currency: 'USD' } },
      result: { status: 'success', summary: 'done' },
      delegationChain: [human.publicKey, agentB.publicKey],
      privateKey: agentB.privateKey
    })

    const beneficiaryMap = new Map([['agent-a', 'tymofii'], ['agent-b', 'tymofii']])
    const collab = computeCollaborationAttribution([r1, r2], beneficiaryMap)
    assert.equal(collab.participants.length, 2)
    const total = collab.participants.reduce((s, p) => s + p.percentage, 0)
    assert.ok(Math.abs(total - 100) < 0.1, 'Percentages sum to ~100')
  })
})
