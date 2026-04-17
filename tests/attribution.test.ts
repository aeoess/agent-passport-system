// Attribution — Merkle primitives and beneficiary tracing
// Report-generator tests (computeAttribution, computeCollaborationAttribution)
// moved to the gateway at tests/sdk-migrated/core/attribution-reports.test.ts

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createDelegation, createReceipt, clearStores,
  hashReceipt, traceBeneficiary,
  buildMerkleRoot, generateMerkleProof, verifyMerkleProof,
} from '../src/index.js'
import type { BeneficiaryInfo, ActionReceipt, Delegation } from '../src/index.js'

const human = generateKeyPair()
const agentA = generateKeyPair()

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

describe('Receipt hashing', () => {
  beforeEach(() => clearStores())

  it('produces a 64-hex SHA-256 digest', () => {
    const d = makeDelegation()
    const r = makeReceipt(d, 'code_execution', 10)
    const h = hashReceipt(r)
    assert.equal(h.length, 64)
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
