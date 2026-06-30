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

  it('traces receipt back to human beneficiary (resolved AND cryptographically verified)', () => {
    const d = makeDelegation()
    const receipt = makeReceipt(d, 'code_execution', 10)
    const beneficiaryMap = new Map<string, BeneficiaryInfo>([
      [human.publicKey, { principalId: 'tymofii', relationship: 'creator' }]
    ])
    const trace = traceBeneficiary(receipt, [d], beneficiaryMap)
    assert.equal(trace.beneficiary, 'tymofii')
    assert.ok(trace.resolved, 'lineage resolves to a known beneficiary')
    assert.ok(trace.verified, 'receipt + delegation signatures verify')
    assert.equal(trace.totalDepth, 1)
  })

  it('[behavior] beneficiary lookup drives resolved, not verified (crypto is independent of the label map)', () => {
    const d = makeDelegation()
    const receipt = makeReceipt(d, 'code_execution', 10)
    const emptyMap = new Map<string, BeneficiaryInfo>()
    const trace = traceBeneficiary(receipt, [d], emptyMap)
    // Old semantics conflated these. Now: no known beneficiary => not resolved,
    // but the lineage still cryptographically verifies.
    assert.ok(!trace.resolved, 'unknown beneficiary -> not resolved')
    assert.ok(trace.verified, 'crypto holds regardless of the label map')
  })

  it('[ADVERSARIAL] a forged/creator-supplied chain resolves but does NOT verify', () => {
    const attacker = generateKeyPair()
    // The attacker forges a delegation CLAIMING the human delegated to them,
    // but only the attacker ever signed it.
    const forged = createDelegation({
      delegatedBy: human.publicKey,       // claims the human as delegator
      delegatedTo: attacker.publicKey,
      scope: ['code_execution'],
      spendLimit: 1000,
      privateKey: attacker.privateKey      // signed by the attacker, not the human
    })
    // The attacker holds a legitimate self-delegation so createReceipt will sign a
    // receipt for them, then asserts the spoofed lineage human -> attacker.
    const self = createDelegation({
      delegatedBy: attacker.publicKey, delegatedTo: attacker.publicKey,
      scope: ['code_execution'], spendLimit: 1000, privateKey: attacker.privateKey
    })
    const receipt = createReceipt({
      agentId: 'attacker',
      delegationId: self.delegationId,
      delegation: self,
      action: { type: 'execute', target: 'task', scopeUsed: 'code_execution', spend: { amount: 1, currency: 'USD' } },
      result: { status: 'success', summary: 'spoof' },
      delegationChain: [human.publicKey, attacker.publicKey],   // the lie
      privateKey: attacker.privateKey
    })
    const beneficiaryMap = new Map<string, BeneficiaryInfo>([
      [human.publicKey, { principalId: 'tymofii', relationship: 'creator' }]
    ])
    const trace = traceBeneficiary(receipt, [forged], beneficiaryMap)
    assert.ok(trace.resolved, 'structural lookup resolves against the forged record')
    assert.ok(!trace.verified, 'a forged chain must NOT come back verified: the hop fails verifyDelegation')
  })

  it('[ADVERSARIAL] a tampered receipt does NOT verify', () => {
    const d = makeDelegation()
    const receipt = makeReceipt(d, 'code_execution', 10)
    // Mutate the signed receipt after the fact.
    const tampered = { ...receipt, action: { ...receipt.action, spend: { amount: 999999, currency: 'USD' } } } as ActionReceipt
    const beneficiaryMap = new Map<string, BeneficiaryInfo>([
      [human.publicKey, { principalId: 'tymofii', relationship: 'creator' }]
    ])
    const trace = traceBeneficiary(tampered, [d], beneficiaryMap)
    assert.ok(!trace.verified, 'mutating a signed receipt breaks verified')
  })

  it('[ADVERSARIAL] cannot verify without the delegation records', () => {
    const d = makeDelegation()
    const receipt = makeReceipt(d, 'code_execution', 10)
    const beneficiaryMap = new Map<string, BeneficiaryInfo>([
      [human.publicKey, { principalId: 'tymofii', relationship: 'creator' }]
    ])
    const trace = traceBeneficiary(receipt, [], beneficiaryMap)  // no delegations supplied
    assert.ok(!trace.resolved, 'unknown delegation id -> not resolved')
    assert.ok(!trace.verified, 'no delegation to verify -> not verified')
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
