// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
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

  it('[edge] empty delegationChain does not throw and is neither resolved nor verified', () => {
    const d = makeDelegation()
    const receipt = createReceipt({
      agentId: 'agent-a', delegationId: d.delegationId, delegation: d,
      action: { type: 'execute', target: 'task', scopeUsed: 'code_execution', spend: { amount: 1, currency: 'USD' } },
      result: { status: 'success', summary: 'done' },
      delegationChain: [],
      privateKey: agentA.privateKey
    })
    const beneficiaryMap = new Map<string, BeneficiaryInfo>([[human.publicKey, { principalId: 'tymofii' }]])
    const trace = traceBeneficiary(receipt, [d], beneficiaryMap)
    assert.equal(trace.totalDepth, 0)
    assert.ok(!trace.resolved)
    assert.ok(!trace.verified)
  })

  it('[edge] single-key chain (no delegation hop) is not verified', () => {
    const d = makeDelegation()
    const receipt = createReceipt({
      agentId: 'agent-a', delegationId: d.delegationId, delegation: d,
      action: { type: 'execute', target: 'task', scopeUsed: 'code_execution', spend: { amount: 1, currency: 'USD' } },
      result: { status: 'success', summary: 'done' },
      delegationChain: [human.publicKey],   // executor == principal, zero hops
      privateKey: human.privateKey
    })
    const beneficiaryMap = new Map<string, BeneficiaryInfo>([[human.publicKey, { principalId: 'tymofii' }]])
    const trace = traceBeneficiary(receipt, [d], beneficiaryMap)
    assert.ok(!trace.verified, 'a chain with no delegation hop is not verified')
  })

  it('[ADVERSARIAL] an expired delegation in the lineage resolves but does NOT verify', () => {
    const agentExp = generateKeyPair()
    // Authentic signature, but already expired.
    const expired = createDelegation({
      delegatedBy: human.publicKey,
      delegatedTo: agentExp.publicKey,
      scope: ['code_execution'],
      spendLimit: 1000,
      expiresAt: new Date(Date.now() - 86_400_000).toISOString(),  // yesterday
      privateKey: human.privateKey
    })
    // The agent holds a current self-delegation so createReceipt will sign a receipt,
    // and asserts the (now expired) human -> agentExp lineage.
    const self = createDelegation({
      delegatedBy: agentExp.publicKey, delegatedTo: agentExp.publicKey,
      scope: ['code_execution'], spendLimit: 1000, privateKey: agentExp.privateKey
    })
    const receipt = createReceipt({
      agentId: 'agent-exp', delegationId: self.delegationId, delegation: self,
      action: { type: 'execute', target: 'task', scopeUsed: 'code_execution', spend: { amount: 1, currency: 'USD' } },
      result: { status: 'success', summary: 'late' },
      delegationChain: [human.publicKey, agentExp.publicKey],
      privateKey: agentExp.privateKey
    })
    const beneficiaryMap = new Map<string, BeneficiaryInfo>([
      [human.publicKey, { principalId: 'tymofii', relationship: 'creator' }]
    ])
    const trace = traceBeneficiary(receipt, [expired], beneficiaryMap)
    assert.ok(trace.resolved, 'the expired record still resolves structurally')
    assert.ok(!trace.verified, 'an expired hop must NOT come back verified')
  })
})

describe('Beneficiary Tracing - deterministic lineage (re-used key pairs)', () => {
  beforeEach(() => clearStores())

  it('[determinism] tail hop reports receipt.delegationId when multiple delegations share the (from,to) pair', () => {
    const dOld = makeDelegation()
    const dNew = makeDelegation()
    assert.notEqual(dOld.delegationId, dNew.delegationId)
    // Receipt issued under dNew specifically.
    const receipt = createReceipt({
      agentId: 'agent-a', delegationId: dNew.delegationId, delegation: dNew,
      action: { type: 'execute', target: 'task', scopeUsed: 'code_execution', spend: { amount: 5, currency: 'USD' } },
      result: { status: 'success', summary: 'done' },
      delegationChain: [human.publicKey, agentA.publicKey],
      privateKey: agentA.privateKey
    })
    const beneficiaryMap = new Map<string, BeneficiaryInfo>([[human.publicKey, { principalId: 'tymofii' }]])
    // Same inputs, both array orders -> identical reported chain, tail tied to receipt.delegationId.
    const t1 = traceBeneficiary(receipt, [dOld, dNew], beneficiaryMap)
    const t2 = traceBeneficiary(receipt, [dNew, dOld], beneficiaryMap)
    assert.equal(t1.chain.at(-1)!.delegationId, dNew.delegationId, 'tail tied to receipt.delegationId')
    assert.equal(t2.chain.at(-1)!.delegationId, dNew.delegationId, 'order-independent')
    assert.deepEqual(t1.chain, t2.chain, 'same inputs -> same reported chain regardless of array order')
    assert.ok(t1.verified && t2.verified, 'both valid duplicates -> verified true')
  })

  it('[no false-negative] a re-issued delegation verifies even when an EXPIRED duplicate is listed first', () => {
    const expiredOld = createDelegation({
      delegatedBy: human.publicKey, delegatedTo: agentA.publicKey,
      scope: ['code_execution', 'web_search', 'git_operations'], spendLimit: 1000,
      expiresAt: new Date(Date.now() - 86_400_000).toISOString(),
      privateKey: human.privateKey
    })
    const freshNew = makeDelegation()  // valid human -> agentA
    const receipt = createReceipt({
      agentId: 'agent-a', delegationId: freshNew.delegationId, delegation: freshNew,
      action: { type: 'execute', target: 'task', scopeUsed: 'code_execution', spend: { amount: 5, currency: 'USD' } },
      result: { status: 'success', summary: 'done' },
      delegationChain: [human.publicKey, agentA.publicKey],
      privateKey: agentA.privateKey
    })
    const beneficiaryMap = new Map<string, BeneficiaryInfo>([[human.publicKey, { principalId: 'tymofii' }]])
    // Expired listed FIRST: a first-match rule would have flipped verified=false.
    const trace = traceBeneficiary(receipt, [expiredOld, freshNew], beneficiaryMap)
    assert.ok(trace.verified, 'a valid delegation exists for the hop -> verified stays true')
    assert.equal(trace.chain.at(-1)!.delegationId, freshNew.delegationId, 'tail reports the valid re-issued delegation')
  })

  it('[security unchanged] a hop whose every matching delegation is invalid is still not verified', () => {
    const exp1 = createDelegation({
      delegatedBy: human.publicKey, delegatedTo: agentA.publicKey, scope: ['code_execution'], spendLimit: 1000,
      expiresAt: new Date(Date.now() - 2 * 86_400_000).toISOString(), privateKey: human.privateKey
    })
    const exp2 = createDelegation({
      delegatedBy: human.publicKey, delegatedTo: agentA.publicKey, scope: ['code_execution'], spendLimit: 1000,
      expiresAt: new Date(Date.now() - 86_400_000).toISOString(), privateKey: human.privateKey
    })
    // A current self-delegation only so createReceipt will sign a receipt for the agent.
    const self = createDelegation({
      delegatedBy: agentA.publicKey, delegatedTo: agentA.publicKey, scope: ['code_execution'], spendLimit: 1000, privateKey: agentA.privateKey
    })
    const receipt = createReceipt({
      agentId: 'agent-a', delegationId: self.delegationId, delegation: self,
      action: { type: 'execute', target: 'task', scopeUsed: 'code_execution', spend: { amount: 1, currency: 'USD' } },
      result: { status: 'success', summary: 'x' },
      delegationChain: [human.publicKey, agentA.publicKey],
      privateKey: agentA.privateKey
    })
    const beneficiaryMap = new Map<string, BeneficiaryInfo>([[human.publicKey, { principalId: 'tymofii' }]])
    const trace = traceBeneficiary(receipt, [exp1, exp2], beneficiaryMap)
    assert.ok(!trace.verified, 'no valid delegation for the hop -> not verified')
  })

  it('[determinism] inner-hop selection is order-independent', () => {
    const agentBk = generateKeyPair()
    const dA1 = makeDelegation()  // human -> agentA (valid)
    const dA2 = makeDelegation()  // human -> agentA (valid, duplicate pair)
    const dAtoB = createDelegation({
      delegatedBy: agentA.publicKey, delegatedTo: agentBk.publicKey,
      scope: ['code_execution'], spendLimit: 500, privateKey: agentA.privateKey
    })
    const receipt = createReceipt({
      agentId: 'agent-b', delegationId: dAtoB.delegationId, delegation: dAtoB,
      action: { type: 'execute', target: 'task', scopeUsed: 'code_execution', spend: { amount: 5, currency: 'USD' } },
      result: { status: 'success', summary: 'done' },
      delegationChain: [human.publicKey, agentA.publicKey, agentBk.publicKey],
      privateKey: agentBk.privateKey
    })
    const beneficiaryMap = new Map<string, BeneficiaryInfo>([[human.publicKey, { principalId: 'tymofii' }]])
    const t1 = traceBeneficiary(receipt, [dA1, dA2, dAtoB], beneficiaryMap)
    const t2 = traceBeneficiary(receipt, [dA2, dA1, dAtoB], beneficiaryMap)
    assert.deepEqual(t1.chain, t2.chain, 'inner-hop pick is deterministic across input order')
    const expectedInner = [dA1.delegationId, dA2.delegationId].sort()[0]
    assert.equal(t1.chain[0].delegationId, expectedInner, 'inner hop picks the deterministic (id-ordered) delegation')
    assert.equal(t1.chain.at(-1)!.delegationId, dAtoB.delegationId, 'tail tied to receipt.delegationId')
    assert.ok(t1.verified, 'valid lineage verifies')
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
