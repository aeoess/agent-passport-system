// v1.4 — Cascade Revocation, Chain Validation, Batch Revocation
// Tests for the cascade revocation system

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createDelegation, subDelegate,
  verifyDelegation, cascadeRevoke, revokeByAgent,
  validateChain, getDescendants, getChainEntry,
  onRevocation, clearStores
} from '../src/index.js'
import type { RevocationEvent } from '../src/index.js'

const human = generateKeyPair()
const agentA = generateKeyPair()
const agentB = generateKeyPair()
const agentC = generateKeyPair()
const agentD = generateKeyPair()

// Helper: create a chain Human → A → B → C
function createChain() {
  const d1 = createDelegation({
    delegatedTo: agentA.publicKey,
    delegatedBy: human.publicKey,
    scope: ['code_execution', 'web_search', 'data_read'],
    spendLimit: 1000,
    maxDepth: 3,
    privateKey: human.privateKey
  })
  const d2 = subDelegate({
    parentDelegation: d1,
    delegatedTo: agentB.publicKey,
    scope: ['code_execution', 'web_search'],
    spendLimit: 500,
    privateKey: agentA.privateKey
  })
  const d3 = subDelegate({
    parentDelegation: d2,
    delegatedTo: agentC.publicKey,
    scope: ['web_search'],
    spendLimit: 100,
    privateKey: agentB.privateKey
  })
  return { d1, d2, d3 }
}

describe('Chain Registry', () => {
  beforeEach(() => clearStores())

  it('tracks root delegation in registry', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      privateKey: human.privateKey
    })
    const entry = getChainEntry(d.delegationId)
    assert.ok(entry)
    assert.equal(entry!.parentId, null)
    assert.deepEqual(entry!.childIds, [])
  })

  it('tracks parent→child relationship', () => {
    const { d1, d2 } = createChain()
    const parentEntry = getChainEntry(d1.delegationId)
    const childEntry = getChainEntry(d2.delegationId)
    assert.ok(parentEntry!.childIds.includes(d2.delegationId))
    assert.equal(childEntry!.parentId, d1.delegationId)
  })

  it('tracks full 3-level chain', () => {
    const { d1, d2, d3 } = createChain()
    assert.ok(getChainEntry(d1.delegationId)!.childIds.includes(d2.delegationId))
    assert.ok(getChainEntry(d2.delegationId)!.childIds.includes(d3.delegationId))
    assert.equal(getChainEntry(d3.delegationId)!.childIds.length, 0)
  })
})

describe('Cascade Revocation', () => {
  beforeEach(() => clearStores())

  it('revokes root and all descendants', () => {
    const { d1, d2, d3 } = createChain()
    // All valid before
    assert.ok(verifyDelegation(d1).valid)
    assert.ok(verifyDelegation(d2).valid)
    assert.ok(verifyDelegation(d3).valid)

    const result = cascadeRevoke(
      d1.delegationId, human.publicKey, 'Trust withdrawn', human.privateKey
    )
    assert.equal(result.totalRevoked, 3) // d1 + d2 + d3
    assert.equal(result.cascadedRevocations.length, 2)

    // All invalid after
    assert.ok(!verifyDelegation(d1).valid)
    assert.ok(!verifyDelegation(d2).valid)
    assert.ok(!verifyDelegation(d3).valid)
  })

  it('cascade from middle of chain', () => {
    const { d1, d2, d3 } = createChain()
    // Revoke d2 — should cascade to d3 but leave d1
    const result = cascadeRevoke(
      d2.delegationId, agentA.publicKey, 'Sub-agent compromised', agentA.privateKey
    )
    assert.equal(result.totalRevoked, 2) // d2 + d3
    assert.ok(verifyDelegation(d1).valid)  // d1 still valid
    assert.ok(!verifyDelegation(d2).valid)
    assert.ok(!verifyDelegation(d3).valid)
  })

  it('cascade on leaf is just single revocation', () => {
    const { d1, d2, d3 } = createChain()
    const result = cascadeRevoke(
      d3.delegationId, agentB.publicKey, 'Leaf revoked', agentB.privateKey
    )
    assert.equal(result.totalRevoked, 1)
    assert.equal(result.cascadedRevocations.length, 0)
    assert.ok(verifyDelegation(d1).valid)
    assert.ok(verifyDelegation(d2).valid)
    assert.ok(!verifyDelegation(d3).valid)
  })

  it('[ADVERSARIAL] does not double-revoke already revoked descendants', () => {
    const { d1, d2, d3 } = createChain()
    // Pre-revoke d3
    cascadeRevoke(d3.delegationId, agentB.publicKey, 'Pre-revoked', agentB.privateKey)
    // Now cascade from d1 — d3 already revoked, should skip
    const result = cascadeRevoke(
      d1.delegationId, human.publicKey, 'Full revoke', human.privateKey
    )
    // d2 cascaded, d3 was already revoked so not counted again
    assert.equal(result.cascadedRevocations.length, 1) // only d2
    assert.equal(result.totalRevoked, 2) // d1 + d2
  })

  it('handles branching chains', () => {
    // Human → A, then A → B and A → C (two children)
    const d1 = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution', 'web_search'],
      spendLimit: 10000,
      maxDepth: 2,
      privateKey: human.privateKey
    })
    const d2 = subDelegate({
      parentDelegation: d1,
      delegatedTo: agentB.publicKey,
      scope: ['code_execution'],
      spendLimit: 5000,
      privateKey: agentA.privateKey
    })
    const d3 = subDelegate({
      parentDelegation: d1,
      delegatedTo: agentC.publicKey,
      scope: ['web_search'],
      spendLimit: 5000,
      privateKey: agentA.privateKey
    })
    const result = cascadeRevoke(
      d1.delegationId, human.publicKey, 'Full revoke', human.privateKey
    )
    assert.equal(result.totalRevoked, 3) // d1 + d2 + d3
    assert.ok(!verifyDelegation(d2).valid)
    assert.ok(!verifyDelegation(d3).valid)
  })
})

describe('Batch Revocation by Agent', () => {
  beforeEach(() => clearStores())

  it('revokes all delegations granted to an agent', () => {
    // Human → A (two separate delegations)
    const d1 = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      privateKey: human.privateKey
    })
    const d2 = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['web_search'],
      privateKey: human.privateKey
    })
    const revocations = revokeByAgent(
      agentA.publicKey, human.publicKey, 'Agent compromised', human.privateKey
    )
    assert.ok(revocations.length >= 2)
    assert.ok(!verifyDelegation(d1).valid)
    assert.ok(!verifyDelegation(d2).valid)
  })

  it('cascade-revokes descendants when batch revoking', () => {
    const { d1, d2, d3 } = createChain() // Human→A→B→C
    // Revoke everything granted to A — should cascade to B and C
    const revocations = revokeByAgent(
      agentA.publicKey, human.publicKey, 'Agent A decommissioned', human.privateKey
    )
    assert.ok(!verifyDelegation(d1).valid)
    assert.ok(!verifyDelegation(d2).valid)
    assert.ok(!verifyDelegation(d3).valid)
  })

  it('does not revoke delegations to other agents', () => {
    const dA = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      privateKey: human.privateKey
    })
    const dB = createDelegation({
      delegatedTo: agentB.publicKey,
      delegatedBy: human.publicKey,
      scope: ['web_search'],
      privateKey: human.privateKey
    })
    revokeByAgent(agentA.publicKey, human.publicKey, 'Only A', human.privateKey)
    assert.ok(!verifyDelegation(dA).valid)
    assert.ok(verifyDelegation(dB).valid) // B untouched
  })
})

describe('Chain Validation', () => {
  beforeEach(() => clearStores())

  it('validates a healthy chain', () => {
    const { d1, d2, d3 } = createChain()
    const result = validateChain([d1.delegationId, d2.delegationId, d3.delegationId])
    assert.ok(result.valid)
    assert.equal(result.chainLength, 3)
    assert.equal(result.firstFailure, undefined)
  })

  it('detects revoked link in chain', () => {
    const { d1, d2, d3 } = createChain()
    cascadeRevoke(d2.delegationId, agentA.publicKey, 'Revoked', agentA.privateKey)
    const result = validateChain([d1.delegationId, d2.delegationId, d3.delegationId])
    assert.ok(!result.valid)
    assert.ok(result.firstFailure)
    assert.equal(result.firstFailure!.delegationId, d2.delegationId)
  })

  it('detects unknown delegation in chain', () => {
    const { d1 } = createChain()
    const result = validateChain([d1.delegationId, 'del_fake123456'])
    assert.ok(!result.valid)
    assert.equal(result.firstFailure!.reason, 'Delegation not found in registry')
  })

  it('detects chain continuity break', () => {
    // Create two unrelated delegations
    const d1 = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      privateKey: human.privateKey
    })
    const d2 = createDelegation({
      delegatedTo: agentC.publicKey,
      delegatedBy: agentB.publicKey, // Not connected to d1
      scope: ['web_search'],
      privateKey: agentB.privateKey
    })
    const result = validateChain([d1.delegationId, d2.delegationId])
    assert.ok(!result.valid)
    assert.ok(result.firstFailure!.reason.includes('Chain break'))
  })
})

describe('getDescendants', () => {
  beforeEach(() => clearStores())

  it('returns all descendants', () => {
    const { d1, d2, d3 } = createChain()
    const desc = getDescendants(d1.delegationId)
    assert.equal(desc.length, 2)
    assert.ok(desc.includes(d2.delegationId))
    assert.ok(desc.includes(d3.delegationId))
  })

  it('returns empty for leaf', () => {
    const { d3 } = createChain()
    assert.deepEqual(getDescendants(d3.delegationId), [])
  })

  it('returns empty for unknown delegation', () => {
    assert.deepEqual(getDescendants('del_nonexistent'), [])
  })
})

describe('Revocation Events', () => {
  beforeEach(() => clearStores())

  it('emits events on cascade revocation', () => {
    const events: RevocationEvent[] = []
    onRevocation(e => events.push(e))

    const { d1 } = createChain()
    cascadeRevoke(d1.delegationId, human.publicKey, 'Test', human.privateKey)

    // Should have 1 direct + 2 cascade events
    assert.ok(events.length >= 3)
    assert.ok(events.some(e => e.type === 'direct'))
    assert.ok(events.some(e => e.type === 'cascade'))
  })

  it('unsubscribe stops events', () => {
    const events: RevocationEvent[] = []
    const unsub = onRevocation(e => events.push(e))
    unsub()

    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      privateKey: human.privateKey
    })
    cascadeRevoke(d.delegationId, human.publicKey, 'Test', human.privateKey)
    assert.equal(events.length, 0) // no events after unsub
  })
})
