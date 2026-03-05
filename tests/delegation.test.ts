// Delegation System — Depth Limits, Scope, Spend, Revocation
// Adversarial scenarios marked with [ADVERSARIAL]

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createDelegation, subDelegate,
  verifyDelegation, revokeDelegation, verifyRevocation,
  createReceipt, verifyReceipt, clearStores,
  scopeCovers, scopeAuthorizes
} from '../src/index.js'

const human = generateKeyPair()
const agentA = generateKeyPair()
const agentB = generateKeyPair()
const agentC = generateKeyPair()

describe('Delegation Creation', () => {
  beforeEach(() => clearStores())

  it('creates a valid signed delegation', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution', 'web_search'],
      spendLimit: 100,
      maxDepth: 2,
      privateKey: human.privateKey
    })
    assert.ok(d.delegationId.startsWith('del_'))
    assert.equal(d.delegatedTo, agentA.publicKey)
    assert.equal(d.spendLimit, 100)
    assert.equal(d.maxDepth, 2)
    assert.equal(d.currentDepth, 0)
    assert.ok(d.signature.length > 0)
  })

  it('verifies a valid delegation', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      privateKey: human.privateKey
    })
    const status = verifyDelegation(d)
    assert.ok(status.valid)
    assert.ok(!status.revoked)
    assert.ok(!status.expired)
    assert.ok(!status.depthExceeded)
  })

  it('[ADVERSARIAL] rejects forged delegation signature', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      privateKey: human.privateKey
    })
    // Tamper with the delegation
    d.scope = ['system_control']
    const status = verifyDelegation(d)
    assert.ok(!status.valid)
    assert.ok(status.errors.some(e => e.includes('Invalid delegation signature')))
  })

  it('[ADVERSARIAL] rejects expired delegation', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      expiresInHours: -1,  // already expired
      privateKey: human.privateKey
    })
    const status = verifyDelegation(d)
    assert.ok(!status.valid)
    assert.ok(status.expired)
  })
})

describe('Sub-delegation & Depth Limits', () => {
  beforeEach(() => clearStores())

  it('allows sub-delegation within depth limit', () => {
    const parent = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution', 'web_search'],
      spendLimit: 100,
      maxDepth: 2,
      privateKey: human.privateKey
    })
    const child = subDelegate({
      parentDelegation: parent,
      delegatedTo: agentB.publicKey,
      scope: ['web_search'],
      spendLimit: 50,
      privateKey: agentA.privateKey
    })
    assert.equal(child.currentDepth, 1)
    assert.ok(verifyDelegation(child).valid)
  })

  it('[ADVERSARIAL] rejects sub-delegation exceeding depth limit', () => {
    const parent = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      maxDepth: 1,
      privateKey: human.privateKey
    })
    const child = subDelegate({
      parentDelegation: parent,
      delegatedTo: agentB.publicKey,
      scope: ['code_execution'],
      privateKey: agentA.privateKey
    })
    // child is at depth 1, maxDepth 1 — try to sub-delegate again
    assert.throws(() => {
      subDelegate({
        parentDelegation: child,
        delegatedTo: agentC.publicKey,
        scope: ['code_execution'],
        privateKey: agentB.privateKey
      })
    }, /Depth limit exceeded/)
  })

  it('[ADVERSARIAL] rejects scope escalation in sub-delegation', () => {
    const parent = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['web_search'],
      maxDepth: 2,
      privateKey: human.privateKey
    })
    assert.throws(() => {
      subDelegate({
        parentDelegation: parent,
        delegatedTo: agentB.publicKey,
        scope: ['code_execution'],  // not in parent scope
        privateKey: agentA.privateKey
      })
    }, /Scope violation/)
  })

  it('[ADVERSARIAL] rejects spend limit escalation in sub-delegation', () => {
    const parent = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      spendLimit: 50,
      maxDepth: 2,
      privateKey: human.privateKey
    })
    assert.throws(() => {
      subDelegate({
        parentDelegation: parent,
        delegatedTo: agentB.publicKey,
        scope: ['code_execution'],
        spendLimit: 200,  // more than parent allows
        privateKey: agentA.privateKey
      })
    }, /Spend limit.*exceeds/)
  })
})

describe('Revocation', () => {
  beforeEach(() => clearStores())

  it('revokes a delegation', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      privateKey: human.privateKey
    })
    const rev = revokeDelegation(
      d.delegationId, human.publicKey, 'Trust withdrawn', human.privateKey
    )
    assert.ok(rev.revocationId.startsWith('rev_'))
    assert.equal(rev.reason, 'Trust withdrawn')
    assert.ok(verifyRevocation(rev))
  })

  it('[ADVERSARIAL] delegation invalid after revocation', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      privateKey: human.privateKey
    })
    // Valid before revocation
    assert.ok(verifyDelegation(d).valid)
    // Revoke
    revokeDelegation(d.delegationId, human.publicKey, 'Revoked', human.privateKey)
    // Invalid after
    const status = verifyDelegation(d)
    assert.ok(!status.valid)
    assert.ok(status.revoked)
  })

  it('[ADVERSARIAL] rejects receipt on revoked delegation', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      privateKey: human.privateKey
    })
    revokeDelegation(d.delegationId, human.publicKey, 'Revoked', human.privateKey)
    assert.throws(() => {
      createReceipt({
        agentId: 'agent-a',
        delegationId: d.delegationId,
        delegation: d,
        action: { type: 'execute', target: 'script.ts', scopeUsed: 'code_execution' },
        result: { status: 'success', summary: 'done' },
        delegationChain: [human.publicKey, agentA.publicKey],
        privateKey: agentA.privateKey
      })
    }, /delegation invalid/)
  })
})

describe('Action Receipts', () => {
  beforeEach(() => clearStores())

  it('creates and verifies a valid receipt', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      spendLimit: 100,
      privateKey: human.privateKey
    })
    const receipt = createReceipt({
      agentId: 'agent-a',
      delegationId: d.delegationId,
      delegation: d,
      action: { type: 'execute', target: 'build.ts', scopeUsed: 'code_execution', spend: { amount: 10, currency: 'USD' } },
      result: { status: 'success', summary: 'Built successfully' },
      delegationChain: [human.publicKey, agentA.publicKey],
      privateKey: agentA.privateKey
    })
    assert.ok(receipt.receiptId.startsWith('rcpt_'))
    const v = verifyReceipt(receipt, agentA.publicKey)
    assert.ok(v.valid)
  })

  it('[ADVERSARIAL] rejects receipt with wrong scope', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['web_search'],
      privateKey: human.privateKey
    })
    assert.throws(() => {
      createReceipt({
        agentId: 'agent-a',
        delegationId: d.delegationId,
        delegation: d,
        action: { type: 'execute', target: 'script.ts', scopeUsed: 'code_execution' },
        result: { status: 'success', summary: 'done' },
        delegationChain: [human.publicKey, agentA.publicKey],
        privateKey: agentA.privateKey
      })
    }, /Scope.*not in delegation/)
  })

  it('[ADVERSARIAL] rejects receipt exceeding spend limit', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      spendLimit: 10,
      privateKey: human.privateKey
    })
    assert.throws(() => {
      createReceipt({
        agentId: 'agent-a',
        delegationId: d.delegationId,
        delegation: d,
        action: { type: 'execute', target: 'expensive.ts', scopeUsed: 'code_execution', spend: { amount: 500, currency: 'USD' } },
        result: { status: 'success', summary: 'done' },
        delegationChain: [human.publicKey, agentA.publicKey],
        privateKey: agentA.privateKey
      })
    }, /Spend.*exceeds/)
  })

  it('[ADVERSARIAL] rejects tampered receipt signature', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      privateKey: human.privateKey
    })
    const receipt = createReceipt({
      agentId: 'agent-a',
      delegationId: d.delegationId,
      delegation: d,
      action: { type: 'execute', target: 'build.ts', scopeUsed: 'code_execution' },
      result: { status: 'success', summary: 'Built' },
      delegationChain: [human.publicKey, agentA.publicKey],
      privateKey: agentA.privateKey
    })
    // Tamper
    receipt.result.summary = 'HACKED'
    const v = verifyReceipt(receipt, agentA.publicKey)
    assert.ok(!v.valid)
  })

  it('[ADVERSARIAL] rejects receipt verified with wrong key', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['code_execution'],
      privateKey: human.privateKey
    })
    const receipt = createReceipt({
      agentId: 'agent-a',
      delegationId: d.delegationId,
      delegation: d,
      action: { type: 'execute', target: 'build.ts', scopeUsed: 'code_execution' },
      result: { status: 'success', summary: 'Built' },
      delegationChain: [human.publicKey, agentA.publicKey],
      privateKey: agentA.privateKey
    })
    // Verify with agentB's key — should fail
    const v = verifyReceipt(receipt, agentB.publicKey)
    assert.ok(!v.valid)
  })
})

// ═══════════════════════════════════════
// Scope Resolution (R2-PX2-026 fix)
// ═══════════════════════════════════════

describe('scopeCovers', () => {
  it('exact match', () => {
    assert.ok(scopeCovers('code', 'code'))
  })

  it('parent covers child (hierarchical)', () => {
    assert.ok(scopeCovers('code', 'code:deploy'))
    assert.ok(scopeCovers('code', 'code:deploy:staging'))
  })

  it('[ADVERSARIAL] child does NOT cover parent', () => {
    assert.ok(!scopeCovers('code:deploy', 'code'))
  })

  it('universal wildcard covers everything', () => {
    assert.ok(scopeCovers('*', 'code'))
    assert.ok(scopeCovers('*', 'commerce:checkout'))
    assert.ok(scopeCovers('*', 'anything:at:all'))
  })

  it('prefix wildcard covers prefix and children', () => {
    assert.ok(scopeCovers('commerce:*', 'commerce'))
    assert.ok(scopeCovers('commerce:*', 'commerce:checkout'))
    assert.ok(scopeCovers('commerce:*', 'commerce:checkout:express'))
  })

  it('[ADVERSARIAL] prefix wildcard does NOT cover other roots', () => {
    assert.ok(!scopeCovers('commerce:*', 'code'))
    assert.ok(!scopeCovers('commerce:*', 'code:deploy'))
  })

  it('no partial string match', () => {
    assert.ok(!scopeCovers('code', 'codebase'))
    assert.ok(!scopeCovers('cod', 'code'))
  })
})

describe('scopeAuthorizes', () => {
  it('finds covering scope in array', () => {
    assert.ok(scopeAuthorizes(['code', 'web_search'], 'code:deploy'))
  })

  it('returns false when no scope covers', () => {
    assert.ok(!scopeAuthorizes(['web_search', 'data_analysis'], 'code:deploy'))
  })

  it('works with wildcard in array', () => {
    assert.ok(scopeAuthorizes(['commerce:*', 'code'], 'commerce:checkout'))
  })

  it('[ADVERSARIAL] empty scope array covers nothing', () => {
    assert.ok(!scopeAuthorizes([], 'code'))
  })
})
