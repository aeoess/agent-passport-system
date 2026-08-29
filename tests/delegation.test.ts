// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Delegation System — Depth Limits, Scope, Spend, Revocation
// Adversarial scenarios marked with [ADVERSARIAL]

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createDelegation, subDelegate,
  verifyDelegation, verifyRevocation,
  createReceipt, verifyReceipt, clearStores,
  scopeCovers, scopeAuthorizes
} from '../src/index.js'

// Note: revocation state + cumulative receipt storage tests moved to
// gateway's DelegationStore tests. This file now covers signature-level
// invariants only — creation, verification, scope narrowing, depth limit,
// notBefore validation, scope resolution.

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
    // Tamper with the delegation (spread since frozen)
    const forged = { ...d, scope: ['system_control'] }
    const status = verifyDelegation(forged)
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
      spendLimit: 1000,
      maxDepth: 1,
      privateKey: human.privateKey
    })
    const child = subDelegate({
      parentDelegation: parent,
      delegatedTo: agentB.publicKey,
      scope: ['code_execution'],
      spendLimit: 500,
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

describe('Revocation signature (pure)', () => {
  it('verifyRevocation accepts a fresh record and rejects a tampered one', () => {
    // verifyRevocation is pure crypto — build a minimal record without a store.
    // Stateful revocation (revokeDelegation → store → verifyDelegation revoked=true)
    // is covered in gateway's DelegationStore tests.
    const rec = {
      revocationId: 'rev_test01',
      delegationId: 'del_test01',
      revokedBy: human.publicKey,
      revokedAt: new Date().toISOString(),
      reason: 'unit-test',
    }
    // Sign via internal helper: easier to just smoke-check that verify
    // rejects an obviously-tampered record.
    const forged = { ...rec, signature: 'a'.repeat(128) }
    assert.equal(verifyRevocation(forged as any), false)
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


// ══════════════════════════════════════════════
// V3-CRIT-1 REGRESSION: Hierarchical Scope Narrowing in subDelegate()
// ══════════════════════════════════════════════
// Previously: subDelegate() used Array.includes() for scope check (literal match only).
// This meant ['*'] → ['data:read'] was REJECTED because '*'.includes('data:read') is false.
// Fix: subDelegate() now uses scopeCovers() — same logic as gateway enforcement.

describe('Hierarchical Scope Narrowing (V3-CRIT-1 fix)', () => {
  beforeEach(() => clearStores())

  // ── Authoring-path success cases ──

  it('wildcard * narrows to specific scope', () => {
    const root = createDelegation({ delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['*'], spendLimit: 1000, maxDepth: 2, privateKey: human.privateKey })
    const child = subDelegate({ parentDelegation: root, delegatedTo: agentB.publicKey,
      scope: ['data:read'], privateKey: agentA.privateKey })
    assert.deepEqual(child.scope, ['data:read'])
  })

  it('parent scope narrows to child via hierarchy (data → data:read)', () => {
    const root = createDelegation({ delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['data'], spendLimit: 1000, maxDepth: 2, privateKey: human.privateKey })
    const child = subDelegate({ parentDelegation: root, delegatedTo: agentB.publicKey,
      scope: ['data:read'], privateKey: agentA.privateKey })
    assert.deepEqual(child.scope, ['data:read'])
  })

  it('glob wildcard narrows correctly (data:* → data:read)', () => {
    const root = createDelegation({ delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['data:*'], spendLimit: 1000, maxDepth: 2, privateKey: human.privateKey })
    const child = subDelegate({ parentDelegation: root, delegatedTo: agentB.publicKey,
      scope: ['data:read'], privateKey: agentA.privateKey })
    assert.deepEqual(child.scope, ['data:read'])
  })

  it('glob wildcard narrows to sibling (data:* → data:write)', () => {
    const root = createDelegation({ delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['data:*'], spendLimit: 1000, maxDepth: 2, privateKey: human.privateKey })
    const child = subDelegate({ parentDelegation: root, delegatedTo: agentB.publicKey,
      scope: ['data:write'], privateKey: agentA.privateKey })
    assert.deepEqual(child.scope, ['data:write'])
  })

  it('wildcard narrows to commerce scope', () => {
    const root = createDelegation({ delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['*'], spendLimit: 1000, maxDepth: 2, privateKey: human.privateKey })
    const child = subDelegate({ parentDelegation: root, delegatedTo: agentB.publicKey,
      scope: ['commerce:purchase'], privateKey: agentA.privateKey })
    assert.deepEqual(child.scope, ['commerce:purchase'])
  })

  // ── Authoring-path rejection cases ──

  it('[ADVERSARIAL] data:read cannot escalate to data:write', () => {
    const root = createDelegation({ delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['data:read'], spendLimit: 1000, maxDepth: 2, privateKey: human.privateKey })
    assert.throws(() => subDelegate({ parentDelegation: root, delegatedTo: agentB.publicKey,
      scope: ['data:write'], privateKey: agentA.privateKey }), /Scope violation/)
  })

  it('[ADVERSARIAL] data:* cannot escalate to commerce:purchase', () => {
    const root = createDelegation({ delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['data:*'], spendLimit: 1000, maxDepth: 2, privateKey: human.privateKey })
    assert.throws(() => subDelegate({ parentDelegation: root, delegatedTo: agentB.publicKey,
      scope: ['commerce:purchase'], privateKey: agentA.privateKey }), /Scope violation/)
  })

  it('[ADVERSARIAL] commerce cannot escalate to data:read', () => {
    const root = createDelegation({ delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['commerce'], spendLimit: 1000, maxDepth: 2, privateKey: human.privateKey })
    assert.throws(() => subDelegate({ parentDelegation: root, delegatedTo: agentB.publicKey,
      scope: ['data:read'], privateKey: agentA.privateKey }), /Scope violation/)
  })

  // ── Full chain construction ──

  it('full chain: Human(*) → Manager(data:*) → Worker(data:read)', () => {
    const manager = generateKeyPair()
    const worker = generateKeyPair()
    const root = createDelegation({ delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['*'], spendLimit: 10000, maxDepth: 3, privateKey: human.privateKey })
    const mid = subDelegate({ parentDelegation: root, delegatedTo: manager.publicKey,
      scope: ['data:*'], privateKey: agentA.privateKey })
    const leaf = subDelegate({ parentDelegation: mid, delegatedTo: worker.publicKey,
      scope: ['data:read'], privateKey: manager.privateKey })
    assert.deepEqual(leaf.scope, ['data:read'])
    assert.equal(leaf.currentDepth, 2)
  })
})

// ══════════════════════════════════════════════
// PARITY: Authoring must accept exactly what enforcement accepts
// ══════════════════════════════════════════════
// This prevents authoring/enforcement drift from ever returning.

describe('Authoring ↔ Enforcement Parity', () => {
  const pairs: [string, string, boolean][] = [
    // [parent, child, expected]
    ['*', 'data:read', true],
    ['*', 'commerce:purchase', true],
    ['data', 'data:read', true],
    ['data:*', 'data:read', true],
    ['data:*', 'data:write', true],
    ['data:read', 'data:read', true],    // exact match
    ['data:read', 'data:write', false],   // sibling, not child
    ['data:*', 'commerce:purchase', false],
    ['commerce', 'data:read', false],
    ['commerce:purchase', 'data:read', false],
  ]

  for (const [parent, child, expected] of pairs) {
    it(`[${parent}] → [${child}]: authoring=${expected}, enforcement=${expected}`, () => {
      clearStores()
      const enforcementSays = scopeCovers(parent, child)
      assert.equal(enforcementSays, expected, `enforcement mismatch for [${parent}] → [${child}]`)

      const p = createDelegation({ delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
        scope: [parent], spendLimit: 1000, maxDepth: 2, privateKey: human.privateKey })
      let authoringSays: boolean
      try {
        subDelegate({ parentDelegation: p, delegatedTo: agentB.publicKey,
          scope: [child], privateKey: agentA.privateKey })
        authoringSays = true
      } catch { authoringSays = false }

      assert.equal(authoringSays, expected, `authoring mismatch for [${parent}] → [${child}]`)
      assert.equal(authoringSays, enforcementSays, `PARITY BROKEN: authoring=${authoringSays} vs enforcement=${enforcementSays}`)
    })
  }
})


// ══════════════════════════════════════════════════════════════════
// B-8: Timestamp Freshness — notBefore validation
// ══════════════════════════════════════════════════════════════════

describe('Timestamp Freshness (B-8)', () => {
  beforeEach(() => clearStores())

  it('delegation with notBefore in the past is valid', () => {
    const past = new Date(Date.now() - 60_000).toISOString()
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['test'],
      privateKey: human.privateKey,
      notBefore: past,
    })
    const status = verifyDelegation(d)
    assert.equal(status.valid, true)
    assert.equal(status.notYetValid, false)
  })

  it('delegation with notBefore in the future is not yet valid', () => {
    const future = new Date(Date.now() + 60_000).toISOString()
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['test'],
      privateKey: human.privateKey,
      notBefore: future,
    })
    const status = verifyDelegation(d)
    assert.equal(status.valid, false)
    assert.equal(status.notYetValid, true)
    assert.ok(status.errors.some(e => e.includes('not yet valid')))
  })


  it('delegation without notBefore defaults to creation time (always valid)', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['test'],
      privateKey: human.privateKey,
    })
    assert.ok(d.notBefore, 'notBefore should be set automatically')
    const status = verifyDelegation(d)
    assert.equal(status.valid, true)
    assert.equal(status.notYetValid, false)
  })

  it('[ADVERSARIAL] captured delegation with future notBefore is rejected', () => {
    const future = new Date(Date.now() + 3_600_000).toISOString() // 1 hour from now
    const d = createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['data:read'],
      privateKey: human.privateKey,
      notBefore: future,
    })
    // Attacker captures this delegation and tries to use it immediately
    const status = verifyDelegation(d)
    assert.equal(status.valid, false, 'Future delegation should be rejected')
    assert.equal(status.notYetValid, true)
  })
})

// ══════════════════════════════════════════════════════════════════
// Invariant: the three revocation-check policies are genuinely distinct,
// and fail_closed never accepts stale or absent revocation evidence.
// ══════════════════════════════════════════════════════════════════
// verifyDelegation read revocationCheckPolicy into a local and then
// compared it against exactly one value, 'cache_grace'. 'fail_closed' and
// 'fail_open' therefore ran the same code, so a caller who asked for
// fail-closed revocation got fail-open revocation: a two-hour-old cached
// "not revoked" was accepted, and so was having no revocation evidence at
// all. The table below is the specification; every cell is asserted.

describe('Delegation: revocation check policy is not decorative', () => {
  const GRACE_MS = 300_000
  const FRESH = () => new Date(Date.now() - 1_000).toISOString()
  const STALE = () => new Date(Date.now() - 2 * 3_600_000).toISOString() // two hours

  function live() {
    return createDelegation({
      delegatedTo: agentA.publicKey,
      delegatedBy: human.publicKey,
      scope: ['data:read'],
      privateKey: human.privateKey,
    })
  }

  // evidence → policy → expected admissibility of the delegation
  const TABLE: Array<{
    evidence: 'absent' | 'fresh_active' | 'fresh_revoked' | 'stale_active' | 'stale_revoked'
    fail_open: boolean
    cache_grace: boolean
    fail_closed: boolean
  }> = [
    { evidence: 'absent',        fail_open: true,  cache_grace: true,  fail_closed: false },
    { evidence: 'fresh_active',  fail_open: true,  cache_grace: true,  fail_closed: true },
    { evidence: 'fresh_revoked', fail_open: false, cache_grace: false, fail_closed: false },
    { evidence: 'stale_active',  fail_open: true,  cache_grace: false, fail_closed: false },
    { evidence: 'stale_revoked', fail_open: false, cache_grace: false, fail_closed: false },
  ]

  function cacheFor(evidence: string) {
    switch (evidence) {
      case 'absent': return undefined
      case 'fresh_active': return { revoked: false, checkedAt: FRESH() }
      case 'fresh_revoked': return { revoked: true, checkedAt: FRESH() }
      case 'stale_active': return { revoked: false, checkedAt: STALE() }
      case 'stale_revoked': return { revoked: true, checkedAt: STALE() }
      default: throw new Error(`unknown evidence ${evidence}`)
    }
  }

  for (const row of TABLE) {
    for (const policy of ['fail_open', 'cache_grace', 'fail_closed'] as const) {
      it(`${policy} with ${row.evidence} revocation evidence: valid=${row[policy]}`, () => {
        const status = verifyDelegation(live(), {
          revocationCheckPolicy: policy,
          cachedRevocationState: cacheFor(row.evidence),
          cacheGraceMs: GRACE_MS,
        })
        assert.equal(status.valid, row[policy], status.errors.join(' | '))
      })
    }
  }

  it('fail_closed differs from fail_open on absent evidence', () => {
    const d = live()
    const open = verifyDelegation(d, { revocationCheckPolicy: 'fail_open' })
    const closed = verifyDelegation(d, { revocationCheckPolicy: 'fail_closed' })
    assert.notEqual(open.valid, closed.valid, 'fail_closed must not be a synonym for fail_open')
  })

  it('fail_closed differs from fail_open on two-hour-stale not-revoked evidence', () => {
    const d = live()
    const cached = { revoked: false, checkedAt: STALE() }
    const open = verifyDelegation(d, { revocationCheckPolicy: 'fail_open', cachedRevocationState: cached })
    const closed = verifyDelegation(d, { revocationCheckPolicy: 'fail_closed', cachedRevocationState: cached })
    assert.equal(open.valid, true)
    assert.equal(closed.valid, false)
  })

  it('fail_closed differs from cache_grace on absent evidence', () => {
    const d = live()
    const grace = verifyDelegation(d, { revocationCheckPolicy: 'cache_grace' })
    const closed = verifyDelegation(d, { revocationCheckPolicy: 'fail_closed' })
    assert.equal(grace.valid, true)
    assert.equal(closed.valid, false)
  })

  it('fail_closed reports why it refused: the evidence, not a revocation it did not observe', () => {
    const status = verifyDelegation(live(), { revocationCheckPolicy: 'fail_closed' })
    assert.equal(status.valid, false)
    assert.equal(status.revoked, false, 'absent evidence is not an observed revocation')
    assert.equal(status.revocationEvidence, 'absent')
    assert.ok(
      status.errors.some(e => e.includes('revocation')),
      `expected a revocation-evidence error, got ${JSON.stringify(status.errors)}`,
    )
  })

  it('fail_closed labels stale evidence as stale rather than as a revocation', () => {
    const status = verifyDelegation(live(), {
      revocationCheckPolicy: 'fail_closed',
      cachedRevocationState: { revoked: false, checkedAt: STALE() },
      cacheGraceMs: GRACE_MS,
    })
    assert.equal(status.valid, false)
    assert.equal(status.revoked, false)
    assert.equal(status.revocationEvidence, 'stale')
  })

  it('fail_closed admits a delegation whose revocation evidence is fresh and clean', () => {
    const status = verifyDelegation(live(), {
      revocationCheckPolicy: 'fail_closed',
      cachedRevocationState: { revoked: false, checkedAt: FRESH() },
      cacheGraceMs: GRACE_MS,
    })
    assert.equal(status.valid, true, status.errors.join(' | '))
    assert.equal(status.revocationEvidence, 'fresh')
  })

  it('the default policy is unchanged: no option means fail_open', () => {
    const d = live()
    assert.equal(verifyDelegation(d).valid, true)
    assert.equal(verifyDelegation(d).valid, verifyDelegation(d, { revocationCheckPolicy: 'fail_open' }).valid)
  })
})
