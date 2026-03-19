import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import { createDelegation } from '../src/core/delegation.js'
import { lintDelegation, lintTaskFeasibility } from '../src/core/feasibility.js'
import type { TaskRoleSpec } from '../src/types/coordination.js'

describe('Feasibility Linting (Gap 7)', () => {
  const kp1 = generateKeyPair()
  const kp2 = generateKeyPair()

  describe('lintDelegation', () => {
    it('passes for valid delegation params', () => {
      const r = lintDelegation({
        delegatedTo: kp2.publicKey,
        delegatedBy: kp1.publicKey,
        scope: ['data:read', 'data:write'],
        spendLimit: 100,
        expiresInHours: 24,
      })
      assert.equal(r.feasible, true)
      assert.equal(r.errorCount, 0)
    })

    it('errors on empty scope', () => {
      const r = lintDelegation({
        delegatedTo: kp2.publicKey,
        delegatedBy: kp1.publicKey,
        scope: [],
      })
      assert.equal(r.feasible, false)
      assert.ok(r.issues.some(i => i.code === 'EMPTY_SCOPE'))
    })

    it('warns on self-delegation', () => {
      const r = lintDelegation({
        delegatedTo: kp1.publicKey,
        delegatedBy: kp1.publicKey,
        scope: ['data:read'],
      })
      assert.equal(r.feasible, true) // warning, not error
      assert.ok(r.issues.some(i => i.code === 'SELF_DELEGATION'))
      assert.equal(r.warningCount, 1)
    })

    it('errors on missing delegate', () => {
      const r = lintDelegation({
        delegatedTo: '',
        delegatedBy: kp1.publicKey,
        scope: ['data:read'],
      })
      assert.equal(r.feasible, false)
      assert.ok(r.issues.some(i => i.code === 'MISSING_DELEGATE'))
    })

    it('errors on negative spend limit', () => {
      const r = lintDelegation({
        delegatedTo: kp2.publicKey,
        delegatedBy: kp1.publicKey,
        scope: ['data:read'],
        spendLimit: -50,
      })
      assert.equal(r.feasible, false)
      assert.ok(r.issues.some(i => i.code === 'NEGATIVE_SPEND'))
    })

    it('warns on zero spend limit', () => {
      const r = lintDelegation({
        delegatedTo: kp2.publicKey,
        delegatedBy: kp1.publicKey,
        scope: ['data:read'],
        spendLimit: 0,
      })
      assert.equal(r.feasible, true)
      assert.ok(r.issues.some(i => i.code === 'ZERO_SPEND'))
    })

    it('errors on depth exceeded', () => {
      const r = lintDelegation({
        delegatedTo: kp2.publicKey,
        delegatedBy: kp1.publicKey,
        scope: ['data:read'],
        maxDepth: 2,
        currentDepth: 3,
      })
      assert.equal(r.feasible, false)
      assert.ok(r.issues.some(i => i.code === 'DEPTH_EXCEEDED'))
    })

    it('errors on expired-at-creation', () => {
      const r = lintDelegation({
        delegatedTo: kp2.publicKey,
        delegatedBy: kp1.publicKey,
        scope: ['data:read'],
        expiresInHours: -1,
      })
      assert.equal(r.feasible, false)
      assert.ok(r.issues.some(i => i.code === 'EXPIRED_AT_CREATION'))
    })

    it('warns on very short expiry', () => {
      const r = lintDelegation({
        delegatedTo: kp2.publicKey,
        delegatedBy: kp1.publicKey,
        scope: ['data:read'],
        expiresInHours: 0.5,
      })
      assert.equal(r.feasible, true)
      assert.ok(r.issues.some(i => i.code === 'SHORT_EXPIRY'))
    })

    it('warns on wildcard scope', () => {
      const r = lintDelegation({
        delegatedTo: kp2.publicKey,
        delegatedBy: kp1.publicKey,
        scope: ['*'],
      })
      assert.equal(r.feasible, true)
      assert.ok(r.issues.some(i => i.code === 'WILDCARD_SCOPE'))
    })

    it('collects multiple issues', () => {
      const r = lintDelegation({
        delegatedTo: '',
        delegatedBy: '',
        scope: [],
        spendLimit: -10,
        expiresInHours: -1,
      })
      assert.equal(r.feasible, false)
      assert.ok(r.errorCount >= 4)
    })
  })

  describe('lintTaskFeasibility', () => {
    const role: TaskRoleSpec = {
      role: 'researcher',
      description: 'Research task',
      allowedScopes: ['data:read', 'search'],
      forbiddenScopes: ['admin:delete'],
    }

    it('passes when delegation covers role scopes', () => {
      const del = createDelegation({
        delegatedTo: kp2.publicKey,
        delegatedBy: kp1.publicKey,
        scope: ['data:read', 'search', 'data:write'],
        expiresInHours: 48,
        privateKey: kp1.privateKey,
      })
      const r = lintTaskFeasibility({ delegation: del, role })
      assert.equal(r.feasible, true)
      assert.equal(r.errorCount, 0)
    })

    it('errors when delegation missing required scope', () => {
      const del = createDelegation({
        delegatedTo: kp2.publicKey,
        delegatedBy: kp1.publicKey,
        scope: ['data:read'],  // missing 'search'
        expiresInHours: 48,
        privateKey: kp1.privateKey,
      })
      const r = lintTaskFeasibility({ delegation: del, role })
      assert.equal(r.feasible, false)
      assert.ok(r.issues.some(i => i.code === 'SCOPE_MISMATCH'))
    })

    it('warns on forbidden scope granted', () => {
      const del = createDelegation({
        delegatedTo: kp2.publicKey,
        delegatedBy: kp1.publicKey,
        scope: ['data:read', 'search', 'admin:delete'],
        expiresInHours: 48,
        privateKey: kp1.privateKey,
      })
      const r = lintTaskFeasibility({ delegation: del, role })
      assert.ok(r.issues.some(i => i.code === 'FORBIDDEN_SCOPE'))
      assert.equal(r.warningCount, 1)
    })

    it('errors when delegation expires before deadline', () => {
      const del = createDelegation({
        delegatedTo: kp2.publicKey,
        delegatedBy: kp1.publicKey,
        scope: ['data:read', 'search'],
        expiresInHours: 1,
        privateKey: kp1.privateKey,
      })
      const futureDeadline = new Date()
      futureDeadline.setHours(futureDeadline.getHours() + 48)
      const r = lintTaskFeasibility({
        delegation: del,
        role,
        taskDeadline: futureDeadline.toISOString(),
      })
      assert.equal(r.feasible, false)
      assert.ok(r.issues.some(i => i.code === 'DELEGATION_EXPIRES_BEFORE_DEADLINE'))
    })

    it('errors when budget is exhausted', () => {
      const del = createDelegation({
        delegatedTo: kp2.publicKey,
        delegatedBy: kp1.publicKey,
        scope: ['data:read', 'search'],
        spendLimit: 100,
        expiresInHours: 48,
        privateKey: kp1.privateKey,
      })
      // Simulate exhausted budget
      del.spentAmount = 100
      const r = lintTaskFeasibility({ delegation: del, role })
      assert.equal(r.feasible, false)
      assert.ok(r.issues.some(i => i.code === 'BUDGET_EXHAUSTED'))
    })

    it('info when at depth limit', () => {
      const del = createDelegation({
        delegatedTo: kp2.publicKey,
        delegatedBy: kp1.publicKey,
        scope: ['data:read', 'search'],
        maxDepth: 1,
        currentDepth: 1,
        expiresInHours: 48,
        privateKey: kp1.privateKey,
      })
      const r = lintTaskFeasibility({ delegation: del, role })
      assert.ok(r.issues.some(i => i.code === 'CANNOT_SUBDELEGATE'))
      // Info severity — still feasible
      assert.equal(r.feasible, true)
    })

    it('passes with hierarchical scope coverage (data:* covers data:read)', () => {
      const del = createDelegation({
        delegatedTo: kp2.publicKey,
        delegatedBy: kp1.publicKey,
        scope: ['data:*', 'search'],
        expiresInHours: 48,
        privateKey: kp1.privateKey,
      })
      const r = lintTaskFeasibility({ delegation: del, role })
      assert.equal(r.feasible, true)
      assert.equal(r.errorCount, 0)
    })

    it('collects multiple issues', () => {
      const del = createDelegation({
        delegatedTo: kp2.publicKey,
        delegatedBy: kp1.publicKey,
        scope: ['unrelated:scope', 'admin:delete'],
        spendLimit: 50,
        expiresInHours: 48,
        privateKey: kp1.privateKey,
      })
      del.spentAmount = 50 // budget exhausted
      const futureDeadline = new Date()
      futureDeadline.setHours(futureDeadline.getHours() + 96)
      const r = lintTaskFeasibility({
        delegation: del,
        role,
        taskDeadline: futureDeadline.toISOString(),
      })
      // Should have: SCOPE_MISMATCH (x2), FORBIDDEN_SCOPE, DELEGATION_EXPIRES_BEFORE_DEADLINE, BUDGET_EXHAUSTED
      assert.equal(r.feasible, false)
      assert.ok(r.issues.length >= 3)
    })
  })
})
