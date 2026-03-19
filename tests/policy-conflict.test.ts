// Policy Conflict Detection Tests (Module 30)
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  detectCycles, detectShadowedRules, detectContradictions,
  detectUnreachableActions, analyzePolicyRules,
} from '../src/core/policy-conflict.js'
import type { PolicyRule } from '../src/core/policy-conflict.js'

function rule(id: string, scope: string, verdict: 'permit' | 'deny', priority: number, opts?: {
  dependsOn?: string[], conditions?: Record<string, string>
}): PolicyRule {
  return {
    ruleId: id, actionScope: scope, verdict, priority,
    dependsOn: opts?.dependsOn ?? [],
    conditions: opts?.conditions ?? {},
  }
}

describe('Cycle Detection (DFS)', () => {
  it('no cycles in independent rules', () => {
    const rules = [
      rule('r1', 'data:read', 'permit', 10),
      rule('r2', 'data:write', 'deny', 10),
    ]
    assert.equal(detectCycles(rules).length, 0)
  })

  it('detects simple A→B→A cycle', () => {
    const rules = [
      rule('r1', 'data:read', 'permit', 10, { dependsOn: ['r2'] }),
      rule('r2', 'data:write', 'deny', 10, { dependsOn: ['r1'] }),
    ]
    const cycles = detectCycles(rules)
    assert.ok(cycles.length > 0, 'Should detect at least one cycle')
    // Cycle should contain both r1 and r2
    const flat = cycles.flat()
    assert.ok(flat.includes('r1'))
    assert.ok(flat.includes('r2'))
  })

  it('detects 3-node cycle A→B→C→A', () => {
    const rules = [
      rule('r1', 'a', 'permit', 10, { dependsOn: ['r2'] }),
      rule('r2', 'b', 'permit', 10, { dependsOn: ['r3'] }),
      rule('r3', 'c', 'deny', 10, { dependsOn: ['r1'] }),
    ]
    const cycles = detectCycles(rules)
    assert.ok(cycles.length > 0)
  })

  it('no false positive on DAG (no cycle)', () => {
    const rules = [
      rule('r1', 'a', 'permit', 10, { dependsOn: ['r2'] }),
      rule('r2', 'b', 'permit', 10, { dependsOn: ['r3'] }),
      rule('r3', 'c', 'deny', 10),
    ]
    assert.equal(detectCycles(rules).length, 0)
  })
})

describe('Shadowed Rule Detection', () => {
  it('detects rule shadowed by higher-priority same-scope rule', () => {
    const rules = [
      rule('r-high', 'data:read', 'permit', 100),
      rule('r-low', 'data:read', 'deny', 10),
    ]
    const shadowed = detectShadowedRules(rules)
    assert.equal(shadowed.length, 1)
    assert.equal(shadowed[0].shadowedRuleId, 'r-low')
    assert.equal(shadowed[0].shadowedByRuleId, 'r-high')
  })

  it('detects rule shadowed by wildcard parent scope', () => {
    const rules = [
      rule('r-broad', 'data:*', 'permit', 100),
      rule('r-narrow', 'data:read', 'deny', 10),
    ]
    const shadowed = detectShadowedRules(rules)
    assert.equal(shadowed.length, 1)
    assert.equal(shadowed[0].shadowedRuleId, 'r-narrow')
  })

  it('does NOT shadow when conditions differ', () => {
    const rules = [
      rule('r-high', 'data:read', 'permit', 100, { conditions: { env: 'prod' } }),
      rule('r-low', 'data:read', 'deny', 10, { conditions: { env: 'staging' } }),
    ]
    const shadowed = detectShadowedRules(rules)
    assert.equal(shadowed.length, 0)
  })
})

describe('Contradiction Detection', () => {
  it('detects permit/deny contradiction at same priority', () => {
    const rules = [
      rule('r-permit', 'data:read', 'permit', 10),
      rule('r-deny', 'data:read', 'deny', 10),
    ]
    const contradictions = detectContradictions(rules)
    assert.equal(contradictions.length, 1)
    assert.equal(contradictions[0].permitRuleId, 'r-permit')
    assert.equal(contradictions[0].denyRuleId, 'r-deny')
  })

  it('no contradiction when priorities differ (tiebreak exists)', () => {
    const rules = [
      rule('r-permit', 'data:read', 'permit', 100),
      rule('r-deny', 'data:read', 'deny', 10),
    ]
    assert.equal(detectContradictions(rules).length, 0)
  })
})

describe('Unreachable Actions', () => {
  it('detects actions no rule covers', () => {
    const rules = [
      rule('r1', 'data:read', 'permit', 10),
      rule('r2', 'data:write', 'deny', 10),
    ]
    const unreachable = detectUnreachableActions(rules, ['data:read', 'data:write', 'data:delete', 'commerce:purchase'])
    assert.deepEqual(unreachable, ['data:delete', 'commerce:purchase'])
  })

  it('wildcard rule covers everything', () => {
    const rules = [rule('r1', '*', 'deny', 10)]
    const unreachable = detectUnreachableActions(rules, ['data:read', 'commerce:purchase'])
    assert.equal(unreachable.length, 0)
  })
})

describe('Full Analysis — analyzePolicyRules', () => {
  it('healthy rule set reports clean', () => {
    const rules = [
      rule('r1', 'data:read', 'permit', 100),
      rule('r2', 'data:write', 'deny', 50),
    ]
    const report = analyzePolicyRules(rules, ['data:read', 'data:write'])
    assert.equal(report.healthy, true)
    assert.equal(report.cycles.length, 0)
    assert.equal(report.contradictions.length, 0)
    assert.equal(report.unreachableActions.length, 0)
  })

  it('unhealthy rule set with cycle + contradiction', () => {
    const rules = [
      rule('r1', 'data:read', 'permit', 10, { dependsOn: ['r2'] }),
      rule('r2', 'data:read', 'deny', 10, { dependsOn: ['r1'] }),
    ]
    const report = analyzePolicyRules(rules)
    assert.equal(report.healthy, false)
    assert.ok(report.cycles.length > 0, 'Should have cycles')
    assert.ok(report.contradictions.length > 0, 'Should have contradictions')
  })
})
