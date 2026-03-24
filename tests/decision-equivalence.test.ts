import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  CANONICAL_PROFILES,
  resolveProfile,
  registerProfile,
  compareProfiles,
  compareDecisions,
  tagDecisionWithProfile,
  computeThresholdDistance,
} from '../src/index.js'
import type { BoundaryProfile, ProfileTaggedDecision } from '../src/index.js'

// ═══════════════════════════════════════
// Tests: Canonical Boundary Profiles
// ═══════════════════════════════════════

describe('Decision Equivalence — Boundary Profiles', () => {
  it('has 4 canonical profiles', () => {
    assert.ok(CANONICAL_PROFILES['aps:commerce:preflight'])
    assert.ok(CANONICAL_PROFILES['aps:data:access'])
    assert.ok(CANONICAL_PROFILES['aps:delegation:evaluate'])
    assert.ok(CANONICAL_PROFILES['aps:settlement:contribution'])
  })

  it('resolves known profile by name', () => {
    const p = resolveProfile('aps:commerce:preflight')
    assert.ok(p)
    assert.equal(p!.decisionType, 'commerce_authorization')
    assert.ok(p!.fields.includes('agentId'))
    assert.ok(p!.fields.includes('amount'))
  })

  it('returns undefined for unknown profile', () => {
    assert.equal(resolveProfile('nonexistent'), undefined)
  })

  it('registers custom profile', () => {
    registerProfile({
      name: 'test:custom:profile',
      version: '1.0',
      decisionType: 'test',
      fields: ['fieldA', 'fieldB'],
    })
    assert.ok(resolveProfile('test:custom:profile'))
    // cleanup
    delete CANONICAL_PROFILES['test:custom:profile']
  })

  it('rejects unnamespaced profile', () => {
    assert.throws(() => registerProfile({
      name: 'nonamespace',
      version: '1.0',
      decisionType: 'test',
      fields: ['a'],
    }), /must be namespaced/)
  })
})

// ═══════════════════════════════════════
// Tests: Profile Compatibility
// ═══════════════════════════════════════

describe('Decision Equivalence — Profile Compatibility', () => {
  it('identical profiles', () => {
    const a = resolveProfile('aps:commerce:preflight')!
    const result = compareProfiles(a, a)
    assert.equal(result.compatibility, 'identical')
    assert.equal(result.onlyInA.length, 0)
    assert.equal(result.onlyInB.length, 0)
  })

  it('superset profile', () => {
    const big: BoundaryProfile = { name: 'x:big', version: '1', decisionType: 't', fields: ['a', 'b', 'c'] }
    const small: BoundaryProfile = { name: 'x:small', version: '1', decisionType: 't', fields: ['a', 'b'] }
    const result = compareProfiles(big, small)
    assert.equal(result.compatibility, 'superset')
    assert.deepEqual(result.onlyInA, ['c'])
    assert.equal(result.onlyInB.length, 0)
  })

  it('subset profile', () => {
    const small: BoundaryProfile = { name: 'x:s', version: '1', decisionType: 't', fields: ['a'] }
    const big: BoundaryProfile = { name: 'x:b', version: '1', decisionType: 't', fields: ['a', 'b'] }
    const result = compareProfiles(small, big)
    assert.equal(result.compatibility, 'subset')
  })

  it('overlapping profiles', () => {
    const a: BoundaryProfile = { name: 'x:a', version: '1', decisionType: 't', fields: ['a', 'b', 'c'] }
    const b: BoundaryProfile = { name: 'x:b', version: '1', decisionType: 't', fields: ['b', 'c', 'd'] }
    const result = compareProfiles(a, b)
    assert.equal(result.compatibility, 'overlapping')
    assert.deepEqual(result.sharedFields, ['b', 'c'])
    assert.deepEqual(result.onlyInA, ['a'])
    assert.deepEqual(result.onlyInB, ['d'])
  })

  it('disjoint profiles', () => {
    const a: BoundaryProfile = { name: 'x:a', version: '1', decisionType: 't', fields: ['a', 'b'] }
    const b: BoundaryProfile = { name: 'x:b', version: '1', decisionType: 't', fields: ['c', 'd'] }
    const result = compareProfiles(a, b)
    assert.equal(result.compatibility, 'disjoint')
    assert.equal(result.sharedFields.length, 0)
  })
})

// ═══════════════════════════════════════
// Tests: Decision Comparison
// ═══════════════════════════════════════

describe('Decision Equivalence — compareDecisions', () => {
  it('equivalent: same profile, same data', () => {
    const fields = { agentId: 'a1', delegationId: 'd1', merchantOrigin: 'shop.com', intentName: 'buy', amount: 50, currency: 'USDC' }
    const a = tagDecisionWithProfile('aps:commerce:preflight', fields)
    const b = tagDecisionWithProfile('aps:commerce:preflight', { ...fields })
    const result = compareDecisions(a, b)
    assert.equal(result.equivalence, 'equivalent')
  })

  it('divergent: same profile, different data', () => {
    const a = tagDecisionWithProfile('aps:commerce:preflight', {
      agentId: 'a1', delegationId: 'd1', merchantOrigin: 'shop.com', intentName: 'buy', amount: 50, currency: 'USDC',
    })
    const b = tagDecisionWithProfile('aps:commerce:preflight', {
      agentId: 'a1', delegationId: 'd1', merchantOrigin: 'shop.com', intentName: 'buy', amount: 999, currency: 'USDC',
    })
    const result = compareDecisions(a, b)
    assert.equal(result.equivalence, 'divergent')
    assert.ok(result.divergentFields!.includes('amount'))
  })

  it('equivalent_on_intersection: overlapping profiles, matching shared fields', () => {
    registerProfile({ name: 'test:wide', version: '1', decisionType: 't', fields: ['agentId', 'action', 'extra'] })
    registerProfile({ name: 'test:narrow', version: '1', decisionType: 't', fields: ['agentId', 'action', 'other'] })
    const a = tagDecisionWithProfile('test:wide', { agentId: 'a1', action: 'read', extra: 'x' })
    const b = tagDecisionWithProfile('test:narrow', { agentId: 'a1', action: 'read', other: 'y' })
    const result = compareDecisions(a, b)
    assert.equal(result.equivalence, 'equivalent_on_intersection')
    assert.ok(result.projectedHashA)
    assert.equal(result.projectedHashA, result.projectedHashB)
    delete CANONICAL_PROFILES['test:wide']
    delete CANONICAL_PROFILES['test:narrow']
  })

  it('divergent_on_intersection: overlapping profiles, different shared values', () => {
    registerProfile({ name: 'test:x', version: '1', decisionType: 't', fields: ['agentId', 'amount'] })
    registerProfile({ name: 'test:y', version: '1', decisionType: 't', fields: ['agentId', 'currency'] })
    const a = tagDecisionWithProfile('test:x', { agentId: 'a1', amount: 50 })
    const b = tagDecisionWithProfile('test:y', { agentId: 'DIFFERENT', currency: 'USD' })
    const result = compareDecisions(a, b)
    assert.equal(result.equivalence, 'divergent_on_intersection')
    delete CANONICAL_PROFILES['test:x']
    delete CANONICAL_PROFILES['test:y']
  })

  it('incomparable: disjoint profiles', () => {
    registerProfile({ name: 'test:p', version: '1', decisionType: 't', fields: ['fieldA'] })
    registerProfile({ name: 'test:q', version: '1', decisionType: 't', fields: ['fieldZ'] })
    const a = tagDecisionWithProfile('test:p', { fieldA: 'v1' })
    const b = tagDecisionWithProfile('test:q', { fieldZ: 'v2' })
    const result = compareDecisions(a, b)
    assert.equal(result.equivalence, 'incomparable')
    delete CANONICAL_PROFILES['test:p']
    delete CANONICAL_PROFILES['test:q']
  })

  it('incomparable: unknown profile', () => {
    const a: ProfileTaggedDecision = { profileName: 'unknown:x', contentHash: { algorithm: 'sha256', hash: 'a', canonicalForm: 'canonical_json_sorted_keys' }, fields: {} }
    const b: ProfileTaggedDecision = { profileName: 'unknown:y', contentHash: { algorithm: 'sha256', hash: 'b', canonicalForm: 'canonical_json_sorted_keys' }, fields: {} }
    const result = compareDecisions(a, b)
    assert.equal(result.equivalence, 'incomparable')
  })
})

// ═══════════════════════════════════════
// Tests: Threshold Distance
// ═══════════════════════════════════════

describe('Decision Equivalence — Threshold Distance', () => {
  it('computes distance above threshold', () => {
    const td = computeThresholdDistance('risk_score', 0.75, 0.7)
    assert.equal(td.metric, 'risk_score')
    assert.equal(td.side, 'above')
    assert.ok(Math.abs(td.distance - 0.05) < 0.0001)
  })

  it('computes distance below threshold', () => {
    const td = computeThresholdDistance('risk_score', 0.69, 0.7)
    assert.equal(td.side, 'below')
    assert.ok(Math.abs(td.distance - 0.01) < 0.0001)
  })

  it('zero distance at exact threshold', () => {
    const td = computeThresholdDistance('risk_score', 0.7, 0.7)
    assert.equal(td.distance, 0)
    assert.equal(td.side, 'above')
  })
})

// ═══════════════════════════════════════
// Tests: Decision Question Invariant (xsa520 layer)
// ═══════════════════════════════════════

import {
  isSameDecisionQuestion,
  computeDecisionQuestionHash,
} from '../src/index.js'

describe('Decision Equivalence — Decision Question Invariant', () => {
  it('same question: identical profile fields → true', () => {
    const fields = { agentId: 'a1', delegationId: 'd1', merchantOrigin: 'shop.com', intentName: 'buy', amount: 50, currency: 'USDC' }
    const a = tagDecisionWithProfile('aps:commerce:preflight', fields)
    const b = tagDecisionWithProfile('aps:commerce:preflight', { ...fields })
    assert.equal(isSameDecisionQuestion(a, b), true)
  })

  it('same question even with extra non-profile fields differing', () => {
    const a = tagDecisionWithProfile('aps:commerce:preflight', {
      agentId: 'a1', delegationId: 'd1', merchantOrigin: 'shop.com', intentName: 'buy', amount: 50, currency: 'USDC',
      extraField: 'value1',
    })
    const b = tagDecisionWithProfile('aps:commerce:preflight', {
      agentId: 'a1', delegationId: 'd1', merchantOrigin: 'shop.com', intentName: 'buy', amount: 50, currency: 'USDC',
      extraField: 'DIFFERENT',
    })
    assert.equal(isSameDecisionQuestion(a, b), true)
  })

  it('different question: profile field differs → false', () => {
    const a = tagDecisionWithProfile('aps:commerce:preflight', {
      agentId: 'a1', delegationId: 'd1', merchantOrigin: 'shop.com', intentName: 'buy', amount: 50, currency: 'USDC',
    })
    const b = tagDecisionWithProfile('aps:commerce:preflight', {
      agentId: 'a1', delegationId: 'd1', merchantOrigin: 'OTHER-SHOP.com', intentName: 'buy', amount: 50, currency: 'USDC',
    })
    assert.equal(isSameDecisionQuestion(a, b), false)
  })

  it('different profiles → false (cannot compare)', () => {
    const a = tagDecisionWithProfile('aps:commerce:preflight', {
      agentId: 'a1', delegationId: 'd1', merchantOrigin: 'shop.com', intentName: 'buy', amount: 50, currency: 'USDC',
    })
    const b = tagDecisionWithProfile('aps:data:access', {
      agentId: 'a1', delegationId: 'd1', sourceId: 's1', termsVersion: '1.0', accessType: 'read',
    })
    assert.equal(isSameDecisionQuestion(a, b), false)
  })

  it('question hash is deterministic', () => {
    const fields = { agentId: 'a1', delegationId: 'd1', merchantOrigin: 'shop.com', intentName: 'buy', amount: 50, currency: 'USDC' }
    const h1 = computeDecisionQuestionHash(fields, 'aps:commerce:preflight')
    const h2 = computeDecisionQuestionHash(fields, 'aps:commerce:preflight')
    assert.equal(h1, h2)
    assert.equal(h1.length, 64) // sha256 hex
  })
})

// ═══════════════════════════════════════
// Tests: End-to-End — xsa520's scenario
// ═══════════════════════════════════════

describe('Decision Equivalence — End-to-End (xsa520 scenario)', () => {
  it('two systems, same question, different risk evaluations, threshold distance recorded', () => {
    // xsa520's example: risk=0.69 → ALLOW vs risk=0.7000001 → DENY
    const question = {
      agentId: 'agent-risk',
      delegationId: 'del-risk',
      scopeRequired: 'trade:execute',
      'action.type': 'trade',
      'action.target': 'AAPL',
    }

    const systemA = tagDecisionWithProfile('aps:delegation:evaluate', {
      ...question,
      verdict: 'permit',
      riskScore: 0.69,
    }, [computeThresholdDistance('risk_score', 0.69, 0.7)])

    const systemB = tagDecisionWithProfile('aps:delegation:evaluate', {
      ...question,
      verdict: 'deny',
      riskScore: 0.7000001,
    }, [computeThresholdDistance('risk_score', 0.7000001, 0.7)])

    // Same question? YES — profile fields match
    assert.equal(isSameDecisionQuestion(systemA, systemB), true)

    // Full comparison? EQUIVALENT — because the profile fields are identical
    // (verdict and riskScore are NOT in the delegation:evaluate profile)
    const result = compareDecisions(systemA, systemB)
    assert.equal(result.equivalence, 'equivalent')

    // But threshold distances reveal the divergence source
    assert.ok(systemA.thresholdDistances![0].side === 'below')  // 0.69 < 0.7
    assert.ok(systemB.thresholdDistances![0].side === 'above')  // 0.7000001 > 0.7
    assert.ok(systemA.thresholdDistances![0].distance < 0.02)   // close to boundary
    assert.ok(systemB.thresholdDistances![0].distance < 0.001)  // very close to boundary

    // The protocol proves: same question, threshold-adjacent evaluation,
    // divergent outcomes. It does NOT resolve which is "correct" —
    // that's the engine's responsibility.
  })
})
