// ══════════════════════════════════════════════════════════════════
// Governance Posture — SDK primitive tests
// ══════════════════════════════════════════════════════════════════
// State-machine tests (createInitialPosture, recordBehavioralFailure,
// recordBehavioralSuccess, upgradePosture) moved to gateway
// tests/sdk-migrated/core/posture-state.test.ts on 2026-04-17.
// SDK keeps tier definitions, default constraints, and pure helpers.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  getPostureConstraints, isScopeBlocked, comparePostureTiers,
} from '../src/core/governance-posture.js'

describe('Governance Posture — Constraints & Scope Blocking', () => {
  it('quarantine blocks all scopes', () => {
    assert.ok(isScopeBlocked('quarantine', 'data:read'))
    assert.ok(isScopeBlocked('quarantine', 'anything'))
  })

  it('restricted blocks commerce and admin', () => {
    assert.ok(isScopeBlocked('restricted', 'commerce:checkout'))
    assert.ok(isScopeBlocked('restricted', 'admin'))
    assert.ok(isScopeBlocked('restricted', 'data:write'))
    assert.ok(!isScopeBlocked('restricted', 'data:read'))
  })

  it('standard blocks nothing', () => {
    assert.ok(!isScopeBlocked('standard', 'commerce:checkout'))
    assert.ok(!isScopeBlocked('standard', 'admin'))
  })

  it('constraints get more restrictive at lower tiers', () => {
    const full = getPostureConstraints('full_trust')
    const cautious = getPostureConstraints('cautious')
    const restricted = getPostureConstraints('restricted')
    assert.ok((full.maxSpendPerAction ?? Infinity) > (cautious.maxSpendPerAction ?? Infinity))
    assert.ok((cautious.maxSpendPerAction ?? Infinity) > (restricted.maxSpendPerAction ?? Infinity))
  })

  it('comparePostureTiers orders correctly', () => {
    assert.ok(comparePostureTiers('full_trust', 'standard') > 0)
    assert.ok(comparePostureTiers('quarantine', 'restricted') < 0)
    assert.strictEqual(comparePostureTiers('standard', 'standard'), 0)
  })

  it('custom overrides merge into base constraints', () => {
    const c = getPostureConstraints('standard', {
      standard: { maxSpendPerAction: 9999 },
    })
    assert.equal(c.maxSpendPerAction, 9999)
    assert.equal(c.maxDelegationDepth, 3)
  })
})
