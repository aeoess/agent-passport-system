// Delegation Linting — Gateway-compatible feasibility checks
// Only tests the 2 checks that work against current gateway schema:
// SPEND_TOO_LOW, SCOPE_MISSING. All other checks skipped with reasons.

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { lintDelegationForGateway } from '../src/core/feasibility.js'
import { createDelegation, clearStores } from '../src/core/delegation.js'
import { generateKeyPair } from '../src/crypto/keys.js'
import type { Delegation } from '../src/types/passport.js'

function makeDelegation(overrides: Partial<Delegation> = {}): Delegation {
  const kpFrom = generateKeyPair()
  const kpTo = generateKeyPair()
  return createDelegation({
    delegatedBy: kpFrom.publicKey,
    delegatedTo: kpTo.publicKey,
    scope: ['read:docs', 'write:issues'],
    maxDepth: 3,
    expiresAt: new Date(Date.now() + 86400000).toISOString(),
    spendLimit: 100,
    privateKey: kpFrom.privateKey,
    ...overrides,
  })
}

describe('Delegation Linting — Gateway-Compatible Checks', () => {
  beforeEach(() => { clearStores() })

  it('SPEND_TOO_LOW detected when budget below estimated cost', () => {
    const del = makeDelegation({ spendLimit: 5 })
    const report = lintDelegationForGateway(del, { estimatedSpend: 50 })

    assert.equal(report.errors, 1)
    assert.equal(report.results[0].code, 'SPEND_TOO_LOW')
    assert.ok(report.results[0].message.includes('$5'))
    assert.ok(report.results[0].message.includes('$50'))
  })

  it('SCOPE_MISSING detected when required scope not covered', () => {
    const del = makeDelegation()
    const report = lintDelegationForGateway(del, {
      requiredScopes: ['deploy:production', 'admin:delete'],
    })

    assert.equal(report.errors, 1)
    assert.equal(report.results[0].code, 'SCOPE_MISSING')
    assert.ok(report.results[0].message.includes('deploy:production'))
  })

  it('clean report when all checks pass', () => {
    const del = makeDelegation({ spendLimit: 100 })
    const report = lintDelegationForGateway(del, {
      requiredScopes: ['read:docs'],
      estimatedSpend: 10,
    })

    assert.equal(report.errors, 0)
    assert.equal(report.warnings, 0)
    assert.equal(report.checks_run, 2)
    assert.ok(report.checks_skipped >= 3) // gateway schema limitations
  })

  it('no context: checks skipped with reasons', () => {
    const del = makeDelegation()
    const report = lintDelegationForGateway(del)

    assert.equal(report.checks_run, 0)
    assert.ok(report.checks_skipped >= 5)
    assert.ok(report.skipped_reasons.length >= 5)
    assert.ok(report.skipped_reasons.some(r => r.includes('estimatedSpend not provided')))
    assert.ok(report.skipped_reasons.some(r => r.includes('requiredScopes not provided')))
    assert.ok(report.skipped_reasons.some(r => r.includes('ALREADY_EXPIRED')))
  })

  it('multiple errors: all reported', () => {
    const del = makeDelegation({ spendLimit: 5 })
    const report = lintDelegationForGateway(del, {
      requiredScopes: ['deploy:production'],
      estimatedSpend: 50,
    })

    assert.equal(report.errors, 2)
    assert.equal(report.checks_run, 2)
    const codes = report.results.map(r => r.code)
    assert.ok(codes.includes('SPEND_TOO_LOW'))
    assert.ok(codes.includes('SCOPE_MISSING'))
  })

  it('backward compat: minimal Delegation shape works', () => {
    const kp = generateKeyPair()
    const kp2 = generateKeyPair()
    const del = createDelegation({
      delegatedBy: kp.publicKey,
      delegatedTo: kp2.publicKey,
      scope: ['*'],
      maxDepth: 1,
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
      privateKey: kp.privateKey,
    })
    // No spendLimit set
    const report = lintDelegationForGateway(del, {
      requiredScopes: ['anything'],
      estimatedSpend: 100,
    })

    // Wildcard scope covers everything
    assert.equal(report.results.filter(r => r.code === 'SCOPE_MISSING').length, 0)
    // Spend check skipped (no spendLimit on delegation)
    assert.ok(report.skipped_reasons.some(r => r.includes('spendLimit')))
  })

  it('skipped_reasons always include gateway schema limitations', () => {
    const del = makeDelegation()
    const report = lintDelegationForGateway(del, {
      requiredScopes: ['read:docs'],
      estimatedSpend: 10,
    })

    assert.ok(report.skipped_reasons.some(r => r.includes('ALREADY_EXPIRED')))
    assert.ok(report.skipped_reasons.some(r => r.includes('DEADLINE_IMPOSSIBLE')))
    assert.ok(report.skipped_reasons.some(r => r.includes('DEPTH_MAXED')))
  })

  it('delegation_id is included in report', () => {
    const del = makeDelegation()
    const report = lintDelegationForGateway(del)
    assert.ok(report.delegation_id)
    assert.equal(report.delegation_id, del.delegationId)
  })
})
