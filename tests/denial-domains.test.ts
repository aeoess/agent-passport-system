// ══════════════════════════════════════════════════════════════════
// Denial Domains — Tests
// ══════════════════════════════════════════════════════════════════
// Consilium Priority 4 — unanimous that 15 facets need grouping.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  getDomain, getDomainLabel, summarizeDenial, groupByDomain,
  EVALUATION_ORDER,
} from '../src/core/denial-domains.js'
import type { ConstraintFailure } from '../src/types/gateway.js'

function makeFailure(facet: string, code: string, msg: string): ConstraintFailure {
  return {
    facet: facet as any, status: 'fail', code, severity: 'hard',
    retryable: false, message: msg,
  }
}

describe('Denial Domains — Facet-to-Domain Mapping', () => {
  it('maps all 14 facets to domains', () => {
    const facets = [
      'identity', 'reputation', 'fidelity',
      'scope', 'reversibility', 'escalation', 'revocation',
      'spend', 'data',
      'time', 'replay', 'governance', 'cross_chain',
      'values',
    ]
    for (const f of facets) {
      const domain = getDomain(f as any)
      assert.ok(domain, `Facet '${f}' should map to a domain`)
    }
  })

  it('identity cluster maps to identity_trust', () => {
    assert.strictEqual(getDomain('identity'), 'identity_trust')
    assert.strictEqual(getDomain('reputation'), 'identity_trust')
    assert.strictEqual(getDomain('fidelity'), 'identity_trust')
  })

  it('authority cluster maps to authority_scope', () => {
    assert.strictEqual(getDomain('scope'), 'authority_scope')
    assert.strictEqual(getDomain('revocation'), 'authority_scope')
    assert.strictEqual(getDomain('escalation'), 'authority_scope')
    assert.strictEqual(getDomain('reversibility'), 'authority_scope')
  })

  it('economic cluster maps correctly', () => {
    assert.strictEqual(getDomain('spend'), 'economic')
    assert.strictEqual(getDomain('data'), 'economic')
  })

  it('temporal cluster maps correctly', () => {
    assert.strictEqual(getDomain('time'), 'temporal_integrity')
    assert.strictEqual(getDomain('replay'), 'temporal_integrity')
    assert.strictEqual(getDomain('governance'), 'temporal_integrity')
    assert.strictEqual(getDomain('cross_chain'), 'temporal_integrity')
  })

  it('values maps to safety_values', () => {
    assert.strictEqual(getDomain('values'), 'safety_values')
  })

  it('domain labels are human-readable', () => {
    assert.strictEqual(getDomainLabel('identity_trust'), 'Identity & Trust')
    assert.strictEqual(getDomainLabel('economic'), 'Economic Controls')
  })
})

describe('Denial Domains — Denial Summary', () => {
  it('returns null for no failures', () => {
    assert.strictEqual(summarizeDenial([]), null)
  })

  it('single failure becomes primary with no contributing', () => {
    const failures = [makeFailure('spend', 'SPEND_EXCEEDED', 'Over budget')]
    const summary = summarizeDenial(failures)!
    assert.ok(summary)
    assert.strictEqual(summary.primary.facet, 'spend')
    assert.strictEqual(summary.primary.domain, 'economic')
    assert.strictEqual(summary.primary.domainLabel, 'Economic Controls')
    assert.strictEqual(summary.contributing.length, 0)
    assert.strictEqual(summary.totalFailures, 1)
  })

  it('primary is the cheapest check that failed (evaluation order)', () => {
    const failures = [
      makeFailure('values', 'VALUES_VIOLATION', 'Values floor'),
      makeFailure('replay', 'REPLAY_DETECTED', 'Duplicate request'),
      makeFailure('scope', 'SCOPE_DENIED', 'No scope'),
    ]
    const summary = summarizeDenial(failures)!
    // replay is cheapest → primary
    assert.strictEqual(summary.primary.facet, 'replay')
    assert.strictEqual(summary.contributing.length, 2)
    assert.strictEqual(summary.totalFailures, 3)
  })

  it('provides nearestSatisfiable for spend failure', () => {
    const failures = [
      { ...makeFailure('spend', 'SPEND_EXCEEDED', 'Over budget'), limit: 100, actual: 250 },
    ]
    const summary = summarizeDenial(failures)!
    assert.ok(summary.nearestSatisfiable)
    assert.ok(summary.nearestSatisfiable!.includes('250'))
  })

  it('provides remediationHint based on domain', () => {
    const failures = [makeFailure('fidelity', 'FIDELITY_LOW', 'Below threshold')]
    const summary = summarizeDenial(failures)!
    assert.ok(summary.remediationHint)
    assert.ok(summary.remediationHint!.includes('trust'))
  })
})

describe('Denial Domains — Group By Domain', () => {
  it('groups failures into domain buckets', () => {
    const failures = [
      makeFailure('spend', 'SPEND_EXCEEDED', 'Over budget'),
      makeFailure('scope', 'SCOPE_DENIED', 'No scope'),
      makeFailure('reputation', 'TIER_LOW', 'Tier too low'),
      makeFailure('time', 'EXPIRED', 'Delegation expired'),
    ]
    const groups = groupByDomain(failures)
    assert.strictEqual(groups.economic.length, 1)
    assert.strictEqual(groups.authority_scope.length, 1)
    assert.strictEqual(groups.identity_trust.length, 1)
    assert.strictEqual(groups.temporal_integrity.length, 1)
    assert.strictEqual(groups.safety_values.length, 0)
  })
})

describe('Denial Domains — Evaluation Order', () => {
  it('has all 14 facets in the evaluation order', () => {
    assert.strictEqual(EVALUATION_ORDER.length, 14)
  })

  it('cheap checks come before expensive ones', () => {
    const replayIdx = EVALUATION_ORDER.indexOf('replay')
    const valuesIdx = EVALUATION_ORDER.indexOf('values')
    const fidelityIdx = EVALUATION_ORDER.indexOf('fidelity')
    assert.ok(replayIdx < valuesIdx, 'replay should be before values')
    assert.ok(replayIdx < fidelityIdx, 'replay should be before fidelity')
  })
})
