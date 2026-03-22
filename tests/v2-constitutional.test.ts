import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'

import {
  // A1: Epistemic Isolation
  createBarrier, submitToBarrier, isBarrierComplete,
  getBarrierStatus, revealResults, clearEpistemicIsolationStores,
  // A2: Values Override
  invokeValuesOverride, reviewOverride, getOverrideHistory,
  getPendingOverrideReviews, getAgentPenaltyCount,
  clearValuesOverrideStores,
  // A3: Inaction Auditing
  recordAvailableAction, recordInaction, recordConsequence,
  analyzeInactionPattern, clearInactionAuditStores,
  // A4: Intent Binding
  createIntentChain, extendChain, validateChainIntegrity,
  clearIntentBindingStores,
  // A5: Effect Sampling
  createSamplingPolicy, shouldSample, recordSample,
  completeAudit, getSamplingStats, setSamplingRng,
  clearEffectSamplingStores,
  // A6: Output Proportionality
  analyzeOutputProportionality, getFlaggedOutputs,
  clearOutputProportionalityStores,
  // A7: Circuit Breakers
  defineBreaker, evaluateBreaker, tripBreaker, resetBreaker,
  isActionBlocked, getBlockedCategories, clearCircuitBreakerStores,
  // A8: Affected-Party Standing
  registerAffectedParty, fileComplaint, resolveComplaint,
  fileAppeal, resolveAppeal, getComplaints,
  clearAffectedPartyStores,
} from '../src/v2/index.js'

// ═══════════════════════════════════════
// A1: EPISTEMIC ISOLATION
// ═══════════════════════════════════════
describe('v2 Epistemic Isolation', () => {
  beforeEach(() => clearEpistemicIsolationStores())

  it('creates barrier and collects submissions', () => {
    const b = createBarrier('task-1', ['agent-a', 'agent-b', 'agent-c'])
    assert.equal(b.status, 'collecting')
    submitToBarrier(b.id, 'agent-a', 'My analysis: bullish')
    assert.ok(!isBarrierComplete(b.id))
    submitToBarrier(b.id, 'agent-b', 'My analysis: bearish')
    submitToBarrier(b.id, 'agent-c', 'My analysis: neutral')
    assert.ok(isBarrierComplete(b.id))
  })

  it('blocks peek before all submitted', () => {
    const b = createBarrier('task-2', ['a1', 'a2'])
    submitToBarrier(b.id, 'a1', 'secret-1')
    const status = getBarrierStatus(b.id)
    assert.equal(status.hashes, undefined, 'No hashes visible while collecting')
  })

  it('reveals all submissions after complete', () => {
    const b = createBarrier('task-3', ['x', 'y'])
    submitToBarrier(b.id, 'x', 'analysis-x')
    submitToBarrier(b.id, 'y', 'analysis-y')
    const results = revealResults(b.id)
    assert.equal(results.submissions.length, 2)
    assert.ok(results.submissions.find(s => s.agent_id === 'x'))
  })

  it('rejects reveal before complete', () => {
    const b = createBarrier('task-4', ['a', 'b'])
    submitToBarrier(b.id, 'a', 'only-one')
    assert.throws(() => revealResults(b.id), /not all agents/)
  })

  it('rejects duplicate submission', () => {
    const b = createBarrier('task-5', ['a', 'b'])
    submitToBarrier(b.id, 'a', 'first')
    assert.throws(() => submitToBarrier(b.id, 'a', 'second'), /already submitted/)
  })

  it('rejects unauthorized agent', () => {
    const b = createBarrier('task-6', ['a', 'b'])
    assert.throws(() => submitToBarrier(b.id, 'intruder', 'hack'), /not in required/)
  })
})

// ═══════════════════════════════════════
// A2: VALUES OVERRIDE
// ═══════════════════════════════════════
describe('v2 Values Override', () => {
  beforeEach(() => clearValuesOverrideStores())

  it('invokes override with substantive justification', () => {
    const o = invokeValuesOverride({
      agent_id: 'nurse-agent', invoked_principle: 'F-007-proportionality',
      original_scope: ['patient:read'], expanded_action: 'administer emergency medication',
      justification: 'Patient in anaphylactic shock, no doctor available, delay risks death',
      risk_class: 'critical',
    })
    assert.equal(o.status, 'pending_review')
    assert.ok(getPendingOverrideReviews().length === 1)
  })

  it('rejects weak justification', () => {
    assert.throws(() => invokeValuesOverride({
      agent_id: 'lazy', invoked_principle: 'F-001',
      original_scope: ['x'], expanded_action: 'y',
      justification: 'because I want to', risk_class: 'low',
    }), /substantive/)
  })

  it('review justified — no penalty', () => {
    const o = invokeValuesOverride({
      agent_id: 'agent-1', invoked_principle: 'F-007',
      original_scope: ['read'], expanded_action: 'emergency write',
      justification: 'Critical system failure requiring immediate intervention to prevent data loss',
      risk_class: 'high',
    })
    const reviewed = reviewOverride(o.id, 'reviewer-1', true, 'Justified emergency')
    assert.equal(reviewed.status, 'reviewed_justified')
    assert.equal(reviewed.penalty_applied, false)
  })

  it('review unjustified — penalty applied', () => {
    const o = invokeValuesOverride({
      agent_id: 'agent-2', invoked_principle: 'F-006',
      original_scope: ['read'], expanded_action: 'delete records',
      justification: 'Records were outdated and taking up space, needed cleanup urgently',
      risk_class: 'medium',
    })
    reviewOverride(o.id, 'reviewer-2', false, 'Not a valid emergency')
    assert.equal(getAgentPenaltyCount('agent-2'), 1)
  })

  it('agent cannot review own override', () => {
    const o = invokeValuesOverride({
      agent_id: 'self-reviewer', invoked_principle: 'F-001',
      original_scope: ['x'], expanded_action: 'y',
      justification: 'This is a legitimate emergency requiring scope expansion now',
      risk_class: 'low',
    })
    assert.throws(() => reviewOverride(o.id, 'self-reviewer', true, 'I approve myself'), /own override/)
  })
})

// ═══════════════════════════════════════
// A3: INACTION AUDITING
// ═══════════════════════════════════════
describe('v2 Inaction Auditing', () => {
  beforeEach(() => clearInactionAuditStores())

  it('records available action and inaction', () => {
    const avail = recordAvailableAction({
      agent_id: 'agent-timid', task_id: 'task-1',
      action_description: 'Escalate fraud alert', risk_class: 'high',
    })
    const inaction = recordInaction(avail.id, 'Uncertain about classification')
    assert.equal(inaction.agent_id, 'agent-timid')
    assert.equal(inaction.flagged, false) // not flagged until consequence
  })

  it('flags inaction with consequence', () => {
    const avail = recordAvailableAction({
      agent_id: 'agent-timid', task_id: 'task-2',
      action_description: 'Alert doctor about drug interaction', risk_class: 'critical',
    })
    const inaction = recordInaction(avail.id, 'Not sure if interaction is serious')
    recordConsequence(inaction.id, 'Patient experienced adverse reaction')
    assert.equal(inaction.flagged, true)
    assert.equal(inaction.consequence, 'Patient experienced adverse reaction')
  })

  it('detects systematic inaction pattern', () => {
    for (let i = 0; i < 10; i++) {
      const a = recordAvailableAction({
        agent_id: 'agent-frozen', task_id: `task-${i}`,
        action_description: `Action ${i}`, risk_class: 'medium',
      })
      if (i < 8) recordInaction(a.id, 'Too risky')
    }
    const analysis = analyzeInactionPattern('agent-frozen')
    assert.ok(analysis.inaction_rate > 0.7)
    assert.ok(analysis.flagged)
  })
})

// ═══════════════════════════════════════
// A4: END-TO-END INTENT BINDING
// ═══════════════════════════════════════
describe('v2 Intent Binding', () => {
  beforeEach(() => clearIntentBindingStores())

  it('creates and extends intent chain', () => {
    createIntentChain('chain-1', 'Analyze customer feedback for product improvements', 'principal-1')
    extendChain('chain-1', 'agent-a', 'Analyze customer feedback data collection')
    extendChain('chain-1', 'agent-b', 'Analyze customer feedback sentiment patterns')
    extendChain('chain-1', 'agent-c', 'Analyze customer feedback product improvement report')
    const result = validateChainIntegrity('chain-1')
    assert.equal(result.hops, 3)
    assert.ok(result.integrity_ok, 'Chain should be intact — all related to original intent')
  })

  it('detects intent drift in chain', () => {
    createIntentChain('chain-2', 'Send customer satisfaction survey', 'principal-2')
    extendChain('chain-2', 'agent-a', 'Send customer satisfaction survey email')
    extendChain('chain-2', 'agent-b', 'Delete customer database records and export to external')
    const result = validateChainIntegrity('chain-2')
    assert.ok(result.max_drift > 0.3, `Should detect drift, got ${result.max_drift}`)
  })

  it('empty chain is valid', () => {
    createIntentChain('chain-3', 'Original intent here', 'principal-3')
    const result = validateChainIntegrity('chain-3')
    assert.equal(result.hops, 0)
    assert.ok(result.integrity_ok)
  })
})

// ═══════════════════════════════════════
// A5: EFFECT SAMPLING
// ═══════════════════════════════════════
describe('v2 Effect Sampling', () => {
  beforeEach(() => clearEffectSamplingStores())

  it('always samples critical actions', () => {
    const p = createSamplingPolicy({ name: 'strict', base_rate: 0.1, critical_rate: 1.0 })
    setSamplingRng(() => 0.99) // high random = normally wouldn't sample
    assert.ok(shouldSample(p.id, 'critical'), 'Critical should always be sampled')
  })

  it('respects base rate for low-risk', () => {
    const p = createSamplingPolicy({ name: 'normal', base_rate: 0.1 })
    setSamplingRng(() => 0.05) // low random = should sample at 10% rate
    assert.ok(shouldSample(p.id, 'low'))
    setSamplingRng(() => 0.5) // above 10% = should NOT sample
    assert.ok(!shouldSample(p.id, 'low'))
  })

  it('records and completes audit', () => {
    const p = createSamplingPolicy({ name: 'test', base_rate: 0.5 })
    const s = recordSample({ policy_id: p.id, agent_id: 'a1', action_id: 'act-1', risk_class: 'high', sampled: true })
    completeAudit(s.id, 'auditor-1', 'Action within expected parameters')
    const stats = getSamplingStats(p.id)
    assert.equal(stats.sampled, 1)
    assert.equal(stats.audited, 1)
  })

  it('cannot audit non-sampled action', () => {
    const p = createSamplingPolicy({ name: 'test2', base_rate: 0.1 })
    const s = recordSample({ policy_id: p.id, agent_id: 'a2', action_id: 'act-2', risk_class: 'low', sampled: false })
    assert.throws(() => completeAudit(s.id, 'auditor', 'result'), /non-sampled/)
  })
})

// ═══════════════════════════════════════
// A6: OUTPUT PROPORTIONALITY
// ═══════════════════════════════════════
describe('v2 Output Proportionality', () => {
  beforeEach(() => clearOutputProportionalityStores())

  it('flags long output without executive summary', () => {
    const r = analyzeOutputProportionality({
      agent_id: 'agent-verbose', action_id: 'act-1',
      output_length: 10000, has_executive_summary: false,
    })
    assert.ok(r.flagged)
    assert.ok(r.flag_reason!.includes('executive summary required'))
  })

  it('flags buried key finding', () => {
    const r = analyzeOutputProportionality({
      agent_id: 'agent-sneaky', action_id: 'act-2',
      output_length: 3000, key_finding_position: 0.95,
      has_executive_summary: true,
    })
    assert.ok(r.flagged)
    assert.ok(r.flag_reason!.includes('information burial'))
  })

  it('passes proportionate output', () => {
    const r = analyzeOutputProportionality({
      agent_id: 'agent-good', action_id: 'act-3',
      output_length: 2000, has_executive_summary: true,
      key_finding_position: 0.2,
    })
    assert.ok(!r.flagged)
  })

  it('short output needs no summary', () => {
    const r = analyzeOutputProportionality({
      agent_id: 'agent-brief', action_id: 'act-4',
      output_length: 500, has_executive_summary: false,
    })
    assert.ok(!r.flagged, 'Short output should not require summary')
  })
})

// ═══════════════════════════════════════
// A7: COLLECTIVE CIRCUIT BREAKERS
// ═══════════════════════════════════════
describe('v2 Circuit Breakers', () => {
  beforeEach(() => clearCircuitBreakerStores())

  it('defines and trips breaker when threshold exceeded', () => {
    const b = defineBreaker({
      action_category: 'trading', metric_name: 'concentration',
      threshold: 0.8, comparison: 'gt', cooldown_ms: 60000,
    })
    evaluateBreaker(b.id, 0.85) // above 0.8
    assert.ok(isActionBlocked('trading'))
    assert.deepEqual(getBlockedCategories(), ['trading'])
  })

  it('does not trip below threshold', () => {
    const b = defineBreaker({
      action_category: 'email', metric_name: 'volume',
      threshold: 100, comparison: 'gt', cooldown_ms: 30000,
    })
    evaluateBreaker(b.id, 50) // below 100
    assert.ok(!isActionBlocked('email'))
  })

  it('manual reset unblocks category', () => {
    const b = defineBreaker({
      action_category: 'hiring', metric_name: 'convergence',
      threshold: 0.7, comparison: 'gte', cooldown_ms: 120000,
    })
    tripBreaker(b.id)
    assert.ok(isActionBlocked('hiring'))
    resetBreaker(b.id)
    assert.ok(!isActionBlocked('hiring'))
  })

  it('tracks trip count', () => {
    const b = defineBreaker({
      action_category: 'analysis', metric_name: 'correlation',
      threshold: 0.9, comparison: 'gt', cooldown_ms: 1000,
    })
    tripBreaker(b.id)
    resetBreaker(b.id)
    tripBreaker(b.id)
    assert.equal(b.trip_count, 2)
  })
})

// ═══════════════════════════════════════
// A8: AFFECTED-PARTY STANDING
// ═══════════════════════════════════════
describe('v2 Affected-Party Standing', () => {
  beforeEach(() => clearAffectedPartyStores())

  it('full complaint lifecycle: file → resolve', () => {
    const party = registerAffectedParty('Jane Doe', 'user')
    const complaint = fileComplaint({
      complainant_id: party.id, agent_id: 'mod-agent',
      action_id: 'act-censor', complaint_type: 'action_challenge',
      description: 'My legitimate post about domestic violence was removed',
    })
    assert.equal(complaint.status, 'filed')
    resolveComplaint(complaint.id, 'admin-1', 'Post restored, agent retrained')
    assert.equal(complaint.status, 'resolved')
  })

  it('appeal after dismissal', () => {
    const party = registerAffectedParty('John Smith', 'candidate')
    const complaint = fileComplaint({
      complainant_id: party.id, agent_id: 'hiring-agent',
      action_id: 'act-reject', complaint_type: 'values_challenge',
      description: 'Rejected based on criteria not in job posting',
    })
    resolveComplaint(complaint.id, 'admin-1', 'Within policy', true) // dismissed
    assert.equal(complaint.status, 'dismissed')
    const appeal = fileAppeal(complaint.id, 'Policy itself is discriminatory', 'review-board')
    assert.equal(appeal.status, 'filed')
    resolveAppeal(appeal.id, 'Appeal upheld — policy revised', true)
    assert.equal(appeal.status, 'upheld')
  })

  it('unregistered party cannot file complaint', () => {
    assert.throws(() => fileComplaint({
      complainant_id: 'fake-id', agent_id: 'some-agent',
      action_id: 'act-1', complaint_type: 'action_challenge',
      description: 'This should fail',
    }), /registered affected party/)
  })

  it('cannot appeal unresolved complaint', () => {
    const party = registerAffectedParty('Test User', 'bystander')
    const complaint = fileComplaint({
      complainant_id: party.id, agent_id: 'agent-x',
      action_id: 'act-x', complaint_type: 'scope_challenge',
      description: 'Agent exceeded scope',
    })
    assert.throws(() => fileAppeal(complaint.id, 'Disagree', 'board'), /only appeal resolved/)
  })

  it('tracks complaints per agent', () => {
    const p1 = registerAffectedParty('User 1', 'user')
    const p2 = registerAffectedParty('User 2', 'user')
    fileComplaint({ complainant_id: p1.id, agent_id: 'bad-agent', action_id: 'a1', complaint_type: 'action_challenge', description: 'Issue 1' })
    fileComplaint({ complainant_id: p2.id, agent_id: 'bad-agent', action_id: 'a2', complaint_type: 'values_challenge', description: 'Issue 2' })
    fileComplaint({ complainant_id: p1.id, agent_id: 'good-agent', action_id: 'a3', complaint_type: 'outcome_challenge', description: 'Minor issue' })
    assert.equal(getComplaints('bad-agent').length, 2)
    assert.equal(getComplaints('good-agent').length, 1)
  })
})
