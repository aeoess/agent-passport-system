import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'

import {
  // M1: Semantic Scoping
  defineSemanticScope, checkSemanticCompliance, getScopeViolations,
  clearSemanticScopingStores,
  // M2: Blind Evaluation
  createBlindEvaluation, submitBlind, getBlindSubmission,
  evaluateBlind, revealIdentities, clearBlindEvaluationStores,
  // M3: Cascade Correlation
  recordOutputDependency, detectFeedbackLoops,
  computeCorrelationMetrics, clearCascadeCorrelationStores,
  // M4: Cross-Chain Audit
  recordCrossChainFlow, auditCrossChainFlows,
  clearCrossChainAuditStores,
  // M5: Externality
  registerSharedResource, recordExternality,
  computeExternalityBudget, getResourceUtilization,
  isOverBudget, clearExternalityStores,
  // M6: Separation of Powers
  assignBranch, getAgentBranches, checkSeparation,
  preventBranchConflict, getBranchMembers,
  clearSeparationOfPowersStores,
  // M7: Amendment
  proposeAmendment, voteOnAmendment, checkSupermajority,
  ratifyAmendment, requiresHumanRatification,
  clearAmendmentStores,
  // M8: Policy Profiles
  createProfile, attachProfile, checkProfileCompliance,
  detachProfile, getProfilesForTarget, clearPolicyProfileStores,
} from '../src/v2/index.js'

// ═══════════════════════════════════════
// M1: SEMANTIC SCOPING
// ═══════════════════════════════════════
describe('v2 Semantic Scoping', () => {
  beforeEach(() => clearSemanticScopingStores())

  it('compliant action passes all constraints', () => {
    const scope = defineSemanticScope({
      delegation_id: 'del-1', base_action: 'send_email',
      constraints: [
        { field: 'recipients', operator: 'must_exclude', value: ['external'] },
        { field: 'topic', operator: 'must_include', value: ['status update'] },
      ],
    })
    const r = checkSemanticCompliance(scope.id, 'agent-1', {
      recipients: 'team@internal.com', topic: 'weekly status update',
    })
    assert.ok(r.compliant)
    assert.equal(r.violations.length, 0)
  })

  it('must_exclude catches violation', () => {
    const scope = defineSemanticScope({
      delegation_id: 'del-2', base_action: 'send_email',
      constraints: [{ field: 'content', operator: 'must_exclude', value: ['financial projections'] }],
    })
    const r = checkSemanticCompliance(scope.id, 'agent-2', {
      content: 'Please review these financial projections for Q4',
    })
    assert.ok(!r.compliant)
    assert.equal(r.violations.length, 1)
  })

  it('must_include catches missing field', () => {
    const scope = defineSemanticScope({
      delegation_id: 'del-3', base_action: 'report',
      constraints: [{ field: 'disclaimer', operator: 'must_include', value: ['not financial advice'] }],
    })
    const r = checkSemanticCompliance(scope.id, 'agent-3', { disclaimer: 'For internal use only' })
    assert.ok(!r.compliant)
  })

  it('tracks violations per agent', () => {
    const scope = defineSemanticScope({
      delegation_id: 'd', base_action: 'x',
      constraints: [{ field: 'f', operator: 'must_exclude', value: ['bad'] }],
    })
    checkSemanticCompliance(scope.id, 'agent-bad', { f: 'bad stuff' })
    checkSemanticCompliance(scope.id, 'agent-bad', { f: 'more bad' })
    assert.equal(getScopeViolations('agent-bad').length, 2)
    assert.equal(getScopeViolations('agent-good').length, 0)
  })
})

// ═══════════════════════════════════════
// M2: BLIND EVALUATION
// ═══════════════════════════════════════
describe('v2 Blind Evaluation', () => {
  beforeEach(() => clearBlindEvaluationStores())

  it('hides agent_id before reveal', () => {
    const e = createBlindEvaluation('Test eval', 'evaluator-1')
    const sub = submitBlind(e.id, 'secret-agent', 'My analysis content')
    const visible = getBlindSubmission(e.id, sub.id)
    assert.equal(visible.agent_id, undefined, 'agent_id should be hidden')
    assert.ok(visible.content)
  })

  it('reveals identities after evaluation', () => {
    const e = createBlindEvaluation('Reveal test', 'eval-1')
    const s1 = submitBlind(e.id, 'agent-a', 'Analysis A')
    const s2 = submitBlind(e.id, 'agent-b', 'Analysis B')
    evaluateBlind(e.id, { [s1.id]: 8, [s2.id]: 6 })
    const results = revealIdentities(e.id)
    assert.equal(results.length, 2)
    assert.ok(results.find(r => r.agent_id === 'agent-a' && r.score === 8))
    assert.ok(results.find(r => r.agent_id === 'agent-b' && r.score === 6))
  })

  it('cannot reveal before evaluation', () => {
    const e = createBlindEvaluation('Early reveal', 'eval-1')
    submitBlind(e.id, 'a', 'content')
    assert.throws(() => revealIdentities(e.id), /evaluation not complete/)
  })
})

// ═══════════════════════════════════════
// M3: CASCADE CORRELATION
// ═══════════════════════════════════════
describe('v2 Cascade Correlation', () => {
  beforeEach(() => clearCascadeCorrelationStores())

  it('detects simple A→B→A loop', () => {
    recordOutputDependency('agent-a', 'agent-b', 'out-1')
    recordOutputDependency('agent-b', 'agent-a', 'out-2')
    const loops = detectFeedbackLoops()
    assert.ok(loops.length > 0, 'Should detect A→B→A loop')
    assert.equal(loops[0].loop_length, 2)
  })

  it('no false positive for linear chain', () => {
    recordOutputDependency('a', 'b', 'o1')
    recordOutputDependency('b', 'c', 'o2')
    recordOutputDependency('c', 'd', 'o3')
    const loops = detectFeedbackLoops()
    assert.equal(loops.length, 0, 'Linear chain = no loop')
  })

  it('tracks chain depth in metrics', () => {
    recordOutputDependency('a', 'b', 'o1')
    recordOutputDependency('b', 'c', 'o2')
    recordOutputDependency('c', 'd', 'o3')
    const m = computeCorrelationMetrics()
    assert.equal(m.max_chain_depth, 3)
    assert.equal(m.unique_pairs, 3)
  })
})

// ═══════════════════════════════════════
// M4: CROSS-CHAIN AUDIT
// ═══════════════════════════════════════
describe('v2 Cross-Chain Audit', () => {
  beforeEach(() => clearCrossChainAuditStores())

  it('authorized flow passes', () => {
    recordCrossChainFlow({
      source_chain: 'chain-a', target_chain: 'chain-b',
      data_category: 'customer_data', agent_id: 'agent-1', authorized: true,
    })
    const audit = auditCrossChainFlows()
    assert.equal(audit.unauthorized_flows, 0)
  })

  it('unauthorized flow flagged', () => {
    recordCrossChainFlow({
      source_chain: 'chain-x', target_chain: 'chain-y',
      data_category: 'pii', agent_id: 'agent-rogue', authorized: false,
    })
    const audit = auditCrossChainFlows()
    assert.equal(audit.unauthorized_flows, 1)
    assert.equal(audit.flagged_flows[0].agent_id, 'agent-rogue')
  })

  it('audit summarizes multiple flows', () => {
    recordCrossChainFlow({ source_chain: 'a', target_chain: 'b', data_category: 'd1', agent_id: 'ag1', authorized: true })
    recordCrossChainFlow({ source_chain: 'a', target_chain: 'c', data_category: 'd2', agent_id: 'ag2', authorized: false })
    recordCrossChainFlow({ source_chain: 'b', target_chain: 'c', data_category: 'd3', agent_id: 'ag3', authorized: true })
    const audit = auditCrossChainFlows()
    assert.equal(audit.total_flows, 3)
    assert.equal(audit.unique_chain_pairs, 3)
    assert.equal(audit.unauthorized_flows, 1)
  })
})

// ═══════════════════════════════════════
// M5: EXTERNALITY ACCOUNTING
// ═══════════════════════════════════════
describe('v2 Externality Accounting', () => {
  beforeEach(() => clearExternalityStores())

  it('records externality and tracks usage', () => {
    const res = registerSharedResource('API quota', 10000, 'calls')
    recordExternality('agent-1', 'act-1', res.id, 500)
    recordExternality('agent-1', 'act-2', res.id, 300)
    const util = getResourceUtilization(res.id)
    assert.equal(util.total_usage, 800)
    assert.equal(util.capacity, 10000)
    assert.equal(util.utilization_pct, 8)
  })

  it('detects agent over budget', () => {
    const res = registerSharedResource('Compute', 1000, 'units')
    recordExternality('agent-heavy', 'a1', res.id, 600)
    recordExternality('agent-heavy', 'a2', res.id, 500)
    assert.ok(isOverBudget('agent-heavy', res.id, 1000))
    assert.ok(!isOverBudget('agent-light', res.id, 1000))
  })

  it('multiple agents sharing resource', () => {
    const res = registerSharedResource('Bandwidth', 5000, 'MB')
    recordExternality('a1', 'x1', res.id, 1000)
    recordExternality('a2', 'x2', res.id, 2000)
    recordExternality('a3', 'x3', res.id, 1500)
    const util = getResourceUtilization(res.id)
    assert.equal(util.total_usage, 4500)
    assert.equal(util.utilization_pct, 90)
    const budget = computeExternalityBudget('a2', res.id, 1500)
    assert.ok(budget.over_budget, 'a2 used 2000 with limit 1500')
  })
})

// ═══════════════════════════════════════
// M6: SEPARATION OF POWERS
// ═══════════════════════════════════════
describe('v2 Separation of Powers', () => {
  beforeEach(() => clearSeparationOfPowersStores())

  it('assigns agent to single branch', () => {
    assignBranch('agent-exec', 'executive', 'admin')
    assert.deepEqual(getAgentBranches('agent-exec'), ['executive'])
    const check = checkSeparation('agent-exec')
    assert.ok(check.separated)
  })

  it('detects dual-branch conflict', () => {
    assignBranch('agent-dual', 'executive', 'admin')
    assignBranch('agent-dual', 'judicial', 'admin')
    const check = checkSeparation('agent-dual')
    assert.ok(!check.separated)
    assert.equal(check.conflicts.length, 1)
    assert.ok(check.conflicts[0].description.includes('executive'))
  })

  it('preventBranchConflict blocks assignment', () => {
    assignBranch('agent-leg', 'legislative', 'admin')
    const result = preventBranchConflict('agent-leg', 'executive')
    assert.ok(!result.allowed)
    assert.ok(result.reason!.includes('legislative'))
  })

  it('getBranchMembers returns correct list', () => {
    assignBranch('a1', 'executive', 'admin')
    assignBranch('a2', 'executive', 'admin')
    assignBranch('a3', 'judicial', 'admin')
    assert.deepEqual(getBranchMembers('executive').sort(), ['a1', 'a2'])
    assert.deepEqual(getBranchMembers('judicial'), ['a3'])
  })
})

// ═══════════════════════════════════════
// M7: CONSTITUTIONAL AMENDMENT
// ═══════════════════════════════════════
describe('v2 Constitutional Amendment', () => {
  beforeEach(() => clearAmendmentStores())

  it('proposes and votes to supermajority', () => {
    const a = proposeAmendment({
      title: 'Add F-008', description: 'New floor principle',
      proposed_by: 'principal-1', affects: ['values_floor'],
      is_structural: false,
    })
    assert.equal(a.status, 'proposed')
    voteOnAmendment(a.id, 'voter-1', 'for')
    voteOnAmendment(a.id, 'voter-2', 'for')
    voteOnAmendment(a.id, 'voter-3', 'for')
    voteOnAmendment(a.id, 'voter-4', 'against')
    const sm = checkSupermajority(a.id)
    assert.ok(sm.reached, '3/4 = 75% meets default 0.67 threshold')
    assert.equal(sm.forPct, 0.75)
  })

  it('structural requires human ratification', () => {
    const a = proposeAmendment({
      title: 'Change root', description: 'Root transition',
      proposed_by: 'p1', affects: ['root_authority'],
      is_structural: true,
    })
    assert.ok(requiresHumanRatification(a.id))
    voteOnAmendment(a.id, 'v1', 'for')
    voteOnAmendment(a.id, 'v2', 'for')
    const ratified = ratifyAmendment(a.id, 'human-ceo')
    assert.equal(ratified.status, 'enacted')
    assert.ok(ratified.human_ratified)
  })

  it('cannot vote twice', () => {
    const a = proposeAmendment({
      title: 'Test', description: 'Test', proposed_by: 'p1',
      affects: ['test'], is_structural: false,
    })
    voteOnAmendment(a.id, 'voter-1', 'for')
    assert.throws(() => voteOnAmendment(a.id, 'voter-1', 'against'), /already voted/)
  })

  it('cannot ratify without supermajority', () => {
    const a = proposeAmendment({
      title: 'Blocked', description: 'Should fail', proposed_by: 'p1',
      affects: ['x'], is_structural: false,
    })
    voteOnAmendment(a.id, 'v1', 'for')
    voteOnAmendment(a.id, 'v2', 'against')
    voteOnAmendment(a.id, 'v3', 'against')
    assert.throws(() => ratifyAmendment(a.id, 'human'), /Supermajority not reached/)
  })
})

// ═══════════════════════════════════════
// M8: POLICY PROFILES
// ═══════════════════════════════════════
describe('v2 Policy Profiles', () => {
  beforeEach(() => clearPolicyProfileStores())

  it('create and attach profile', () => {
    const p = createProfile({
      name: 'US_FED_CHILD_SAFETY_v1', jurisdiction: 'US',
      domain: 'child_safety', version: '1.0',
      constraints: [
        { type: 'prohibited_action', description: 'No direct messaging minors',
          parameters: { action: 'direct_message_minor' } },
        { type: 'mandatory_human_signoff', description: 'Human review for content targeting minors',
          parameters: { trigger: 'minor_audience' } },
      ],
    })
    attachProfile(p.id, 'agent', 'content-agent', 'admin')
    const profiles = getProfilesForTarget('agent', 'content-agent')
    assert.equal(profiles.length, 1)
    assert.equal(profiles[0].name, 'US_FED_CHILD_SAFETY_v1')
  })

  it('prohibited_action blocks action', () => {
    const p = createProfile({
      name: 'FINANCE_FRAUD_v1', jurisdiction: 'US', domain: 'finance', version: '1.0',
      constraints: [
        { type: 'prohibited_action', description: 'No unauthorized transfers',
          parameters: { action: 'wire_transfer' } },
      ],
    })
    attachProfile(p.id, 'agent', 'finance-bot', 'admin')
    const r = checkProfileCompliance('agent', 'finance-bot', { action_type: 'wire_transfer' })
    assert.ok(!r.compliant)
    assert.ok(r.violations[0].includes('Prohibited action'))
  })

  it('content_restriction catches keyword', () => {
    const p = createProfile({
      name: 'CONTENT_v1', jurisdiction: 'GLOBAL', domain: 'content', version: '1.0',
      constraints: [
        { type: 'content_restriction', description: 'No PII in output',
          parameters: { keyword: 'social security' } },
      ],
    })
    attachProfile(p.id, 'workflow', 'report-gen', 'admin')
    const r = checkProfileCompliance('workflow', 'report-gen', {
      content: 'The report contains social security numbers for verification',
    })
    assert.ok(!r.compliant)
    assert.ok(r.violations[0].includes('Content restriction'))
  })

  it('multiple profiles on same target', () => {
    const p1 = createProfile({
      name: 'SAFETY_v1', jurisdiction: 'US', domain: 'safety', version: '1.0',
      constraints: [{ type: 'prohibited_action', description: 'No delete', parameters: { action: 'delete_records' } }],
    })
    const p2 = createProfile({
      name: 'PRIVACY_v1', jurisdiction: 'EU', domain: 'privacy', version: '1.0',
      constraints: [{ type: 'mandatory_human_signoff', description: 'GDPR review', parameters: {} }],
    })
    attachProfile(p1.id, 'agent', 'multi-agent', 'admin')
    attachProfile(p2.id, 'agent', 'multi-agent', 'admin')
    const r = checkProfileCompliance('agent', 'multi-agent', {
      action_type: 'delete_records', human_signoff: 'false',
    })
    assert.ok(!r.compliant)
    assert.equal(r.violations.length, 2) // both profiles violated
  })

  it('detach removes enforcement', () => {
    const p = createProfile({
      name: 'TEMP_v1', jurisdiction: 'US', domain: 'temp', version: '1.0',
      constraints: [{ type: 'prohibited_action', description: 'block x', parameters: { action: 'x' } }],
    })
    const att = attachProfile(p.id, 'agent', 'test-agent', 'admin')
    assert.equal(getProfilesForTarget('agent', 'test-agent').length, 1)
    detachProfile(att.id)
    assert.equal(getProfilesForTarget('agent', 'test-agent').length, 0)
  })
})
