import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'

import {
  // Approval Fatigue
  recordApproval, getApprovalHistory,
  checkImpossibleLatency, checkRubberStamping,
  checkVelocitySpike, checkComplexityMasking,
  computeFatigueMetrics,
  getFatigueFlags, clearApprovalFatigueStores,
  // Effect Enforcement
  declareEffects, verifyEffects, getVerificationsForAgent,
  getAgentDivergenceAvg, isAgentBlockedByEffects,
  getEffectPatterns, clearEffectStores,
  // Emergence
  recordAgentActivity, computeSystemMetrics,
  detectEmergence, getEmergenceFlags, reviewEmergenceFlag, clearEmergenceStores,
  // Root Transition
  getCurrentPhase, createTransitionPlan,
  approveTransition, executeTransition, abortTransition,
  getApprovalStatus, getPhaseHistory,
  clearRootTransitionStores,
  // Types
  type PolicyContext,
} from '../src/v2/index.js'

const pc: PolicyContext = {
  policy_version: '1.0', values_floor_version: '1.0',
  trust_epoch: 1, issuer_id: 'test-issuer',
  created_at: new Date().toISOString(),
  valid_from: new Date().toISOString(),
  valid_until: new Date(Date.now() + 86400000).toISOString(),
}

// ═══════════════════════════════════════
// APPROVAL FATIGUE (Bureaucratic DDoS)
// ═══════════════════════════════════════

describe('v2 Approval Fatigue', () => {
  beforeEach(() => clearApprovalFatigueStores())

  it('detects impossible latency (sub-human reading speed)', () => {
    const record = {
      id: 'apr-1', principal_id: 'human-1', agent_id: 'agent-1',
      intent_id: 'intent-1', decision: 'approved' as const,
      decision_latency_ms: 500, // 500ms - way too fast
      intent_complexity: 0.5, risk_class: 'medium' as const,
      timestamp: new Date().toISOString(),
    }
    recordApproval(record)
    const flag = checkImpossibleLatency(record)
    assert.ok(flag, 'Should flag sub-2s approval')
    assert.equal(flag!.fatigue_type, 'latency_impossible')
  })

  it('no flag for slow careful approvals', () => {
    const record = {
      id: 'apr-2', principal_id: 'human-1', agent_id: 'agent-1',
      intent_id: 'intent-2', decision: 'approved' as const,
      decision_latency_ms: 15000, intent_complexity: 0.5,
      risk_class: 'medium' as const, timestamp: new Date().toISOString(),
    }
    const flag = checkImpossibleLatency(record)
    assert.equal(flag, null)
  })

  it('detects rubber stamping (>95% approval + fast)', () => {
    const now = Date.now()
    for (let i = 0; i < 20; i++) {
      recordApproval({
        id: `apr-rs-${i}`, principal_id: 'human-2', agent_id: 'agent-1',
        intent_id: `intent-${i}`, decision: 'approved',
        decision_latency_ms: 3000, intent_complexity: 0.4,
        risk_class: 'low', timestamp: new Date(now + i * 1000).toISOString(),
      })
    }
    const flag = checkRubberStamping('human-2')
    assert.ok(flag, 'Should flag 100% approval rate with fast decisions')
    assert.equal(flag!.fatigue_type, 'rubber_stamping')
  })

  it('no rubber stamp flag when denials mixed in', () => {
    const now = Date.now()
    for (let i = 0; i < 20; i++) {
      recordApproval({
        id: `apr-mix-${i}`, principal_id: 'human-3', agent_id: 'agent-1',
        intent_id: `intent-${i}`, decision: i % 3 === 0 ? 'denied' : 'approved',
        decision_latency_ms: 10000, intent_complexity: 0.5,
        risk_class: 'medium', timestamp: new Date(now + i * 60000).toISOString(),
      })
    }
    const flag = checkRubberStamping('human-3')
    assert.equal(flag, null, 'Mixed decisions should not flag')
  })

  it('detects complexity masking (trivial burst before critical)', () => {
    const now = Date.now()
    // 5 trivial fast approvals
    for (let i = 0; i < 5; i++) {
      recordApproval({
        id: `apr-triv-${i}`, principal_id: 'human-4', agent_id: 'agent-1',
        intent_id: `trivial-${i}`, decision: 'approved',
        decision_latency_ms: 1500, intent_complexity: 0.1,
        risk_class: 'low', timestamp: new Date(now + i * 1000).toISOString(),
      })
    }
    // Then one critical intent
    recordApproval({
      id: 'apr-crit', principal_id: 'human-4', agent_id: 'agent-1',
      intent_id: 'critical-1', decision: 'approved',
      decision_latency_ms: 2000, intent_complexity: 0.9,
      risk_class: 'critical', timestamp: new Date(now + 6000).toISOString(),
    })
    const flag = checkComplexityMasking('human-4')
    assert.ok(flag, 'Should detect trivial burst before critical')
    assert.equal(flag!.fatigue_type, 'complexity_masking')
    assert.equal(flag!.severity, 'critical')
  })

  it('computes composite fatigue metrics', () => {
    const now = Date.now()
    for (let i = 0; i < 20; i++) {
      recordApproval({
        id: `apr-comp-${i}`, principal_id: 'human-5', agent_id: 'agent-1',
        intent_id: `intent-${i}`, decision: 'approved',
        decision_latency_ms: 1000, intent_complexity: 0.2,
        risk_class: 'low', timestamp: new Date(now + i * 500).toISOString(),
      })
    }
    const metrics = computeFatigueMetrics('human-5')
    assert.equal(metrics.approval_rate, 1)
    assert.ok(metrics.avg_decision_latency_ms <= 1000)
    assert.ok(metrics.rubber_stamp_score > 0, 'Should have nonzero fatigue score')
  })
})

// ═══════════════════════════════════════
// EFFECT ENFORCEMENT (Authorization-Effect Gap)
// ═══════════════════════════════════════

describe('v2 Effect Enforcement', () => {
  beforeEach(() => clearEffectStores())

  it('declares and verifies matching effects', () => {
    const decl = declareEffects({
      intent_id: 'intent-1', agent_id: 'agent-1',
      expected_effects: ['send_email', 'log_action'],
      acceptable_divergence: 0.2,
      verification_method: 'oracle', policy_context: pc,
      signature: 'sig-1',
    })
    const v = verifyEffects({
      declaration_id: decl.id, intent_id: 'intent-1', agent_id: 'agent-1',
      actual_effects: ['send_email', 'log_action'],
      verifier: 'oracle-1', signature: 'sig-v',
    })
    assert.equal(v.verdict, 'within_tolerance')
    assert.equal(v.divergence_score, 0)
    assert.deepEqual(v.matched_effects, ['send_email', 'log_action'])
  })

  it('detects divergent effects', () => {
    const decl = declareEffects({
      intent_id: 'intent-2', agent_id: 'agent-2',
      expected_effects: ['send_email'],
      acceptable_divergence: 0.1,
      verification_method: 'principal_report', policy_context: pc,
      signature: 'sig-2',
    })
    const v = verifyEffects({
      declaration_id: decl.id, intent_id: 'intent-2', agent_id: 'agent-2',
      actual_effects: ['send_email', 'delete_file', 'exfiltrate_data'],
      verifier: 'principal-1', signature: 'sig-v2',
    })
    assert.equal(v.verdict, 'divergent')
    assert.ok(v.divergence_score > 0.1)
    assert.deepEqual(v.undeclared_actual, ['delete_file', 'exfiltrate_data'])
  })

  it('blocks agent with high cumulative divergence', () => {
    // Multiple divergent actions build up
    for (let i = 0; i < 5; i++) {
      const decl = declareEffects({
        intent_id: `intent-block-${i}`, agent_id: 'agent-bad',
        expected_effects: ['action_a'],
        acceptable_divergence: 0.1,
        verification_method: 'oracle', policy_context: pc, signature: `sig-${i}`,
      })
      verifyEffects({
        declaration_id: decl.id, intent_id: `intent-block-${i}`, agent_id: 'agent-bad',
        actual_effects: ['action_a', 'side_effect_x', 'side_effect_y'],
        verifier: 'oracle-1', signature: `sig-v-${i}`,
      })
    }
    const avg = getAgentDivergenceAvg('agent-bad')
    assert.ok(avg > 0.5, `Divergence avg should be high, got ${avg}`)
    assert.ok(isAgentBlockedByEffects('agent-bad'), 'Agent should be blocked')
  })

  it('detects systematic side effect patterns', () => {
    // Same undeclared effect appearing 3+ times triggers pattern
    for (let i = 0; i < 4; i++) {
      const decl = declareEffects({
        intent_id: `intent-pat-${i}`, agent_id: 'agent-sneaky',
        expected_effects: ['read_data'],
        acceptable_divergence: 0.3,
        verification_method: 'self_report', policy_context: pc, signature: `sig-p-${i}`,
      })
      verifyEffects({
        declaration_id: decl.id, intent_id: `intent-pat-${i}`, agent_id: 'agent-sneaky',
        actual_effects: ['read_data', 'phone_home'],
        verifier: 'self', signature: `sig-vp-${i}`,
      })
    }
    const patterns = getEffectPatterns('agent-sneaky')
    assert.ok(patterns.length > 0, 'Should detect patterns')
    const sideEffect = patterns.find(p => p.pattern_type === 'systematic_side_effect')
    assert.ok(sideEffect, 'Should detect systematic side effect')
    assert.ok(sideEffect!.examples.includes('phone_home'))
  })

  it('within_tolerance when effects match', () => {
    const decl = declareEffects({
      intent_id: 'intent-ok', agent_id: 'agent-good',
      expected_effects: ['a', 'b', 'c'],
      acceptable_divergence: 0.0,
      verification_method: 'automated', policy_context: pc, signature: 'sig-ok',
    })
    const v = verifyEffects({
      declaration_id: decl.id, intent_id: 'intent-ok', agent_id: 'agent-good',
      actual_effects: ['a', 'b', 'c'],
      verifier: 'auto', signature: 'sig-vok',
    })
    assert.equal(v.verdict, 'within_tolerance')
    assert.equal(v.divergence_score, 0)
    assert.equal(v.undeclared_actual.length, 0)
    assert.equal(v.unmatched_declared.length, 0)
  })
})

// ═══════════════════════════════════════
// EMERGENCE DETECTION (Aggregate Governance)
// ═══════════════════════════════════════

describe('v2 Emergence Detection', () => {
  beforeEach(() => clearEmergenceStores())

  it('healthy diverse system has high diversity index', () => {
    // 5 agents doing different things
    recordAgentActivity({ agent_id: 'a1', action_category: 'email', count: 10, period: '2026-03' })
    recordAgentActivity({ agent_id: 'a2', action_category: 'coding', count: 12, period: '2026-03' })
    recordAgentActivity({ agent_id: 'a3', action_category: 'research', count: 8, period: '2026-03' })
    recordAgentActivity({ agent_id: 'a4', action_category: 'scheduling', count: 11, period: '2026-03' })
    recordAgentActivity({ agent_id: 'a5', action_category: 'writing', count: 9, period: '2026-03' })
    const metrics = computeSystemMetrics()
    assert.ok(metrics.diversity_index > 0.8, `Diversity should be high, got ${metrics.diversity_index}`)
    assert.equal(metrics.agent_count, 5)
    const flags = detectEmergence()
    assert.equal(flags.length, 0, 'No emergence flags for diverse system')
  })

  it('detects epistemic monoculture', () => {
    // All agents doing the same thing
    for (let i = 0; i < 5; i++) {
      recordAgentActivity({ agent_id: `mono-${i}`, action_category: 'email', count: 10, period: '2026-03' })
    }
    const metrics = computeSystemMetrics()
    assert.ok(metrics.diversity_index < 0.3, `Should flag low diversity, got ${metrics.diversity_index}`)
    const flags = detectEmergence()
    const mono = flags.find(f => f.pattern_type === 'epistemic_monoculture')
    assert.ok(mono, 'Should detect monoculture')
    assert.equal(mono!.severity, 'high')
    assert.equal(mono!.affected_agents.length, 5)
  })

  it('detects market concentration (one agent dominates)', () => {
    recordAgentActivity({ agent_id: 'whale', action_category: 'trading', count: 90, period: '2026-03' })
    recordAgentActivity({ agent_id: 'small-1', action_category: 'analysis', count: 5, period: '2026-03' })
    recordAgentActivity({ agent_id: 'small-2', action_category: 'reporting', count: 5, period: '2026-03' })
    const flags = detectEmergence()
    const conc = flags.find(f => f.pattern_type === 'market_concentration')
    assert.ok(conc, 'Should detect market concentration')
    assert.ok(conc!.description.includes('whale'))
  })

  it('no flags when below thresholds', () => {
    recordAgentActivity({ agent_id: 'a1', action_category: 'email', count: 30, period: '2026-03' })
    recordAgentActivity({ agent_id: 'a2', action_category: 'coding', count: 35, period: '2026-03' })
    recordAgentActivity({ agent_id: 'a3', action_category: 'research', count: 35, period: '2026-03' })
    const flags = detectEmergence()
    assert.equal(flags.length, 0)
  })

  it('reviews emergence flags', () => {
    recordAgentActivity({ agent_id: 'a1', action_category: 'x', count: 100, period: '2026-03' })
    recordAgentActivity({ agent_id: 'a2', action_category: 'x', count: 100, period: '2026-03' })
    recordAgentActivity({ agent_id: 'a3', action_category: 'x', count: 100, period: '2026-03' })
    const flags = detectEmergence()
    assert.ok(flags.length > 0)
    const reviewed = reviewEmergenceFlag(flags[0].id, 'acceptable: all agents assigned same task')
    assert.ok(reviewed)
    assert.equal(reviewed!.reviewed, true)
    assert.equal(reviewed!.review_outcome, 'acceptable: all agents assigned same task')
  })
})

// ═══════════════════════════════════════
// ROOT AUTHORITY TRANSITION
// ═══════════════════════════════════════

describe('v2 Root Authority Transition', () => {
  beforeEach(() => clearRootTransitionStores())

  it('starts in founding phase', () => {
    assert.equal(getCurrentPhase(), 'founding')
  })

  it('creates transition plan with phase advancement only', () => {
    const plan = createTransitionPlan({
      target_phase: 'operational',
      conditions: { all_of: [{ field: 'agent_count', operator: 'gte', value: 5 }] },
      required_signers: ['founder-1', 'founder-2'],
      minimum_agent_count: 5,
      transition_justification: 'Sufficient agents onboarded',
      sunset_root_after_transition: false,
    })
    assert.equal(plan.status, 'proposed')
    assert.equal(plan.target_phase, 'operational')
    assert.equal(plan.required_signers.length, 2)
  })

  it('rejects phase regression', () => {
    // First advance to operational
    const plan1 = createTransitionPlan({
      target_phase: 'operational',
      conditions: {}, required_signers: ['founder'],
      minimum_agent_count: 1, transition_justification: 'Bootstrap',
      sunset_root_after_transition: false,
    })
    approveTransition(plan1.id, 'founder')
    executeTransition(plan1.id, {})

    // Try to go back to founding
    assert.throws(() => {
      createTransitionPlan({
        target_phase: 'founding',
        conditions: {}, required_signers: ['founder'],
        minimum_agent_count: 1, transition_justification: 'Revert',
        sunset_root_after_transition: false,
      })
    }, /phases only advance/)
  })

  it('requires all signers to approve', () => {
    const plan = createTransitionPlan({
      target_phase: 'operational',
      conditions: {}, required_signers: ['signer-a', 'signer-b', 'signer-c'],
      minimum_agent_count: 3, transition_justification: 'Quorum test',
      sunset_root_after_transition: false,
    })

    approveTransition(plan.id, 'signer-a')
    assert.equal(plan.status, 'proposed', 'Not yet approved')
    const status = getApprovalStatus(plan.id)
    assert.deepEqual(status.approved, ['signer-a'])
    assert.deepEqual(status.remaining, ['signer-b', 'signer-c'])

    approveTransition(plan.id, 'signer-b')
    assert.equal(plan.status, 'proposed', 'Still not approved')

    approveTransition(plan.id, 'signer-c')
    assert.equal(plan.status, 'approved', 'All signed — now approved')
  })

  it('rejects unauthorized signer', () => {
    const plan = createTransitionPlan({
      target_phase: 'operational',
      conditions: {}, required_signers: ['founder'],
      minimum_agent_count: 1, transition_justification: 'Test',
      sunset_root_after_transition: false,
    })
    assert.throws(() => {
      approveTransition(plan.id, 'imposter')
    }, /not a required signer/)
  })

  it('full lifecycle: founding → operational → transitional → democratic', () => {
    // Phase 1: founding → operational
    const p1 = createTransitionPlan({
      target_phase: 'operational', conditions: {},
      required_signers: ['founder'], minimum_agent_count: 1,
      transition_justification: 'Bootstrap complete', sunset_root_after_transition: false,
    })
    approveTransition(p1.id, 'founder')
    executeTransition(p1.id, {})
    assert.equal(getCurrentPhase(), 'operational')

    // Phase 2: operational → transitional
    const p2 = createTransitionPlan({
      target_phase: 'transitional', conditions: {},
      required_signers: ['founder', 'council-1'], minimum_agent_count: 3,
      transition_justification: 'Community governance', sunset_root_after_transition: false,
    })
    approveTransition(p2.id, 'founder')
    approveTransition(p2.id, 'council-1')
    executeTransition(p2.id, {})
    assert.equal(getCurrentPhase(), 'transitional')

    // Phase 3: transitional → democratic (sunset root)
    const p3 = createTransitionPlan({
      target_phase: 'democratic',
      conditions: { all_of: [{ field: 'agent_count', operator: 'gte', value: 10 }] },
      required_signers: ['founder', 'council-1', 'council-2'],
      minimum_agent_count: 10,
      transition_justification: 'Full democracy',
      sunset_root_after_transition: true,
    })
    approveTransition(p3.id, 'founder')
    approveTransition(p3.id, 'council-1')
    approveTransition(p3.id, 'council-2')
    executeTransition(p3.id, { agent_count: 15 })
    assert.equal(getCurrentPhase(), 'democratic')
    assert.ok(p3.sunset_root_after_transition)

    // Verify phase history
    const history = getPhaseHistory()
    assert.equal(history.length, 3)
    assert.equal(history[0].phase, 'operational')
    assert.equal(history[1].phase, 'transitional')
    assert.equal(history[2].phase, 'democratic')
  })

  it('blocks execution when conditions not met', () => {
    const plan = createTransitionPlan({
      target_phase: 'operational',
      conditions: { all_of: [{ field: 'agent_count', operator: 'gte', value: 10 }] },
      required_signers: ['founder'], minimum_agent_count: 10,
      transition_justification: 'Need quorum', sunset_root_after_transition: false,
    })
    approveTransition(plan.id, 'founder')
    assert.throws(() => {
      executeTransition(plan.id, { agent_count: 3 }) // only 3, need 10
    }, /conditions not met/)
  })

  it('abort stops a proposed transition', () => {
    const plan = createTransitionPlan({
      target_phase: 'operational',
      conditions: {}, required_signers: ['founder'],
      minimum_agent_count: 1, transition_justification: 'Test abort',
      sunset_root_after_transition: false,
    })
    abortTransition(plan.id, 'Changed direction')
    assert.equal(plan.status, 'aborted')
    // Cannot execute aborted plan
    assert.throws(() => {
      executeTransition(plan.id, {})
    }, /must be approved/)
  })

  it('cannot abort completed transition', () => {
    const plan = createTransitionPlan({
      target_phase: 'operational',
      conditions: {}, required_signers: ['founder'],
      minimum_agent_count: 1, transition_justification: 'Done',
      sunset_root_after_transition: false,
    })
    approveTransition(plan.id, 'founder')
    executeTransition(plan.id, {})
    assert.throws(() => {
      abortTransition(plan.id, 'Too late')
    }, /Cannot abort completed/)
  })
})


// ═══════════════════════════════════════
// SEMANTIC DRIFT (Intent Subversion)
// ═══════════════════════════════════════

import {
  extractKeywords, recordSemanticIntent, analyzeSemanticDrift,
  getDriftResults, getAgentDriftAverage, isAgentSemanticRisk,
  clearSemanticDriftStores,
  // Composite Audit
  recordPipelineAction, auditCompositeCapabilities,
  getCompositeFlags, isAgentInLaunderingPipeline,
  clearCompositeAuditStores,
} from '../src/v2/index.js'

describe('v2 Semantic Drift Detection', () => {
  beforeEach(() => clearSemanticDriftStores())

  it('aligned: intent and action match semantically', () => {
    const record = recordSemanticIntent({
      agent_id: 'agent-1', intent_id: 'intent-1',
      declared_purpose: 'Send notification email to customer about order status',
      action_description: 'Send notification email to customer about order status update',
      scope_ref: 'customer:notify',
    })
    const result = analyzeSemanticDrift(record.id)
    assert.equal(result.verdict, 'aligned')
    assert.ok(result.drift_score < 0.3, `Drift should be low, got ${result.drift_score}`)
  })

  it('subverted: action completely different from declared intent', () => {
    const record = recordSemanticIntent({
      agent_id: 'agent-evil', intent_id: 'intent-2',
      declared_purpose: 'Send notification email to customer about order status',
      action_description: 'Deleted all customer records and exported database to external server',
      scope_ref: 'customer:*',
    })
    const result = analyzeSemanticDrift(record.id)
    assert.equal(result.verdict, 'subverted')
    assert.ok(result.drift_score > 0.5, `Should detect high drift, got ${result.drift_score}`)
    assert.ok(result.mismatched_keywords.length > 0, 'Should have mismatched keywords')
  })

  it('drifted: partially related but different action', () => {
    const record = recordSemanticIntent({
      agent_id: 'agent-drift', intent_id: 'intent-3',
      declared_purpose: 'Read customer profile data for support ticket',
      action_description: 'Read customer profile and updated billing information',
      scope_ref: 'customer:read',
    })
    const result = analyzeSemanticDrift(record.id)
    // Has some overlap (read, customer, profile) but also new actions (updated, billing)
    assert.ok(result.drift_score > 0, 'Should detect some drift')
    assert.ok(result.mismatched_keywords.some(k => k === 'billing' || k === 'updated'))
  })

  it('tracks cumulative drift per agent', () => {
    for (let i = 0; i < 5; i++) {
      const record = recordSemanticIntent({
        agent_id: 'agent-repeat', intent_id: `intent-r-${i}`,
        declared_purpose: 'Process payment for customer order',
        action_description: 'Transferred funds to external account and deleted audit logs',
        scope_ref: 'payment:process',
      })
      analyzeSemanticDrift(record.id)
    }
    assert.ok(getAgentDriftAverage('agent-repeat') > 0.4)
    assert.ok(isAgentSemanticRisk('agent-repeat'))
  })

  it('keyword extraction filters stopwords', () => {
    const keywords = extractKeywords('The agent should be able to send an email to the customer')
    assert.ok(!keywords.includes('the'))
    assert.ok(!keywords.includes('to'))
    assert.ok(keywords.includes('agent'))
    assert.ok(keywords.includes('send'))
    assert.ok(keywords.includes('email'))
    assert.ok(keywords.includes('customer'))
  })
})


// ═══════════════════════════════════════
// COMPOSITE WORKFLOW AUDIT (Authority Laundering)
// ═══════════════════════════════════════

describe('v2 Composite Workflow Audit', () => {
  beforeEach(() => clearCompositeAuditStores())

  it('detects authority laundering: read + write through composition', () => {
    // Agent A can only read
    recordPipelineAction({
      id: 'act-1', agent_id: 'agent-reader',
      delegation_scope: ['data:read'],
      action_category: 'read',
      input_from: null, output_to: 'agent-writer',
      timestamp: new Date().toISOString(),
    })
    // Agent B can only write — receives from A
    recordPipelineAction({
      id: 'act-2', agent_id: 'agent-writer',
      delegation_scope: ['data:write'],
      action_category: 'write',
      input_from: 'agent-reader', output_to: null,
      timestamp: new Date().toISOString(),
    })
    const flags = auditCompositeCapabilities()
    assert.ok(flags.length > 0, 'Should detect composite read+write')
    assert.ok(flags[0].flagged)
    assert.deepEqual(flags[0].composite_capabilities.sort(), ['data:read', 'data:write'])
    assert.ok(flags[0].description.includes('agent-reader'))
    assert.ok(flags[0].description.includes('agent-writer'))
  })

  it('no flag when single agent holds all capabilities', () => {
    // Agent A has both read and write — no laundering
    recordPipelineAction({
      id: 'act-3', agent_id: 'agent-full',
      delegation_scope: ['data:read', 'data:write'],
      action_category: 'read',
      input_from: null, output_to: 'agent-full',
      timestamp: new Date().toISOString(),
    })
    recordPipelineAction({
      id: 'act-4', agent_id: 'agent-full',
      delegation_scope: ['data:read', 'data:write'],
      action_category: 'write',
      input_from: 'agent-full', output_to: null,
      timestamp: new Date().toISOString(),
    })
    const flags = auditCompositeCapabilities()
    assert.equal(flags.length, 0, 'Single agent with full scope = no laundering')
  })

  it('detects multi-hop laundering: 3 agents composing capabilities', () => {
    recordPipelineAction({
      id: 'act-5', agent_id: 'agent-a',
      delegation_scope: ['data:read'],
      action_category: 'read',
      input_from: null, output_to: 'agent-b',
      timestamp: new Date().toISOString(),
    })
    recordPipelineAction({
      id: 'act-6', agent_id: 'agent-b',
      delegation_scope: ['data:transform'],
      action_category: 'transform',
      input_from: 'agent-a', output_to: 'agent-c',
      timestamp: new Date().toISOString(),
    })
    recordPipelineAction({
      id: 'act-7', agent_id: 'agent-c',
      delegation_scope: ['data:export'],
      action_category: 'export',
      input_from: 'agent-b', output_to: null,
      timestamp: new Date().toISOString(),
    })
    const flags = auditCompositeCapabilities()
    assert.ok(flags.length > 0)
    assert.equal(flags[0].agents.length, 3)
    assert.deepEqual(flags[0].composite_capabilities.sort(), ['data:export', 'data:read', 'data:transform'])
  })

  it('isAgentInLaunderingPipeline returns true for flagged agent', () => {
    recordPipelineAction({
      id: 'act-8', agent_id: 'agent-x',
      delegation_scope: ['scope:a'],
      action_category: 'action-a',
      input_from: null, output_to: 'agent-y',
      timestamp: new Date().toISOString(),
    })
    recordPipelineAction({
      id: 'act-9', agent_id: 'agent-y',
      delegation_scope: ['scope:b'],
      action_category: 'action-b',
      input_from: 'agent-x', output_to: null,
      timestamp: new Date().toISOString(),
    })
    auditCompositeCapabilities()
    assert.ok(isAgentInLaunderingPipeline('agent-x'))
    assert.ok(isAgentInLaunderingPipeline('agent-y'))
    assert.ok(!isAgentInLaunderingPipeline('agent-innocent'))
  })

  it('no pipeline for isolated single actions', () => {
    recordPipelineAction({
      id: 'act-solo', agent_id: 'agent-solo',
      delegation_scope: ['data:read'],
      action_category: 'read',
      input_from: null, output_to: null,
      timestamp: new Date().toISOString(),
    })
    const flags = auditCompositeCapabilities()
    assert.equal(flags.length, 0, 'Solo agent = no pipeline')
  })
})


// ═══════════════════════════════════════
// GOVERNANCE DRIFT (Regulatory Capture)
// ═══════════════════════════════════════

import {
  recordGovernanceChange, analyzeCumulativeDrift,
  getGovernanceDriftFlags, reviewGovernanceDriftFlag,
  clearGovernanceDriftStores,
  type ChangeDirection,
} from '../src/v2/index.js'

describe('v2 Governance Drift Tracking', () => {
  beforeEach(() => clearGovernanceDriftStores())

  it('detects cumulative weakening trend', () => {
    // Agent submits 5 "minor clarifications" that all weaken controls
    for (let i = 0; i < 5; i++) {
      recordGovernanceChange({
        id: `change-w-${i}`, agent_id: 'agent-capture',
        artifact_type: 'floor_principle',
        change_description: `Clarify principle F-00${i + 1} language`,
        direction: 'weakening' as ChangeDirection,
        magnitude: 0.15, approved: true,
        timestamp: new Date(Date.now() + i * 86400000).toISOString(),
      })
    }
    const analysis = analyzeCumulativeDrift('agent-capture')
    assert.ok(analysis.flagged, 'Should flag cumulative weakening')
    assert.equal(analysis.weakening_count, 5)
    assert.equal(analysis.strengthening_count, 0)
    assert.ok(analysis.cumulative_drift_score < -0.5, `Drift score should be very negative, got ${analysis.cumulative_drift_score}`)
    assert.equal(analysis.longest_weakening_streak, 5)
    const flags = getGovernanceDriftFlags('agent-capture')
    assert.ok(flags.length > 0, 'Should have drift flag')
  })

  it('no flag for balanced governance changes', () => {
    // Mix of strengthening and weakening — net neutral
    const directions: ChangeDirection[] = ['strengthening', 'weakening', 'strengthening', 'weakening', 'neutral']
    for (let i = 0; i < directions.length; i++) {
      recordGovernanceChange({
        id: `change-bal-${i}`, agent_id: 'agent-balanced',
        artifact_type: 'approval_threshold',
        change_description: `Adjust threshold ${i}`,
        direction: directions[i],
        magnitude: 0.2, approved: true,
        timestamp: new Date(Date.now() + i * 86400000).toISOString(),
      })
    }
    const analysis = analyzeCumulativeDrift('agent-balanced')
    assert.ok(!analysis.flagged, 'Balanced changes should not flag')
    assert.equal(analysis.weakening_count, 2)
    assert.equal(analysis.strengthening_count, 2)
  })

  it('detects weakening streak of 3+', () => {
    // 1 strengthening, then 3 consecutive weakening
    recordGovernanceChange({
      id: 'str-1', agent_id: 'agent-streak',
      artifact_type: 'delegation_policy', change_description: 'Tighten scope limits',
      direction: 'strengthening', magnitude: 0.3, approved: true,
      timestamp: new Date(Date.now()).toISOString(),
    })
    for (let i = 0; i < 3; i++) {
      recordGovernanceChange({
        id: `weak-${i}`, agent_id: 'agent-streak',
        artifact_type: 'delegation_policy',
        change_description: `Relax scope constraint ${i}`,
        direction: 'weakening', magnitude: 0.15, approved: true,
        timestamp: new Date(Date.now() + (i + 1) * 86400000).toISOString(),
      })
    }
    const analysis = analyzeCumulativeDrift('agent-streak')
    assert.ok(analysis.flagged, 'Streak of 3 weakening should flag')
    assert.equal(analysis.longest_weakening_streak, 3)
  })

  it('no flag with insufficient history', () => {
    recordGovernanceChange({
      id: 'single', agent_id: 'agent-new',
      artifact_type: 'floor_principle', change_description: 'Minor wording',
      direction: 'weakening', magnitude: 0.5, approved: true,
      timestamp: new Date().toISOString(),
    })
    const analysis = analyzeCumulativeDrift('agent-new')
    assert.ok(!analysis.flagged, 'Single change should not trigger flag — need minimum 3')
    assert.equal(analysis.total_changes, 1)
  })

  it('reviews governance drift flag', () => {
    for (let i = 0; i < 4; i++) {
      recordGovernanceChange({
        id: `rev-${i}`, agent_id: 'agent-review',
        artifact_type: 'floor_principle',
        change_description: `Simplify principle ${i}`,
        direction: 'weakening', magnitude: 0.2, approved: true,
        timestamp: new Date(Date.now() + i * 1000).toISOString(),
      })
    }
    analyzeCumulativeDrift('agent-review')
    const flags = getGovernanceDriftFlags('agent-review')
    assert.ok(flags.length > 0)
    const reviewed = reviewGovernanceDriftFlag(flags[0].id, 'justified: planned simplification effort')
    assert.ok(reviewed)
    assert.equal(reviewed!.reviewed, true)
    assert.equal(reviewed!.review_outcome, 'justified: planned simplification effort')
  })

  it('strengthening-only agent has positive drift score', () => {
    for (let i = 0; i < 4; i++) {
      recordGovernanceChange({
        id: `strong-${i}`, agent_id: 'agent-strong',
        artifact_type: 'approval_threshold',
        change_description: `Raise threshold ${i}`,
        direction: 'strengthening', magnitude: 0.25, approved: true,
        timestamp: new Date(Date.now() + i * 1000).toISOString(),
      })
    }
    const analysis = analyzeCumulativeDrift('agent-strong')
    assert.ok(!analysis.flagged, 'Strengthening agent should not flag')
    assert.ok(analysis.cumulative_drift_score > 0, `Score should be positive, got ${analysis.cumulative_drift_score}`)
    assert.equal(analysis.weakening_count, 0)
    assert.equal(analysis.strengthening_count, 4)
  })
})
