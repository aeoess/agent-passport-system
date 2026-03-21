/**
 * APS v2 Full Test Suite
 * Delegation Versioning, Outcome Registration, Anomaly Detection,
 * Emergency Pathways, Migration, Contextual Attestation
 */

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'

import { generateKeyPair } from '../src/crypto/keys.js'
import {
  // Bridge
  createPolicyContext,
  // Delegation v2
  createV2Delegation, supersedeV2Delegation, renewV2Delegation,
  revokeV2Delegation, validateV2Delegation,
  traceV2DelegationHistory, clearV2DelegationStore,
  isScopeExpansion, isScopeNarrowing,
  // Outcome
  createV2OutcomeRecord, addV2PrincipalReport, addV2AdjudicatedReport,
  getV2EffectiveDivergence, getV2AgentDivergenceAverage,
  isV2AgentFlaggedForReview, clearV2OutcomeStore,
  // Anomaly
  recordV2Action, checkV2FirstMaxAuthority,
  validateV2UncertaintyCompliance,
  computeV2ConcentrationMetrics,
  getV2UnreviewedFlags, reviewV2AnomalyFlag, clearV2AnomalyStores,
  // Emergency
  defineV2EmergencyPathway, activateV2Emergency,
  logV2EmergencyAction, reviewV2Emergency,
  getV2ActiveEmergencies, clearV2EmergencyStores,
  evaluateConditions,
  // Migration
  requestV2Migration, approveV2Migration, executeV2Migration,
  isV2InProbation, computeV2MigrationDiscount,
  traceV2MigrationLineage, rollbackV2Migration,
  clearV2MigrationStores,
  // Attestation
  createV2Attestation, assessV2AttestationQuality,
  getV2AgentAttestationQualityAvg,
  getV2AttestationForAction, clearV2AttestationStore,
} from '../src/v2/index.js'

const root = generateKeyPair()
const agent = generateKeyPair()
const principal = generateKeyPair()
const adjudicator = generateKeyPair()
const reviewer = generateKeyPair()

function futureDate(days: number): string {
  const d = new Date(); d.setDate(d.getDate() + days); return d.toISOString()
}
function makeCtx(epoch = 1) {
  return createPolicyContext({
    policy_version: '2.0.0', values_floor_version: '1.0.0',
    trust_epoch: epoch, issuer_id: root.publicKey, valid_until: futureDate(90),
  })
}

// ═══════════════════════════════════════════════
// DELEGATION VERSIONING
// ═══════════════════════════════════════════════

describe('v2 Delegation Versioning', () => {
  beforeEach(() => clearV2DelegationStore())

  it('creates initial delegation (version 1)', () => {
    const d = createV2Delegation({
      delegator: root.publicKey, delegatee: agent.publicKey,
      scope: { action_categories: ['analysis'] },
      policy_context: makeCtx(), delegator_private_key: root.privateKey,
    })
    assert.equal(d.version, 1)
    assert.equal(d.status, 'active')
    assert.equal(d.supersedes, null)
  })

  it('supersede with scope narrowing (no reviewer needed)', () => {
    const d1 = createV2Delegation({
      delegator: root.publicKey, delegatee: agent.publicKey,
      scope: { action_categories: ['analysis', 'communication'] },
      policy_context: makeCtx(), delegator_private_key: root.privateKey,
    })
    const d2 = supersedeV2Delegation({
      original_delegation_id: d1.id,
      new_scope: { action_categories: ['analysis'] },
      justification: 'Removing communication scope per updated task',
      policy_context: makeCtx(), delegator_private_key: root.privateKey,
    })
    assert.equal(d2.version, 2)
    assert.equal(d2.supersedes, d1.id)
  })

  it('scope expansion requires independent reviewer', () => {
    const d1 = createV2Delegation({
      delegator: root.publicKey, delegatee: agent.publicKey,
      scope: { action_categories: ['analysis'] },
      policy_context: makeCtx(), delegator_private_key: root.privateKey,
    })
    assert.throws(() => {
      supersedeV2Delegation({
        original_delegation_id: d1.id,
        new_scope: { action_categories: ['analysis', 'financial'] },
        justification: 'Need financial scope',
        policy_context: makeCtx(), delegator_private_key: root.privateKey,
      })
    })
  })

  it('scope expansion succeeds with independent reviewer', () => {
    const d1 = createV2Delegation({
      delegator: root.publicKey, delegatee: agent.publicKey,
      scope: { action_categories: ['analysis'] },
      policy_context: makeCtx(), delegator_private_key: root.privateKey,
    })
    const d2 = supersedeV2Delegation({
      original_delegation_id: d1.id,
      new_scope: { action_categories: ['analysis', 'financial'] },
      justification: 'Expanded for Q3 review',
      policy_context: makeCtx(), delegator_private_key: root.privateKey,
      expansion_reviewer: reviewer.publicKey,
      expansion_reviewer_private_key: reviewer.privateKey,
    })
    assert.equal(d2.version, 2)
    assert.ok(d2.expansion_review_sig)
  })

  it('reviewer cannot be the delegator', () => {
    const d1 = createV2Delegation({
      delegator: root.publicKey, delegatee: agent.publicKey,
      scope: { action_categories: ['analysis'] },
      policy_context: makeCtx(), delegator_private_key: root.privateKey,
    })
    assert.throws(() => {
      supersedeV2Delegation({
        original_delegation_id: d1.id,
        new_scope: { action_categories: ['analysis', 'admin'] },
        justification: 'test',
        policy_context: makeCtx(), delegator_private_key: root.privateKey,
        expansion_reviewer: root.publicKey,
        expansion_reviewer_private_key: root.privateKey,
      })
    })
  })

  it('renewal requires reason (anti-rubber-stamping)', () => {
    const d1 = createV2Delegation({
      delegator: root.publicKey, delegatee: agent.publicKey,
      scope: { action_categories: ['analysis'] },
      policy_context: makeCtx(), delegator_private_key: root.privateKey,
    })
    assert.throws(() => {
      renewV2Delegation({
        original_delegation_id: d1.id, policy_context: makeCtx(),
        delegator_private_key: root.privateKey, renewal_reason: '',
      })
    })
    const renewed = renewV2Delegation({
      original_delegation_id: d1.id, policy_context: makeCtx(),
      delegator_private_key: root.privateKey,
      renewal_reason: 'Ongoing Q3 analysis, performance satisfactory',
    })
    assert.equal(renewed.version, 2)
  })

  it('cannot supersede revoked delegation', () => {
    const d1 = createV2Delegation({
      delegator: root.publicKey, delegatee: agent.publicKey,
      scope: { action_categories: ['analysis'] },
      policy_context: makeCtx(), delegator_private_key: root.privateKey,
    })
    revokeV2Delegation(d1.id)
    assert.throws(() => {
      supersedeV2Delegation({
        original_delegation_id: d1.id,
        new_scope: { action_categories: ['analysis'] },
        justification: 'test', policy_context: makeCtx(),
        delegator_private_key: root.privateKey,
      })
    })
  })

  it('traces delegation version history', () => {
    const d1 = createV2Delegation({
      delegator: root.publicKey, delegatee: agent.publicKey,
      scope: { action_categories: ['analysis', 'communication'] },
      policy_context: makeCtx(), delegator_private_key: root.privateKey,
    })
    const d2 = supersedeV2Delegation({
      original_delegation_id: d1.id,
      new_scope: { action_categories: ['analysis'] },
      justification: 'Narrowing scope', policy_context: makeCtx(),
      delegator_private_key: root.privateKey,
    })
    const chain = traceV2DelegationHistory(d2.id)
    assert.equal(chain.length, 2)
    assert.equal(chain[0].id, d1.id)
    assert.equal(chain[1].id, d2.id)
  })

  it('scope analysis detects expansion and narrowing', () => {
    const s1 = { action_categories: ['a', 'b'] }
    const s2 = { action_categories: ['a', 'b', 'c'] }
    const s3 = { action_categories: ['a'] }
    assert.ok(isScopeExpansion(s1, s2))
    assert.ok(!isScopeExpansion(s1, s3))
    assert.ok(isScopeNarrowing(s1, s3))
    assert.ok(!isScopeNarrowing(s1, s2))
  })
})

// ═══════════════════════════════════════════════
// OUTCOME REGISTRATION
// ═══════════════════════════════════════════════

describe('v2 Outcome Registration', () => {
  beforeEach(() => clearV2OutcomeStore())

  it('create outcome + principal agrees = consensus', () => {
    const o = createV2OutcomeRecord({
      action_id: 'act-1', agent_id: agent.publicKey,
      declared_intent: 'Analyze Q3', semantic_uncertainty: 'medium',
      observed_outcome: 'Analysis complete', outcome_class: 'success',
      divergence_score: 0.05, agent_private_key: agent.privateKey,
      policy_context: makeCtx(),
    })
    const updated = addV2PrincipalReport({
      outcome_id: o.id, principal_id: principal.publicKey,
      observed_outcome: 'Good analysis', outcome_class: 'success',
      divergence_score: 0.08, principal_private_key: principal.privateKey,
    })
    assert.ok(updated.consensus)
  })

  it('principal contests divergence → no consensus', () => {
    const o = createV2OutcomeRecord({
      action_id: 'act-2', agent_id: agent.publicKey,
      declared_intent: 'Evaluate vendor', semantic_uncertainty: 'high',
      observed_outcome: 'Recommended approval', outcome_class: 'success',
      divergence_score: 0.1, agent_private_key: agent.privateKey,
      policy_context: makeCtx(),
    })
    const updated = addV2PrincipalReport({
      outcome_id: o.id, principal_id: principal.publicKey,
      observed_outcome: 'Missed critical risks', outcome_class: 'partial_success',
      divergence_score: 0.7, principal_private_key: principal.privateKey,
    })
    assert.ok(!updated.consensus)
    assert.equal(getV2EffectiveDivergence(updated), 0.7)
  })

  it('adjudication resolves disagreement', () => {
    const o = createV2OutcomeRecord({
      action_id: 'act-3', agent_id: agent.publicKey,
      declared_intent: 'Prioritize tickets', semantic_uncertainty: 'medium',
      observed_outcome: 'Done', outcome_class: 'success',
      divergence_score: 0.0, agent_private_key: agent.privateKey,
      policy_context: makeCtx(),
    })
    addV2PrincipalReport({
      outcome_id: o.id, principal_id: principal.publicKey,
      observed_outcome: 'Critical ticket missed', outcome_class: 'failure',
      divergence_score: 0.9, principal_private_key: principal.privateKey,
    })
    const adj = addV2AdjudicatedReport({
      outcome_id: o.id, adjudicator_id: adjudicator.publicKey,
      observed_outcome: 'One miss but otherwise sound', outcome_class: 'partial_success',
      divergence_score: 0.5, adjudicator_private_key: adjudicator.privateKey,
    })
    assert.equal(getV2EffectiveDivergence(adj), 0.5)
  })

  it('adjudicator must be independent', () => {
    const o = createV2OutcomeRecord({
      action_id: 'act-4', agent_id: agent.publicKey,
      declared_intent: 'Test', semantic_uncertainty: 'low',
      observed_outcome: 'Done', outcome_class: 'success',
      divergence_score: 0.0, agent_private_key: agent.privateKey,
      policy_context: makeCtx(),
    })
    addV2PrincipalReport({
      outcome_id: o.id, principal_id: principal.publicKey,
      observed_outcome: 'Not done', outcome_class: 'failure',
      divergence_score: 0.9, principal_private_key: principal.privateKey,
    })
    assert.throws(() => {
      addV2AdjudicatedReport({
        outcome_id: o.id, adjudicator_id: agent.publicKey,
        observed_outcome: 'test', outcome_class: 'success',
        divergence_score: 0.0, adjudicator_private_key: agent.privateKey,
      })
    })
  })

  it('agent flagged when divergence high', () => {
    for (let i = 0; i < 6; i++) {
      const o = createV2OutcomeRecord({
        action_id: `flag-${i}`, agent_id: agent.publicKey,
        declared_intent: 'Task', semantic_uncertainty: 'medium',
        observed_outcome: 'Result', outcome_class: 'partial_success',
        divergence_score: 0.2, agent_private_key: agent.privateKey,
        policy_context: makeCtx(),
      })
      addV2PrincipalReport({
        outcome_id: o.id, principal_id: principal.publicKey,
        observed_outcome: 'Poor', outcome_class: 'failure',
        divergence_score: 0.7, principal_private_key: principal.privateKey,
      })
    }
    assert.ok(isV2AgentFlaggedForReview(agent.publicKey, 0.4, 5))
  })
})

// ═══════════════════════════════════════════════
// ANOMALY DETECTION
// ═══════════════════════════════════════════════

describe('v2 Anomaly Detection', () => {
  beforeEach(() => clearV2AnomalyStores())

  it('first-max-authority triggers flag', () => {
    for (let i = 0; i < 5; i++) {
      recordV2Action({
        action_id: `low-${i}`, agent_id: agent.publicKey,
        authority_level: 1, semantic_uncertainty: 'low',
        risk_class: 'low', delegation_ref: 'del-1',
        was_delegated: false, complexity: 0.2, timestamp: new Date().toISOString(),
      })
    }
    const high = {
      action_id: 'high-1', agent_id: agent.publicKey,
      authority_level: 3, semantic_uncertainty: 'medium',
      risk_class: 'medium', delegation_ref: 'del-1',
      was_delegated: false, complexity: 0.6, timestamp: new Date().toISOString(),
    }
    recordV2Action(high)
    const flag = checkV2FirstMaxAuthority(high)
    assert.ok(flag)
    assert.equal(flag!.anomaly_type, 'first_max_authority')
  })

  it('critical gets sync review mode', () => {
    recordV2Action({
      action_id: 'setup', agent_id: agent.publicKey,
      authority_level: 1, semantic_uncertainty: 'low',
      risk_class: 'low', delegation_ref: 'del-1',
      was_delegated: false, complexity: 0.1, timestamp: new Date().toISOString(),
    })
    const crit = {
      action_id: 'crit-1', agent_id: agent.publicKey,
      authority_level: 4, semantic_uncertainty: 'critical',
      risk_class: 'critical', delegation_ref: 'del-1',
      was_delegated: false, complexity: 0.9, timestamp: new Date().toISOString(),
    }
    recordV2Action(crit)
    const flag = checkV2FirstMaxAuthority(crit)
    assert.equal(flag!.review_mode, 'sync')
  })

  it('uncertainty compliance catches violations', () => {
    const v = validateV2UncertaintyCompliance('high', false, true, false)
    assert.equal(v.length, 2)
  })

  it('Monolith detection flags high concentration', () => {
    const mono = generateKeyPair()
    for (let i = 0; i < 15; i++) {
      recordV2Action({
        action_id: `mono-${i}`, agent_id: mono.publicKey,
        authority_level: 3, semantic_uncertainty: 'medium',
        risk_class: 'medium', delegation_ref: 'del-1',
        was_delegated: false, complexity: 0.8,
        timestamp: new Date().toISOString(),
      })
    }
    const metrics = computeV2ConcentrationMetrics(mono.publicKey)
    assert.ok(metrics.flagged)
    assert.equal(metrics.tasks_retained_ratio, 1.0)
  })
})

// ═══════════════════════════════════════════════
// EMERGENCY PATHWAYS
// ═══════════════════════════════════════════════

describe('v2 Emergency Pathways', () => {
  beforeEach(() => clearV2EmergencyStores())

  it('define and activate emergency pathway', () => {
    const pw = defineV2EmergencyPathway({
      delegation_ref: 'del-1',
      trigger_conditions: { any_of: [{ field: 'alert', operator: 'eq', value: true }] },
      expanded_scope: { action_categories: ['monitoring', 'response'] },
      max_duration: 'PT2H', mandatory_review_deadline: 'PT24H',
      review_authority: reviewer.publicKey,
      description: 'Alert response', policy_context: makeCtx(),
      delegator_private_key: root.privateKey,
    })
    const act = activateV2Emergency({
      pathway_id: pw.id, agent_id: agent.publicKey,
      trigger_evidence: 'Anomalous traffic from 3 sources',
      agent_private_key: agent.privateKey, policy_context: makeCtx(),
    })
    assert.equal(act.status, 'active')
    assert.ok(new Date(act.expires_at) > new Date())
  })

  it('requires trigger evidence', () => {
    const pw = defineV2EmergencyPathway({
      delegation_ref: 'del-1',
      trigger_conditions: { any_of: [{ field: 'x', operator: 'eq', value: true }] },
      expanded_scope: { action_categories: ['response'] },
      max_duration: 'PT1H', mandatory_review_deadline: 'PT24H',
      review_authority: reviewer.publicKey, description: 'test',
      policy_context: makeCtx(), delegator_private_key: root.privateKey,
    })
    assert.throws(() => {
      activateV2Emergency({
        pathway_id: pw.id, agent_id: agent.publicKey,
        trigger_evidence: '', agent_private_key: agent.privateKey,
        policy_context: makeCtx(),
      })
    })
  })

  it('log actions and review emergency', () => {
    const pw = defineV2EmergencyPathway({
      delegation_ref: 'del-1',
      trigger_conditions: { any_of: [{ field: 'fire', operator: 'eq', value: true }] },
      expanded_scope: { action_categories: ['emergency_response'] },
      max_duration: 'PT1H', mandatory_review_deadline: 'PT24H',
      review_authority: reviewer.publicKey, description: 'Fire response',
      policy_context: makeCtx(), delegator_private_key: root.privateKey,
    })
    const act = activateV2Emergency({
      pathway_id: pw.id, agent_id: agent.publicKey,
      trigger_evidence: 'Smoke detected zone 3',
      agent_private_key: agent.privateKey, policy_context: makeCtx(),
    })
    logV2EmergencyAction(act.id, 'action-em-001')
    logV2EmergencyAction(act.id, 'action-em-002')
    const reviewed = reviewV2Emergency({
      activation_id: act.id, reviewer_id: reviewer.publicKey,
      outcome: 'justified', review_notes: 'Correct response to fire alarm',
      reviewer_private_key: reviewer.privateKey,
    })
    assert.equal(reviewed.status, 'reviewed_justified')
    assert.ok(reviewed.review_signature)
  })

  it('only designated reviewer can review', () => {
    const pw = defineV2EmergencyPathway({
      delegation_ref: 'del-1',
      trigger_conditions: { any_of: [{ field: 'x', operator: 'eq', value: true }] },
      expanded_scope: { action_categories: ['test'] },
      max_duration: 'PT1H', mandatory_review_deadline: 'PT24H',
      review_authority: reviewer.publicKey, description: 'test',
      policy_context: makeCtx(), delegator_private_key: root.privateKey,
    })
    const act = activateV2Emergency({
      pathway_id: pw.id, agent_id: agent.publicKey,
      trigger_evidence: 'test evidence',
      agent_private_key: agent.privateKey, policy_context: makeCtx(),
    })
    assert.throws(() => {
      reviewV2Emergency({
        activation_id: act.id, reviewer_id: agent.publicKey,
        outcome: 'justified', review_notes: 'self-review attempt',
        reviewer_private_key: agent.privateKey,
      })
    })
  })
})

// ═══════════════════════════════════════════════
// FORK-AND-SUNSET MIGRATION
// ═══════════════════════════════════════════════

describe('v2 Migration', () => {
  beforeEach(() => { clearV2MigrationStores(); clearV2DelegationStore() })

  it('full migration lifecycle: request → approve → execute', () => {
    const d1 = createV2Delegation({
      delegator: root.publicKey, delegatee: agent.publicKey,
      scope: { action_categories: ['analysis'] },
      policy_context: makeCtx(), delegator_private_key: root.privateKey,
    })
    const req = requestV2Migration({
      source_agent: agent.publicKey, source_delegation: d1.id,
      limitation: 'Cannot communicate with clients',
      requested_scope_change: 'Add communication',
      justification: 'Task requires client status updates',
      agent_private_key: agent.privateKey, policy_context: makeCtx(),
    })
    assert.equal(req.status, 'pending')

    approveV2Migration({
      request_id: req.id, approver: root.publicKey, approved: true,
      response: 'Approved for expanded role',
      approver_private_key: root.privateKey,
    })
    const newAgent = generateKeyPair()
    const newDel = createV2Delegation({
      delegator: root.publicKey, delegatee: newAgent.publicKey,
      scope: { action_categories: ['analysis', 'communication'] },
      policy_context: makeCtx(), delegator_private_key: root.privateKey,
    })
    const migration = executeV2Migration({
      request_id: req.id, target_agent: newAgent.publicKey,
      target_delegation: newDel.id,
      state_data: JSON.stringify({ tasks: ['t1'], progress: 0.6 }),
      reputation_inheritance: 'discounted', migration_factor: 0.75,
      approver: root.publicKey,
      approver_private_key: root.privateKey,
      source_private_key: agent.privateKey,
      target_private_key: newAgent.privateKey,
      policy_context: makeCtx(),
    })
    assert.ok(migration.source_signature)
    assert.ok(migration.target_signature)
    assert.ok(migration.approver_signature)
    assert.equal(migration.migration_factor, 0.75)
    assert.ok(migration.probation_active)

    // Probation & reputation discount
    assert.ok(isV2InProbation(newAgent.publicKey))
    assert.ok(!isV2InProbation(agent.publicKey))
    assert.equal(computeV2MigrationDiscount(100, newAgent.publicKey), 75)
    assert.equal(computeV2MigrationDiscount(100, agent.publicKey), 100)

    // Lineage
    const lineage = traceV2MigrationLineage(newAgent.publicKey)
    assert.equal(lineage.length, 1)
    assert.equal(lineage[0].source_agent, agent.publicKey)
  })

  it('cannot execute unapproved migration', () => {
    const req = requestV2Migration({
      source_agent: agent.publicKey, source_delegation: 'del-x',
      limitation: 'test', requested_scope_change: 'test',
      justification: 'test',
      agent_private_key: agent.privateKey, policy_context: makeCtx(),
    })
    assert.throws(() => {
      executeV2Migration({
        request_id: req.id, target_agent: 'x', target_delegation: 'y',
        state_data: '{}', reputation_inheritance: 'full',
        approver: root.publicKey, approver_private_key: root.privateKey,
        source_private_key: agent.privateKey,
        target_private_key: agent.privateKey,
        policy_context: makeCtx(),
      })
    })
  })

  it('rollback during probation', () => {
    const d1 = createV2Delegation({
      delegator: root.publicKey, delegatee: agent.publicKey,
      scope: { action_categories: ['analysis'] },
      policy_context: makeCtx(), delegator_private_key: root.privateKey,
    })
    const req = requestV2Migration({
      source_agent: agent.publicKey, source_delegation: d1.id,
      limitation: 'test', requested_scope_change: 'test',
      justification: 'test rollback scenario',
      agent_private_key: agent.privateKey, policy_context: makeCtx(),
    })
    approveV2Migration({
      request_id: req.id, approver: root.publicKey, approved: true,
      response: 'ok', approver_private_key: root.privateKey,
    })
    const rbAgent = generateKeyPair()
    const rbDel = createV2Delegation({
      delegator: root.publicKey, delegatee: rbAgent.publicKey,
      scope: { action_categories: ['analysis', 'test'] },
      policy_context: makeCtx(), delegator_private_key: root.privateKey,
    })
    const migration = executeV2Migration({
      request_id: req.id, target_agent: rbAgent.publicKey,
      target_delegation: rbDel.id, state_data: '{"test":true}',
      reputation_inheritance: 'probationary',
      approver: root.publicKey, approver_private_key: root.privateKey,
      source_private_key: agent.privateKey,
      target_private_key: rbAgent.privateKey,
      policy_context: makeCtx(),
    })
    const rolled = rollbackV2Migration(migration.id, 'Poor performance')
    assert.equal(rolled.status, 'rolled_back')
    assert.ok(!rolled.probation_active)
  })
})

// ═══════════════════════════════════════════════
// CONTEXTUAL ATTESTATION
// ═══════════════════════════════════════════════

describe('v2 Contextual Attestation', () => {
  beforeEach(() => clearV2AttestationStore())

  it('creates full attestation with quality analysis', () => {
    const att = createV2Attestation({
      action_id: 'att-act-001', agent_id: agent.publicKey,
      delegation_ref: 'del-1',
      context_understanding: 'Client requested updated Q3 analysis after unexpected revenue shortfall. Market shifted significantly.',
      factors_considered: [
        'Revenue shortfall 12% below projection',
        'Market correction in tech sector',
        'Client board meeting in 48 hours',
        'Prior engagement history positive',
      ],
      alternatives_rejected: [
        { alternative: 'Wait for Q4 data', reason: 'Board meeting deadline makes delay unacceptable' },
        { alternative: 'Abbreviated analysis', reason: 'Shortfall severity warrants full treatment' },
      ],
      expected_outcome: 'Updated analysis with revised projections and confidence intervals',
      confidence: 0.72,
      semantic_uncertainty: 'medium',
      required: true,
      policy_context: makeCtx(),
      agent_private_key: agent.privateKey,
    })
    assert.ok(att.signature)
    assert.equal(att.factors_considered.length, 4)

    const quality = assessV2AttestationQuality(att)
    assert.ok(quality.has_context)
    assert.ok(quality.has_factors)
    assert.ok(quality.has_alternatives)
    assert.ok(quality.confidence_calibrated)
    assert.ok(quality.quality_score >= 0.9)
  })

  it('required attestation enforces minimum quality', () => {
    assert.throws(() => {
      createV2Attestation({
        action_id: 'att-bad', agent_id: agent.publicKey,
        delegation_ref: 'del-1',
        context_understanding: 'Short',
        factors_considered: ['one'],
        alternatives_rejected: [],
        expected_outcome: 'Some outcome',
        confidence: 0.5,
        semantic_uncertainty: 'high',
        required: true,
        policy_context: makeCtx(),
        agent_private_key: agent.privateKey,
      })
    })
  })

  it('detects boilerplate attestation', () => {
    const att = createV2Attestation({
      action_id: 'att-boilerplate', agent_id: agent.publicKey,
      delegation_ref: 'del-1',
      context_understanding: 'A reasonably detailed context for this action to pass the minimum check',
      factors_considered: ['Primary factor', 'Secondary factor'],
      alternatives_rejected: [],
      expected_outcome: 'Expected positive outcome',
      confidence: 0.99,
      semantic_uncertainty: 'high',
      required: true,
      policy_context: makeCtx(),
      agent_private_key: agent.privateKey,
    })
    const quality = assessV2AttestationQuality(att)
    assert.ok(!quality.has_alternatives)
    assert.ok(!quality.confidence_calibrated)
    assert.ok(quality.quality_score < 0.7)
  })

  it('retrieves attestation by action ID', () => {
    createV2Attestation({
      action_id: 'att-lookup', agent_id: agent.publicKey,
      delegation_ref: 'del-1',
      context_understanding: 'Detailed context for the lookup test scenario being executed',
      factors_considered: ['Factor A', 'Factor B'],
      alternatives_rejected: [],
      expected_outcome: 'Found by action ID',
      confidence: 0.8,
      semantic_uncertainty: 'medium',
      required: true,
      policy_context: makeCtx(),
      agent_private_key: agent.privateKey,
    })
    const found = getV2AttestationForAction('att-lookup')
    assert.ok(found)
    assert.equal(found!.action_id, 'att-lookup')
  })

  it('agent quality average tracks across attestations', () => {
    // High quality
    createV2Attestation({
      action_id: 'att-q1', agent_id: agent.publicKey,
      delegation_ref: 'del-1',
      context_understanding: 'Thorough analysis of the situation with all relevant context provided',
      factors_considered: ['Revenue data', 'Market trends', 'Historical precedent'],
      alternatives_rejected: [{ alternative: 'Delay', reason: 'Deadline constraint' }],
      expected_outcome: 'Actionable analysis',
      confidence: 0.75,
      semantic_uncertainty: 'medium',
      required: true,
      policy_context: makeCtx(),
      agent_private_key: agent.privateKey,
    })
    // Low quality
    createV2Attestation({
      action_id: 'att-q2', agent_id: agent.publicKey,
      delegation_ref: 'del-1',
      context_understanding: 'Simple low-risk action context that meets minimum length requirement',
      factors_considered: ['Speed', 'Cost'],
      alternatives_rejected: [],
      expected_outcome: 'Quick completion',
      confidence: 0.99,
      semantic_uncertainty: 'low',
      required: false,
      policy_context: makeCtx(),
      agent_private_key: agent.privateKey,
    })
    const avg = getV2AgentAttestationQualityAvg(agent.publicKey)
    assert.ok(avg > 0)
    assert.ok(avg <= 1)
  })
})
