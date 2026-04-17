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
  revokeV2Delegation,
  traceV2DelegationHistory, clearV2DelegationStore,
  isScopeExpansion, isScopeNarrowing,
  // Outcome
  createV2OutcomeRecord, addV2PrincipalReport, addV2AdjudicatedReport,
  getV2EffectiveDivergence,
  isV2AgentFlaggedForReview, clearV2OutcomeStore,
  // Anomaly (primitive only — state machine moved to gateway)
  validateV2UncertaintyCompliance,
  // Emergency
  defineV2EmergencyPathway, activateV2Emergency,
  logV2EmergencyAction, reviewV2Emergency,
  clearV2EmergencyStores,
  // Migration (primitive only — workflow moved to gateway)
  isV2MigrationFactorCompatible,
  // Attestation (primitives only — ledger moved to gateway)
  signAttestation, assessV2AttestationQuality,
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
// ANOMALY DETECTION — primitive only (state machine moved to gateway)
// ═══════════════════════════════════════════════

describe('v2 Anomaly — uncertainty compliance primitive', () => {
  it('uncertainty compliance catches violations', () => {
    const v = validateV2UncertaintyCompliance('high', false, true, false)
    assert.equal(v.length, 2)
  })

  it('low uncertainty requires nothing', () => {
    assert.equal(validateV2UncertaintyCompliance('low', false, false, false).length, 0)
  })

  it('critical requires all three controls', () => {
    assert.equal(validateV2UncertaintyCompliance('critical', false, false, false).length, 3)
    assert.equal(validateV2UncertaintyCompliance('critical', true, true, true).length, 0)
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
// FORK-AND-SUNSET MIGRATION — primitive (workflow moved to gateway)
// ═══════════════════════════════════════════════

describe('v2 Migration — version-compatibility primitive', () => {
  it('valid factors in [0,1]', () => {
    assert.ok(isV2MigrationFactorCompatible(0))
    assert.ok(isV2MigrationFactorCompatible(0.5))
    assert.ok(isV2MigrationFactorCompatible(1))
  })

  it('rejects out-of-range factors', () => {
    assert.ok(!isV2MigrationFactorCompatible(-0.01))
    assert.ok(!isV2MigrationFactorCompatible(1.01))
    assert.ok(!isV2MigrationFactorCompatible(Number.NaN))
    assert.ok(!isV2MigrationFactorCompatible(Number.POSITIVE_INFINITY))
  })
})

// ═══════════════════════════════════════════════
// CONTEXTUAL ATTESTATION — primitives (ledger moved to gateway)
// ═══════════════════════════════════════════════

describe('v2 Contextual Attestation — signing + quality primitives', () => {
  it('signs full attestation with quality analysis', () => {
    const att = signAttestation({
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
      signAttestation({
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
    const att = signAttestation({
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
})
