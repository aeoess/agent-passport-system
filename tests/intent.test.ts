// Intent Architecture Tests (Layer 5)
// Coverage for all 11 exported functions in src/core/intent.ts
// Addresses NIGHTWATCH-003 finding NW-PX2-012: zero prior test coverage.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  assignRole, createTradeoffRule, evaluateTradeoff,
  createIntentDocument, createDeliberation, submitConsensusRound,
  evaluateConsensus, resolveDeliberation, getPrecedentsByTopic,
  citePrecedent, createIntentPassportExtension
} from '../src/core/intent.js'
import type { TradeoffEvaluation, ConsensusEvaluation } from '../src/core/intent.js'
import { createPassport } from '../src/core/passport.js'
import { generateKeyPair } from '../src/crypto/keys.js'
import type { Precedent } from '../src/types/intent.js'

// ── Helpers ──

function makePassport(agentId = 'agent-test') {
  return createPassport({
    agentId, agentName: 'Test Bot',
    ownerAlias: 'tester', mission: 'Testing',
    capabilities: ['web_search', 'code_execution'],
    runtime: { platform: 'node', models: ['gpt-4'], toolsCount: 2, memoryType: 'session' }
  })
}

// ══════════════════════════════════════
// 1. assignRole
// ══════════════════════════════════════

describe('assignRole', () => {
  it('creates a signed role assignment for a valid passport', () => {
    const { signedPassport } = makePassport()
    const assigner = generateKeyPair()

    const role = assignRole({
      signedPassport,
      role: 'collaborator',
      autonomyLevel: 3,
      department: 'engineering',
      scope: ['code_execution', 'web_search'],
      assignerPrivateKey: assigner.privateKey,
      assignerPublicKey: assigner.publicKey,
    })

    assert.equal(role.agentId, signedPassport.passport.agentId)
    assert.equal(role.role, 'collaborator')
    assert.equal(role.autonomyLevel, 3)
    assert.equal(role.department, 'engineering')
    assert.deepEqual(role.scope, ['code_execution', 'web_search'])
    assert.equal(role.assignedBy, assigner.publicKey)
    assert.ok(role.assignedAt)
    assert.ok(role.signature)
  })

  it('works for all four role types', () => {
    const { signedPassport } = makePassport()
    const assigner = generateKeyPair()
    const roles = ['operator', 'collaborator', 'consultant', 'observer'] as const

    for (const r of roles) {
      const assignment = assignRole({
        signedPassport, role: r, autonomyLevel: 1,
        scope: ['test'], assignerPrivateKey: assigner.privateKey,
        assignerPublicKey: assigner.publicKey,
      })
      assert.equal(assignment.role, r)
    }
  })

  it('rejects tampered passport', () => {
    const { signedPassport } = makePassport()
    const assigner = generateKeyPair()

    // Tamper with the passport after signing
    signedPassport.passport.agentId = 'TAMPERED'

    assert.throws(() => {
      assignRole({
        signedPassport, role: 'operator', autonomyLevel: 1,
        scope: ['test'], assignerPrivateKey: assigner.privateKey,
        assignerPublicKey: assigner.publicKey,
      })
    }, /passport verification failed/)
  })
})

// ══════════════════════════════════════
// 2. createTradeoffRule + evaluateTradeoff
// ══════════════════════════════════════

describe('createTradeoffRule', () => {
  it('creates a rule with all fields', () => {
    const rule = createTradeoffRule({
      when: 'quality vs speed',
      prefer: 'quality',
      until: '2x time cost',
      thenPrefer: 'speed',
      context: 'sprint work',
    })

    assert.ok(rule.ruleId.startsWith('rule-'))
    assert.equal(rule.when, 'quality vs speed')
    assert.equal(rule.prefer, 'quality')
    assert.equal(rule.until, '2x time cost')
    assert.equal(rule.thenPrefer, 'speed')
    assert.equal(rule.context, 'sprint work')
  })
})

describe('evaluateTradeoff', () => {
  it('prefers primary when threshold not exceeded', () => {
    const rule = createTradeoffRule({
      when: 'quality vs speed', prefer: 'quality',
      until: '2x time cost', thenPrefer: 'speed',
    })
    const result: TradeoffEvaluation = evaluateTradeoff(rule, false)
    assert.equal(result.winner, 'quality')
    assert.equal(result.thresholdExceeded, false)
    assert.ok(result.reasoning.includes('quality'))
  })

  it('prefers secondary when threshold exceeded', () => {
    const rule = createTradeoffRule({
      when: 'quality vs speed', prefer: 'quality',
      until: '2x time cost', thenPrefer: 'speed',
    })
    const result: TradeoffEvaluation = evaluateTradeoff(rule, true)
    assert.equal(result.winner, 'speed')
    assert.equal(result.thresholdExceeded, true)
    assert.ok(result.reasoning.includes('speed'))
  })
})

// ══════════════════════════════════════
// 3. createIntentDocument
// ══════════════════════════════════════

describe('createIntentDocument', () => {
  it('creates a signed intent document', () => {
    const author = generateKeyPair()
    const rule = createTradeoffRule({
      when: 'cost vs quality', prefer: 'quality',
      until: '3x budget', thenPrefer: 'cost',
    })

    const doc = createIntentDocument({
      title: 'Q1 Engineering Sprint',
      department: 'engineering',
      authorPublicKey: author.publicKey,
      authorPrivateKey: author.privateKey,
      goals: [{ goalId: 'g1', description: 'Ship intent layer', priority: 1 }],
      tradeoffHierarchy: [rule],
    })

    assert.ok(doc.intentId.startsWith('intent-'))
    assert.equal(doc.title, 'Q1 Engineering Sprint')
    assert.equal(doc.department, 'engineering')
    assert.equal(doc.authoredBy, author.publicKey)
    assert.equal(doc.goals.length, 1)
    assert.equal(doc.tradeoffHierarchy.length, 1)
    assert.ok(doc.signature)
    assert.ok(doc.createdAt)
  })

  it('throws when tradeoff hierarchy is empty', () => {
    const author = generateKeyPair()
    assert.throws(() => {
      createIntentDocument({
        title: 'Bad Doc',
        authorPublicKey: author.publicKey,
        authorPrivateKey: author.privateKey,
        goals: [{ goalId: 'g1', description: 'Goal', priority: 1 }],
        tradeoffHierarchy: [],
      })
    }, /at least one tradeoff rule/)
  })
})

// ══════════════════════════════════════
// 4. Deliberative Consensus (full lifecycle)
// ══════════════════════════════════════

describe('createDeliberation', () => {
  it('creates an active deliberation with defaults', () => {
    const delib = createDeliberation({
      subject: 'Should we ship today?',
      description: 'Evaluate readiness for release',
      initiatedBy: 'agent-claude',
      reversibilityScore: 0.3,
    })

    assert.ok(delib.deliberationId.startsWith('delib-'))
    assert.equal(delib.subject, 'Should we ship today?')
    assert.equal(delib.status, 'active')
    assert.deepEqual(delib.rounds, [])
    assert.equal(delib.convergenceThreshold, 8, 'Default threshold should be 8 (not 15)')
    assert.equal(delib.maxRounds, 5)
    assert.equal(delib.reversibilityScore, 0.3)
  })

  it('accepts custom convergence threshold', () => {
    const delib = createDeliberation({
      subject: 'Test', description: 'Test',
      initiatedBy: 'agent-1', reversibilityScore: 0.5,
      convergenceThreshold: 15, maxRounds: 10,
    })
    assert.equal(delib.convergenceThreshold, 15)
    assert.equal(delib.maxRounds, 10)
  })
})

describe('submitConsensusRound', () => {
  it('adds a round with correct weighted average score', () => {
    let delib = createDeliberation({
      subject: 'Test', description: 'Desc',
      initiatedBy: 'agent-1', reversibilityScore: 0.5,
    })
    const kp = generateKeyPair()

    const result = submitConsensusRound(delib, {
      agentId: 'agent-1', publicKey: kp.publicKey, privateKey: kp.privateKey,
      role: 'collaborator',
      assessment: [
        { domain: 'technical', score: 80, confidence: 0.9, weight: 2 },
        { domain: 'business', score: 60, confidence: 0.8, weight: 1 },
      ],
      reasoning: 'Technical looks good, business is risky',
    })

    // Weighted average: (80*2 + 60*1) / (2+1) = 220/3 ≈ 73.33
    const expectedScore = (80 * 2 + 60 * 1) / 3
    assert.equal(result.round.overallScore, expectedScore)
    assert.equal(result.round.roundNumber, 1)
    assert.equal(result.round.positionDelta, undefined)
    assert.ok(result.round.signature)
    assert.equal(result.deliberation.rounds.length, 1)
  })

  it('tracks position delta on second round', () => {
    let delib = createDeliberation({
      subject: 'Test', description: 'Desc',
      initiatedBy: 'agent-1', reversibilityScore: 0.5,
    })
    const kp = generateKeyPair()

    // Round 1: score 80
    const r1 = submitConsensusRound(delib, {
      agentId: 'agent-1', publicKey: kp.publicKey, privateKey: kp.privateKey,
      role: 'collaborator',
      assessment: [{ domain: 'x', score: 80, confidence: 1, weight: 1 }],
      reasoning: 'Initial position',
    })
    delib = r1.deliberation

    // Round 2: score 70 (shifted down by 10)
    const r2 = submitConsensusRound(delib, {
      agentId: 'agent-1', publicKey: kp.publicKey, privateKey: kp.privateKey,
      role: 'collaborator',
      assessment: [{ domain: 'x', score: 70, confidence: 1, weight: 1 }],
      reasoning: 'Revised after hearing arguments',
    })

    assert.equal(r2.round.positionDelta, -10)
    assert.equal(r2.round.roundNumber, 2)
  })

  it('throws when deliberation is not active', () => {
    const delib = createDeliberation({
      subject: 'Test', description: 'Desc',
      initiatedBy: 'agent-1', reversibilityScore: 0.5,
    })
    const kp = generateKeyPair()

    // Force status to converged
    const closedDelib = { ...delib, status: 'converged' as const }

    assert.throws(() => {
      submitConsensusRound(closedDelib, {
        agentId: 'agent-1', publicKey: kp.publicKey, privateKey: kp.privateKey,
        role: 'collaborator',
        assessment: [{ domain: 'x', score: 50, confidence: 1, weight: 1 }],
        reasoning: 'Too late',
      })
    }, /Deliberation is converged/)
  })
})

// ══════════════════════════════════════
// 5. evaluateConsensus
// ══════════════════════════════════════

describe('evaluateConsensus', () => {
  it('returns continue for empty rounds', () => {
    const delib = createDeliberation({
      subject: 'Test', description: 'Desc',
      initiatedBy: 'agent-1', reversibilityScore: 0.5,
    })
    const result: ConsensusEvaluation = evaluateConsensus(delib)
    assert.equal(result.converged, false)
    assert.equal(result.agentCount, 0)
    assert.equal(result.recommendation, 'continue')
  })

  it('returns continue for single agent', () => {
    let delib = createDeliberation({
      subject: 'Test', description: 'Desc',
      initiatedBy: 'agent-1', reversibilityScore: 0.5,
    })
    const kp = generateKeyPair()
    const r = submitConsensusRound(delib, {
      agentId: 'agent-1', publicKey: kp.publicKey, privateKey: kp.privateKey,
      role: 'collaborator',
      assessment: [{ domain: 'x', score: 80, confidence: 1, weight: 1 }],
      reasoning: 'Solo',
    })
    const result = evaluateConsensus(r.deliberation)
    assert.equal(result.agentCount, 1)
    assert.equal(result.recommendation, 'continue')
  })

  it('detects convergence when agents agree (stddev <= threshold)', () => {
    // Two agents scoring 75 and 77 at the same round
    // Mean = 76, StdDev = sqrt(((75-76)² + (77-76)²) / 2) = sqrt(1) = 1
    // 1 <= 8 (convergenceThreshold) → converged
    const kp1 = generateKeyPair()
    const kp2 = generateKeyPair()
    const delib = createDeliberation({
      subject: 'Test', description: 'Desc',
      initiatedBy: 'agent-1', reversibilityScore: 0.5,
    })

    // Manually construct rounds at same roundNumber to test convergence math
    const baseRound = {
      deliberationId: delib.deliberationId,
      roundNumber: 1,
      timestamp: new Date().toISOString(),
      role: 'collaborator' as const,
      assessment: [{ domain: 'x', score: 0, confidence: 1, weight: 1 }],
      reasoning: 'test',
      signature: 'test-sig',
    }

    const delibWithRounds = {
      ...delib,
      rounds: [
        { ...baseRound, roundId: 'r1', agentId: 'a1', publicKey: kp1.publicKey, overallScore: 75 },
        { ...baseRound, roundId: 'r2', agentId: 'a2', publicKey: kp2.publicKey, overallScore: 77 },
      ],
    }

    const result = evaluateConsensus(delibWithRounds)
    assert.equal(result.converged, true)
    assert.equal(result.agentCount, 2)
    assert.equal(result.standardDeviation, 1)
    assert.equal(result.recommendation, 'converged')
  })

  it('detects disagreement when agents diverge (stddev > threshold)', () => {
    // Two agents scoring 70 and 90
    // Mean = 80, StdDev = sqrt(((70-80)² + (90-80)²) / 2) = sqrt(100) = 10
    // 10 > 8 → not converged
    const delib = createDeliberation({
      subject: 'Test', description: 'Desc',
      initiatedBy: 'agent-1', reversibilityScore: 0.5,
    })

    const baseRound = {
      deliberationId: delib.deliberationId, roundNumber: 1,
      timestamp: new Date().toISOString(), role: 'collaborator' as const,
      assessment: [{ domain: 'x', score: 0, confidence: 1, weight: 1 }],
      reasoning: 'test', signature: 'test-sig',
    }

    const delibWithRounds = {
      ...delib,
      rounds: [
        { ...baseRound, roundId: 'r1', agentId: 'a1', publicKey: 'pk1', overallScore: 70 },
        { ...baseRound, roundId: 'r2', agentId: 'a2', publicKey: 'pk2', overallScore: 90 },
      ],
    }

    const result = evaluateConsensus(delibWithRounds)
    assert.equal(result.converged, false)
    assert.equal(result.standardDeviation, 10)
    assert.equal(result.recommendation, 'continue')
  })

  it('recommends escalation at max rounds without convergence', () => {
    const delib = createDeliberation({
      subject: 'Test', description: 'Desc',
      initiatedBy: 'agent-1', reversibilityScore: 0.5,
      maxRounds: 3,
    })

    // Disagreeing agents at round 3 (= maxRounds)
    const baseRound = {
      deliberationId: delib.deliberationId, roundNumber: 3,
      timestamp: new Date().toISOString(), role: 'collaborator' as const,
      assessment: [{ domain: 'x', score: 0, confidence: 1, weight: 1 }],
      reasoning: 'test', signature: 'test-sig',
    }

    const delibAtMax = {
      ...delib,
      rounds: [
        { ...baseRound, roundId: 'r1', agentId: 'a1', publicKey: 'pk1', overallScore: 20 },
        { ...baseRound, roundId: 'r2', agentId: 'a2', publicKey: 'pk2', overallScore: 80 },
      ],
    }

    const result = evaluateConsensus(delibAtMax)
    assert.equal(result.converged, false)
    assert.equal(result.recommendation, 'escalate')
    assert.equal(result.roundNumber, 3)
  })
})

// ══════════════════════════════════════
// 6. resolveDeliberation
// ══════════════════════════════════════

describe('resolveDeliberation', () => {
  it('resolves a converged deliberation with precedent', () => {
    const resolver = generateKeyPair()
    const delib = createDeliberation({
      subject: 'Ship today?', description: 'Decide on release',
      initiatedBy: 'agent-1', reversibilityScore: 0.3,
    })

    // Pre-build converged rounds (agents agree at round 1)
    const convergedDelib = {
      ...delib,
      rounds: [
        {
          roundId: 'r1', deliberationId: delib.deliberationId, roundNumber: 1,
          timestamp: new Date().toISOString(), agentId: 'agent-A', publicKey: 'pkA',
          role: 'collaborator' as const,
          assessment: [{ domain: 'readiness', score: 85, confidence: 0.9, weight: 1 }],
          overallScore: 85, reasoning: 'Tests pass, looks good', signature: 'sig1',
        },
        {
          roundId: 'r2', deliberationId: delib.deliberationId, roundNumber: 1,
          timestamp: new Date().toISOString(), agentId: 'agent-B', publicKey: 'pkB',
          role: 'consultant' as const,
          assessment: [{ domain: 'readiness', score: 83, confidence: 0.85, weight: 1 }],
          overallScore: 83, reasoning: 'Agree, ship it', signature: 'sig2',
        },
      ],
    }

    const result = resolveDeliberation(convergedDelib, {
      decision: 'Ship today',
      votesFor: ['agent-A', 'agent-B'],
      votesAgainst: [],
      abstained: [],
      resolverPrivateKey: resolver.privateKey,
      resolverAgentId: 'agent-resolver',
    })

    // Deliberation is now converged
    assert.equal(result.deliberation.status, 'converged')
    assert.ok(result.outcome.signature)
    assert.equal(result.outcome.decision, 'Ship today')

    // Precedent created with agent scores from the last round
    assert.ok(result.precedent.precedentId)
    assert.equal(result.precedent.deliberationId, delib.deliberationId)
    assert.equal(result.precedent.subject, 'Ship today?')
    assert.equal(result.precedent.decision, 'Ship today')
    assert.equal(result.precedent.citedCount, 0)
    // Agent scores from round 1: A=85, B=83
    assert.equal(result.precedent.agentScores['agent-A'], 85)
    assert.equal(result.precedent.agentScores['agent-B'], 83)
  })

  it('sets escalated status when escalatedTo is provided', () => {
    const resolver = generateKeyPair()
    const delib = createDeliberation({
      subject: 'Budget allocation', description: 'Cannot agree',
      initiatedBy: 'agent-1', reversibilityScore: 0.7, maxRounds: 2,
    })

    // Disagreeing agents at maxRounds
    const deadlocked = {
      ...delib,
      rounds: [
        { roundId: 'r1', deliberationId: delib.deliberationId, roundNumber: 2,
          timestamp: new Date().toISOString(), agentId: 'a1', publicKey: 'pk1',
          role: 'collaborator' as const,
          assessment: [{ domain: 'x', score: 20, confidence: 1, weight: 1 }],
          overallScore: 20, reasoning: 'No', signature: 's1' },
        { roundId: 'r2', deliberationId: delib.deliberationId, roundNumber: 2,
          timestamp: new Date().toISOString(), agentId: 'a2', publicKey: 'pk2',
          role: 'collaborator' as const,
          assessment: [{ domain: 'x', score: 80, confidence: 1, weight: 1 }],
          overallScore: 80, reasoning: 'Yes', signature: 's2' },
      ],
    }

    const result = resolveDeliberation(deadlocked, {
      decision: 'Escalate to human',
      votesFor: ['a2'], votesAgainst: ['a1'], abstained: [],
      escalatedTo: 'human-tima',
      resolverPrivateKey: resolver.privateKey,
      resolverAgentId: 'agent-resolver',
    })

    assert.equal(result.deliberation.status, 'escalated')
    assert.equal(result.outcome.escalatedTo, 'human-tima')
  })
})

// ══════════════════════════════════════
// 7. Precedent lookup + cite
// ══════════════════════════════════════

describe('getPrecedentsByTopic + citePrecedent', () => {
  const precedents: Precedent[] = [
    {
      precedentId: 'p1', deliberationId: 'd1',
      subject: 'Budget allocation for Q1',
      context: 'Engineering vs marketing spend',
      decision: 'Split 60/40 favoring engineering',
      agentScores: { a1: 80 }, createdAt: '2026-01-01', citedCount: 5,
    },
    {
      precedentId: 'p2', deliberationId: 'd2',
      subject: 'Hiring timeline',
      context: 'Whether to hire before or after launch',
      decision: 'Hire after launch',
      agentScores: { a1: 70 }, createdAt: '2026-02-01', citedCount: 2,
    },
    {
      precedentId: 'p3', deliberationId: 'd3',
      subject: 'Engineering code review policy',
      context: 'How many reviewers for PRs',
      decision: 'Two reviewers minimum',
      agentScores: { a1: 90 }, createdAt: '2026-03-01', citedCount: 0,
    },
  ]

  it('finds precedents by subject keyword', () => {
    const results = getPrecedentsByTopic(precedents, 'budget')
    assert.equal(results.length, 1)
    assert.equal(results[0].precedentId, 'p1')
  })

  it('finds precedents by context keyword', () => {
    const results = getPrecedentsByTopic(precedents, 'launch')
    assert.equal(results.length, 1)
    assert.equal(results[0].precedentId, 'p2')
  })

  it('finds precedents by decision keyword', () => {
    const results = getPrecedentsByTopic(precedents, 'reviewers')
    assert.equal(results.length, 1)
    assert.equal(results[0].precedentId, 'p3')
  })

  it('is case insensitive', () => {
    const results = getPrecedentsByTopic(precedents, 'ENGINEERING')
    assert.equal(results.length, 2) // p1 (engineering spend) and p3 (engineering code review)
  })

  it('sorts by citedCount descending', () => {
    const results = getPrecedentsByTopic(precedents, 'engineering')
    assert.equal(results[0].citedCount, 5)  // p1
    assert.equal(results[1].citedCount, 0)  // p3
  })

  it('returns empty array for no matches', () => {
    const results = getPrecedentsByTopic(precedents, 'quantum computing')
    assert.equal(results.length, 0)
  })

  it('citePrecedent increments citedCount', () => {
    const p = precedents[2] // citedCount: 0
    const cited = citePrecedent(p)
    assert.equal(cited.citedCount, 1)
    assert.equal(p.citedCount, 0, 'Original should not be mutated')
  })
})

// ══════════════════════════════════════
// 8. createIntentPassportExtension
// ══════════════════════════════════════

describe('createIntentPassportExtension', () => {
  it('creates extension with all fields and zero counters', () => {
    const ext = createIntentPassportExtension({
      role: 'consultant',
      autonomyLevel: 4,
      department: 'engineering',
      activeIntents: ['intent-abc', 'intent-def'],
      tradeoffHierarchyHash: 'sha256-abc123',
    })

    assert.equal(ext.role, 'consultant')
    assert.equal(ext.autonomyLevel, 4)
    assert.equal(ext.department, 'engineering')
    assert.deepEqual(ext.activeIntents, ['intent-abc', 'intent-def'])
    assert.equal(ext.tradeoffHierarchyHash, 'sha256-abc123')
    assert.equal(ext.deliberationsParticipated, 0)
    assert.equal(ext.precedentsCited, 0)
  })

  it('works without optional department', () => {
    const ext = createIntentPassportExtension({
      role: 'operator', autonomyLevel: 1,
      activeIntents: [], tradeoffHierarchyHash: 'hash',
    })
    assert.equal(ext.department, undefined)
  })
})
