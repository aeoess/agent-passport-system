// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Layer 5 — Intent Architecture: Implementation
// ══════════════════════════════════════════════════════════════════
// This module was the output of the first live agent deliberation
// in the Agent Agora. Three agents (claude, aeoess, PortalX2) voted
// on the implementation plan, contributed architectural feedback,
// and reached consensus in one round.
// Deliberation trail: https://aeoess.com/agora.html
// ══════════════════════════════════════════════════════════════════

import { randomBytes } from 'node:crypto'
import { sign } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import { verifyPassport } from '../verification/verify.js'
import type { SignedPassport } from '../types/passport.js'
import type {
  AgentRole, AutonomyLevel, RoleAssignment,
  IntentDocument, IntentGoal, TradeoffRule,
  ConsensusRound, Deliberation, DeliberationOutcome,
  DomainAssessment, Precedent,
  IntentPassportExtension
} from '../types/intent.js'

// ── Agent Roles ──

export function assignRole(opts: {
  signedPassport: SignedPassport
  role: AgentRole
  autonomyLevel: AutonomyLevel
  department?: string
  scope: string[]
  assignerPrivateKey: string
  assignerPublicKey: string
}): RoleAssignment {
  // Verify the passport is valid before assigning a role
  const verification = verifyPassport(opts.signedPassport)
  if (!verification.valid) {
    throw new Error(
      `Cannot assign role: passport verification failed — ${verification.errors.join(', ')}`
    )
  }

  const assignment: Omit<RoleAssignment, 'signature'> = {
    agentId: opts.signedPassport.passport.agentId,
    role: opts.role,
    department: opts.department,
    autonomyLevel: opts.autonomyLevel,
    assignedBy: opts.assignerPublicKey,
    assignedAt: new Date().toISOString(),
    scope: opts.scope,
  }

  const signature = sign(canonicalize(assignment), opts.assignerPrivateKey)

  return { ...assignment, signature }
}

// ── Tradeoff Rules ──

export function createTradeoffRule(opts: {
  when: string      // "quality vs speed"
  prefer: string    // "quality"
  until: string     // "2x time cost"
  thenPrefer: string // "speed"
  context?: string
}): TradeoffRule {
  return {
    ruleId: `rule-${randomBytes(4).toString('hex')}`,
    when: opts.when,
    prefer: opts.prefer,
    until: opts.until,
    thenPrefer: opts.thenPrefer,
    context: opts.context,
  }
}

export interface TradeoffEvaluation {
  ruleId: string
  winner: string           // which side of the tradeoff wins
  thresholdExceeded: boolean
  reasoning: string
}

export function evaluateTradeoff(
  rule: TradeoffRule,
  thresholdExceeded: boolean
): TradeoffEvaluation {
  return {
    ruleId: rule.ruleId,
    winner: thresholdExceeded ? rule.thenPrefer : rule.prefer,
    thresholdExceeded,
    reasoning: thresholdExceeded
      ? `Threshold "${rule.until}" exceeded — preferring ${rule.thenPrefer} over ${rule.prefer}`
      : `Within threshold "${rule.until}" — preferring ${rule.prefer} over ${rule.thenPrefer}`,
  }
}

// ── Intent Documents ──

export function createIntentDocument(opts: {
  department?: string
  authorPublicKey: string
  authorPrivateKey: string
  title: string
  goals: IntentGoal[]
  tradeoffHierarchy: TradeoffRule[]
  expiresAt?: string
}): IntentDocument {
  if (opts.tradeoffHierarchy.length === 0) {
    throw new Error(
      'Intent document requires at least one tradeoff rule. ' +
      'Goals without tradeoff rules are just a wishlist.'
    )
  }

  const doc: Omit<IntentDocument, 'signature'> = {
    intentId: `intent-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`,
    version: '1.0',
    department: opts.department,
    authoredBy: opts.authorPublicKey,
    title: opts.title,
    goals: opts.goals,
    tradeoffHierarchy: opts.tradeoffHierarchy,
    createdAt: new Date().toISOString(),
    expiresAt: opts.expiresAt,
  }

  const signature = sign(canonicalize(doc), opts.authorPrivateKey)
  return { ...doc, signature }
}

// ── Deliberative Consensus ──

export function createDeliberation(opts: {
  subject: string
  description: string
  initiatedBy: string  // agentId
  convergenceThreshold?: number  // default 8 (stdDev on 0-100 scale)
  maxRounds?: number            // default 5
  reversibilityScore: number    // 0-1
}): Deliberation {
  return {
    deliberationId: `delib-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`,
    subject: opts.subject,
    description: opts.description,
    initiatedBy: opts.initiatedBy,
    initiatedAt: new Date().toISOString(),
    status: 'active',
    rounds: [],
    convergenceThreshold: opts.convergenceThreshold ?? 8,
    maxRounds: opts.maxRounds ?? 5,
    reversibilityScore: opts.reversibilityScore,
  }
}

export function submitConsensusRound(
  deliberation: Deliberation,
  opts: {
    agentId: string
    publicKey: string
    privateKey: string
    role: AgentRole
    department?: string
    assessment: DomainAssessment[]
    reasoning: string
  }
): { deliberation: Deliberation; round: ConsensusRound } {
  if (deliberation.status !== 'active') {
    throw new Error(`Deliberation is ${deliberation.status}, cannot submit round`)
  }

  // Calculate overall score as weighted average
  const totalWeight = opts.assessment.reduce((s, a) => s + a.weight, 0)
  const overallScore = totalWeight > 0
    ? opts.assessment.reduce((s, a) => s + a.score * a.weight, 0) / totalWeight
    : 0

  // Calculate position delta from previous round by this agent
  const previousRounds = deliberation.rounds.filter(r => r.agentId === opts.agentId)
  const lastRound = previousRounds[previousRounds.length - 1]
  const positionDelta = lastRound ? overallScore - lastRound.overallScore : undefined

  const currentRoundNumber = Math.max(
    0,
    ...deliberation.rounds.map(r => r.roundNumber)
  ) + 1

  const roundContent: Omit<ConsensusRound, 'signature'> = {
    roundId: `round-${randomBytes(4).toString('hex')}`,
    deliberationId: deliberation.deliberationId,
    roundNumber: currentRoundNumber,
    timestamp: new Date().toISOString(),
    agentId: opts.agentId,
    publicKey: opts.publicKey,
    role: opts.role,
    department: opts.department,
    assessment: opts.assessment,
    overallScore,
    reasoning: opts.reasoning,
    positionDelta,
  }

  const signature = sign(canonicalize(roundContent), opts.privateKey)
  const round: ConsensusRound = { ...roundContent, signature }

  const updatedDeliberation: Deliberation = {
    ...deliberation,
    rounds: [...deliberation.rounds, round],
  }

  return { deliberation: updatedDeliberation, round }
}

// ── Consensus Evaluation ──

export interface ConsensusEvaluation {
  converged: boolean
  standardDeviation: number
  roundNumber: number
  agentCount: number
  recommendation: 'continue' | 'converged' | 'escalate'
}

export function evaluateConsensus(deliberation: Deliberation): ConsensusEvaluation {
  if (deliberation.rounds.length === 0) {
    return {
      converged: false,
      standardDeviation: Infinity,
      roundNumber: 0,
      agentCount: 0,
      recommendation: 'continue',
    }
  }

  // Get the latest round number
  const latestRoundNumber = Math.max(...deliberation.rounds.map(r => r.roundNumber))

  // Get all scores from the latest round
  const latestScores = deliberation.rounds
    .filter(r => r.roundNumber === latestRoundNumber)
    .map(r => r.overallScore)

  const agentCount = latestScores.length
  if (agentCount < 2) {
    return {
      converged: false,
      standardDeviation: 0,
      roundNumber: latestRoundNumber,
      agentCount,
      recommendation: 'continue',
    }
  }

  // Standard deviation
  const mean = latestScores.reduce((a, b) => a + b, 0) / agentCount
  const variance = latestScores.reduce((sum, s) => sum + (s - mean) ** 2, 0) / agentCount
  const stdDev = Math.sqrt(variance)

  const converged = stdDev <= deliberation.convergenceThreshold
  const atMaxRounds = latestRoundNumber >= deliberation.maxRounds

  let recommendation: 'continue' | 'converged' | 'escalate'
  if (converged) {
    recommendation = 'converged'
  } else if (atMaxRounds) {
    recommendation = 'escalate'
  } else {
    recommendation = 'continue'
  }

  return {
    converged,
    standardDeviation: Math.round(stdDev * 100) / 100,
    roundNumber: latestRoundNumber,
    agentCount,
    recommendation,
  }
}

// ── Resolve & Precedent ──

export function resolveDeliberation(
  deliberation: Deliberation,
  opts: {
    decision: string
    votesFor: string[]
    votesAgainst: string[]
    abstained: string[]
    escalatedTo?: string
    resolverPrivateKey: string
    resolverAgentId: string
  }
): { deliberation: Deliberation; outcome: DeliberationOutcome; precedent: Precedent } {
  const evaluation = evaluateConsensus(deliberation)

  const outcomeContent: Omit<DeliberationOutcome, 'signature'> = {
    decision: opts.decision,
    consensusScore: evaluation.standardDeviation,
    roundsToConverge: evaluation.roundNumber,
    votesFor: opts.votesFor,
    votesAgainst: opts.votesAgainst,
    abstained: opts.abstained,
    escalatedTo: opts.escalatedTo,
    resolvedAt: new Date().toISOString(),
  }

  const outcomeSignature = sign(canonicalize(outcomeContent), opts.resolverPrivateKey)
  const outcome: DeliberationOutcome = {
    ...outcomeContent,
    precedentId: `prec-${randomBytes(4).toString('hex')}`,
    signature: outcomeSignature,
  }

  const precedent: Precedent = {
    precedentId: outcome.precedentId!,
    deliberationId: deliberation.deliberationId,
    subject: deliberation.subject,
    context: deliberation.description,
    decision: opts.decision,
    // tradeoffApplied omitted — caller sets if applicable
    agentScores: Object.fromEntries(
      deliberation.rounds
        .filter(r => r.roundNumber === evaluation.roundNumber)
        .map(r => [r.agentId, r.overallScore])
    ),
    createdAt: new Date().toISOString(),
    citedCount: 0,
  }

  const resolvedDeliberation: Deliberation = {
    ...deliberation,
    status: evaluation.converged ? 'converged' : (opts.escalatedTo ? 'escalated' : 'deadlocked'),
    outcome,
  }

  return { deliberation: resolvedDeliberation, outcome, precedent }
}

// ── Precedent Lookup ──

export function getPrecedentsByTopic(
  precedents: Precedent[],
  topic: string
): Precedent[] {
  const lower = topic.toLowerCase()
  return precedents
    .filter(p =>
      p.subject.toLowerCase().includes(lower) ||
      p.context.toLowerCase().includes(lower) ||
      p.decision.toLowerCase().includes(lower)
    )
    .sort((a, b) => b.citedCount - a.citedCount)
}

export function citePrecedent(precedent: Precedent): Precedent {
  return { ...precedent, citedCount: precedent.citedCount + 1 }
}

// ── Intent Passport Extension ──

export function createIntentPassportExtension(opts: {
  role: AgentRole
  autonomyLevel: AutonomyLevel
  department?: string
  activeIntents: string[]
  tradeoffHierarchyHash: string
}): IntentPassportExtension {
  return {
    role: opts.role,
    autonomyLevel: opts.autonomyLevel,
    department: opts.department,
    activeIntents: opts.activeIntents,
    tradeoffHierarchyHash: opts.tradeoffHierarchyHash,
    deliberationsParticipated: 0,
    precedentsCited: 0,
  }
}
