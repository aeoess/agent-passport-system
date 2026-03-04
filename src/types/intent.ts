// ══════════════════════════════════════
// LAYER 5 — Intent Architecture
// ══════════════════════════════════════
// Organizational intent, agent roles, deliberative consensus,
// and governance for multi-agent decision-making.

// ── Agent Roles ──

export type AgentRole = 'operator' | 'collaborator' | 'consultant' | 'observer';

export type AutonomyLevel = 1 | 2 | 3 | 4 | 5;

export interface RoleAssignment {
  agentId: string
  role: AgentRole
  department?: string           // e.g. "engineering", "legal", "marketing"
  autonomyLevel: AutonomyLevel
  assignedBy: string            // public key of assigner
  assignedAt: string
  scope: string[]               // what this role covers
  signature: string             // signed by assigner
}

/**
 * Role definitions:
 * 
 * operator (autonomy 1-2):
 *   Executes tasks within defined parameters. Does not initiate decisions.
 *   Can escalate but not resolve conflicts.
 * 
 * collaborator (autonomy 2-3):
 *   Co-creates with humans or other agents. Can propose actions,
 *   participate in deliberations, adjust approach within bounds.
 * 
 * consultant (autonomy 3-4):
 *   Advises on strategy, values, and tradeoffs within their domain.
 *   Articulates organizational intent. Higher vote weight in domain expertise.
 *   Can initiate deliberations.
 * 
 * observer (autonomy 1):
 *   Monitors and reports. Read-only access to intent and decisions.
 *   Cannot vote or propose. Can flag anomalies.
 */

// ── Organizational Intent ──

export interface IntentDocument {
  intentId: string
  version: string
  department?: string           // null = org-wide
  authoredBy: string            // public key of Intent Architect or board
  title: string
  goals: IntentGoal[]
  tradeoffHierarchy: TradeoffRule[]
  createdAt: string
  expiresAt?: string
  signature: string
}

export interface IntentGoal {
  goalId: string
  description: string
  priority: number              // 1 = highest
  metrics?: string[]            // how success is measured
  constraints?: string[]        // hard limits
}

export interface TradeoffRule {
  ruleId: string
  when: string                  // "quality vs speed"
  prefer: string                // "quality"
  until: string                 // "2x time cost"
  thenPrefer: string            // "speed"
  context?: string              // when this rule applies
}

// ── Deliberative Consensus ──

export interface ConsensusRound {
  roundId: string
  deliberationId: string        // groups rounds into a deliberation
  roundNumber: number
  timestamp: string
  agentId: string
  publicKey: string
  role: AgentRole
  department?: string
  assessment: DomainAssessment[]
  overallScore: number          // 0-100 weighted aggregate
  reasoning: string
  positionDelta?: number        // change from previous round (null if round 1)
  signature: string             // Ed25519 signed by the agent
}

export interface DomainAssessment {
  domain: string                // "legal_risk", "growth_potential", "brand_alignment", etc.
  score: number                 // 0-100
  confidence: number            // 0-1 how sure the agent is
  weight: number                // how much this agent's score matters (by expertise)
}

export interface Deliberation {
  deliberationId: string
  subject: string
  description: string
  initiatedBy: string           // agentId
  initiatedAt: string
  status: 'active' | 'converged' | 'deadlocked' | 'escalated'
  rounds: ConsensusRound[]
  convergenceThreshold: number  // std dev below which consensus is reached (default: 15)
  maxRounds: number             // circuit breaker (default: 5)
  reversibilityScore: number    // 0-1. Low = easily undone, high = permanent
  outcome?: DeliberationOutcome
}

export interface DeliberationOutcome {
  decision: string
  consensusScore: number        // final std dev across agents
  roundsToConverge: number
  votesFor: string[]            // agentIds
  votesAgainst: string[]
  abstained: string[]
  escalatedTo?: string          // human Intent Architect if deadlocked
  precedentId?: string          // stored as precedent for future reference
  resolvedAt: string
  signature: string             // signed by deliberation initiator
}

// ── Precedent Memory ──

export interface Precedent {
  precedentId: string
  deliberationId: string
  subject: string
  context: string               // what situation triggered this
  decision: string              // what was decided
  tradeoffApplied?: string      // which tradeoff rule was used (if applicable)
  agentScores: Record<string, number>  // final scores by agentId
  createdAt: string
  citedCount: number            // how many future deliberations reference this
}

// ── Context Governance ──

export type MemoryTier = 'working' | 'session' | 'long_term' | 'artifact';

export interface ContextGovernance {
  tier: MemoryTier
  readRoles: AgentRole[]        // who can read
  writeRoles: AgentRole[]       // who can write
  persistDuration: string       // "ephemeral", "task", "permanent"
  requiresApproval: boolean     // does writing require consensus?
  approvalThreshold?: number    // min agents to approve
}

// ── Intent Passport Extension ──

export interface IntentPassportExtension {
  role: AgentRole
  autonomyLevel: AutonomyLevel
  department?: string
  activeIntents: string[]       // intentIds this agent operates under
  tradeoffHierarchyHash: string // SHA-256 of the tradeoff rules this agent follows
  deliberationsParticipated: number
  precedentsCited: number
  lastDeliberationAt?: string
}
