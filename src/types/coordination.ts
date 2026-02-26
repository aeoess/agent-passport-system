// ══════════════════════════════════════
// LAYER 6 — Coordination Primitives
// ══════════════════════════════════════
// Protocol-native task coordination for multi-agent units.
// Turns manual orchestration into signed, verifiable operations.
//
// Lifecycle: Brief → Assign → Evidence → Review → Handoff → Deliver → Complete

// ── Task Roles (extends Layer 5 AgentRole for coordination) ──

export type CoordinationRole = 'operator' | 'researcher' | 'analyst' | 'builder' | 'reviewer';

export type TaskStatus = 'draft' | 'assigned' | 'in_progress' | 'evidence_submitted' |
  'under_review' | 'rework_requested' | 'approved' | 'delivered' | 'completed' | 'failed';

export type ReviewVerdict = 'approve' | 'rework' | 'reject';

// ── Task Brief ──
// Operator decomposes work into roles with scopes and deliverables

export interface TaskBrief {
  taskId: string
  version: '1.0'
  title: string
  description: string
  createdBy: string             // operator's public key
  createdAt: string
  deadline?: string             // ISO 8601
  roles: TaskRoleSpec[]
  deliverables: DeliverableSpec[]
  acceptanceCriteria: string[]  // what "done" looks like
  status: TaskStatus
  signature: string             // signed by operator
}

export interface TaskRoleSpec {
  role: CoordinationRole
  description: string
  allowedScopes: string[]       // maps to delegation scopes
  forbiddenScopes: string[]     // explicit restrictions
  requiredCapabilities?: string[] // agent must have these
  assignedTo?: string           // agent public key (filled on assignment)
  delegationId?: string         // links to actual delegation
}

export interface DeliverableSpec {
  deliverableId: string
  name: string
  description: string
  format: string                // "json", "markdown", "matrix", etc.
  producedBy: CoordinationRole  // which role produces this
  requiredFields?: string[]     // minimum fields in output
  minCitations?: number         // minimum evidence citations
}

// ── Task Assignment ──
// Links a delegation to a specific role in a task

export interface TaskAssignment {
  assignmentId: string
  taskId: string
  role: CoordinationRole
  agentId: string
  agentPublicKey: string
  delegationId: string          // the delegation granting scope for this role
  assignedBy: string            // operator's public key
  assignedAt: string
  acceptedAt?: string           // agent confirms acceptance
  agentSignature?: string       // agent signs to accept
  operatorSignature: string     // operator signs assignment
}

// ── Evidence Packet ──
// Signed research output with citations and metadata

export interface EvidencePacket {
  packetId: string
  taskId: string
  submittedBy: string           // researcher's public key
  role: CoordinationRole
  submittedAt: string
  claims: EvidenceClaim[]
  metadata: {
    sourcesSearched: number
    totalClaims: number
    citedClaims: number
    gapCount: number            // explicit NOT FOUND count
    methodology: string         // how evidence was gathered
  }
  signature: string             // signed by researcher
}

export interface EvidenceClaim {
  claimId: string
  dimension: string             // evaluation dimension
  subject: string               // what's being evaluated
  claim: string                 // the factual claim
  quote: string                 // supporting quote (10+ words)
  sourceUrl: string             // verifiable source
  confidence: 'high' | 'medium' | 'low' | 'not_found'
}

// ── Review Decision ──
// Operator's quality gate on evidence

export interface ReviewDecision {
  reviewId: string
  taskId: string
  packetId: string              // which evidence packet
  reviewedBy: string            // operator's public key
  reviewedAt: string
  verdict: ReviewVerdict
  score: number                 // 0-100
  threshold: number             // minimum to pass (e.g. 70)
  rationale: string
  issues?: ReviewIssue[]        // specific problems found
  signature: string             // signed by operator
}

export interface ReviewIssue {
  claimId: string
  issue: string                 // "quote too short", "source unreachable", etc.
  severity: 'critical' | 'major' | 'minor'
}

// ── Evidence Handoff ──
// Signed transfer of approved evidence from one role to another

export interface EvidenceHandoff {
  handoffId: string
  taskId: string
  packetId: string              // the approved evidence
  reviewId: string              // the approval decision
  fromRole: CoordinationRole
  toRole: CoordinationRole
  fromAgent: string             // researcher's public key
  toAgent: string               // analyst's public key
  handoffAt: string
  operatorSignature: string     // operator authorizes the handoff
}

// ── Deliverable ──
// Final output from a role, tied to task and evidence

export interface Deliverable {
  deliverableId: string
  taskId: string
  specId: string                // links to DeliverableSpec
  submittedBy: string           // analyst's public key
  role: CoordinationRole
  submittedAt: string
  content: string               // the actual output (or reference to it)
  evidencePacketIds: string[]   // which evidence packets were used
  citationCount: number
  gapsFlagged: number           // explicit gaps in output
  signature: string             // signed by producing agent
}

// ── Task Completion ──
// Operator closes the task unit

export interface TaskCompletion {
  taskId: string
  completedBy: string           // operator's public key
  completedAt: string
  status: 'completed' | 'failed' | 'partial'
  deliverableIds: string[]
  metrics: TaskMetrics
  retrospective?: string        // what went well, what didn't
  signature: string             // signed by operator
}

export interface TaskMetrics {
  totalDuration: number         // seconds from brief to completion
  coordinationOverhead: number  // seconds spent on handoffs/reviews
  taskWorkTime: number          // seconds of actual work
  overheadRatio: number         // coordination / task work
  evidenceGapRate: number       // gaps / total claims
  reworkCount: number           // how many rework cycles
  errorsCaught: number          // errors found during review
  agentCount: number            // how many agents participated
}

// ── Task Unit (full lifecycle) ──
// Represents the entire coordination workflow

export interface TaskUnit {
  brief: TaskBrief
  assignments: TaskAssignment[]
  evidencePackets: EvidencePacket[]
  reviews: ReviewDecision[]
  handoffs: EvidenceHandoff[]
  deliverables: Deliverable[]
  completion?: TaskCompletion
}
