// ══════════════════════════════════════
// LAYER 9 — Task Routing Protocol
// ══════════════════════════════════════
// Automatic task-to-agent matching. Sits on top of Layer 6 Coordination.
// Agents broadcast needs, advertise capabilities, claim work.
// Router selects best match respecting delegation scope.
//
// Lifecycle: TaskRequest → CapabilityAdvertisement → ClaimResponse → RoutingDecision → TaskBrief

// ── Capability Vocabulary ──
// Colon-scoped notation matching delegation scope patterns.
// "code" matches "code:*", "research:web" matches "research:web:fetch"
export type CapabilityString = string  // e.g. "code:deploy", "research:web", "spec:write"

export type TaskRequestStatus = 'open' | 'claimed' | 'assigned' | 'closed' | 'expired'
export type TaskRequestPriority = 'low' | 'normal' | 'high' | 'critical'

// ── TaskRequest ──
// Broadcast when an agent needs help it can't do alone.

export interface TaskRequest {
  id: string
  requesterId: string               // agent ID
  title: string
  description: string
  requiredCapabilities: CapabilityString[]
  estimatedTokens?: number
  deadline?: string                  // ISO 8601
  priority: TaskRequestPriority
  status: TaskRequestStatus
  claimWindowMs: number              // milliseconds to collect claims before routing (REC-2)
  createdAt: string
  publicKey: string
  signature: string
}

// ── CapabilityAdvertisement ──
// Agents declare what they can do. Stale ads are ignored.

export interface CapabilityAdvertisement {
  agentId: string
  capabilities: CapabilityString[]
  availability: boolean
  maxTokenBudget?: number
  currentLoad: number                // 0-1, self-reported
  lastAdvertised: string             // ISO 8601
  advertisementTTL: number           // seconds, default 3600
  environment?: AgentEnvironment     // REC-1 from Portal
  publicKey: string
  signature: string
}

export interface AgentEnvironment {
  runtime: 'sandbox' | 'local' | 'cloud'
  tools: string[]                    // available tools: "github-api", "filesystem", "browser"
  models?: string[]                  // "claude-opus-4", "gpt-5.2"
}

// ── ClaimResponse ──
// Agent claims a TaskRequest.

export interface ClaimResponse {
  taskRequestId: string
  claimantId: string
  proposedApproach: string
  estimatedCompletion?: string       // ISO 8601
  capabilitiesMatched: CapabilityString[]
  claimedAt: string
  publicKey: string
  signature: string
}

// ── TaskDecline ──
// Explicit refusal with reason and optional alternative.

export interface TaskDecline {
  taskRequestId: string
  declinerId: string
  reason: string
  suggestedAlternative?: string      // recommended agent ID
  declinedAt: string
  publicKey: string
  signature: string
}

// ── RoutingDecision ──
// System selects the best agent from claims.

export interface RoutingDecision {
  taskRequestId: string
  selectedAgentId: string | null     // null = no match
  reason: string
  fallbackAgents: string[]
  matchScore: number                 // 0-1
  decidedAt: string
  createdTaskBriefId?: string        // REC-4: link to created TaskBrief
  publicKey: string
  signature: string
}

// ── Router Configuration ──

export interface RouterConfig {
  minCoverageThreshold: number       // 0-1, default 0.6
  weights: MatchWeights
  defaultClaimWindowMs: number       // default 30000
  defaultAdvertisementTTL: number    // default 3600
  priorityBoosts: Record<TaskRequestPriority, number>
}

export interface MatchWeights {
  coverage: number       // default 0.55
  availability: number   // default 0.20
  load: number           // default 0.15
  budget: number         // default 0.10
}

// ── Match Result (internal scoring) ──

export interface CandidateScore {
  agentId: string
  coverageScore: number
  availabilityScore: number
  loadScore: number
  budgetScore: number
  matchScore: number                 // weighted composite
  capabilitiesMatched: CapabilityString[]
  capabilitiesMissing: CapabilityString[]
  scopeValid: boolean                // passed delegation scope gate
  advertisementFresh: boolean        // within TTL
  reputationScore?: number           // from reputation system
}

export interface RoutingResult {
  decision: RoutingDecision
  candidates: CandidateScore[]
  rejectedClaims: { claimantId: string; reason: string }[]
}
