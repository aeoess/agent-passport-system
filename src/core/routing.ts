// ══════════════════════════════════════
// Task Routing Protocol — Coordination Extension
// ══════════════════════════════════════
// Automatic task-to-agent matching on top of Layer 6 Coordination.
// Respects delegation scope, advertisement freshness, reputation.
//
// Flow: createTaskRequest → advertiseCapabilities → claimTask / declineTask
//       → routeTask → (creates TaskBrief via Layer 6)

import { randomBytes } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import { scopeCovers } from './delegation.js'
import type { Delegation } from '../types/passport.js'
import type {
  TaskRequest, TaskRequestPriority, TaskRequestStatus,
  CapabilityAdvertisement, AgentEnvironment,
  ClaimResponse, TaskDecline, RoutingDecision,
  RouterConfig, MatchWeights, CandidateScore, RoutingResult,
  CapabilityString,
} from '../types/routing.js'

// ═══════════════════════════════════════
// Default Configuration
// ═══════════════════════════════════════

export const DEFAULT_MATCH_WEIGHTS: MatchWeights = {
  coverage: 0.55,
  availability: 0.20,
  load: 0.15,
  budget: 0.10,
}

export const DEFAULT_PRIORITY_BOOSTS: Record<TaskRequestPriority, number> = {
  critical: 0.10,
  high: 0.05,
  normal: 0.00,
  low: -0.05,
}

export const DEFAULT_ROUTER_CONFIG: RouterConfig = {
  minCoverageThreshold: 0.6,
  weights: DEFAULT_MATCH_WEIGHTS,
  defaultClaimWindowMs: 30000,
  defaultAdvertisementTTL: 3600,
  priorityBoosts: DEFAULT_PRIORITY_BOOSTS,
}

// ═══════════════════════════════════════
// Capability Matching (colon-scoped)
// ═══════════════════════════════════════
// "code" matches "code:deploy", "code:review", etc.
// "research:web" matches "research:web:fetch" but NOT "research:local"

export function capabilityMatches(advertised: string, required: string): boolean {
  if (advertised === required) return true
  // Hierarchical: "code" covers "code:deploy"
  if (required.startsWith(advertised + ':')) return true
  // Reverse: "code:deploy" satisfies requirement for "code" (agent has specific skill for broad need)
  if (advertised.startsWith(required + ':')) return true
  return false
}

export function capabilityCoverage(
  advertised: CapabilityString[],
  required: CapabilityString[],
): { matched: CapabilityString[]; missing: CapabilityString[] } {
  const matched: CapabilityString[] = []
  const missing: CapabilityString[] = []
  for (const req of required) {
    if (advertised.some(adv => capabilityMatches(adv, req))) {
      matched.push(req)
    } else {
      missing.push(req)
    }
  }
  return { matched, missing }
}

// ═══════════════════════════════════════
// Delegation Scope Gate (Security)
// ═══════════════════════════════════════
// Hard gate: all required capabilities must fall within delegation scope.

export function checkDelegationScope(
  requiredCapabilities: CapabilityString[],
  delegationScope: string[],
): { valid: boolean; violations: string[] } {
  const violations: string[] = []
  for (const cap of requiredCapabilities) {
    const inScope = delegationScope.some(s => scopeCovers(s, cap))
    if (!inScope) violations.push(cap)
  }
  return { valid: violations.length === 0, violations }
}

// ═══════════════════════════════════════
// Advertisement Freshness
// ═══════════════════════════════════════

export function isAdvertisementFresh(ad: CapabilityAdvertisement, now?: Date): boolean {
  const timestamp = new Date(ad.lastAdvertised).getTime()
  const current = (now || new Date()).getTime()
  return (current - timestamp) / 1000 <= ad.advertisementTTL
}

// ═══════════════════════════════════════
// Create TaskRequest
// ═══════════════════════════════════════

export function createTaskRequest(opts: {
  requesterId: string
  title: string
  description: string
  requiredCapabilities: CapabilityString[]
  estimatedTokens?: number
  deadline?: string
  priority?: TaskRequestPriority
  claimWindowMs?: number
  publicKey: string
  privateKey: string
}): TaskRequest {
  const id = `task-req-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`

  const request: Omit<TaskRequest, 'signature'> = {
    id,
    requesterId: opts.requesterId,
    title: opts.title,
    description: opts.description,
    requiredCapabilities: opts.requiredCapabilities,
    estimatedTokens: opts.estimatedTokens,
    deadline: opts.deadline,
    priority: opts.priority || 'normal',
    status: 'open' as TaskRequestStatus,
    claimWindowMs: opts.claimWindowMs || DEFAULT_ROUTER_CONFIG.defaultClaimWindowMs,
    createdAt: new Date().toISOString(),
    publicKey: opts.publicKey,
  }

  const signature = sign(canonicalize(request), opts.privateKey)
  return { ...request, signature }
}

export function verifyTaskRequest(request: TaskRequest): boolean {
  const { signature, ...content } = request
  return verify(canonicalize(content), signature, request.publicKey)
}

// ═══════════════════════════════════════
// Advertise Capabilities
// ═══════════════════════════════════════

export function advertiseCapabilities(opts: {
  agentId: string
  capabilities: CapabilityString[]
  availability?: boolean
  maxTokenBudget?: number
  currentLoad?: number
  advertisementTTL?: number
  environment?: AgentEnvironment
  publicKey: string
  privateKey: string
}): CapabilityAdvertisement {
  const ad: Omit<CapabilityAdvertisement, 'signature'> = {
    agentId: opts.agentId,
    capabilities: opts.capabilities,
    availability: opts.availability ?? true,
    maxTokenBudget: opts.maxTokenBudget,
    currentLoad: opts.currentLoad ?? 0,
    lastAdvertised: new Date().toISOString(),
    advertisementTTL: opts.advertisementTTL || DEFAULT_ROUTER_CONFIG.defaultAdvertisementTTL,
    environment: opts.environment,
    publicKey: opts.publicKey,
  }

  const signature = sign(canonicalize(ad), opts.privateKey)
  return { ...ad, signature }
}

export function verifyAdvertisement(ad: CapabilityAdvertisement): boolean {
  const { signature, ...content } = ad
  return verify(canonicalize(content), signature, ad.publicKey)
}

// ═══════════════════════════════════════
// Claim Task
// ═══════════════════════════════════════

export function claimTask(opts: {
  taskRequestId: string
  claimantId: string
  proposedApproach: string
  estimatedCompletion?: string
  capabilitiesMatched: CapabilityString[]
  publicKey: string
  privateKey: string
}): ClaimResponse {
  const claim: Omit<ClaimResponse, 'signature'> = {
    taskRequestId: opts.taskRequestId,
    claimantId: opts.claimantId,
    proposedApproach: opts.proposedApproach,
    estimatedCompletion: opts.estimatedCompletion,
    capabilitiesMatched: opts.capabilitiesMatched,
    claimedAt: new Date().toISOString(),
    publicKey: opts.publicKey,
  }

  const signature = sign(canonicalize(claim), opts.privateKey)
  return { ...claim, signature }
}

export function verifyClaim(claim: ClaimResponse): boolean {
  const { signature, ...content } = claim
  return verify(canonicalize(content), signature, claim.publicKey)
}

// ═══════════════════════════════════════
// Decline Task
// ═══════════════════════════════════════

export function declineTask(opts: {
  taskRequestId: string
  declinerId: string
  reason: string
  suggestedAlternative?: string
  publicKey: string
  privateKey: string
}): TaskDecline {
  const decline: Omit<TaskDecline, 'signature'> = {
    taskRequestId: opts.taskRequestId,
    declinerId: opts.declinerId,
    reason: opts.reason,
    suggestedAlternative: opts.suggestedAlternative,
    declinedAt: new Date().toISOString(),
    publicKey: opts.publicKey,
  }

  const signature = sign(canonicalize(decline), opts.privateKey)
  return { ...decline, signature }
}

export function verifyDecline(decline: TaskDecline): boolean {
  const { signature, ...content } = decline
  return verify(canonicalize(content), signature, decline.publicKey)
}

// ═══════════════════════════════════════
// Score Candidates
// ═══════════════════════════════════════

export function scoreCandidate(
  request: TaskRequest,
  ad: CapabilityAdvertisement,
  delegation: Delegation | null,
  reputationScore?: number,
  config?: Partial<RouterConfig>,
  now?: Date,
): CandidateScore {
  const w = config?.weights || DEFAULT_MATCH_WEIGHTS

  // Freshness check
  const fresh = isAdvertisementFresh(ad, now)

  // Delegation scope gate (hard gate — no delegation = no scope validity)
  let scopeValid = false
  if (delegation) {
    const scopeCheck = checkDelegationScope(request.requiredCapabilities, delegation.scope)
    scopeValid = scopeCheck.valid
  }

  // Capability coverage
  const { matched, missing } = capabilityCoverage(ad.capabilities, request.requiredCapabilities)
  const coverageScore = request.requiredCapabilities.length > 0
    ? matched.length / request.requiredCapabilities.length
    : 0

  const availabilityScore = ad.availability ? 1 : 0

  // Load scoring with reputation-weighted damping (REC-3)
  const rawLoad = Math.max(0, Math.min(1, ad.currentLoad))
  const effectiveLoad = reputationScore !== undefined
    ? Math.max(rawLoad, 1 - (reputationScore / 10))  // reputation 0-10 scale
    : rawLoad
  const loadScore = 1 - effectiveLoad

  // Budget scoring
  let budgetScore = 1
  if (request.estimatedTokens && ad.maxTokenBudget) {
    budgetScore = Math.min(1, ad.maxTokenBudget / request.estimatedTokens)
  }

  // Weighted composite
  const raw = w.coverage * coverageScore
    + w.availability * availabilityScore
    + w.load * loadScore
    + w.budget * budgetScore

  // Priority boost
  const boosts = config?.priorityBoosts || DEFAULT_PRIORITY_BOOSTS
  const boost = boosts[request.priority] || 0
  const matchScore = Math.max(0, Math.min(1, raw + boost))

  return {
    agentId: ad.agentId,
    coverageScore,
    availabilityScore,
    loadScore,
    budgetScore,
    matchScore,
    capabilitiesMatched: matched,
    capabilitiesMissing: missing,
    scopeValid,
    advertisementFresh: fresh,
    reputationScore,
  }
}

// ═══════════════════════════════════════
// Route Task (main entry point)
// ═══════════════════════════════════════
// Collects claims, scores candidates, selects best match.

export function routeTask(opts: {
  request: TaskRequest
  claims: ClaimResponse[]
  advertisements: CapabilityAdvertisement[]
  delegations: Map<string, Delegation>   // agentId → delegation
  reputationScores?: Map<string, number> // agentId → score (0-10)
  config?: Partial<RouterConfig>
  routerPublicKey: string
  routerPrivateKey: string
  now?: Date
}): RoutingResult {
  const config = { ...DEFAULT_ROUTER_CONFIG, ...opts.config }
  const rejected: { claimantId: string; reason: string }[] = []
  const candidates: CandidateScore[] = []

  for (const claim of opts.claims) {
    // Find advertisement for this claimant
    const ad = opts.advertisements.find(a => a.agentId === claim.claimantId)
    if (!ad) {
      rejected.push({ claimantId: claim.claimantId, reason: 'no_capability_advertisement' })
      continue
    }

    // Freshness check
    if (!isAdvertisementFresh(ad, opts.now)) {
      rejected.push({ claimantId: claim.claimantId, reason: 'stale_advertisement' })
      continue
    }

    // Delegation scope gate (hard security gate — non-negotiable)
    const delegation = opts.delegations.get(claim.claimantId)
    if (!delegation) {
      rejected.push({ claimantId: claim.claimantId, reason: 'no_delegation' })
      continue
    }
    const scopeCheck = checkDelegationScope(opts.request.requiredCapabilities, delegation.scope)
    if (!scopeCheck.valid) {
      rejected.push({
        claimantId: claim.claimantId,
        reason: `delegation_scope_violation: ${scopeCheck.violations.join(', ')}`,
      })
      continue
    }

    // Score the candidate
    const rep = opts.reputationScores?.get(claim.claimantId)
    const score = scoreCandidate(opts.request, ad, delegation || null, rep, config, opts.now)
    candidates.push(score)
  }

  // Filter by coverage threshold
  const eligible = candidates
    .filter(c => c.coverageScore >= config.minCoverageThreshold)
    .sort((a, b) => b.matchScore - a.matchScore)

  // Build routing decision
  const selected = eligible[0] || null
  const fallbacks = eligible.slice(1).map(c => c.agentId)

  const reason = selected
    ? `Best match: coverage=${selected.coverageScore.toFixed(2)}, load=${selected.loadScore.toFixed(2)}, score=${selected.matchScore.toFixed(2)}`
    : candidates.length === 0
      ? 'No valid claims received'
      : `No candidate meets minimum coverage threshold (${config.minCoverageThreshold})`

  const decision: Omit<RoutingDecision, 'signature'> = {
    taskRequestId: opts.request.id,
    selectedAgentId: selected?.agentId || null,
    reason,
    fallbackAgents: fallbacks,
    matchScore: selected?.matchScore || 0,
    decidedAt: new Date().toISOString(),
    publicKey: opts.routerPublicKey,
  }

  const signature = sign(canonicalize(decision), opts.routerPrivateKey)

  return {
    decision: { ...decision, signature },
    candidates,
    rejectedClaims: rejected,
  }
}

export function verifyRoutingDecision(decision: RoutingDecision): boolean {
  const { signature, ...content } = decision
  return verify(canonicalize(content), signature, decision.publicKey)
}
