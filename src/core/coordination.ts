// ══════════════════════════════════════
// LAYER 6 — Coordination Primitives
// ══════════════════════════════════════
// Protocol-native task coordination for multi-agent units.
// Every operation is Ed25519 signed. Every handoff is verifiable.

import { randomBytes } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import { createDelegation, verifyDelegation } from './delegation.js'
import type {
  TaskBrief, TaskRoleSpec, DeliverableSpec,
  TaskAssignment, EvidencePacket, EvidenceClaim,
  ReviewDecision, ReviewVerdict, ReviewIssue,
  EvidenceHandoff, Deliverable, TaskCompletion,
  TaskMetrics, TaskUnit, CoordinationRole, TaskStatus,
} from '../types/coordination.js'

// ═══════════════════════════════════════
// Task Brief — Operator decomposes work
// ═══════════════════════════════════════

export function createTaskBrief(opts: {
  title: string
  description: string
  operatorPublicKey: string
  operatorPrivateKey: string
  roles: Omit<TaskRoleSpec, 'assignedTo' | 'delegationId'>[]
  deliverables: Omit<DeliverableSpec, 'deliverableId'>[]
  acceptanceCriteria: string[]
  deadline?: string
}): TaskBrief {
  const taskId = `task-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`

  const roles: TaskRoleSpec[] = opts.roles.map(r => ({
    ...r,
    assignedTo: undefined,
    delegationId: undefined,
  }))

  const deliverables: DeliverableSpec[] = opts.deliverables.map((d, i) => ({
    ...d,
    deliverableId: `${taskId}-del-${i}`,
  }))

  const brief: Omit<TaskBrief, 'signature'> = {
    taskId,
    version: '1.0',
    title: opts.title,
    description: opts.description,
    createdBy: opts.operatorPublicKey,
    createdAt: new Date().toISOString(),
    deadline: opts.deadline,
    roles,
    deliverables,
    acceptanceCriteria: opts.acceptanceCriteria,
    status: 'draft' as TaskStatus,
  }

  const signature = sign(canonicalize(brief), opts.operatorPrivateKey)
  return { ...brief, signature }
}

export function verifyTaskBrief(brief: TaskBrief): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  const { signature, ...content } = brief
  try {
    if (!verify(canonicalize(content), signature, brief.createdBy)) {
      errors.push('Invalid operator signature on task brief')
    }
  } catch (e) {
    errors.push(`Signature verification failed: ${(e as Error).message}`)
  }

  // Validate structure
  if (!brief.roles.length) errors.push('Task brief must have at least one role')
  if (!brief.deliverables.length) errors.push('Task brief must have at least one deliverable')
  if (!brief.acceptanceCriteria.length) errors.push('Task brief must have acceptance criteria')

  // Validate role constraints
  const roleNames = brief.roles.map(r => r.role)
  for (const del of brief.deliverables) {
    if (!roleNames.includes(del.producedBy)) {
      errors.push(`Deliverable "${del.name}" assigned to role "${del.producedBy}" which is not in the task`)
    }
  }

  return { valid: errors.length === 0, errors }
}

// ═══════════════════════════════════════
// Task Assignment — Link delegation to role
// ═══════════════════════════════════════

export function assignTask(opts: {
  brief: TaskBrief
  role: CoordinationRole
  agentId: string
  agentPublicKey: string
  delegationId: string
  operatorPrivateKey: string
}): { assignment: TaskAssignment; updatedBrief: TaskBrief } {
  const roleSpec = opts.brief.roles.find(r => r.role === opts.role)
  if (!roleSpec) {
    throw new Error(`Role "${opts.role}" not found in task brief`)
  }
  if (roleSpec.assignedTo) {
    throw new Error(`Role "${opts.role}" already assigned to ${roleSpec.assignedTo}`)
  }

  const assignmentId = `assign-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`

  const assignmentContent = {
    assignmentId,
    taskId: opts.brief.taskId,
    role: opts.role,
    agentId: opts.agentId,
    agentPublicKey: opts.agentPublicKey,
    delegationId: opts.delegationId,
    assignedBy: opts.brief.createdBy,
    assignedAt: new Date().toISOString(),
  }

  const operatorSignature = sign(canonicalize(assignmentContent), opts.operatorPrivateKey)

  const assignment: TaskAssignment = {
    ...assignmentContent,
    operatorSignature,
  }

  // Update brief with assignment
  const updatedRoles = opts.brief.roles.map(r =>
    r.role === opts.role
      ? { ...r, assignedTo: opts.agentPublicKey, delegationId: opts.delegationId }
      : r
  )

  const allAssigned = updatedRoles.every(r => r.assignedTo)
  const { signature: _oldSig, ...briefContent } = opts.brief
  const updatedBriefContent = {
    ...briefContent,
    roles: updatedRoles,
    status: (allAssigned ? 'assigned' : 'draft') as TaskStatus,
  }
  const newSig = sign(canonicalize(updatedBriefContent), opts.operatorPrivateKey)
  const updatedBrief: TaskBrief = { ...updatedBriefContent, signature: newSig }

  return { assignment, updatedBrief }
}

export function acceptTask(
  assignment: TaskAssignment,
  agentPrivateKey: string
): TaskAssignment {
  const acceptedAt = new Date().toISOString()
  const toSign = { assignmentId: assignment.assignmentId, taskId: assignment.taskId, acceptedAt }
  const agentSignature = sign(canonicalize(toSign), agentPrivateKey)
  return { ...assignment, acceptedAt, agentSignature }
}

// ═══════════════════════════════════════
// Evidence Submission — Researcher output
// ═══════════════════════════════════════

export function submitEvidence(opts: {
  taskId: string
  submitterPublicKey: string
  submitterPrivateKey: string
  role: CoordinationRole
  claims: Omit<EvidenceClaim, 'claimId'>[]
  methodology: string
}): EvidencePacket {
  const packetId = `evid-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`

  const claims: EvidenceClaim[] = opts.claims.map((c, i) => ({
    ...c,
    claimId: `${packetId}-c${i}`,
  }))

  const gapCount = claims.filter(c => c.confidence === 'not_found').length
  const citedClaims = claims.filter(c => c.sourceUrl && c.confidence !== 'not_found').length

  const packetContent = {
    packetId,
    taskId: opts.taskId,
    submittedBy: opts.submitterPublicKey,
    role: opts.role,
    submittedAt: new Date().toISOString(),
    claims,
    metadata: {
      sourcesSearched: new Set(claims.map(c => c.sourceUrl).filter(Boolean)).size,
      totalClaims: claims.length,
      citedClaims,
      gapCount,
      methodology: opts.methodology,
    },
  }

  const signature = sign(canonicalize(packetContent), opts.submitterPrivateKey)
  return { ...packetContent, signature }
}

export function verifyEvidence(packet: EvidencePacket): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  const { signature, ...content } = packet

  try {
    if (!verify(canonicalize(content), signature, packet.submittedBy)) {
      errors.push('Invalid signature on evidence packet')
    }
  } catch (e) {
    errors.push(`Signature verification failed: ${(e as Error).message}`)
  }

  // Quality checks
  for (const claim of packet.claims) {
    if (claim.confidence !== 'not_found' && claim.quote.split(' ').length < 3) {
      errors.push(`Claim ${claim.claimId}: quote too short (< 3 words)`)
    }
  }

  return { valid: errors.length === 0, errors }
}

// ═══════════════════════════════════════
// Review Decision — Operator quality gate
// ═══════════════════════════════════════

export function reviewEvidence(opts: {
  taskId: string
  packet: EvidencePacket
  reviewerPublicKey: string
  reviewerPrivateKey: string
  verdict: ReviewVerdict
  score: number
  threshold: number
  rationale: string
  issues?: ReviewIssue[]
}): ReviewDecision {
  const reviewId = `review-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`

  // Auto-derive verdict from score vs threshold if not explicitly set
  let verdict = opts.verdict
  if (opts.score >= opts.threshold && verdict === 'rework') {
    // Operator can still force rework above threshold
  } else if (opts.score < opts.threshold && verdict === 'approve') {
    throw new Error(`Cannot approve: score ${opts.score} below threshold ${opts.threshold}`)
  }

  const decisionContent = {
    reviewId,
    taskId: opts.taskId,
    packetId: opts.packet.packetId,
    reviewedBy: opts.reviewerPublicKey,
    reviewedAt: new Date().toISOString(),
    verdict,
    score: opts.score,
    threshold: opts.threshold,
    rationale: opts.rationale,
    issues: opts.issues,
  }

  const signature = sign(canonicalize(decisionContent), opts.reviewerPrivateKey)
  return { ...decisionContent, signature }
}

export function verifyReview(review: ReviewDecision): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  const { signature, ...content } = review
  try {
    if (!verify(canonicalize(content), signature, review.reviewedBy)) {
      errors.push('Invalid signature on review decision')
    }
  } catch (e) {
    errors.push(`Signature verification failed: ${(e as Error).message}`)
  }
  if (review.score < 0 || review.score > 100) errors.push('Score must be 0-100')
  return { valid: errors.length === 0, errors }
}

// ═══════════════════════════════════════
// Evidence Handoff — Transfer between roles
// ═══════════════════════════════════════

export function handoffEvidence(opts: {
  taskId: string
  packet: EvidencePacket
  review: ReviewDecision
  fromRole: CoordinationRole
  toRole: CoordinationRole
  toAgentPublicKey: string
  operatorPrivateKey: string
}): EvidenceHandoff {
  if (opts.review.verdict !== 'approve') {
    throw new Error(`Cannot handoff: evidence not approved (verdict: ${opts.review.verdict})`)
  }
  if (opts.review.packetId !== opts.packet.packetId) {
    throw new Error('Review does not match evidence packet')
  }

  const handoffId = `handoff-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`

  const handoffContent = {
    handoffId,
    taskId: opts.taskId,
    packetId: opts.packet.packetId,
    reviewId: opts.review.reviewId,
    fromRole: opts.fromRole,
    toRole: opts.toRole,
    fromAgent: opts.packet.submittedBy,
    toAgent: opts.toAgentPublicKey,
    handoffAt: new Date().toISOString(),
  }

  const operatorSignature = sign(canonicalize(handoffContent), opts.operatorPrivateKey)
  return { ...handoffContent, operatorSignature }
}

export function verifyHandoff(
  handoff: EvidenceHandoff,
  operatorPublicKey: string
): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  const { operatorSignature, ...content } = handoff
  try {
    if (!verify(canonicalize(content), operatorSignature, operatorPublicKey)) {
      errors.push('Invalid operator signature on handoff')
    }
  } catch (e) {
    errors.push(`Signature verification failed: ${(e as Error).message}`)
  }
  return { valid: errors.length === 0, errors }
}

// ═══════════════════════════════════════
// Deliverable — Final output from a role
// ═══════════════════════════════════════

export function submitDeliverable(opts: {
  taskId: string
  specId: string
  submitterPublicKey: string
  submitterPrivateKey: string
  role: CoordinationRole
  content: string
  evidencePacketIds: string[]
  citationCount: number
  gapsFlagged: number
}): Deliverable {
  const deliverableId = `deliv-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`

  const delivContent = {
    deliverableId,
    taskId: opts.taskId,
    specId: opts.specId,
    submittedBy: opts.submitterPublicKey,
    role: opts.role,
    submittedAt: new Date().toISOString(),
    content: opts.content,
    evidencePacketIds: opts.evidencePacketIds,
    citationCount: opts.citationCount,
    gapsFlagged: opts.gapsFlagged,
  }

  const signature = sign(canonicalize(delivContent), opts.submitterPrivateKey)
  return { ...delivContent, signature }
}

export function verifyDeliverable(deliverable: Deliverable): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  const { signature, ...content } = deliverable
  try {
    if (!verify(canonicalize(content), signature, deliverable.submittedBy)) {
      errors.push('Invalid signature on deliverable')
    }
  } catch (e) {
    errors.push(`Signature verification failed: ${(e as Error).message}`)
  }
  return { valid: errors.length === 0, errors }
}

// ═══════════════════════════════════════
// Task Completion — Close the unit
// ═══════════════════════════════════════

export function completeTask(opts: {
  brief: TaskBrief
  unit: TaskUnit
  operatorPublicKey: string
  operatorPrivateKey: string
  status: 'completed' | 'failed' | 'partial'
  retrospective?: string
}): TaskCompletion {
  const deliverableIds = opts.unit.deliverables.map(d => d.deliverableId)

  // Calculate metrics
  const briefTime = new Date(opts.brief.createdAt).getTime()
  const now = Date.now()
  const totalDuration = Math.floor((now - briefTime) / 1000)

  // Sum handoff/review times as coordination overhead
  const reviewTimes = opts.unit.reviews.map(r => new Date(r.reviewedAt).getTime())
  const handoffTimes = opts.unit.handoffs.map(h => new Date(h.handoffAt).getTime())
  const overheadEvents = [...reviewTimes, ...handoffTimes].sort()
  // Rough estimate: each review/handoff = ~30s overhead
  const coordinationOverhead = overheadEvents.length * 30

  const taskWorkTime = totalDuration - coordinationOverhead
  const overheadRatio = taskWorkTime > 0 ? coordinationOverhead / taskWorkTime : 0

  const totalClaims = opts.unit.evidencePackets.reduce((s, p) => s + p.metadata.totalClaims, 0)
  const totalGaps = opts.unit.evidencePackets.reduce((s, p) => s + p.metadata.gapCount, 0)
  const evidenceGapRate = totalClaims > 0 ? totalGaps / totalClaims : 0

  const reworkCount = opts.unit.reviews.filter(r => r.verdict === 'rework').length
  const errorsCaught = opts.unit.reviews.reduce((s, r) => s + (r.issues?.length || 0), 0)

  const agentKeys = new Set([
    ...opts.unit.assignments.map(a => a.agentPublicKey),
  ])

  const metrics: TaskMetrics = {
    totalDuration,
    coordinationOverhead,
    taskWorkTime,
    overheadRatio: Math.round(overheadRatio * 100) / 100,
    evidenceGapRate: Math.round(evidenceGapRate * 100) / 100,
    reworkCount,
    errorsCaught,
    agentCount: agentKeys.size,
  }

  const completionContent = {
    taskId: opts.brief.taskId,
    completedBy: opts.operatorPublicKey,
    completedAt: new Date().toISOString(),
    status: opts.status,
    deliverableIds,
    metrics,
    retrospective: opts.retrospective,
  }

  const signature = sign(canonicalize(completionContent), opts.operatorPrivateKey)
  return { ...completionContent, signature }
}

export function verifyCompletion(
  completion: TaskCompletion,
  operatorPublicKey: string
): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  const { signature, ...content } = completion
  try {
    if (!verify(canonicalize(content), signature, operatorPublicKey)) {
      errors.push('Invalid operator signature on task completion')
    }
  } catch (e) {
    errors.push(`Signature verification failed: ${(e as Error).message}`)
  }
  return { valid: errors.length === 0, errors }
}

// ═══════════════════════════════════════
// Task Unit — Full lifecycle container
// ═══════════════════════════════════════

export function createTaskUnit(brief: TaskBrief): TaskUnit {
  return {
    brief,
    assignments: [],
    evidencePackets: [],
    reviews: [],
    handoffs: [],
    deliverables: [],
    completion: undefined,
  }
}

export function getTaskStatus(unit: TaskUnit): TaskStatus {
  if (unit.completion) return unit.completion.status === 'completed' ? 'completed' : 'failed'
  if (unit.deliverables.length > 0) return 'delivered'
  if (unit.reviews.some(r => r.verdict === 'approve')) return 'approved'
  if (unit.reviews.some(r => r.verdict === 'rework')) return 'rework_requested'
  if (unit.reviews.length > 0) return 'under_review'
  if (unit.evidencePackets.length > 0) return 'evidence_submitted'
  if (unit.assignments.length > 0) {
    return unit.assignments.every(a => a.acceptedAt) ? 'in_progress' : 'assigned'
  }
  return 'draft'
}

// Validate the entire unit's integrity — every signature, every link
export function validateTaskUnit(unit: TaskUnit): { valid: boolean; errors: string[] } {
  const errors: string[] = []

  // 1. Brief
  const briefResult = verifyTaskBrief(unit.brief)
  errors.push(...briefResult.errors)

  // 2. Assignments reference valid roles
  for (const a of unit.assignments) {
    if (a.taskId !== unit.brief.taskId) {
      errors.push(`Assignment ${a.assignmentId}: taskId mismatch`)
    }
    const roleExists = unit.brief.roles.some(r => r.role === a.role)
    if (!roleExists) {
      errors.push(`Assignment ${a.assignmentId}: role "${a.role}" not in brief`)
    }
  }

  // 3. Evidence packets reference this task
  for (const p of unit.evidencePackets) {
    if (p.taskId !== unit.brief.taskId) {
      errors.push(`Evidence ${p.packetId}: taskId mismatch`)
    }
    const evidResult = verifyEvidence(p)
    errors.push(...evidResult.errors)
  }

  // 4. Reviews reference valid packets
  for (const r of unit.reviews) {
    if (r.taskId !== unit.brief.taskId) {
      errors.push(`Review ${r.reviewId}: taskId mismatch`)
    }
    const packetExists = unit.evidencePackets.some(p => p.packetId === r.packetId)
    if (!packetExists) {
      errors.push(`Review ${r.reviewId}: references unknown packet ${r.packetId}`)
    }
    const revResult = verifyReview(r)
    errors.push(...revResult.errors)
  }

  // 5. Handoffs require approved reviews
  for (const h of unit.handoffs) {
    const review = unit.reviews.find(r => r.reviewId === h.reviewId)
    if (!review) {
      errors.push(`Handoff ${h.handoffId}: references unknown review ${h.reviewId}`)
    } else if (review.verdict !== 'approve') {
      errors.push(`Handoff ${h.handoffId}: review not approved (verdict: ${review.verdict})`)
    }
  }

  // 6. Deliverables reference valid evidence
  for (const d of unit.deliverables) {
    const delivResult = verifyDeliverable(d)
    errors.push(...delivResult.errors)
    for (const pId of d.evidencePacketIds) {
      const exists = unit.evidencePackets.some(p => p.packetId === pId)
      if (!exists) {
        errors.push(`Deliverable ${d.deliverableId}: references unknown packet ${pId}`)
      }
    }
  }

  // 7. Completion
  if (unit.completion) {
    const compResult = verifyCompletion(unit.completion, unit.brief.createdBy)
    errors.push(...compResult.errors)
  }

  return { valid: errors.length === 0, errors }
}
