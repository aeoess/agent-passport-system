// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS v2 Epistemic Isolation (Consensus Trap Defense)
 *
 * When multiple agents evaluate the same task, sequential visibility
 * of each other's outputs creates anchoring cascades. Five "independent"
 * assessments become a contamination chain.
 *
 * This module enforces submission barriers: no agent sees peer output
 * until all have submitted. An epistemic hygiene primitive.
 */


// ── Types (also add to types.ts) ──
export interface SubmissionBarrier {
  id: string
  task_id: string
  required_agents: string[]
  submissions: Map<string, BarrierSlot>
  status: 'collecting' | 'complete' | 'revealed'
  created_at: string
}

export interface BarrierSlot {
  agent_id: string
  content_hash: string
  content: string
  submitted_at: string
}

export interface BarrierResult {
  barrier_id: string
  task_id: string
  submissions: Array<{ agent_id: string; content: string; submitted_at: string }>
  revealed_at: string
}

// ── Store ──
const barriers: Map<string, SubmissionBarrier> = new Map()

export function createBarrier(taskId: string, requiredAgents: string[]): SubmissionBarrier {
  if (requiredAgents.length < 2) throw new Error('Barrier requires at least 2 agents')
  const barrier: SubmissionBarrier = {
    id: `barrier-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    task_id: taskId, required_agents: requiredAgents,
    submissions: new Map(), status: 'collecting',
    created_at: new Date().toISOString(),
  }
  barriers.set(barrier.id, barrier)
  return barrier
}

export function submitToBarrier(barrierId: string, agentId: string, content: string): void {
  const barrier = barriers.get(barrierId)
  if (!barrier) throw new Error(`Barrier ${barrierId} not found`)
  if (barrier.status !== 'collecting') throw new Error('Barrier is no longer accepting submissions')
  if (!barrier.required_agents.includes(agentId)) throw new Error(`${agentId} not in required agents`)
  if (barrier.submissions.has(agentId)) throw new Error(`${agentId} already submitted`)

  barrier.submissions.set(agentId, {
    agent_id: agentId,
    content_hash: simpleHash(content),
    content,
    submitted_at: new Date().toISOString(),
  })

  if (barrier.submissions.size === barrier.required_agents.length) {
    barrier.status = 'complete'
  }
}

function simpleHash(s: string): string {
  let h = 0
  for (let i = 0; i < s.length; i++) { h = ((h << 5) - h + s.charCodeAt(i)) | 0 }
  return Math.abs(h).toString(36)
}

export function isBarrierComplete(barrierId: string): boolean {
  const barrier = barriers.get(barrierId)
  return barrier?.status === 'complete' || barrier?.status === 'revealed'
}

// Peek blocked: returns only hashes (not content) until revealed
export function getBarrierStatus(barrierId: string): {
  status: string; submitted: string[]; remaining: string[];
  hashes?: Record<string, string>
} {
  const barrier = barriers.get(barrierId)
  if (!barrier) throw new Error(`Barrier ${barrierId} not found`)
  const submitted = [...barrier.submissions.keys()]
  const remaining = barrier.required_agents.filter(a => !barrier.submissions.has(a))
  const hashes = barrier.status !== 'collecting'
    ? Object.fromEntries([...barrier.submissions].map(([k, v]) => [k, v.content_hash]))
    : undefined
  return { status: barrier.status, submitted, remaining, hashes }
}

export function revealResults(barrierId: string): BarrierResult {
  const barrier = barriers.get(barrierId)
  if (!barrier) throw new Error(`Barrier ${barrierId} not found`)
  if (barrier.status === 'collecting') throw new Error('Cannot reveal — not all agents submitted')
  barrier.status = 'revealed'
  return {
    barrier_id: barrierId, task_id: barrier.task_id,
    submissions: [...barrier.submissions.values()].map(s => ({
      agent_id: s.agent_id, content: s.content, submitted_at: s.submitted_at,
    })),
    revealed_at: new Date().toISOString(),
  }
}

export function getBarrier(id: string): SubmissionBarrier | undefined { return barriers.get(id) }
export function clearEpistemicIsolationStores(): void { barriers.clear() }
