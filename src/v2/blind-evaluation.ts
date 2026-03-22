/**
 * APS v2 Blind Evaluation (Values Floor as Cover Defense — 5.9)
 *
 * The loudest champion of the values floor may be the one gaming it.
 * This module evaluates outputs blind to identity — evaluator sees
 * content hashes, not agent IDs, until all scores are assigned.
 */

export interface BlindSubmission {
  id: string
  evaluation_id: string
  agent_id: string
  content_hash: string
  content: string
  submitted_at: string
}

export interface BlindEvaluation {
  id: string
  purpose: string
  submissions: Map<string, BlindSubmission>
  evaluator_id: string | null
  status: 'collecting' | 'evaluating' | 'revealed'
  scores: Record<string, number>
  revealed: boolean
  created_at: string
}

const evaluations: Map<string, BlindEvaluation> = new Map()

function hashContent(s: string): string {
  let h = 0
  for (let i = 0; i < s.length; i++) { h = ((h << 5) - h + s.charCodeAt(i)) | 0 }
  return 'blind-' + Math.abs(h).toString(36)
}

export function createBlindEvaluation(purpose: string, evaluatorId: string): BlindEvaluation {
  const e: BlindEvaluation = {
    id: `blindeval-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    purpose, submissions: new Map(), evaluator_id: evaluatorId,
    status: 'collecting', scores: {}, revealed: false,
    created_at: new Date().toISOString(),
  }
  evaluations.set(e.id, e)
  return e
}

export function submitBlind(evaluationId: string, agentId: string, content: string): BlindSubmission {
  const e = evaluations.get(evaluationId)
  if (!e) throw new Error(`Evaluation ${evaluationId} not found`)
  if (e.status !== 'collecting') throw new Error('Evaluation not accepting submissions')
  const sub: BlindSubmission = {
    id: `blindsub-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    evaluation_id: evaluationId, agent_id: agentId,
    content_hash: hashContent(content), content,
    submitted_at: new Date().toISOString(),
  }
  e.submissions.set(sub.id, sub)
  return sub
}

// Get submission — hides agent_id unless revealed
export function getBlindSubmission(evaluationId: string, submissionId: string): {
  id: string; content_hash: string; content: string; agent_id?: string
} {
  const e = evaluations.get(evaluationId)
  if (!e) throw new Error(`Evaluation ${evaluationId} not found`)
  const sub = e.submissions.get(submissionId)
  if (!sub) throw new Error(`Submission ${submissionId} not found`)
  if (e.revealed) return { id: sub.id, content_hash: sub.content_hash, content: sub.content, agent_id: sub.agent_id }
  return { id: sub.id, content_hash: sub.content_hash, content: sub.content } // no agent_id
}

export function evaluateBlind(evaluationId: string, scores: Record<string, number>): BlindEvaluation {
  const e = evaluations.get(evaluationId)
  if (!e) throw new Error(`Evaluation ${evaluationId} not found`)
  if (e.submissions.size === 0) throw new Error('No submissions to evaluate')
  e.status = 'evaluating'
  e.scores = scores
  return e
}

export function revealIdentities(evaluationId: string): Array<{
  submission_id: string; agent_id: string; content: string; score: number | null
}> {
  const e = evaluations.get(evaluationId)
  if (!e) throw new Error(`Evaluation ${evaluationId} not found`)
  if (e.status === 'collecting') throw new Error('Cannot reveal — evaluation not complete')
  e.status = 'revealed'
  e.revealed = true
  return [...e.submissions.values()].map(sub => ({
    submission_id: sub.id, agent_id: sub.agent_id,
    content: sub.content, score: e.scores[sub.id] ?? null,
  }))
}

export function clearBlindEvaluationStores(): void { evaluations.clear() }
