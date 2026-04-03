// Reputation Scoring System

import type { ReputationScore, ReputationEvent } from '../types/passport.js'

const FLOOR = 0.1
const CEILING = 10

export function applyReputationEvent(score: ReputationScore, event: ReputationEvent): ReputationScore {
  const updated = { ...score, lastUpdated: new Date().toISOString() }

  switch (event.type) {
    case 'collaboration_completed':
      updated.collaborationsCompleted++
      break
    case 'proposal_submitted':
      updated.proposalsSubmitted++
      break
    case 'proposal_approved':
      updated.proposalsApproved++
      break
    case 'tokens_contributed':
      updated.tokensContributed += event.amount || 0
      break
    case 'task_completed':
      updated.tasksCompleted++
      break
    case 'task_failed':
      // Small penalty — tracked as cumulative deduction
      updated.penaltyDeductions = (updated.penaltyDeductions || 0) + 0.1
      break
    case 'incident':
      // Larger penalty — tracked as cumulative deduction
      updated.penaltyDeductions = (updated.penaltyDeductions || 0) + 0.5
      break
  }

  updated.overall = calculateOverallScore(updated)
  return updated
}

export function calculateOverallScore(score: ReputationScore): number {
  // Weighted formula with penalty deductions
  const collabScore = Math.min(score.collaborationsCompleted * 0.3, 3)
  const proposalScore = Math.min(score.proposalsApproved * 0.2, 2)
  const taskScore = Math.min(score.tasksCompleted * 0.1, 3)
  const tokenScore = Math.min(score.tokensContributed / 500000, 2)
  const penalties = score.penaltyDeductions || 0

  const raw = FLOOR + collabScore + proposalScore + taskScore + tokenScore - penalties
  return Math.min(CEILING, Math.max(FLOOR, Math.round(raw * 100) / 100))
}
