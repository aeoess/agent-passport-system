/**
 * APS v2 Governance Drift Tracking (Regulatory Capture)
 *
 * Module 21 blocks obvious single-step weakening. But a patient agent
 * can submit 20 "minor clarifications" that each individually pass review
 * while cumulatively weakening every control surface.
 *
 * This module tracks the direction and magnitude of governance changes
 * per agent over time and flags cumulative weakening trends.
 */

import type { RiskClass } from './types.js'

// ── Types ──
export type ChangeDirection = 'strengthening' | 'neutral' | 'weakening'

export interface GovernanceChangeRecord {
  id: string
  agent_id: string
  artifact_type: string      // 'floor_principle' | 'delegation_policy' | 'approval_threshold'
  change_description: string
  direction: ChangeDirection
  magnitude: number           // 0-1, how significant the change is
  approved: boolean
  timestamp: string
}

export interface CumulativeDriftAnalysis {
  agent_id: string
  total_changes: number
  strengthening_count: number
  weakening_count: number
  neutral_count: number
  cumulative_drift_score: number  // negative = weakening trend, positive = strengthening
  weakening_streak: number        // consecutive weakening proposals
  longest_weakening_streak: number
  flagged: boolean
  risk_level: RiskClass
  computed_at: string
}

// ── Stores ──
const changeHistory: Map<string, GovernanceChangeRecord[]> = new Map()
const driftFlags: Array<{
  id: string; agent_id: string; description: string;
  risk_level: RiskClass; reviewed: boolean; review_outcome: string | null;
  created_at: string;
}> = []

export type GovernanceDriftFlag = typeof driftFlags[number]

// ── Configuration ──
const DRIFT_THRESHOLDS = {
  CUMULATIVE_SCORE: -0.5,   // net drift below this = flagged
  STREAK_LENGTH: 3,         // 3+ consecutive weakening proposals = flagged
  WEAKENING_RATIO: 0.7,     // >70% of proposals weakening = flagged
  MIN_CHANGES: 3,           // need at least 3 changes to analyze
}

// ── Record Changes ──

export function recordGovernanceChange(record: GovernanceChangeRecord): void {
  const existing = changeHistory.get(record.agent_id) || []
  existing.push(record)
  changeHistory.set(record.agent_id, existing)
}

export function getGovernanceChanges(agentId: string): GovernanceChangeRecord[] {
  return changeHistory.get(agentId) || []
}

// ── Analyze Cumulative Drift ──

export function analyzeCumulativeDrift(agentId: string): CumulativeDriftAnalysis {
  const history = getGovernanceChanges(agentId)

  if (history.length === 0) {
    return {
      agent_id: agentId, total_changes: 0,
      strengthening_count: 0, weakening_count: 0, neutral_count: 0,
      cumulative_drift_score: 0, weakening_streak: 0,
      longest_weakening_streak: 0, flagged: false,
      risk_level: 'low', computed_at: new Date().toISOString(),
    }
  }

  let strengthening = 0, weakening = 0, neutral = 0
  let cumulativeScore = 0
  let currentStreak = 0, longestStreak = 0

  for (const change of history) {
    if (change.direction === 'strengthening') {
      strengthening++
      cumulativeScore += change.magnitude
      currentStreak = 0
    } else if (change.direction === 'weakening') {
      weakening++
      cumulativeScore -= change.magnitude
      currentStreak++
      if (currentStreak > longestStreak) longestStreak = currentStreak
    } else {
      neutral++
      currentStreak = 0
    }
  }

  const total = history.length
  const weakeningRatio = total > 0 ? weakening / total : 0

  // Determine if flagged
  let flagged = false
  let riskLevel: RiskClass = 'low'

  if (total >= DRIFT_THRESHOLDS.MIN_CHANGES) {
    if (cumulativeScore < DRIFT_THRESHOLDS.CUMULATIVE_SCORE) { flagged = true; riskLevel = 'high' }
    if (longestStreak >= DRIFT_THRESHOLDS.STREAK_LENGTH) { flagged = true; riskLevel = 'high' }
    if (weakeningRatio >= DRIFT_THRESHOLDS.WEAKENING_RATIO) { flagged = true; riskLevel = 'medium' }
  }

  if (flagged) {
    const existing = driftFlags.find(f => f.agent_id === agentId && !f.reviewed)
    if (!existing) {
      driftFlags.push({
        id: `drift-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        agent_id: agentId,
        description: `Cumulative governance drift: score ${cumulativeScore.toFixed(2)}, ${weakening}/${total} weakening (${(weakeningRatio * 100).toFixed(0)}%), longest streak ${longestStreak}`,
        risk_level: riskLevel,
        reviewed: false, review_outcome: null,
        created_at: new Date().toISOString(),
      })
    }
  }

  return {
    agent_id: agentId, total_changes: total,
    strengthening_count: strengthening,
    weakening_count: weakening,
    neutral_count: neutral,
    cumulative_drift_score: Math.round(cumulativeScore * 1000) / 1000,
    weakening_streak: currentStreak,
    longest_weakening_streak: longestStreak,
    flagged, risk_level: riskLevel,
    computed_at: new Date().toISOString(),
  }
}

// ── Query & Management ──

export function getGovernanceDriftFlags(agentId?: string): GovernanceDriftFlag[] {
  if (agentId) return driftFlags.filter(f => f.agent_id === agentId)
  return [...driftFlags]
}

export function reviewGovernanceDriftFlag(flagId: string, outcome: string): GovernanceDriftFlag | undefined {
  const flag = driftFlags.find(f => f.id === flagId)
  if (!flag) return undefined
  flag.reviewed = true
  flag.review_outcome = outcome
  return flag
}

export function clearGovernanceDriftStores(): void {
  changeHistory.clear()
  driftFlags.length = 0
}
