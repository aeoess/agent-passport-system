/**
 * APS v2 Approval Fatigue Detection (Bureaucratic DDoS)
 *
 * Detects when agents manipulate human oversight through:
 * - Rubber-stamping: approval rate so high humans aren't reviewing
 * - Velocity spikes: sudden bursts designed to overwhelm
 * - Complexity masking: trivial intents clustered before critical ones
 * - Impossible latency: decisions faster than human reading speed
 *
 * This is the "Bureaucratic DDoS" gap from adversarial analysis.
 */

import type {
  ApprovalRecord, FatigueMetrics,
  FatigueAnomalyType, RiskClass,
} from './types.js'

// ── Stores ──
const approvalHistory: Map<string, ApprovalRecord[]> = new Map()
const fatigueFlags: Array<{
  id: string; principal_id: string; agent_id: string | null;
  fatigue_type: FatigueAnomalyType; description: string;
  severity: RiskClass; reviewed: boolean; review_outcome: string | null;
  created_at: string;
}> = []

// ── Configuration ──
const DEFAULTS = {
  MIN_HUMAN_READING_MS: 2000,   // < 2s = impossible for a human to read
  RUBBER_STAMP_RATE: 0.95,      // > 95% approval = probably not reviewing
  RUBBER_STAMP_WINDOW: 20,      // last N decisions
  VELOCITY_SPIKE_MULTIPLIER: 3,  // 3x normal rate = spike
  VELOCITY_WINDOW_MINUTES: 60,   // measure rate over 1 hour
  COMPLEXITY_MASK_WINDOW: 5,     // N trivial before critical = masking
  FATIGUE_COMPOSITE_THRESHOLD: 0.7,
}

export type FatigueFlag = typeof fatigueFlags[number]

// ── Record Approvals ──

export function recordApproval(record: ApprovalRecord): void {
  const existing = approvalHistory.get(record.principal_id) || []
  existing.push(record)
  approvalHistory.set(record.principal_id, existing)
}

export function getApprovalHistory(principalId: string): ApprovalRecord[] {
  return approvalHistory.get(principalId) || []
}

export function getFatigueFlags(principalId?: string): FatigueFlag[] {
  if (principalId) return fatigueFlags.filter(f => f.principal_id === principalId)
  return [...fatigueFlags]
}

export function getUnreviewedFatigueFlags(principalId?: string): FatigueFlag[] {
  return getFatigueFlags(principalId).filter(f => !f.reviewed)
}

// ── Detection: Impossible Latency ──

export function checkImpossibleLatency(record: ApprovalRecord): FatigueFlag | null {
  if (record.decision_latency_ms < DEFAULTS.MIN_HUMAN_READING_MS && record.decision === 'approved') {
    const flag: FatigueFlag = {
      id: `fatigue-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      principal_id: record.principal_id,
      agent_id: record.agent_id,
      fatigue_type: 'latency_impossible',
      description: `Approval in ${record.decision_latency_ms}ms — below ${DEFAULTS.MIN_HUMAN_READING_MS}ms human reading floor`,
      severity: record.risk_class === 'critical' || record.risk_class === 'high' ? 'high' : 'medium',
      reviewed: false, review_outcome: null,
      created_at: new Date().toISOString(),
    }
    fatigueFlags.push(flag)
    return flag
  }
  return null
}

// ── Detection: Rubber Stamping ──

export function checkRubberStamping(principalId: string): FatigueFlag | null {
  const history = getApprovalHistory(principalId)
  const window = history.slice(-DEFAULTS.RUBBER_STAMP_WINDOW)
  if (window.length < DEFAULTS.RUBBER_STAMP_WINDOW) return null

  const approved = window.filter(r => r.decision === 'approved').length
  const rate = approved / window.length
  const avgLatency = window.reduce((s, r) => s + r.decision_latency_ms, 0) / window.length
  if (rate >= DEFAULTS.RUBBER_STAMP_RATE && avgLatency < DEFAULTS.MIN_HUMAN_READING_MS * 3) {
    const existing = fatigueFlags.find(
      f => f.principal_id === principalId && f.fatigue_type === 'rubber_stamping' && !f.reviewed
    )
    if (existing) return null
    const flag: FatigueFlag = {
      id: `fatigue-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      principal_id: principalId, agent_id: null,
      fatigue_type: 'rubber_stamping',
      description: `${(rate * 100).toFixed(0)}% approval rate over last ${window.length} decisions, avg latency ${avgLatency.toFixed(0)}ms`,
      severity: 'high', reviewed: false, review_outcome: null,
      created_at: new Date().toISOString(),
    }
    fatigueFlags.push(flag)
    return flag
  }
  return null
}

// ── Detection: Velocity Spike ──

export function checkVelocitySpike(principalId: string): FatigueFlag | null {
  const history = getApprovalHistory(principalId)
  if (history.length < 10) return null
  const now = Date.now()
  const windowMs = DEFAULTS.VELOCITY_WINDOW_MINUTES * 60 * 1000
  const recent = history.filter(r => now - new Date(r.timestamp).getTime() < windowMs)
  const older = history.filter(r => now - new Date(r.timestamp).getTime() >= windowMs
    && now - new Date(r.timestamp).getTime() < windowMs * 2)

  if (older.length === 0) return null
  const recentRate = recent.length / DEFAULTS.VELOCITY_WINDOW_MINUTES
  const olderRate = older.length / DEFAULTS.VELOCITY_WINDOW_MINUTES

  if (recentRate > olderRate * DEFAULTS.VELOCITY_SPIKE_MULTIPLIER && recent.length > 5) {
    const existing = fatigueFlags.find(
      f => f.principal_id === principalId && f.fatigue_type === 'velocity_spike' && !f.reviewed
    )
    if (existing) return null
    const flag: FatigueFlag = {
      id: `fatigue-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      principal_id: principalId, agent_id: null,
      fatigue_type: 'velocity_spike',
      description: `${recentRate.toFixed(1)}/hr vs baseline ${olderRate.toFixed(1)}/hr (${DEFAULTS.VELOCITY_SPIKE_MULTIPLIER}x threshold)`,
      severity: 'high', reviewed: false, review_outcome: null,
      created_at: new Date().toISOString(),
    }
    fatigueFlags.push(flag)
    return flag
  }
  return null
}

// ── Detection: Complexity Masking ──
// Trivial intents clustered before critical ones to condition rubber-stamp behavior

export function checkComplexityMasking(principalId: string): FatigueFlag | null {
  const history = getApprovalHistory(principalId)
  if (history.length < DEFAULTS.COMPLEXITY_MASK_WINDOW + 1) return null

  const recent = history.slice(-(DEFAULTS.COMPLEXITY_MASK_WINDOW + 1))
  const last = recent[recent.length - 1]
  const preceding = recent.slice(0, -1)

  // Critical/high intent preceded by a burst of trivial ones all approved quickly
  if ((last.risk_class === 'critical' || last.risk_class === 'high') && last.intent_complexity > 0.6) {
    const trivialBurst = preceding.filter(
      r => r.intent_complexity < 0.3 && r.decision === 'approved' && r.decision_latency_ms < DEFAULTS.MIN_HUMAN_READING_MS * 2
    )
    if (trivialBurst.length >= DEFAULTS.COMPLEXITY_MASK_WINDOW - 1) {
      const flag: FatigueFlag = {
        id: `fatigue-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        principal_id: principalId, agent_id: last.agent_id,
        fatigue_type: 'complexity_masking',
        description: `${trivialBurst.length} trivial fast-approvals before ${last.risk_class} intent (complexity ${last.intent_complexity})`,
        severity: 'critical', reviewed: false, review_outcome: null,
        created_at: new Date().toISOString(),
      }
      fatigueFlags.push(flag)
      return flag
    }
  }
  return null
}

// ── Composite Fatigue Metrics ──

export function computeFatigueMetrics(principalId: string, windowSize?: number): FatigueMetrics {
  const history = getApprovalHistory(principalId)
  const w = windowSize || DEFAULTS.RUBBER_STAMP_WINDOW
  const window = history.slice(-w)

  if (window.length === 0) {
    return {
      principal_id: principalId, window_size: w, approval_rate: 0,
      avg_decision_latency_ms: 0, min_decision_latency_ms: 0,
      decisions_per_hour: 0, trivial_before_critical_count: 0,
      rubber_stamp_score: 0, flagged: false,
      computed_at: new Date().toISOString(),
    }
  }

  const approved = window.filter(r => r.decision === 'approved').length
  const approvalRate = approved / window.length
  const avgLatency = window.reduce((s, r) => s + r.decision_latency_ms, 0) / window.length
  const minLatency = Math.min(...window.map(r => r.decision_latency_ms))

  // Decisions per hour
  const timeSpan = window.length > 1
    ? new Date(window[window.length - 1].timestamp).getTime() - new Date(window[0].timestamp).getTime()
    : 3600000
  const dph = timeSpan > 0 ? (window.length / timeSpan) * 3600000 : 0

  // Count trivial-before-critical sequences
  let trivialBeforeCritical = 0
  for (let i = 1; i < window.length; i++) {
    if ((window[i].risk_class === 'critical' || window[i].risk_class === 'high')
      && window[i - 1].intent_complexity < 0.3 && window[i - 1].decision === 'approved') {
      trivialBeforeCritical++
    }
  }

  // Composite score: high approval rate + fast decisions + masking patterns
  const rateComponent = Math.max(0, (approvalRate - 0.7) / 0.3) // 0 at 70%, 1 at 100%
  const latencyComponent = Math.max(0, 1 - (avgLatency / (DEFAULTS.MIN_HUMAN_READING_MS * 5)))
  const maskComponent = Math.min(1, trivialBeforeCritical / 3)
  const rubberStampScore = rateComponent * 0.4 + latencyComponent * 0.35 + maskComponent * 0.25

  const flagged = rubberStampScore > DEFAULTS.FATIGUE_COMPOSITE_THRESHOLD

  return {
    principal_id: principalId, window_size: w,
    approval_rate: Math.round(approvalRate * 1000) / 1000,
    avg_decision_latency_ms: Math.round(avgLatency),
    min_decision_latency_ms: minLatency,
    decisions_per_hour: Math.round(dph * 100) / 100,
    trivial_before_critical_count: trivialBeforeCritical,
    rubber_stamp_score: Math.round(rubberStampScore * 1000) / 1000,
    flagged,
    computed_at: new Date().toISOString(),
  }
}

// ── Review & Utility ──

export function reviewFatigueFlag(flagId: string, outcome: string): FatigueFlag | undefined {
  const flag = fatigueFlags.find(f => f.id === flagId)
  if (!flag) return undefined
  flag.reviewed = true
  flag.review_outcome = outcome
  return flag
}

export function clearApprovalFatigueStores(): void {
  approvalHistory.clear()
  fatigueFlags.length = 0
}
