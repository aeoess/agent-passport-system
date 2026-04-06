// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Agent Health Status — Enterprise monitoring type
// Public SDK contribution: exports the AgentHealthStatus shape so
// consumers (Datadog, Grafana) know the response format.
// Implementation lives in the private gateway.

import type { RecoveryStrategy } from './recovery.js'

/**
 * Agent governance health posture. Returned by the gateway
 * health endpoint for enterprise monitoring integration.
 *
 * GET /api/v1/agents/:agentId/health
 */
export interface AgentHealthStatus {
  agentId: string
  timestamp: string
  passport: {
    valid: boolean
    expiresAt: string
    grade: number  // 0-3
  }
  delegation: {
    active: boolean
    scopeCount: number
    spendUtilization: number  // 0.0-1.0
    expiresAt: string | null
  }
  behavioral: {
    continuityScore: number  // from context_continuity
    lastActionTimestamp: string
    actionsInWindow: number  // last 24h
    driftDetected: boolean
  }
  recovery: {
    activeRecoveryPolicy: string | null
    recentRecoveryEvents: number  // last 1h
    currentStrategy: RecoveryStrategy | null
  }
  status: 'healthy' | 'degraded' | 'suspended' | 'expired'
}

/** Derives status from health components */
export function deriveHealthStatus(health: Omit<AgentHealthStatus, 'status'>): AgentHealthStatus['status'] {
  if (!health.passport.valid) return 'expired'
  if (health.behavioral.driftDetected) return 'suspended'
  if (health.recovery.recentRecoveryEvents > 0) return 'degraded'
  if (health.delegation.spendUtilization > 0.95) return 'degraded'
  return 'healthy'
}
