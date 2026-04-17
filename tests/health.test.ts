// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Tests for AgentHealthStatus type shape.
// deriveHealthStatus moved to the private gateway as part of the AAIF
// boundary cleanup (specs/AAIF-BOUNDARY-AUDIT.md) — the thresholds were
// product policy, not a protocol primitive. The SDK still ships the
// shape so monitoring consumers (Datadog, Grafana) can type the response.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import type { AgentHealthStatus } from '../src/index.js'

describe('AgentHealthStatus', () => {
  it('type is structurally valid', () => {
    const full: AgentHealthStatus = {
      agentId: 'agent-test-001',
      timestamp: '2026-04-06T12:00:00Z',
      passport: { valid: true, expiresAt: '2026-05-06T12:00:00Z', grade: 2 },
      delegation: {
        active: true,
        scopeCount: 3,
        spendUtilization: 0.4,
        expiresAt: '2026-05-06T12:00:00Z',
      },
      behavioral: {
        continuityScore: 85,
        lastActionTimestamp: '2026-04-06T11:55:00Z',
        actionsInWindow: 42,
        driftDetected: false,
      },
      recovery: {
        activeRecoveryPolicy: null,
        recentRecoveryEvents: 0,
        currentStrategy: null,
      },
      status: 'healthy',
    }
    assert.equal(full.status, 'healthy')
    assert.equal(full.passport.grade, 2)
    assert.equal(full.delegation.scopeCount, 3)
    assert.equal(full.recovery.currentStrategy, null)
  })

  it('status field accepts all four values', () => {
    const statuses: AgentHealthStatus['status'][] = [
      'healthy', 'degraded', 'suspended', 'expired',
    ]
    assert.equal(statuses.length, 4)
  })
})
