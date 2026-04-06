// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Tests for AgentHealthStatus type and deriveHealthStatus

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { deriveHealthStatus } from '../src/index.js'
import type { AgentHealthStatus } from '../src/index.js'

function makeHealth(overrides: Partial<{
  passportValid: boolean
  passportGrade: number
  delegationActive: boolean
  spendUtilization: number
  driftDetected: boolean
  recentRecoveryEvents: number
}>): Omit<AgentHealthStatus, 'status'> {
  return {
    agentId: 'agent-test-001',
    timestamp: '2026-04-06T12:00:00Z',
    passport: {
      valid: overrides.passportValid ?? true,
      expiresAt: '2026-05-06T12:00:00Z',
      grade: overrides.passportGrade ?? 2,
    },
    delegation: {
      active: overrides.delegationActive ?? true,
      scopeCount: 3,
      spendUtilization: overrides.spendUtilization ?? 0.4,
      expiresAt: '2026-05-06T12:00:00Z',
    },
    behavioral: {
      continuityScore: 85,
      lastActionTimestamp: '2026-04-06T11:55:00Z',
      actionsInWindow: 42,
      driftDetected: overrides.driftDetected ?? false,
    },
    recovery: {
      activeRecoveryPolicy: null,
      recentRecoveryEvents: overrides.recentRecoveryEvents ?? 0,
      currentStrategy: null,
    },
  }
}

describe('AgentHealthStatus', () => {
  it('healthy agent returns status healthy', () => {
    const health = makeHealth({})
    assert.equal(deriveHealthStatus(health), 'healthy')
  })

  it('expired passport returns status expired', () => {
    const health = makeHealth({ passportValid: false })
    assert.equal(deriveHealthStatus(health), 'expired')
  })

  it('agent with recent recovery events returns status degraded', () => {
    const health = makeHealth({ recentRecoveryEvents: 3 })
    assert.equal(deriveHealthStatus(health), 'degraded')
  })

  it('agent with high spend utilization returns status degraded', () => {
    const health = makeHealth({ spendUtilization: 0.98 })
    assert.equal(deriveHealthStatus(health), 'degraded')
  })

  it('agent with drift detected returns status suspended', () => {
    const health = makeHealth({ driftDetected: true })
    assert.equal(deriveHealthStatus(health), 'suspended')
  })

  it('expired passport takes priority over drift', () => {
    const health = makeHealth({ passportValid: false, driftDetected: true })
    assert.equal(deriveHealthStatus(health), 'expired')
  })

  it('drift takes priority over recovery degradation', () => {
    const health = makeHealth({ driftDetected: true, recentRecoveryEvents: 5 })
    assert.equal(deriveHealthStatus(health), 'suspended')
  })

  it('AgentHealthStatus type is structurally valid', () => {
    const full: AgentHealthStatus = {
      ...makeHealth({}),
      status: 'healthy',
    }
    assert.equal(full.status, 'healthy')
    assert.equal(full.passport.grade, 2)
    assert.equal(full.delegation.scopeCount, 3)
    assert.equal(full.recovery.currentStrategy, null)
  })
})
