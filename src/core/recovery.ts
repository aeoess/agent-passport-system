// ══════════════════════════════════════════════════════════════════
// Recovery Engine — Evaluate and execute recovery policies
// ══════════════════════════════════════════════════════════════════

import { randomBytes } from 'crypto'
import type {
  RecoveryPolicy,
  RecoveryRule,
  RecoveryEvent,
  RecoveryStrategy,
  RecoveryTrigger,
} from '../types/recovery.js'

/**
 * Evaluate a recovery policy against a failure and return the
 * matching rule and strategy.
 */
export function evaluateRecovery(opts: {
  policy: RecoveryPolicy
  failureType: RecoveryTrigger['failureType']
  consecutiveFailures?: number
  totalAttempts?: number
}): {
  strategy: RecoveryStrategy
  rule: RecoveryRule | null
  hardStop: boolean
  reason: string
} {
  const { policy, failureType, consecutiveFailures = 1, totalAttempts = 0 } = opts

  // Hard stop check
  if (totalAttempts >= policy.maxTotalAttempts) {
    return {
      strategy: 'terminate',
      rule: null,
      hardStop: true,
      reason: `Max total attempts (${policy.maxTotalAttempts}) exceeded`,
    }
  }

  // Sort rules by priority
  const sorted = [...policy.rules].sort(
    (a, b) => (a.priority ?? 100) - (b.priority ?? 100)
  )

  // Find first matching rule
  for (const rule of sorted) {
    if (rule.trigger.failureType !== failureType && rule.trigger.failureType !== 'unknown') {
      continue
    }

    if (
      rule.trigger.afterConsecutiveFailures &&
      consecutiveFailures < rule.trigger.afterConsecutiveFailures
    ) {
      continue
    }

    // Check retry limit
    if (rule.maxRetries && consecutiveFailures > rule.maxRetries) {
      continue // exhausted, fall through to next rule
    }

    return {
      strategy: rule.strategy,
      rule,
      hardStop: false,
      reason: `Matched rule: ${rule.name}`,
    }
  }

  return {
    strategy: policy.defaultStrategy,
    rule: null,
    hardStop: false,
    reason: 'No rule matched, using default strategy',
  }
}

/**
 * Create a signed recovery event for the audit trail.
 */
export function createRecoveryEvent(opts: {
  agentId: string
  delegationId: string
  failedAction: string
  failureType: RecoveryTrigger['failureType']
  failureDetail: string
  matchedRule: string
  strategyApplied: RecoveryStrategy
  attemptNumber: number
  recoverySucceeded: boolean
  recoveryReceiptId?: string
}): RecoveryEvent {
  return {
    eventId: `recovery-${randomBytes(8).toString('hex')}`,
    timestamp: new Date().toISOString(),
    ...opts,
  }
}

/**
 * Create a default recovery policy suitable for most agent deployments.
 * Conservative: escalates to human early, terminates on repeated failures.
 */
export function createDefaultRecoveryPolicy(opts?: {
  policyId?: string
  maxTotalAttempts?: number
}): RecoveryPolicy {
  return {
    policyId: opts?.policyId || `rpol-${randomBytes(4).toString('hex')}`,
    version: '1.0.0',
    maxTotalAttempts: opts?.maxTotalAttempts || 10,
    auditRecoveryActions: true,
    defaultStrategy: 'escalate_human',
    rules: [
      {
        name: 'retry-rate-limit',
        trigger: { failureType: 'rate_limited' },
        strategy: 'retry_backoff',
        maxRetries: 3,
        initialBackoffMs: 1000,
        priority: 10,
      },
      {
        name: 'retry-tool-timeout',
        trigger: { failureType: 'tool_timeout' },
        strategy: 'retry_backoff',
        maxRetries: 2,
        initialBackoffMs: 2000,
        priority: 20,
      },
      {
        name: 'degrade-on-scope-denial',
        trigger: { failureType: 'scope_denied' },
        strategy: 'degrade_scope',
        priority: 30,
      },
      {
        name: 'escalate-budget-exceeded',
        trigger: { failureType: 'budget_exceeded' },
        strategy: 'escalate_human',
        escalationMessage: 'Agent budget exhausted. Approve additional spend or terminate.',
        priority: 40,
      },
      {
        name: 'escalate-human-denied',
        trigger: { failureType: 'human_denied' },
        strategy: 'terminate',
        priority: 50,
      },
      {
        name: 'quarantine-behavioral-drift',
        trigger: { failureType: 'behavioral_drift' },
        strategy: 'quarantine',
        priority: 5, // high priority — drift is serious
      },
      {
        name: 'terminate-revoked-delegation',
        trigger: { failureType: 'delegation_revoked' },
        strategy: 'terminate',
        priority: 1, // highest priority — revocation is absolute
      },
      {
        name: 'terminate-repeated-tool-errors',
        trigger: { failureType: 'tool_error', afterConsecutiveFailures: 3 },
        strategy: 'escalate_human',
        escalationMessage: 'Tool failed 3 consecutive times. Manual intervention needed.',
        priority: 60,
      },
    ],
  }
}
