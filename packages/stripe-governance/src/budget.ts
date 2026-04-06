// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

import type { GovernedStripeConfig, AgentBudgetStatus } from './types.js'

/**
 * Returns the current spend state for an agent's commerce delegation.
 * Useful for financial observability dashboards.
 */
export function getAgentBudgetStatus(config: GovernedStripeConfig): AgentBudgetStatus {
  const spent = config.delegation.spentAmount
  const limit = config.delegation.spendLimit
  const remaining = limit - spent
  const utilization = limit > 0 ? spent / limit : 0

  return {
    agentId: config.passport.passport.agentId,
    delegationId: config.delegation.delegationId,
    currency: config.delegation.currency,
    spendLimit: limit / 100,
    spentAmount: spent / 100,
    remainingBudget: remaining / 100,
    utilizationPercent: Math.round(utilization * 10000) / 100,
    humanApprovalThreshold: config.delegation.humanApprovalThreshold
      ? config.delegation.humanApprovalThreshold / 100
      : null,
    approvedMerchants: config.delegation.approvedMerchants || 'any',
  }
}
