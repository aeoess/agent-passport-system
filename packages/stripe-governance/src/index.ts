// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// @aeoess/stripe-governance — APS governance layer for Stripe agent payments

export { governStripeTools, governMPPPayment } from './adapter.js'
export { getAgentBudgetStatus } from './budget.js'

export type {
  GovernedStripeConfig,
  PreflightDecision,
  MPPPaymentRequest,
  MPPPaymentResult,
  AgentBudgetStatus,
  StripeGovernanceReceipt,
  ACPMoney,
} from './types.js'
