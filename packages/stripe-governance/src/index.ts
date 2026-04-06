// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
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
