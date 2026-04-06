// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

import type {
  SignedPassport,
  CommerceDelegation,
  CommercePreflightResult,
  HumanApprovalRequest,
  ACPMoney,
} from 'agent-passport-system'

/** Receipt emitted after a governed payment action */
export interface StripeGovernanceReceipt {
  receiptId: string
  agentId: string
  delegationId: string
  action: string
  amount: ACPMoney
  merchant?: string
  merchantName?: string
  timestamp: string
  stripeObjectId?: string | null
  preflightHash: string
  [key: string]: unknown
}

export interface GovernedStripeConfig {
  /** Agent's signed passport */
  passport: SignedPassport
  /** Commerce delegation from human principal */
  delegation: CommerceDelegation
  /** Callback when human approval is required (spend above threshold) */
  onHumanApprovalRequired?: (request: HumanApprovalRequest) => Promise<boolean>
  /** Callback for every commerce receipt (audit logging) */
  onReceipt?: (receipt: StripeGovernanceReceipt) => void
  /** If true, log all preflight results to console */
  verbose?: boolean
}

export interface PreflightDecision {
  permitted: boolean
  result: CommercePreflightResult
  remainingBudget: number
  requiresHumanApproval: boolean
}

export interface MPPPaymentRequest {
  amount: number
  currency: string
  merchant: string
  resource: string
  paymentMethod: 'x402' | 'spt' | 'card'
}

export interface MPPPaymentResult {
  authorized: boolean
  receipt?: StripeGovernanceReceipt
  error?: string
  remainingBudget: number
}

export interface AgentBudgetStatus {
  agentId: string
  delegationId: string
  currency: string
  spendLimit: number
  spentAmount: number
  remainingBudget: number
  utilizationPercent: number
  humanApprovalThreshold: number | null
  approvedMerchants: string[] | 'any'
}

export type { ACPMoney }
