// ══════════════════════════════════════════════════════════════════
// Obligations Model — Type Definitions (Module 20)
// ══════════════════════════════════════════════════════════════════
//
// Duties attached to delegations. What agents MUST do, by when,
// with what evidence, or face what consequence.
//
// Consensus of 3-model hostile review (Claude, GPT, Gemini).
// Spec: ~/aeoess_web/specs/OBLIGATIONS-MODEL-BRIEF.md
//
// Hard caps enforced:
//   - Max 10 obligations per delegation
//   - Min 5 minute grace period
//   - Min 1 hour recurrence interval
//   - Max 72 hour survival window
//   - cascade_revoke banned on obligations recurring > daily
//   - Penalty severity monotonically narrows with delegation depth
// ══════════════════════════════════════════════════════════════════

export type ObligationStatus =
  | 'pending'
  | 'fulfilled'
  | 'unfulfilled_no_evidence'
  | 'unfulfilled_tool_failure'
  | 'unfulfilled_blocked_by_policy'
  | 'terminated_by_revocation'
  | 'terminated_by_expiry'
  | 'waived_by_principal'

export type ObligationOutcome = ObligationStatus

export interface Obligation {
  obligationId: string
  delegationId: string
  obligorAgentId: string
  obligorPublicKey: string
  action: ObligationAction
  deadline: string               // ISO 8601 absolute
  evidence: EvidenceRequirement
  penalty: PenaltySpec
  status: ObligationStatus
  survivesTermination: boolean
  survivalWindow?: string        // ISO 8601 duration, max PT72H
  createdAt: string
  createdBy: string              // principal's public key
  signature: string              // signed by principal
}

export interface ObligationAction {
  type: string
  target?: string
  scope: string
  description: string
  minCount?: number
  recurring?: RecurrenceSpec
}

export interface RecurrenceSpec {
  frequency: 'once' | 'hourly' | 'daily' | 'weekly' | 'monthly'
  interval?: number
  until?: string
  timezone?: string
}

export interface EvidenceRequirement {
  type: 'action_receipt' | 'deliverable' | 'agora_post'
  matchCriteria: {
    toolMatch?: string
    scopeMatch?: string
    paramConstraints?: Record<string, ParamConstraint>
  }
}

export type ParamConstraint =
  | { equals: unknown }
  | { min?: number; max?: number; currency?: string }
  | { contains: string }
  | { oneOf: unknown[] }

export interface PenaltySpec {
  type: 'warning' | 'reputation_penalty' | 'revoke_delegation'
        | 'cascade_revoke' | 'escalate_to_principal'
  severity: 'warning' | 'minor' | 'major' | 'critical'
  reputationImpact?: number
  escalationTarget?: string
  gracePeriodMinutes: number
  autoExecute: boolean
}

export interface ObligationBundle {
  delegationId: string
  obligations: Obligation[]
  bundleSignature: string
  principalPublicKey: string
}

export interface FulfillmentReceipt {
  receiptId: string
  obligationId: string
  delegationId: string
  agentId: string
  fulfilledAt: string
  evidence: {
    actionReceiptId?: string
    deliverableId?: string
    agoraMessageId?: string
  }
  gatewayId: string
  gatewaySignature: string
}

export interface ObligationResolution {
  resolutionId: string
  obligationId: string
  delegationId: string
  agentId: string
  outcome: ObligationOutcome
  deadline: string
  detectedAt: string
  gatewayLatencyDelta?: number
  escalationPending?: boolean
  escalationId?: string
  attemptEvidence?: {
    failedReceiptId: string
    errorCode: string
    attemptedAt: string
  }
  penaltyApplied?: PenaltySpec
  penaltyExecuted: boolean
  gatewayId: string
  gatewaySignature: string
}
