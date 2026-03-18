// ══════════════════════════════════════════════════════════════════
// Obligation Monitor — Gateway Integration
// ══════════════════════════════════════════════════════════════════
//
// Plugs into the ProxyGateway to enforce obligations.
// Responsibilities:
//   1. Track active obligations per agent
//   2. Schedule deadline timers (event-driven, not polling)
//   3. Match incoming action receipts against obligation evidence
//   4. Produce FulfillmentReceipts on match
//   5. Produce ObligationResolutions on deadline expiry
//   6. Handle recurring obligation lazy instantiation
//   7. Enforce hard caps and penalty severity narrowing
//
// ══════════════════════════════════════════════════════════════════

import { createHash, randomBytes } from 'node:crypto'
import { sign } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type { ActionReceipt } from '../types/passport.js'
import type {
  Obligation, ObligationOutcome, ObligationResolution,
  FulfillmentReceipt, EvidenceRequirement, PenaltySpec,
  ParamConstraint
} from '../types/obligations.js'

export interface ObligationMonitorConfig {
  gatewayId: string
  gatewayPublicKey: string
  gatewayPrivateKey: string
  onFulfilled?: (receipt: FulfillmentReceipt) => void
  onResolved?: (resolution: ObligationResolution) => void
  onPenalty?: (obligation: Obligation, resolution: ObligationResolution) => void
  onRecurrenceCreated?: (obligation: Obligation) => void
}

export class ObligationMonitor {
  private config: ObligationMonitorConfig
  private activeObligations: Map<string, Obligation> = new Map()
  private agentObligations: Map<string, Set<string>> = new Map()
  private deadlineTimers: Map<string, ReturnType<typeof setTimeout>> = new Map()
  private failedAttempts: Map<string, Array<{ receiptId: string; errorCode: string; attemptedAt: string }>> = new Map()

  constructor(config: ObligationMonitorConfig) { this.config = config }

  registerObligation(obligation: Obligation): void {
    const agentOblIds = this.agentObligations.get(obligation.obligorAgentId) || new Set()
    let sameDelegationCount = 0
    for (const oblId of agentOblIds) {
      const existing = this.activeObligations.get(oblId)
      if (existing && existing.delegationId === obligation.delegationId) sameDelegationCount++
    }
    if (sameDelegationCount >= 10) throw new Error(`Obligation cap exceeded: delegation ${obligation.delegationId} already has 10 obligations`)
    this.activeObligations.set(obligation.obligationId, obligation)
    agentOblIds.add(obligation.obligationId)
    this.agentObligations.set(obligation.obligorAgentId, agentOblIds)
    this.scheduleDeadlineCheck(obligation)
  }

  private scheduleDeadlineCheck(obligation: Obligation): void {
    const deadline = new Date(obligation.deadline).getTime()
    const graceMs = (obligation.penalty.gracePeriodMinutes || 5) * 60 * 1000
    const delay = (deadline + graceMs) - Date.now()
    if (delay <= 0) { this.evaluateObligation(obligation.obligationId); return }
    const timer = setTimeout(() => this.evaluateObligation(obligation.obligationId), delay)
    this.deadlineTimers.set(obligation.obligationId, timer)
  }

  onReceiptProduced(agentId: string, receipt: ActionReceipt): FulfillmentReceipt | null {
    const oblIds = this.agentObligations.get(agentId)
    if (!oblIds) return null
    for (const oblId of oblIds) {
      const obligation = this.activeObligations.get(oblId)
      if (!obligation || obligation.status !== 'pending') continue
      if (this.matchEvidence(obligation.evidence, receipt)) return this.fulfillObligation(obligation, receipt)
    }
    return null
  }

  onToolFailure(agentId: string, toolName: string, errorCode: string): void {
    const oblIds = this.agentObligations.get(agentId)
    if (!oblIds) return
    for (const oblId of oblIds) {
      const obligation = this.activeObligations.get(oblId)
      if (!obligation || obligation.status !== 'pending') continue
      if (obligation.evidence.matchCriteria.toolMatch === toolName) {
        const attempts = this.failedAttempts.get(oblId) || []
        attempts.push({ receiptId: `failed-${randomBytes(6).toString('hex')}`, errorCode, attemptedAt: new Date().toISOString() })
        this.failedAttempts.set(oblId, attempts)
      }
    }
  }

  private matchEvidence(evidence: EvidenceRequirement, receipt: ActionReceipt): boolean {
    if (evidence.type !== 'action_receipt') return false
    const criteria = evidence.matchCriteria
    if (criteria.toolMatch && receipt.action.type !== criteria.toolMatch) return false
    if (criteria.scopeMatch && receipt.action.scopeUsed !== criteria.scopeMatch) return false
    if (criteria.paramConstraints) {
      const params = (receipt as any).params || {}
      for (const [key, constraint] of Object.entries(criteria.paramConstraints)) {
        if (!this.checkParamConstraint(params[key], constraint as ParamConstraint)) return false
      }
    }
    return true
  }

  private checkParamConstraint(value: unknown, constraint: ParamConstraint): boolean {
    if ('equals' in constraint) return value === constraint.equals
    if ('min' in constraint || 'max' in constraint) {
      const numVal = Number(value)
      if (isNaN(numVal)) return false
      if ('min' in constraint && constraint.min !== undefined && numVal < constraint.min) return false
      if ('max' in constraint && constraint.max !== undefined && numVal > constraint.max) return false
      return true
    }
    if ('contains' in constraint) return typeof value === 'string' && value.includes(constraint.contains)
    if ('oneOf' in constraint) return constraint.oneOf.includes(value)
    return false
  }

  private fulfillObligation(obligation: Obligation, receipt: ActionReceipt): FulfillmentReceipt {
    const timer = this.deadlineTimers.get(obligation.obligationId)
    if (timer) clearTimeout(timer)
    this.deadlineTimers.delete(obligation.obligationId)
    obligation.status = 'fulfilled'
    const fr: Omit<FulfillmentReceipt, 'gatewaySignature'> = {
      receiptId: `fr-${randomBytes(8).toString('hex')}`, obligationId: obligation.obligationId,
      delegationId: obligation.delegationId, agentId: obligation.obligorAgentId,
      fulfilledAt: new Date().toISOString(), evidence: { actionReceiptId: receipt.receiptId }, gatewayId: this.config.gatewayId
    }
    const gatewaySignature = sign(canonicalize(fr), this.config.gatewayPrivateKey)
    const fulfillmentReceipt: FulfillmentReceipt = { ...fr, gatewaySignature }
    this.removeObligation(obligation.obligationId, obligation.obligorAgentId)
    this.config.onFulfilled?.(fulfillmentReceipt)
    this.handleRecurrence(obligation, 'fulfilled')
    return fulfillmentReceipt
  }

  private evaluateObligation(obligationId: string): void {
    const obligation = this.activeObligations.get(obligationId)
    if (!obligation || obligation.status !== 'pending') return
    const failedAttempts = this.failedAttempts.get(obligationId)
    let outcome: ObligationOutcome = 'unfulfilled_no_evidence'
    if (failedAttempts && failedAttempts.length > 0) outcome = 'unfulfilled_tool_failure'
    const resolution = this.createResolution(obligation, outcome, failedAttempts)
    const shouldAutoExecute = outcome === 'unfulfilled_no_evidence' && obligation.penalty.autoExecute && !resolution.escalationPending
    resolution.penaltyExecuted = shouldAutoExecute
    if (shouldAutoExecute) resolution.penaltyApplied = obligation.penalty
    obligation.status = outcome as any
    this.removeObligation(obligationId, obligation.obligorAgentId)
    this.config.onResolved?.(resolution)
    if (shouldAutoExecute) this.config.onPenalty?.(obligation, resolution)
    this.handleRecurrence(obligation, outcome)
  }

  terminateByRevocation(delegationId: string): ObligationResolution[] {
    const resolutions: ObligationResolution[] = []
    for (const [oblId, obligation] of this.activeObligations) {
      if (obligation.delegationId !== delegationId) continue
      if (obligation.status !== 'pending') continue
      if (obligation.survivesTermination) continue
      const resolution = this.createResolution(obligation, 'terminated_by_revocation')
      obligation.status = 'terminated_by_revocation' as any
      const timer = this.deadlineTimers.get(oblId)
      if (timer) clearTimeout(timer)
      this.deadlineTimers.delete(oblId)
      this.removeObligation(oblId, obligation.obligorAgentId)
      this.config.onResolved?.(resolution)
      resolutions.push(resolution)
    }
    return resolutions
  }

  private createResolution(
    obligation: Obligation, outcome: ObligationOutcome,
    failedAttempts?: Array<{ receiptId: string; errorCode: string; attemptedAt: string }>
  ): ObligationResolution {
    const now = new Date()
    const deadlineTime = new Date(obligation.deadline).getTime()
    const latencyDelta = now.getTime() - deadlineTime
    const res: Omit<ObligationResolution, 'gatewaySignature'> = {
      resolutionId: `ores-${randomBytes(8).toString('hex')}`, obligationId: obligation.obligationId,
      delegationId: obligation.delegationId, agentId: obligation.obligorAgentId, outcome,
      deadline: obligation.deadline, detectedAt: now.toISOString(),
      gatewayLatencyDelta: latencyDelta > 0 ? latencyDelta : undefined,
      escalationPending: false, penaltyExecuted: false, gatewayId: this.config.gatewayId
    }
    if (failedAttempts && failedAttempts.length > 0) {
      res.attemptEvidence = { failedReceiptId: failedAttempts[0].receiptId, errorCode: failedAttempts[0].errorCode, attemptedAt: failedAttempts[0].attemptedAt }
    }
    const gatewaySignature = sign(canonicalize(res), this.config.gatewayPrivateKey)
    return { ...res, gatewaySignature }
  }

  private handleRecurrence(obligation: Obligation, outcome: ObligationOutcome): void {
    if (!obligation.action.recurring) return
    if (obligation.action.recurring.frequency === 'once') return
    if (obligation.action.recurring.until && new Date(obligation.action.recurring.until) < new Date()) return
    const nextDeadline = this.computeNextDeadline(obligation)
    if (!nextDeadline) return
    const nextObligation: Obligation = {
      ...obligation, obligationId: `obl-${randomBytes(8).toString('hex')}`,
      deadline: nextDeadline, status: 'pending', createdAt: new Date().toISOString()
    }
    this.registerObligation(nextObligation)
    this.config.onRecurrenceCreated?.(nextObligation)
  }

  private computeNextDeadline(obligation: Obligation): string | null {
    const current = new Date(obligation.deadline)
    const rec = obligation.action.recurring!
    const interval = rec.interval || 1
    switch (rec.frequency) {
      case 'hourly': current.setHours(current.getHours() + interval); break
      case 'daily': current.setDate(current.getDate() + interval); break
      case 'weekly': current.setDate(current.getDate() + (7 * interval)); break
      case 'monthly': current.setMonth(current.getMonth() + interval); break
      default: return null
    }
    return current.toISOString()
  }

  private removeObligation(obligationId: string, agentId: string): void {
    this.activeObligations.delete(obligationId)
    this.failedAttempts.delete(obligationId)
    const agentOblIds = this.agentObligations.get(agentId)
    if (agentOblIds) {
      agentOblIds.delete(obligationId)
      if (agentOblIds.size === 0) this.agentObligations.delete(agentId)
    }
  }

  getStats() {
    return {
      activeObligations: this.activeObligations.size,
      agentsWithObligations: this.agentObligations.size,
      pendingTimers: this.deadlineTimers.size
    }
  }

  shutdown(): void {
    for (const timer of this.deadlineTimers.values()) clearTimeout(timer)
    this.deadlineTimers.clear()
  }
}
