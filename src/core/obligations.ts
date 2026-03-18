// ══════════════════════════════════════════════════════════════════
// Obligations Model — Core Implementation (Module 20)
// ══════════════════════════════════════════════════════════════════
import { randomBytes } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import { scopeAuthorizes } from './delegation.js'
import type {
  Obligation, ObligationAction, EvidenceRequirement,
  PenaltySpec, RecurrenceSpec, ObligationBundle,
  FulfillmentReceipt, ObligationResolution, ObligationOutcome,
  ParamConstraint
} from '../types/obligations.js'

// Penalty severity ordering (for monotonic narrowing)
const PENALTY_SEVERITY_ORDER: Record<string, number> = {
  'warning': 0,
  'reputation_penalty': 1,
  'escalate_to_principal': 2,
  'revoke_delegation': 3,
  'cascade_revoke': 4
}

export function createObligation(opts: {
  delegationId: string
  obligorAgentId: string
  obligorPublicKey: string
  action: ObligationAction
  deadline: string
  evidence: EvidenceRequirement
  penalty: PenaltySpec
  survivesTermination?: boolean
  survivalWindow?: string
  principalPrivateKey: string
  principalPublicKey: string
}): Obligation {
  const obligation: Omit<Obligation, 'signature'> = {
    obligationId: `obl-${randomBytes(8).toString('hex')}`,
    delegationId: opts.delegationId,
    obligorAgentId: opts.obligorAgentId,
    obligorPublicKey: opts.obligorPublicKey,
    action: opts.action,
    deadline: opts.deadline,
    evidence: opts.evidence,
    penalty: opts.penalty,
    status: 'pending',
    survivesTermination: opts.survivesTermination ?? false,
    survivalWindow: opts.survivalWindow,
    createdAt: new Date().toISOString(),
    createdBy: opts.principalPublicKey
  }
  const canonical = canonicalize(obligation)
  const signature = sign(canonical, opts.principalPrivateKey)
  return { ...obligation, signature }
}

export function createObligationBundle(opts: {
  delegationId: string
  obligations: Obligation[]
  principalPublicKey: string
  principalPrivateKey: string
}): ObligationBundle {
  const payload = canonicalize({
    delegationId: opts.delegationId,
    obligationIds: opts.obligations.map(o => o.obligationId)
  })
  const bundleSignature = sign(payload, opts.principalPrivateKey)
  return {
    delegationId: opts.delegationId,
    obligations: opts.obligations,
    bundleSignature,
    principalPublicKey: opts.principalPublicKey
  }
}

export function acceptObligationBundle(opts: {
  bundle: ObligationBundle
  agentId: string
  agentPrivateKey: string
  agentPublicKey: string
}): { accepted: boolean; acceptanceSignature: string; obligations: Obligation[] } {
  const payload = canonicalize({
    delegationId: opts.bundle.delegationId,
    obligationIds: opts.bundle.obligations.map(o => o.obligationId),
    agentId: opts.agentId,
    acceptedAt: new Date().toISOString()
  })
  const acceptanceSignature = sign(payload, opts.agentPrivateKey)
  return {
    accepted: true,
    acceptanceSignature,
    obligations: opts.bundle.obligations
  }
}

export function checkFulfillment(
  evidence: EvidenceRequirement,
  receipts: Array<{
    receiptId: string
    action: { type: string; scopeUsed?: string }
    params?: Record<string, unknown>
    timestamp: string
    toolError?: string
  }>
): { fulfilled: boolean; matchingReceiptId?: string } {
  if (evidence.type !== 'action_receipt') return { fulfilled: false }
  const criteria = evidence.matchCriteria
  for (const receipt of receipts) {
    if (receipt.toolError) continue
    if (criteria.toolMatch && receipt.action.type !== criteria.toolMatch) continue
    if (criteria.scopeMatch && receipt.action.scopeUsed !== criteria.scopeMatch) continue
    if (criteria.paramConstraints) {
      const params = receipt.params || {}
      let allConstraintsMet = true
      for (const [key, constraint] of Object.entries(criteria.paramConstraints)) {
        if (!checkParamConstraint(params[key], constraint)) {
          allConstraintsMet = false
          break
        }
      }
      if (!allConstraintsMet) continue
    }
    return { fulfilled: true, matchingReceiptId: receipt.receiptId }
  }
  return { fulfilled: false }
}

function checkParamConstraint(value: unknown, constraint: ParamConstraint): boolean {
  if ('equals' in constraint) return value === (constraint as { equals: unknown }).equals
  if ('min' in constraint || 'max' in constraint) {
    const c = constraint as { min?: number; max?: number }
    const numVal = Number(value)
    if (isNaN(numVal)) return false
    if (c.min !== undefined && numVal < c.min) return false
    if (c.max !== undefined && numVal > c.max) return false
    return true
  }
  if ('contains' in constraint) return typeof value === 'string' && value.includes((constraint as { contains: string }).contains)
  if ('oneOf' in constraint) return (constraint as { oneOf: unknown[] }).oneOf.includes(value)
  return false
}

export function resolveObligation(opts: {
  obligation: Obligation
  receipts: Array<{
    receiptId: string
    action: { type: string; scopeUsed?: string }
    params?: Record<string, unknown>
    timestamp: string
    toolError?: string
  }>
  failedReceipts?: Array<{
    receiptId: string
    action: { type: string; scopeUsed?: string }
    timestamp: string
    toolError: string
  }>
  delegationRevoked?: boolean
  delegationExpired?: boolean
  escalationPending?: boolean
  escalationId?: string
  gatewayId: string
  gatewayPrivateKey: string
}): ObligationResolution {
  const { obligation } = opts
  const now = new Date()
  const deadlineTime = new Date(obligation.deadline).getTime()
  const latencyDelta = now.getTime() - deadlineTime

  let outcome: ObligationOutcome
  let penaltyExecuted = false
  let attemptEvidence: ObligationResolution['attemptEvidence'] | undefined

  if (opts.delegationRevoked && !obligation.survivesTermination) {
    outcome = 'terminated_by_revocation'
  } else if (opts.delegationExpired) {
    outcome = 'terminated_by_expiry'
  } else {
    const fulfillment = checkFulfillment(obligation.evidence, opts.receipts)
    if (fulfillment.fulfilled) {
      outcome = 'fulfilled'
    } else if (opts.failedReceipts && opts.failedReceipts.length > 0) {
      const matchingFailure = opts.failedReceipts.find(fr =>
        obligation.evidence.matchCriteria.toolMatch === fr.action.type
      )
      if (matchingFailure) {
        outcome = 'unfulfilled_tool_failure'
        attemptEvidence = {
          failedReceiptId: matchingFailure.receiptId,
          errorCode: matchingFailure.toolError,
          attemptedAt: matchingFailure.timestamp
        }
      } else {
        outcome = 'unfulfilled_no_evidence'
      }
    } else {
      outcome = 'unfulfilled_no_evidence'
    }
  }

  if (outcome === 'unfulfilled_no_evidence' && obligation.penalty.autoExecute && !opts.escalationPending) {
    penaltyExecuted = true
  }

  const resolution: Omit<ObligationResolution, 'gatewaySignature'> = {
    resolutionId: `ores-${randomBytes(8).toString('hex')}`,
    obligationId: obligation.obligationId,
    delegationId: obligation.delegationId,
    agentId: obligation.obligorAgentId,
    outcome,
    deadline: obligation.deadline,
    detectedAt: now.toISOString(),
    gatewayLatencyDelta: latencyDelta > 0 ? latencyDelta : undefined,
    escalationPending: opts.escalationPending || false,
    escalationId: opts.escalationId,
    attemptEvidence,
    penaltyApplied: penaltyExecuted ? obligation.penalty : undefined,
    penaltyExecuted,
    gatewayId: opts.gatewayId
  }
  const canonical = canonicalize(resolution)
  const gatewaySignature = sign(canonical, opts.gatewayPrivateKey)
  return { ...resolution, gatewaySignature }
}

export function createFulfillmentReceipt(opts: {
  obligation: Obligation
  matchingReceiptId: string
  gatewayId: string
  gatewayPrivateKey: string
}): FulfillmentReceipt {
  const fr: Omit<FulfillmentReceipt, 'gatewaySignature'> = {
    receiptId: `fr-${randomBytes(8).toString('hex')}`,
    obligationId: opts.obligation.obligationId,
    delegationId: opts.obligation.delegationId,
    agentId: opts.obligation.obligorAgentId,
    fulfilledAt: new Date().toISOString(),
    evidence: { actionReceiptId: opts.matchingReceiptId },
    gatewayId: opts.gatewayId
  }
  const canonical = canonicalize(fr)
  const gatewaySignature = sign(canonical, opts.gatewayPrivateKey)
  return { ...fr, gatewaySignature }
}

export function scheduleNextRecurrence(opts: {
  obligation: Obligation
  previousOutcome: ObligationOutcome
  principalPrivateKey: string
  principalPublicKey: string
}): Obligation | null {
  const rec = opts.obligation.action.recurring
  if (!rec || rec.frequency === 'once') return null
  if (rec.until && new Date(rec.until) < new Date()) return null

  const current = new Date(opts.obligation.deadline)
  const interval = rec.interval || 1
  switch (rec.frequency) {
    case 'hourly': current.setHours(current.getHours() + interval); break
    case 'daily': current.setDate(current.getDate() + interval); break
    case 'weekly': current.setDate(current.getDate() + (7 * interval)); break
    case 'monthly': current.setMonth(current.getMonth() + interval); break
    default: return null
  }
  return createObligation({
    delegationId: opts.obligation.delegationId,
    obligorAgentId: opts.obligation.obligorAgentId,
    obligorPublicKey: opts.obligation.obligorPublicKey,
    action: opts.obligation.action,
    deadline: current.toISOString(),
    evidence: opts.obligation.evidence,
    penalty: opts.obligation.penalty,
    survivesTermination: opts.obligation.survivesTermination,
    survivalWindow: opts.obligation.survivalWindow,
    principalPrivateKey: opts.principalPrivateKey,
    principalPublicKey: opts.principalPublicKey
  })
}

function getRecurrenceIntervalHours(rec: RecurrenceSpec): number {
  const interval = rec.interval || 1
  switch (rec.frequency) {
    case 'hourly': return interval
    case 'daily': return interval * 24
    case 'weekly': return interval * 24 * 7
    case 'monthly': return interval * 24 * 30
    default: return Infinity
  }
}

export function validateObligationConstraints(
  obligations: Obligation[],
  delegationScope?: string[]
): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  const byDelegation = new Map<string, number>()
  for (const o of obligations) {
    const count = (byDelegation.get(o.delegationId) || 0) + 1
    byDelegation.set(o.delegationId, count)
    if (count > 10) {
      errors.push(`Delegation ${o.delegationId} exceeds max 10 obligations (has ${count})`)
    }
  }
  for (const o of obligations) {
    // Scope validation: obligation action scope must be within delegation scope
    if (delegationScope && !scopeAuthorizes(delegationScope, o.action.scope)) {
      errors.push(`Obligation ${o.obligationId}: action scope "${o.action.scope}" is not within delegation scope [${delegationScope.join(', ')}]`)
    }
    if (o.penalty.gracePeriodMinutes < 5) {
      errors.push(`Obligation ${o.obligationId}: grace period ${o.penalty.gracePeriodMinutes}min is below 5min minimum`)
    }
    if (o.action.recurring && o.action.recurring.frequency !== 'once') {
      const intervalHours = getRecurrenceIntervalHours(o.action.recurring)
      if (intervalHours < 1) {
        errors.push(`Obligation ${o.obligationId}: recurrence interval ${intervalHours}h is below 1h minimum`)
      }
    }
    if (o.penalty.type === 'cascade_revoke' && o.action.recurring && o.action.recurring.frequency !== 'once') {
      const intervalHours = getRecurrenceIntervalHours(o.action.recurring)
      if (intervalHours < 24) {
        errors.push(`Obligation ${o.obligationId}: cascade_revoke is banned on recurring obligations with interval < 24h`)
      }
    }
  }
  return { valid: errors.length === 0, errors }
}

export function validatePenaltySeverity(
  parentPenalty: PenaltySpec,
  childPenalty: PenaltySpec
): { valid: boolean; error?: string } {
  const parentLevel = PENALTY_SEVERITY_ORDER[parentPenalty.type] ?? 0
  const childLevel = PENALTY_SEVERITY_ORDER[childPenalty.type] ?? 0
  if (childLevel > parentLevel) {
    return {
      valid: false,
      error: `Penalty severity narrowing violated: child penalty '${childPenalty.type}' (${childLevel}) is more severe than parent '${parentPenalty.type}' (${parentLevel})`
    }
  }
  return { valid: true }
}
