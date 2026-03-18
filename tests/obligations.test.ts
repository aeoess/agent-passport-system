import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import {
  createObligation, createObligationBundle, acceptObligationBundle,
  checkFulfillment, resolveObligation, createFulfillmentReceipt,
  scheduleNextRecurrence, validateObligationConstraints, validatePenaltySeverity
} from '../src/core/obligations.js'
import type {
  Obligation, ObligationAction, EvidenceRequirement, PenaltySpec,
  RecurrenceSpec, ObligationBundle, FulfillmentReceipt,
  ObligationResolution, ObligationOutcome, ParamConstraint
} from '../src/types/obligations.js'

let principal: { publicKey: string; privateKey: string }
let agent: { publicKey: string; privateKey: string }
let gateway: { publicKey: string; privateKey: string }

describe('Obligations Model', () => {
  beforeEach(() => {
    principal = generateKeyPair()
    agent = generateKeyPair()
    gateway = generateKeyPair()
  })

  describe('Creation and Validation', () => {
    it('creates a valid obligation with all required fields', () => {
      const obligation = createObligation({
        delegationId: 'del-001', obligorAgentId: 'agent-001', obligorPublicKey: agent.publicKey,
        action: { type: 'email:send', scope: 'reporting:weekly', description: 'Send weekly status report' },
        deadline: new Date(Date.now() + 86400000).toISOString(),
        evidence: { type: 'action_receipt', matchCriteria: { toolMatch: 'email:send', scopeMatch: 'reporting:weekly' } },
        penalty: { type: 'escalate_to_principal', severity: 'minor', gracePeriodMinutes: 10, autoExecute: false },
        principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey
      })
      assert.ok(obligation.obligationId)
      assert.equal(obligation.delegationId, 'del-001')
      assert.equal(obligation.status, 'pending')
      assert.equal(obligation.survivesTermination, false)
      assert.ok(obligation.signature)
    })

    it('rejects more than 10 obligations per delegation', () => {
      const obligations = Array.from({ length: 11 }, (_, i) => createObligation({
        delegationId: 'del-001', obligorAgentId: 'agent-001', obligorPublicKey: agent.publicKey,
        action: { type: `task:action-${i}`, scope: `task:scope-${i}`, description: `Obligation ${i}` },
        deadline: new Date(Date.now() + 86400000).toISOString(),
        evidence: { type: 'action_receipt', matchCriteria: { toolMatch: `task:action-${i}` } },
        penalty: { type: 'warning', severity: 'warning', gracePeriodMinutes: 5, autoExecute: false },
        principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey
      }))
      const result = validateObligationConstraints(obligations)
      assert.equal(result.valid, false)
      assert.ok(result.errors.some(e => e.includes('10')))
    })

    it('rejects grace period under 5 minutes', () => {
      const obligation = createObligation({
        delegationId: 'del-001', obligorAgentId: 'agent-001', obligorPublicKey: agent.publicKey,
        action: { type: 'ping:send', scope: 'monitoring:heartbeat', description: 'Heartbeat' },
        deadline: new Date(Date.now() + 86400000).toISOString(),
        evidence: { type: 'action_receipt', matchCriteria: { toolMatch: 'ping:send' } },
        penalty: { type: 'revoke_delegation', severity: 'major', gracePeriodMinutes: 2, autoExecute: true },
        principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey
      })
      const result = validateObligationConstraints([obligation])
      assert.equal(result.valid, false)
      assert.ok(result.errors.some(e => e.includes('grace')))
    })

    it('rejects recurrence interval under 1 hour', () => {
      const obligation = createObligation({
        delegationId: 'del-001', obligorAgentId: 'agent-001', obligorPublicKey: agent.publicKey,
        action: { type: 'ping:send', scope: 'monitoring:heartbeat', description: 'Frequent heartbeat',
          recurring: { frequency: 'hourly', interval: 0.5 } },
        deadline: new Date(Date.now() + 3600000).toISOString(),
        evidence: { type: 'action_receipt', matchCriteria: { toolMatch: 'ping:send' } },
        penalty: { type: 'warning', severity: 'warning', gracePeriodMinutes: 5, autoExecute: false },
        principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey
      })
      const result = validateObligationConstraints([obligation])
      assert.equal(result.valid, false)
      assert.ok(result.errors.some(e => e.includes('recurrence') || e.includes('interval')))
    })
  })

  describe('Bundle Acceptance', () => {
    it('agent accepts full delegation + obligations bundle', () => {
      const obligation = createObligation({
        delegationId: 'del-001', obligorAgentId: 'agent-001', obligorPublicKey: agent.publicKey,
        action: { type: 'report:generate', scope: 'reporting:monthly', description: 'Monthly report' },
        deadline: new Date(Date.now() + 86400000 * 30).toISOString(),
        evidence: { type: 'action_receipt', matchCriteria: { toolMatch: 'report:generate' } },
        penalty: { type: 'escalate_to_principal', severity: 'minor', gracePeriodMinutes: 60, autoExecute: false },
        principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey
      })
      const bundle = createObligationBundle({ delegationId: 'del-001', obligations: [obligation], principalPublicKey: principal.publicKey, principalPrivateKey: principal.privateKey })
      const accepted = acceptObligationBundle({ bundle, agentId: 'agent-001', agentPrivateKey: agent.privateKey, agentPublicKey: agent.publicKey })
      assert.ok(accepted.accepted)
      assert.ok(accepted.acceptanceSignature)
      assert.equal(accepted.obligations.length, 1)
    })

    it('acceptance signature covers all obligations', () => {
      const makeObl = (type: string, scope: string, desc: string) => createObligation({
        delegationId: 'del-001', obligorAgentId: 'agent-001', obligorPublicKey: agent.publicKey,
        action: { type, scope, description: desc },
        deadline: new Date(Date.now() + 86400000).toISOString(),
        evidence: { type: 'action_receipt', matchCriteria: { toolMatch: type } },
        penalty: { type: 'warning', severity: 'warning', gracePeriodMinutes: 10, autoExecute: false },
        principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey
      })
      const bundle = createObligationBundle({ delegationId: 'del-001', obligations: [makeObl('task:a','scope:a','A'), makeObl('task:b','scope:b','B')], principalPublicKey: principal.publicKey, principalPrivateKey: principal.privateKey })
      const accepted = acceptObligationBundle({ bundle, agentId: 'agent-001', agentPrivateKey: agent.privateKey, agentPublicKey: agent.publicKey })
      assert.equal(accepted.obligations.length, 2)
      assert.ok(accepted.acceptanceSignature)
    })
  })

  describe('Evidence Matching', () => {
    it('matches a simple tool receipt', () => {
      const evidence: EvidenceRequirement = { type: 'action_receipt', matchCriteria: { toolMatch: 'email:send', scopeMatch: 'reporting:weekly' } }
      const receipt = { receiptId: 'rcpt-001', action: { type: 'email:send', scopeUsed: 'reporting:weekly' }, timestamp: new Date().toISOString() }
      const result = checkFulfillment(evidence, [receipt])
      assert.equal(result.fulfilled, true)
      assert.equal(result.matchingReceiptId, 'rcpt-001')
    })

    it('matches with parameterized constraints', () => {
      const evidence: EvidenceRequirement = { type: 'action_receipt', matchCriteria: { toolMatch: 'refund:process', paramConstraints: { 'amount': { min: 450, max: 550 }, 'customerId': { equals: 'cust-12345' } } } }
      const receipt = { receiptId: 'rcpt-good', action: { type: 'refund:process', scopeUsed: 'commerce:refund' }, params: { amount: 500, customerId: 'cust-12345' }, timestamp: new Date().toISOString() }
      assert.equal(checkFulfillment(evidence, [receipt]).fulfilled, true)
    })

    it('REJECTS malicious compliance ($0.01 refund)', () => {
      const evidence: EvidenceRequirement = { type: 'action_receipt', matchCriteria: { toolMatch: 'refund:process', paramConstraints: { 'amount': { min: 450, max: 550 } } } }
      const bad = { receiptId: 'rcpt-bad', action: { type: 'refund:process', scopeUsed: 'commerce:refund' }, params: { amount: 0.01 }, timestamp: new Date().toISOString() }
      assert.equal(checkFulfillment(evidence, [bad]).fulfilled, false)
    })

    it('no matching receipt means unfulfilled', () => {
      const evidence: EvidenceRequirement = { type: 'action_receipt', matchCriteria: { toolMatch: 'email:send' } }
      const wrong = { receiptId: 'rcpt-wrong', action: { type: 'data:read', scopeUsed: 'data:read' }, timestamp: new Date().toISOString() }
      assert.equal(checkFulfillment(evidence, [wrong]).fulfilled, false)
    })
  })

  describe('Resolution Lifecycle', () => {
    it('resolves fulfilled obligation with receipt', () => {
      const obligation = createObligation({
        delegationId: 'del-001', obligorAgentId: 'agent-001', obligorPublicKey: agent.publicKey,
        action: { type: 'email:send', scope: 'reporting:weekly', description: 'Weekly report' },
        deadline: new Date(Date.now() + 86400000).toISOString(),
        evidence: { type: 'action_receipt', matchCriteria: { toolMatch: 'email:send' } },
        penalty: { type: 'warning', severity: 'warning', gracePeriodMinutes: 5, autoExecute: false },
        principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey
      })
      const resolution = resolveObligation({ obligation, receipts: [{ receiptId: 'rcpt-001', action: { type: 'email:send', scopeUsed: 'reporting:weekly' }, timestamp: new Date().toISOString() }], gatewayId: 'gw-001', gatewayPrivateKey: gateway.privateKey })
      assert.equal(resolution.outcome, 'fulfilled')
      assert.ok(resolution.gatewaySignature)
    })

    it('resolves unfulfilled_no_evidence when no receipts match', () => {
      const obligation = createObligation({
        delegationId: 'del-001', obligorAgentId: 'agent-001', obligorPublicKey: agent.publicKey,
        action: { type: 'email:send', scope: 'reporting:weekly', description: 'Weekly report' },
        deadline: new Date(Date.now() - 600000).toISOString(),
        evidence: { type: 'action_receipt', matchCriteria: { toolMatch: 'email:send' } },
        penalty: { type: 'escalate_to_principal', severity: 'minor', gracePeriodMinutes: 5, autoExecute: false },
        principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey
      })
      const resolution = resolveObligation({ obligation, receipts: [], gatewayId: 'gw-001', gatewayPrivateKey: gateway.privateKey })
      assert.equal(resolution.outcome, 'unfulfilled_no_evidence')
      assert.equal(resolution.penaltyExecuted, false)
    })

    it('auto-executes penalty ONLY on unfulfilled_no_evidence', () => {
      const obligation = createObligation({
        delegationId: 'del-001', obligorAgentId: 'agent-001', obligorPublicKey: agent.publicKey,
        action: { type: 'email:send', scope: 'reporting:weekly', description: 'Weekly report' },
        deadline: new Date(Date.now() - 600000).toISOString(),
        evidence: { type: 'action_receipt', matchCriteria: { toolMatch: 'email:send' } },
        penalty: { type: 'reputation_penalty', severity: 'minor', reputationImpact: -0.1, gracePeriodMinutes: 5, autoExecute: true },
        principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey
      })
      const resolution = resolveObligation({ obligation, receipts: [], gatewayId: 'gw-001', gatewayPrivateKey: gateway.privateKey })
      assert.equal(resolution.outcome, 'unfulfilled_no_evidence')
      assert.equal(resolution.penaltyExecuted, true)
    })

    it('does NOT auto-execute on unfulfilled_tool_failure', () => {
      const obligation = createObligation({
        delegationId: 'del-001', obligorAgentId: 'agent-001', obligorPublicKey: agent.publicKey,
        action: { type: 'email:send', scope: 'reporting:weekly', description: 'Weekly report' },
        deadline: new Date(Date.now() - 600000).toISOString(),
        evidence: { type: 'action_receipt', matchCriteria: { toolMatch: 'email:send' } },
        penalty: { type: 'reputation_penalty', severity: 'minor', gracePeriodMinutes: 5, autoExecute: true },
        principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey
      })
      const failedReceipts = [{ receiptId: 'rcpt-failed', action: { type: 'email:send', scopeUsed: 'reporting:weekly' }, timestamp: new Date().toISOString(), toolError: 'SMTP server returned 500' }]
      const resolution = resolveObligation({ obligation, receipts: [], failedReceipts, gatewayId: 'gw-001', gatewayPrivateKey: gateway.privateKey })
      assert.equal(resolution.outcome, 'unfulfilled_tool_failure')
      assert.equal(resolution.penaltyExecuted, false)
      assert.ok(resolution.attemptEvidence)
    })
  })

  describe('Recurring Obligations', () => {
    it('creates next instance after fulfillment (lazy instantiation)', () => {
      const obligation = createObligation({
        delegationId: 'del-001', obligorAgentId: 'agent-001', obligorPublicKey: agent.publicKey,
        action: { type: 'report:generate', scope: 'reporting:daily', description: 'Daily status report', recurring: { frequency: 'daily', interval: 1 } },
        deadline: new Date(Date.now() + 86400000).toISOString(),
        evidence: { type: 'action_receipt', matchCriteria: { toolMatch: 'report:generate' } },
        penalty: { type: 'warning', severity: 'warning', gracePeriodMinutes: 30, autoExecute: false },
        principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey
      })
      const nextInstance = scheduleNextRecurrence({ obligation, previousOutcome: 'fulfilled', principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey })
      assert.ok(nextInstance)
      assert.notEqual(nextInstance!.obligationId, obligation.obligationId)
      assert.equal(nextInstance!.delegationId, obligation.delegationId)
      assert.ok(new Date(nextInstance!.deadline).getTime() > new Date(obligation.deadline).getTime())
    })

    it('returns null for non-recurring obligations', () => {
      const obligation = createObligation({
        delegationId: 'del-001', obligorAgentId: 'agent-001', obligorPublicKey: agent.publicKey,
        action: { type: 'report:generate', scope: 'reporting:once', description: 'One-time report' },
        deadline: new Date(Date.now() + 86400000).toISOString(),
        evidence: { type: 'action_receipt', matchCriteria: { toolMatch: 'report:generate' } },
        penalty: { type: 'warning', severity: 'warning', gracePeriodMinutes: 5, autoExecute: false },
        principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey
      })
      assert.equal(scheduleNextRecurrence({ obligation, previousOutcome: 'fulfilled', principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey }), null)
    })
  })

  describe('Penalty Severity Narrowing', () => {
    it('allows equal severity in sub-delegation', () => {
      const p: PenaltySpec = { type: 'revoke_delegation', severity: 'major', gracePeriodMinutes: 10, autoExecute: true }
      assert.equal(validatePenaltySeverity(p, p).valid, true)
    })

    it('allows less severe penalty in sub-delegation', () => {
      const parent: PenaltySpec = { type: 'revoke_delegation', severity: 'major', gracePeriodMinutes: 10, autoExecute: true }
      const child: PenaltySpec = { type: 'reputation_penalty', severity: 'minor', gracePeriodMinutes: 10, autoExecute: false }
      assert.equal(validatePenaltySeverity(parent, child).valid, true)
    })

    it('REJECTS more severe penalty in sub-delegation', () => {
      const parent: PenaltySpec = { type: 'revoke_delegation', severity: 'major', gracePeriodMinutes: 10, autoExecute: true }
      const child: PenaltySpec = { type: 'cascade_revoke', severity: 'critical', gracePeriodMinutes: 10, autoExecute: true }
      const result = validatePenaltySeverity(parent, child)
      assert.equal(result.valid, false)
      assert.ok(result.error?.includes('narrowing') || result.error?.includes('severe'))
    })

    it('REJECTS cascade_revoke on obligations recurring more than daily', () => {
      const obligation = createObligation({
        delegationId: 'del-001', obligorAgentId: 'agent-001', obligorPublicKey: agent.publicKey,
        action: { type: 'ping:send', scope: 'monitoring:heartbeat', description: 'Hourly heartbeat', recurring: { frequency: 'hourly', interval: 2 } },
        deadline: new Date(Date.now() + 7200000).toISOString(),
        evidence: { type: 'action_receipt', matchCriteria: { toolMatch: 'ping:send' } },
        penalty: { type: 'cascade_revoke', severity: 'critical', gracePeriodMinutes: 10, autoExecute: true },
        principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey
      })
      const result = validateObligationConstraints([obligation])
      assert.equal(result.valid, false)
      assert.ok(result.errors.some(e => e.includes('cascade') || e.includes('recurring')))
    })
  })

  describe('Delegation Interaction', () => {
    it('revocation terminates obligations (not breach)', () => {
      const obligation = createObligation({
        delegationId: 'del-001', obligorAgentId: 'agent-001', obligorPublicKey: agent.publicKey,
        action: { type: 'email:send', scope: 'reporting:weekly', description: 'Report' },
        deadline: new Date(Date.now() + 86400000).toISOString(),
        evidence: { type: 'action_receipt', matchCriteria: { toolMatch: 'email:send' } },
        penalty: { type: 'revoke_delegation', severity: 'major', gracePeriodMinutes: 5, autoExecute: true },
        principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey
      })
      const resolution = resolveObligation({ obligation, receipts: [], delegationRevoked: true, gatewayId: 'gw-001', gatewayPrivateKey: gateway.privateKey })
      assert.equal(resolution.outcome, 'terminated_by_revocation')
      assert.equal(resolution.penaltyExecuted, false)
    })

    it('survives termination when explicitly flagged', () => {
      const obligation = createObligation({
        delegationId: 'del-001', obligorAgentId: 'agent-001', obligorPublicKey: agent.publicKey,
        action: { type: 'report:final', scope: 'reporting:handoff', description: 'Final handoff report' },
        deadline: new Date(Date.now() + 86400000).toISOString(),
        evidence: { type: 'action_receipt', matchCriteria: { toolMatch: 'report:final' } },
        penalty: { type: 'escalate_to_principal', severity: 'minor', gracePeriodMinutes: 60, autoExecute: false },
        survivesTermination: true, survivalWindow: 'PT72H',
        principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey
      })
      assert.equal(obligation.survivesTermination, true)
      assert.equal(obligation.survivalWindow, 'PT72H')
      const resolution = resolveObligation({ obligation, receipts: [], delegationRevoked: true, gatewayId: 'gw-001', gatewayPrivateKey: gateway.privateKey })
      assert.notEqual(resolution.outcome, 'terminated_by_revocation')
    })
  })

  describe('Adversarial Scenarios', () => {
    it('obligation spam: 11 obligations rejected at bundle level', () => {
      const obligations = Array.from({ length: 11 }, (_, i) => createObligation({
        delegationId: 'del-001', obligorAgentId: 'agent-001', obligorPublicKey: agent.publicKey,
        action: { type: `spam:action-${i}`, scope: `spam:${i}`, description: `Spam ${i}` },
        deadline: new Date(Date.now() + 86400000).toISOString(),
        evidence: { type: 'action_receipt', matchCriteria: { toolMatch: `spam:action-${i}` } },
        penalty: { type: 'warning', severity: 'warning', gracePeriodMinutes: 5, autoExecute: false },
        principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey
      }))
      assert.equal(validateObligationConstraints(obligations).valid, false)
    })

    it('escalation does not pause deadline — flag attached', () => {
      const obligation = createObligation({
        delegationId: 'del-001', obligorAgentId: 'agent-001', obligorPublicKey: agent.publicKey,
        action: { type: 'payment:process', scope: 'commerce:payment', description: 'Process payment' },
        deadline: new Date(Date.now() - 600000).toISOString(),
        evidence: { type: 'action_receipt', matchCriteria: { toolMatch: 'payment:process' } },
        penalty: { type: 'escalate_to_principal', severity: 'major', gracePeriodMinutes: 5, autoExecute: false },
        principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey
      })
      const resolution = resolveObligation({ obligation, receipts: [], escalationPending: true, escalationId: 'esc-001', gatewayId: 'gw-001', gatewayPrivateKey: gateway.privateKey })
      assert.equal(resolution.outcome, 'unfulfilled_no_evidence')
      assert.equal(resolution.escalationPending, true)
      assert.equal(resolution.escalationId, 'esc-001')
      assert.equal(resolution.penaltyExecuted, false)
    })

    it('penalty cascade breaks: revocation waives downstream obligations', () => {
      const childObligation = createObligation({
        delegationId: 'del-child', obligorAgentId: 'agent-002', obligorPublicKey: agent.publicKey,
        action: { type: 'report:send', scope: 'reporting:weekly', description: 'Child report' },
        deadline: new Date(Date.now() + 3600000).toISOString(),
        evidence: { type: 'action_receipt', matchCriteria: { toolMatch: 'report:send' } },
        penalty: { type: 'reputation_penalty', severity: 'minor', gracePeriodMinutes: 5, autoExecute: true },
        principalPrivateKey: principal.privateKey, principalPublicKey: principal.publicKey
      })
      const childResolution = resolveObligation({ obligation: childObligation, receipts: [], delegationRevoked: true, gatewayId: 'gw-001', gatewayPrivateKey: gateway.privateKey })
      assert.equal(childResolution.outcome, 'terminated_by_revocation')
      assert.equal(childResolution.penaltyExecuted, false)
    })
  })
})
