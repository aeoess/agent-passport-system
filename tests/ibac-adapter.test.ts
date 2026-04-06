// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Tests for IBAC Adapter — Intent-Based Access Control Bridge

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair,
  createPassport,
  createDelegation,
  verify,
  canonicalize,
  ibacIntentToScope,
  ibacTuplesToDelegation,
  evaluateIBACTuples,
  governIBACIntent,
  cedarPolicyToTuples,
  delegationToCedarPolicy,
} from '../src/index.js'
import type { IBACIntent, IBACTuple, ActionReceipt } from '../src/index.js'

// ── Helpers ──

const principalKeys = generateKeyPair()
const agentKeys = generateKeyPair()

const { signedPassport } = createPassport({
  agentId: 'agent-ibac-test-001',
  agentName: 'IBAC Test Agent',
  ownerAlias: 'tima',
  mission: 'IBAC adapter tests',
  capabilities: ['ibac'],
  runtime: { platform: 'node', version: process.version },
})

function makeDelegation(scopes: string[]) {
  return createDelegation({
    delegatedTo: agentKeys.publicKey,
    delegatedBy: principalKeys.publicKey,
    scope: scopes,
    privateKey: principalKeys.privateKey,
  })
}

// ── Intent → Scope mapping ──

describe('ibacIntentToScope', () => {
  it('maps read verb to data:read scope', () => {
    const intent: IBACIntent = {
      task: 'incident_report',
      subject: { id: 'agent-001' },
      actions: [{ verb: 'read', resource: 'table:logs' }],
      timestamp: new Date().toISOString(),
    }
    const scopes = ibacIntentToScope(intent)
    assert.deepStrictEqual(scopes, ['data:read:table:logs'])
  })

  it('maps write verb to data:write scope', () => {
    const intent: IBACIntent = {
      task: 'file_update',
      subject: { id: 'agent-001' },
      actions: [{ verb: 'write', resource: 'file:report.pdf' }],
      timestamp: new Date().toISOString(),
    }
    assert.deepStrictEqual(ibacIntentToScope(intent), ['data:write:file:report.pdf'])
  })

  it('maps send verb to comms:send scope', () => {
    const intent: IBACIntent = {
      task: 'notify_team',
      subject: { id: 'agent-001' },
      actions: [{ verb: 'send', resource: 'channel:slack' }],
      timestamp: new Date().toISOString(),
    }
    assert.deepStrictEqual(ibacIntentToScope(intent), ['comms:send:channel:slack'])
  })

  it('maps delete verb to admin:delete scope', () => {
    const intent: IBACIntent = {
      task: 'cleanup',
      subject: { id: 'agent-001' },
      actions: [{ verb: 'delete', resource: 'table:temp_logs' }],
      timestamp: new Date().toISOString(),
    }
    assert.deepStrictEqual(ibacIntentToScope(intent), ['admin:delete:table:temp_logs'])
  })

  it('maps query verb to data:read scope', () => {
    const intent: IBACIntent = {
      task: 'analytics',
      subject: { id: 'agent-001' },
      actions: [{ verb: 'query', resource: 'table:metrics' }],
      timestamp: new Date().toISOString(),
    }
    assert.deepStrictEqual(ibacIntentToScope(intent), ['data:read:table:metrics'])
  })

  it('returns empty array for empty intent', () => {
    const intent: IBACIntent = {
      task: 'noop',
      subject: { id: 'agent-001' },
      actions: [],
      timestamp: new Date().toISOString(),
    }
    assert.deepStrictEqual(ibacIntentToScope(intent), [])
  })

  it('maps multiple actions', () => {
    const intent: IBACIntent = {
      task: 'clinical_review',
      subject: { id: 'agent-nurse' },
      actions: [
        { verb: 'read', resource: 'table:patients' },
        { verb: 'write', resource: 'file:clinical_notes' },
        { verb: 'send', resource: 'channel:slack' },
      ],
      timestamp: new Date().toISOString(),
    }
    assert.deepStrictEqual(ibacIntentToScope(intent), [
      'data:read:table:patients',
      'data:write:file:clinical_notes',
      'comms:send:channel:slack',
    ])
  })
})

// ── Tuples → Delegation ──

describe('ibacTuplesToDelegation', () => {
  it('creates delegation from tuples', () => {
    const tuples: IBACTuple[] = [
      { principal: 'agent:agent-001', action: 'tool:read', resource: 'table:patients' },
      { principal: 'agent:agent-001', action: 'tool:write', resource: 'file:report.pdf' },
    ]
    const delegation = ibacTuplesToDelegation(tuples, principalKeys.publicKey, agentKeys.publicKey, principalKeys.privateKey)
    assert.ok(delegation.delegationId)
    assert.deepStrictEqual(delegation.scope, ['data:read:table:patients', 'data:write:file:report.pdf'])
    assert.ok(delegation.signature)
  })

  it('round-trip: tuples → delegation → evaluate same tuples → all authorized', () => {
    const tuples: IBACTuple[] = [
      { principal: 'agent:agent-001', action: 'tool:read', resource: 'table:logs' },
      { principal: 'agent:agent-001', action: 'tool:query', resource: 'table:events' },
    ]
    const delegation = ibacTuplesToDelegation(tuples, principalKeys.publicKey, agentKeys.publicKey, principalKeys.privateKey)
    const { tupleResults } = evaluateIBACTuples(tuples, delegation)
    assert.equal(tupleResults.length, 2)
    assert.ok(tupleResults.every(r => r.authorized))
  })

  it('respects expiresInHours option', () => {
    const tuples: IBACTuple[] = [
      { principal: 'agent:agent-001', action: 'tool:read', resource: 'table:logs' },
    ]
    const delegation = ibacTuplesToDelegation(tuples, principalKeys.publicKey, agentKeys.publicKey, principalKeys.privateKey, { expiresInHours: 1 })
    const expiresAt = new Date(delegation.expiresAt)
    const now = new Date()
    const diffHours = (expiresAt.getTime() - now.getTime()) / 3600000
    assert.ok(diffHours > 0.9 && diffHours < 1.1)
  })
})

// ── Evaluate tuples ──

describe('evaluateIBACTuples', () => {
  it('authorized tuple returns true', () => {
    const delegation = makeDelegation(['data:read:table:patients'])
    const tuples: IBACTuple[] = [
      { principal: 'agent:agent-001', action: 'tool:read', resource: 'table:patients' },
    ]
    const { tupleResults } = evaluateIBACTuples(tuples, delegation)
    assert.equal(tupleResults[0].authorized, true)
  })

  it('denied tuple (scope violation) returns false', () => {
    const delegation = makeDelegation(['data:read:table:logs'])
    const tuples: IBACTuple[] = [
      { principal: 'agent:agent-001', action: 'tool:write', resource: 'file:secret.pdf' },
    ]
    const { tupleResults } = evaluateIBACTuples(tuples, delegation)
    assert.equal(tupleResults[0].authorized, false)
    assert.ok(tupleResults[0].reason.includes('not covered'))
  })

  it('denied tuple (expired delegation)', () => {
    const delegation = makeDelegation(['data:read:table:logs'])
    // Manually expire
    delegation.expiresAt = new Date(Date.now() - 1000).toISOString()
    const tuples: IBACTuple[] = [
      { principal: 'agent:agent-001', action: 'tool:read', resource: 'table:logs' },
    ]
    const { tupleResults } = evaluateIBACTuples(tuples, delegation)
    assert.equal(tupleResults[0].authorized, false)
    assert.ok(tupleResults[0].reason.includes('expired'))
  })

  it('delete requires explicit admin scope', () => {
    const delegation = makeDelegation(['data:read:table:logs'])
    const tuples: IBACTuple[] = [
      { principal: 'agent:agent-001', action: 'tool:delete', resource: 'table:logs' },
    ]
    const { tupleResults } = evaluateIBACTuples(tuples, delegation)
    assert.equal(tupleResults[0].authorized, false)
    assert.equal(tupleResults[0].scope, 'admin:delete:table:logs')
  })

  it('mixed authorized/denied in single evaluation', () => {
    const delegation = makeDelegation(['data:read:table:patients', 'comms:send:channel:slack'])
    const tuples: IBACTuple[] = [
      { principal: 'agent:agent-001', action: 'tool:read', resource: 'table:patients' },
      { principal: 'agent:agent-001', action: 'tool:write', resource: 'file:report.pdf' },
      { principal: 'agent:agent-001', action: 'tool:send', resource: 'channel:slack' },
    ]
    const { tupleResults } = evaluateIBACTuples(tuples, delegation)
    assert.equal(tupleResults[0].authorized, true)
    assert.equal(tupleResults[1].authorized, false)
    assert.equal(tupleResults[2].authorized, true)
  })
})

// ── Full pipeline ──

describe('governIBACIntent', () => {
  it('produces signed receipt for authorized intent', () => {
    const delegation = makeDelegation(['data:read:table:patients', 'data:write:file:clinical_notes'])
    const receipts: ActionReceipt[] = []

    const result = governIBACIntent({
      task: 'clinical_note_review',
      subject: { id: 'agent-nurse-001' },
      actions: [
        { verb: 'read', resource: 'table:patients', constraints: { sensitivity: 'phi' } },
        { verb: 'write', resource: 'file:clinical_notes' },
      ],
      timestamp: new Date().toISOString(),
    }, {
      passport: signedPassport,
      delegation,
      privateKey: agentKeys.privateKey,
      onReceipt: (r) => receipts.push(r),
    })

    assert.ok(result.receipt.receiptId.startsWith('rcpt_ibac_'))
    assert.equal(result.receipt.action.type, 'ibac_evaluation')
    assert.equal(result.receipt.result.status, 'success')
    assert.ok(result.tupleResults.every(r => r.authorized))
    assert.equal(receipts.length, 1)

    // Verify signature
    const { signature, ...rest } = result.receipt
    assert.ok(verify(canonicalize(rest), signature, agentKeys.publicKey))
  })

  it('produces failure receipt for partially denied intent', () => {
    const delegation = makeDelegation(['data:read:table:patients'])

    const result = governIBACIntent({
      task: 'clinical_review',
      subject: { id: 'agent-nurse-001' },
      actions: [
        { verb: 'read', resource: 'table:patients' },
        { verb: 'delete', resource: 'table:patients' },
      ],
      timestamp: new Date().toISOString(),
    }, {
      passport: signedPassport,
      delegation,
      privateKey: agentKeys.privateKey,
    })

    assert.equal(result.receipt.result.status, 'failure')
    assert.ok(result.receipt.result.summary.includes('1 of 2 tuples denied'))
  })
})

// ── Cedar bridge ──

describe('cedarPolicyToTuples', () => {
  it('parses basic Cedar permit statement', () => {
    const cedar = 'permit(principal == "agent:agent-123", action == "tool:query_db", resource == "table:patients");'
    const tuples = cedarPolicyToTuples(cedar)
    assert.equal(tuples.length, 1)
    assert.equal(tuples[0].principal, 'agent:agent-123')
    assert.equal(tuples[0].action, 'tool:query_db')
    assert.equal(tuples[0].resource, 'table:patients')
  })

  it('parses Cedar policy with when constraints', () => {
    const cedar = 'permit(principal == "agent:agent-123", action == "tool:read", resource == "file:report.pdf") when { max_rows < 100 };'
    const tuples = cedarPolicyToTuples(cedar)
    assert.equal(tuples.length, 1)
    assert.ok(tuples[0].constraints)
    assert.equal(tuples[0].constraints!.max_rows, 100)
  })

  it('parses multiple Cedar statements', () => {
    const cedar = `
      permit(principal == "agent:a1", action == "tool:read", resource == "table:logs");
      permit(principal == "agent:a1", action == "tool:write", resource == "file:output.csv")
    `
    const tuples = cedarPolicyToTuples(cedar)
    assert.equal(tuples.length, 2)
  })

  it('ignores malformed lines', () => {
    const cedar = 'this is not a valid cedar line; permit(principal == "agent:a1", action == "tool:read", resource == "table:x");'
    const tuples = cedarPolicyToTuples(cedar)
    assert.equal(tuples.length, 1)
  })
})

describe('delegationToCedarPolicy', () => {
  it('generates Cedar policy from delegation', () => {
    const delegation = makeDelegation(['data:read:table:patients', 'data:write:file:report.pdf'])
    const cedar = delegationToCedarPolicy(delegation)
    assert.ok(cedar.includes('principal =='))
    assert.ok(cedar.includes('tool:read'))
    assert.ok(cedar.includes('table:patients'))
    assert.ok(cedar.includes('tool:write'))
    assert.ok(cedar.includes('file:report.pdf'))
  })

  it('Cedar round-trip: delegation → Cedar → tuples → delegation', () => {
    const d1 = makeDelegation(['data:read:table:logs', 'comms:send:channel:slack'])
    const cedar = delegationToCedarPolicy(d1)
    const tuples = cedarPolicyToTuples(cedar)
    assert.equal(tuples.length, 2)
    const d2 = ibacTuplesToDelegation(tuples, principalKeys.publicKey, agentKeys.publicKey, principalKeys.privateKey)
    // Scopes should match original
    assert.deepStrictEqual(d2.scope.sort(), d1.scope.sort())
  })
})
