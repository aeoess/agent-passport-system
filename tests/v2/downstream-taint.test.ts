// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Downstream Taint (Module 4) — cascade primitive tests.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  RecordType,
  isContestationTainting,
  computeDownstreamTaint,
} from '../../src/index.js'
import type {
  ContestabilityReceipt,
  ContestStatus,
  ScopeOfClaim,
} from '../../src/index.js'

const ACTION_ID = 'action_001'
const SUBJECT_DID = 'did:aps:test-subject-001'
const RESPONDER_DID = 'aa'.repeat(32)

const SCOPE: ScopeOfClaim = {
  asserts: 'Test contestation for taint cascade.',
  does_not_assert: ['that the contestation is meritorious'],
  capture_mode: 'self_attested',
  completeness: 'complete',
  self_attested: true,
}

function makeContestation(status: ContestStatus | undefined): ContestabilityReceipt {
  const base: ContestabilityReceipt = {
    claim_type: 'aps:contestability:v1',
    receipt_id: 'contest_001',
    timestamp: '2026-05-02T00:00:00.000Z',
    signer_did: SUBJECT_DID,
    scope_of_claim: SCOPE,
    contestant: { did: SUBJECT_DID, standing_basis: 'data_subject' },
    action_id: ACTION_ID,
    grounds: 'test',
    requested_remedy: 'review',
    signature: '00'.repeat(64),
  }
  if (status === undefined) return base
  return {
    ...base,
    controller_response: {
      status,
      responded_at: '2026-05-02T01:00:00.000Z',
      responder_did: RESPONDER_DID,
      response_signature: '00'.repeat(64),
    },
  }
}

describe('isContestationTainting', () => {
  it('returns false for filed status', () => {
    assert.equal(isContestationTainting(makeContestation('filed')), false)
  })

  it('returns true for upheld status', () => {
    assert.equal(isContestationTainting(makeContestation('upheld')), true)
  })

  it('returns true for remedied status', () => {
    assert.equal(isContestationTainting(makeContestation('remedied')), true)
  })

  it('returns false for rejected status', () => {
    assert.equal(isContestationTainting(makeContestation('rejected')), false)
  })

  it('returns false when controller_response is absent', () => {
    assert.equal(isContestationTainting(makeContestation(undefined)), false)
  })
})

describe('computeDownstreamTaint', () => {
  it('returns null for non-tainting contestation', () => {
    const result = computeDownstreamTaint(makeContestation('filed'), [
      { receiptId: 'decision_001', recordType: RecordType.DecisionReceipt, references: [ACTION_ID] },
    ])
    assert.equal(result, null)
  })

  it('returns direct references at depth 1', () => {
    const result = computeDownstreamTaint(makeContestation('upheld'), [
      { receiptId: 'decision_001', recordType: RecordType.DecisionReceipt, references: [ACTION_ID] },
    ])
    assert.notEqual(result, null)
    if (result === null) return
    assert.equal(result.tainted.length, 1)
    assert.equal(result.tainted[0].receiptId, 'decision_001')
    assert.equal(result.tainted[0].taintDepth, 1)
  })

  it('returns transitive references at depth 2', () => {
    const result = computeDownstreamTaint(makeContestation('upheld'), [
      { receiptId: 'A', recordType: RecordType.DecisionReceipt, references: [ACTION_ID] },
      { receiptId: 'B', recordType: RecordType.DerivationReceipt, references: ['A'] },
    ])
    assert.notEqual(result, null)
    if (result === null) return
    assert.equal(result.tainted.length, 2)
    const a = result.tainted.find((t) => t.receiptId === 'A')
    const b = result.tainted.find((t) => t.receiptId === 'B')
    assert.equal(a?.taintDepth, 1)
    assert.equal(b?.taintDepth, 2)
  })

  it('returns no false positives for unrelated candidates', () => {
    const result = computeDownstreamTaint(makeContestation('upheld'), [
      { receiptId: 'tainted', recordType: RecordType.DecisionReceipt, references: [ACTION_ID] },
      { receiptId: 'clean', recordType: RecordType.ActionReceipt, references: ['action_999'] },
    ])
    assert.notEqual(result, null)
    if (result === null) return
    assert.equal(result.tainted.length, 1)
    assert.equal(result.tainted[0].receiptId, 'tainted')
  })

  it('handles cycles without infinite loop (neither references action_id)', () => {
    const result = computeDownstreamTaint(makeContestation('upheld'), [
      { receiptId: 'A', recordType: RecordType.DecisionReceipt, references: ['B'] },
      { receiptId: 'B', recordType: RecordType.DerivationReceipt, references: ['A'] },
    ])
    assert.notEqual(result, null)
    if (result === null) return
    assert.equal(result.tainted.length, 0)
  })

  it('handles cycles where one node references action_id (both tainted, BFS depth)', () => {
    const result = computeDownstreamTaint(makeContestation('upheld'), [
      { receiptId: 'A', recordType: RecordType.DecisionReceipt, references: [ACTION_ID, 'B'] },
      { receiptId: 'B', recordType: RecordType.DerivationReceipt, references: ['A'] },
    ])
    assert.notEqual(result, null)
    if (result === null) return
    assert.equal(result.tainted.length, 2)
    const a = result.tainted.find((t) => t.receiptId === 'A')
    const b = result.tainted.find((t) => t.receiptId === 'B')
    assert.equal(a?.taintDepth, 1)
    assert.equal(b?.taintDepth, 2)
  })

  it('rootContestationId and rootActionId are surfaced on the TaintedSet', () => {
    const result = computeDownstreamTaint(makeContestation('upheld'), [])
    assert.notEqual(result, null)
    if (result === null) return
    assert.equal(result.rootActionId, ACTION_ID)
    assert.equal(result.rootContestationId, 'contest_001')
    assert.deepEqual(result.tainted, [])
  })
})
