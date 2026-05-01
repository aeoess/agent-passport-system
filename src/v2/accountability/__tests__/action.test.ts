// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ActionReceipt — construct + verify tests.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { createActionReceipt } from '../construct/action.js'
import { verifyActionReceipt } from '../verify/action.js'
import type { ActionReceipt } from '../types/action.js'
import type { CreateActionReceiptInput } from '../construct/action.js'

const PRIVATE_KEY = '11'.repeat(64)
const FIXED_TS = '2026-04-30T00:00:00.000Z'

function baseInput(): CreateActionReceiptInput {
  return {
    timestamp: FIXED_TS,
    scope_of_claim: {
      asserts: 'Agent issued an HTTP POST to the target URL.',
      does_not_assert: [
        'That the agent understood the consequences of the request.',
        'That the request was authorized by the principal.',
      ],
      capture_mode: 'gateway_observed',
      completeness: 'complete',
      self_attested: false,
    },
    agent_did: 'did:aps:test-agent-001',
    delegation_chain_root: 'a'.repeat(64),
    action: {
      kind: 'http_request',
      target: 'https://example.com/api/v1/users',
    },
    side_effect_classes: ['external_message', 'data_modification'],
  }
}

describe('createActionReceipt', () => {
  it('constructs a receipt that round-trips through verify', () => {
    const receipt = createActionReceipt(baseInput(), PRIVATE_KEY)
    const result = verifyActionReceipt(receipt)
    assert.equal(result.valid, true)
    assert.equal(result.reason, undefined)
  })

  it('produces stable receipt_id for identical inputs (deterministic)', () => {
    const a = createActionReceipt(baseInput(), PRIVATE_KEY)
    const b = createActionReceipt(baseInput(), PRIVATE_KEY)
    assert.equal(a.receipt_id, b.receipt_id)
    assert.equal(a.signature, b.signature)
  })

  it('sets claim_type to aps:action:v1 regardless of input', () => {
    const receipt = createActionReceipt(baseInput(), PRIVATE_KEY)
    assert.equal(receipt.claim_type, 'aps:action:v1')
  })
})

describe('verifyActionReceipt', () => {
  it('detects tampered action.target via SIGNATURE_INVALID', () => {
    const receipt = createActionReceipt(baseInput(), PRIVATE_KEY)
    const tampered: ActionReceipt = {
      ...receipt,
      action: { ...receipt.action, target: 'https://attacker.example/api/v1/users' },
    }
    const result = verifyActionReceipt(tampered)
    assert.equal(result.valid, false)
    // Mutating action.target without recomputing receipt_id flips the
    // receipt_id check first; the bytes are different, so the recomputed
    // id no longer matches the stored one.
    assert.equal(result.reason, 'RECEIPT_ID_MISMATCH')
  })

  it('detects tampered signature bytes via SIGNATURE_INVALID', () => {
    const receipt = createActionReceipt(baseInput(), PRIVATE_KEY)
    // Flip one hex char in the signature; receipt_id stays valid because
    // signature is excluded from receipt_id derivation.
    const flipped =
      receipt.signature.slice(0, -1) + (receipt.signature.endsWith('0') ? '1' : '0')
    const tampered: ActionReceipt = { ...receipt, signature: flipped }
    const result = verifyActionReceipt(tampered)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'SIGNATURE_INVALID')
  })

  it('rejects a wrong claim_type with INVALID_CLAIM_TYPE', () => {
    const receipt = createActionReceipt(baseInput(), PRIVATE_KEY)
    const wrong = { ...receipt, claim_type: 'aps:other:v1' as unknown as 'aps:action:v1' }
    const result = verifyActionReceipt(wrong)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'INVALID_CLAIM_TYPE')
  })

  it('detects tampered receipt_id directly with RECEIPT_ID_MISMATCH', () => {
    const receipt = createActionReceipt(baseInput(), PRIVATE_KEY)
    const tampered: ActionReceipt = { ...receipt, receipt_id: '0'.repeat(64) }
    const result = verifyActionReceipt(tampered)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'RECEIPT_ID_MISMATCH')
  })

  it('detects tampered scope_of_claim via RECEIPT_ID_MISMATCH', () => {
    const receipt = createActionReceipt(baseInput(), PRIVATE_KEY)
    const tampered: ActionReceipt = {
      ...receipt,
      scope_of_claim: {
        ...receipt.scope_of_claim,
        asserts: 'Different assertion text.',
      },
    }
    const result = verifyActionReceipt(tampered)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'RECEIPT_ID_MISMATCH')
  })
})
