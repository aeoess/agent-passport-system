// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// AuthorityBoundaryReceipt — construct + verify tests.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { createAuthorityBoundaryReceipt } from '../construct/authority-boundary.js'
import { verifyAuthorityBoundaryReceipt } from '../verify/authority-boundary.js'
import type { AuthorityBoundaryReceipt, BoundaryResult } from '../types/authority-boundary.js'
import type { CreateAuthorityBoundaryReceiptInput } from '../construct/authority-boundary.js'

const PRIVATE_KEY = '11'.repeat(64)
const FIXED_TS = '2026-04-30T00:00:00.000Z'
const ACTION_ID_REF = 'b'.repeat(64)

function baseInput(result: BoundaryResult, detail?: string): CreateAuthorityBoundaryReceiptInput {
  return {
    timestamp: FIXED_TS,
    scope_of_claim: {
      asserts: 'The evaluator ran a delegation-scope check on the named action.',
      does_not_assert: [
        'That the underlying action receipt was itself valid.',
        'That side effects had occurred at evaluation time.',
      ],
      capture_mode: 'gateway_observed',
      completeness: 'complete',
      self_attested: false,
    },
    action_id: ACTION_ID_REF,
    evaluator_did: 'did:aps:test-gateway-001',
    delegation_chain_root: 'c'.repeat(64),
    result,
    ...(detail !== undefined ? { result_detail: detail } : {}),
  }
}

describe('createAuthorityBoundaryReceipt', () => {
  for (const result of ['inside', 'outside', 'indeterminate'] as const) {
    it(`round-trips construct + verify for result='${result}'`, () => {
      const detail =
        result === 'outside' ? `scope 'commerce.purchase' not in delegation` : undefined
      const receipt = createAuthorityBoundaryReceipt(baseInput(result, detail), PRIVATE_KEY)
      assert.equal(receipt.result, result)
      const v = verifyAuthorityBoundaryReceipt(receipt)
      assert.equal(v.valid, true)
      assert.equal(v.reason, undefined)
    })
  }

  it('produces stable receipt_id for identical inputs (deterministic)', () => {
    const a = createAuthorityBoundaryReceipt(baseInput('inside'), PRIVATE_KEY)
    const b = createAuthorityBoundaryReceipt(baseInput('inside'), PRIVATE_KEY)
    assert.equal(a.receipt_id, b.receipt_id)
    assert.equal(a.signature, b.signature)
  })

  it('sets claim_type to aps:authority_boundary:v1', () => {
    const receipt = createAuthorityBoundaryReceipt(baseInput('inside'), PRIVATE_KEY)
    assert.equal(receipt.claim_type, 'aps:authority_boundary:v1')
  })
})

describe('verifyAuthorityBoundaryReceipt', () => {
  it('detects tampered result field via RECEIPT_ID_MISMATCH', () => {
    const receipt = createAuthorityBoundaryReceipt(baseInput('inside'), PRIVATE_KEY)
    const tampered: AuthorityBoundaryReceipt = { ...receipt, result: 'outside' }
    const v = verifyAuthorityBoundaryReceipt(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'RECEIPT_ID_MISMATCH')
  })

  it('detects tampered signature bytes via SIGNATURE_INVALID', () => {
    const receipt = createAuthorityBoundaryReceipt(baseInput('outside', 'reason'), PRIVATE_KEY)
    const flipped =
      receipt.signature.slice(0, -1) + (receipt.signature.endsWith('0') ? '1' : '0')
    const tampered: AuthorityBoundaryReceipt = { ...receipt, signature: flipped }
    const v = verifyAuthorityBoundaryReceipt(tampered)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'SIGNATURE_INVALID')
  })

  it('rejects wrong claim_type with INVALID_CLAIM_TYPE', () => {
    const receipt = createAuthorityBoundaryReceipt(baseInput('inside'), PRIVATE_KEY)
    const wrong = {
      ...receipt,
      claim_type: 'aps:action:v1' as unknown as 'aps:authority_boundary:v1',
    }
    const v = verifyAuthorityBoundaryReceipt(wrong)
    assert.equal(v.valid, false)
    assert.equal(v.reason, 'INVALID_CLAIM_TYPE')
  })
})
