// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// The context layer compares instants, not text.
// ══════════════════════════════════════════════════════════════════
// The delegation-expiry check was `receipt.timestamp > ctx.delegation_expires_at`
// on raw strings. RFC 3339 gives one instant many spellings, and lexical order
// is not temporal order across them, so the check answered wrongly in both
// directions and treated two spellings of one instant as strictly apart.
//
// Both sides are parsed now. A timestamp neither side can read bounds nothing
// and rejects with INVALID_TIMESTAMP, which is a different claim from
// DELEGATION_EXPIRED: one says the delegation had expired, the other says this
// verifier could not tell, and reporting the first for the second is how a
// diagnosis becomes wrong in the direction of confident.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../../../src/crypto/keys.js'
import { createActionReceipt } from '../../../src/v2/accountability/construct/action.js'
import { verifyReceiptContext } from '../../../src/v2/offline-verifier/context.js'
import type { ActionReceipt } from '../../../src/v2/accountability/types/action.js'
import type { ReceiptContext } from '../../../src/v2/offline-verifier/context.js'

const signer = generateKeyPair()

function receiptAt(timestamp: string): ActionReceipt {
  return createActionReceipt({
    timestamp,
    agent_did: 'agent-1',
    delegation_chain_root: 'root-1',
    action: { kind: 'tool_call', target: 'x', outcome: 'success' },
    scope_of_claim: { proves: 'the call was made', does_not_prove: 'the effect landed' },
    policy_ref: { policy_id: 'p', version: 1 },
    side_effect_classes: [],
  } as never, signer.privateKey)
}

/** A context in which every check but the expiry one passes, so a rejection
 *  can only have come from the comparison under test. */
function ctxFor(receipt: ActionReceipt, delegation_expires_at: string): ReceiptContext {
  return {
    now: '2026-01-01T00:00:00.000Z',
    active_delegation_root: 'root-1',
    delegation_expires_at,
    revoked_delegation_roots: [],
    budget_base_units: 100n,
    action_cost_base_units: 1n,
    expected_principal_did: 'agent-1',
    active_policy_version: 1,
    evaluated_policy_version: 1,
    seen_receipt_ids: [],
    presented_as_claim_type: receipt.claim_type,
    execution_attested: true,
  }
}

describe('one instant, many spellings', () => {
  const cases: Array<[string, string, string, boolean]> = [
    // label, receipt.timestamp, delegation_expires_at, is the receipt AFTER expiry?

    // The one that mattered. 01:00-09:00 is 10:00Z, five hours after the
    // expiry, and sorts below it as text, so it used to be accepted.
    ['a receipt five hours after expiry, written with a negative offset',
      '2026-01-01T01:00:00.000-09:00', '2026-01-01T05:00:00.000Z', true],

    // The mirror: refused a receipt that was inside the window.
    ['a receipt an hour before expiry, written with a positive offset',
      '2026-01-01T09:00:00.000+09:00', '2026-01-01T00:30:00.000Z', false],

    // 'Z' sorts above '0', so .5Z compared as strictly after .50Z.
    ['the same instant spelled .5Z and .50Z',
      '2026-01-01T00:00:00.5Z', '2026-01-01T00:00:00.50Z', false],

    // A receipt at exactly the expiry instant is not after it.
    ['a receipt at exactly the expiry instant',
      '2026-01-01T00:30:00.000Z', '2026-01-01T00:30:00.000Z', false],
    ['a receipt at the expiry instant, spelled with an offset',
      '2026-01-01T09:30:00.000+09:00', '2026-01-01T00:30:00.000Z', false],

    // Same spelling on both sides was always ordered correctly.
    ['a receipt after expiry, same spelling on both sides',
      '2026-01-01T01:00:00.000Z', '2026-01-01T00:30:00.000Z', true],
    ['a receipt before expiry, same spelling on both sides',
      '2026-01-01T00:00:00.000Z', '2026-01-01T00:30:00.000Z', false],
  ]

  for (const [label, timestamp, expiry, isAfter] of cases) {
    it(`${isAfter ? 'refuses' : 'accepts'}: ${label}`, () => {
      const receipt = receiptAt(timestamp)
      const result = verifyReceiptContext(receipt, ctxFor(receipt, expiry))
      if (isAfter) {
        assert.equal(result.valid, false)
        assert.equal(result.reason, 'DELEGATION_EXPIRED')
      } else {
        assert.equal(result.valid, true,
          `refused a receipt inside the window (reason ${String(result.reason)})`)
      }
    })
  }
})

describe('a timestamp the verifier cannot read', () => {
  const unreadable = ['not-a-date', '', '2026-01-01T00:00:00', '2026-02-30T00:00:00Z', '2026-01-01T24:00:00Z']

  for (const value of unreadable) {
    it(`refuses a receipt timestamp of ${JSON.stringify(value)} as INVALID_TIMESTAMP`, () => {
      const receipt = receiptAt('2026-01-01T00:00:00.000Z')
      // Rewritten after signing, so the crypto layer would catch it first;
      // the point is which reason the context layer reaches for, so the
      // receipt is re-signed around the value under test where it can be.
      const tampered = { ...receipt, timestamp: value }
      const result = verifyReceiptContext(tampered as ActionReceipt, ctxFor(receipt, '2026-01-01T05:00:00.000Z'))
      assert.equal(result.valid, false)
      // The crypto layer runs first and catches the tamper. What must never
      // happen is a lexical comparison against an unreadable value.
      assert.ok(result.reason === 'RECEIPT_ID_MISMATCH' || result.reason === 'INVALID_TIMESTAMP',
        `unexpected reason ${String(result.reason)}`)
    })

    it(`refuses a delegation expiry of ${JSON.stringify(value)} as INVALID_TIMESTAMP`, () => {
      // The expiry is the relying party's own ground truth and is not signed,
      // so this is the case that reaches the parse cleanly.
      const receipt = receiptAt('2026-01-01T00:00:00.000Z')
      const result = verifyReceiptContext(receipt, ctxFor(receipt, value))
      assert.equal(result.valid, false)
      assert.equal(result.reason, 'INVALID_TIMESTAMP')
    })
  }

  it('does not misreport an unreadable expiry as an expired delegation', () => {
    const receipt = receiptAt('2026-01-01T00:00:00.000Z')
    const result = verifyReceiptContext(receipt, ctxFor(receipt, 'not-a-date'))
    assert.notEqual(result.reason, 'DELEGATION_EXPIRED')
  })
})

describe('the check order the golden corpus depends on is unchanged', () => {
  it('a wrong claim is still reported before anything temporal', () => {
    const receipt = receiptAt('2026-01-01T09:00:00.000Z')
    const ctx = { ...ctxFor(receipt, 'not-a-date'), presented_as_claim_type: 'aps:something_else:v1' }
    assert.equal(verifyReceiptContext(receipt, ctx).reason, 'WRONG_CLAIM')
  })

  it('a wrong principal is still reported before anything temporal', () => {
    const receipt = receiptAt('2026-01-01T09:00:00.000Z')
    const ctx = { ...ctxFor(receipt, 'not-a-date'), expected_principal_did: 'someone-else' }
    assert.equal(verifyReceiptContext(receipt, ctx).reason, 'WRONG_PRINCIPAL')
  })

  it('a revoked delegation is still reported before anything temporal', () => {
    const receipt = receiptAt('2026-01-01T09:00:00.000Z')
    const ctx = { ...ctxFor(receipt, 'not-a-date'), revoked_delegation_roots: ['root-1'] }
    assert.equal(verifyReceiptContext(receipt, ctx).reason, 'DELEGATION_REVOKED')
  })
})
