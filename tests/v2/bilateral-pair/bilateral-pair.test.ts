// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Bilateral pair reconciliation tests (FREEZE-VWE F2, SCHEMAS-DRAFT 3a).
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { reconcileBilateralPair } from '../../../src/v2/bilateral-pair/reconcile.js'
import { createBilateralReceipt, verifyBilateralReceipt } from '../../../src/core/bilateral-receipt.js'
import { bindAudience } from '../../../src/v2/audience-binding/verify.js'
import { generateKeyPair } from '../../../src/crypto/keys.js'
import type { BilateralReceipt } from '../../../src/types/bilateral-receipt.js'
import type { BilateralPairPolicy } from '../../../src/v2/bilateral-pair/types.js'

const fixture = JSON.parse(
  readFileSync(new URL('./fixtures/bilateral-pair-vectors.json', import.meta.url), 'utf-8'),
)

describe('bilateral pair fixtures (one reconciled + one per frozen mismatch class)', () => {
  for (const v of fixture.vectors) {
    it(`vector: ${v.name}`, () => {
      const verdict = reconcileBilateralPair(v.local, v.counterparty, v.policy)
      assert.equal(verdict.status, v.expected.status)
      assert.deepEqual(verdict.mismatches, v.expected.mismatches)
    })
  }

  it('every fixture receipt is genuinely co-signed (precondition holds)', () => {
    const { requestingAgentPublicKey, servingAgentPublicKey } = fixture.keys
    for (const v of fixture.vectors) {
      for (const copy of [v.local, v.counterparty]) {
        if (copy === null) continue
        const res = verifyBilateralReceipt(copy, requestingAgentPublicKey, servingAgentPublicKey)
        assert.equal(res.valid, true, `${v.name}: fixture copy fails signature verification`)
      }
    }
  })
})

describe('bilateral pair reconciliation behavior (FREEZE-VWE F2)', () => {
  const req = generateKeyPair()
  const srv = generateKeyPair()
  const REQ = 'did:aps:zReqAgent'
  const SRV = 'did:aps:zSrvAgent'

  const outcome = {
    toolName: 'web_search',
    requestHash: 'r'.repeat(64),
    responseHash: 's'.repeat(64),
    status: 'success' as const,
    summary: 'ok',
  }
  const mk = (over: Partial<Parameters<typeof createBilateralReceipt>[0]> = {}): BilateralReceipt =>
    createBilateralReceipt({
      requestingAgentId: REQ,
      servingAgentId: SRV,
      outcome,
      requestedAt: '2026-07-10T02:00:00Z',
      completedAt: '2026-07-10T02:00:01Z',
      requestingAgentPrivateKey: req.privateKey,
      servingAgentPrivateKey: srv.privateKey,
      aud: bindAudience([REQ, SRV]),
      ...over,
    })
  const policy: BilateralPairPolicy = { selfRecipientId: REQ, requireAudience: true }

  it('wrong_audience emits the audience ConstraintFailure via audienceFailure, no other facet', () => {
    const local = mk()
    const counterparty = mk({ aud: bindAudience(['did:aps:zSomeoneElse']) })
    const verdict = reconcileBilateralPair(local, counterparty, policy)
    assert.deepEqual(verdict.mismatches, ['wrong_audience'])
    assert.ok(verdict.constraintFailures.length >= 1)
    for (const f of verdict.constraintFailures) {
      assert.equal(f.facet, 'audience')
      assert.equal(f.severity, 'hard')
      assert.equal(f.retryable, false)
    }
    assert.equal(verdict.constraintFailures[0].code, 'audience_mismatch')
    assert.equal(verdict.audience.counterpartyCopyToSelf?.status, 'fail')
  })

  it('requireAudience: an unbound counterparty copy fails with audience_required_absent', () => {
    const local = mk()
    const counterparty = mk({ aud: undefined })
    const verdict = reconcileBilateralPair(local, counterparty, policy)
    assert.ok(verdict.mismatches.includes('wrong_audience'))
    assert.equal(verdict.audience.counterpartyCopyToSelf?.reason, 'audience_required_absent')
  })

  it('reverse direction: a local copy that does not admit the counterparty is wrong_audience', () => {
    const local = mk({ aud: bindAudience([REQ]) }) // names only self, not the counterparty
    const counterparty = mk()
    const verdict = reconcileBilateralPair(local, counterparty, policy)
    assert.ok(verdict.mismatches.includes('wrong_audience'))
    assert.equal(verdict.audience.localCopyToCounterparty?.status, 'fail')
    assert.equal(verdict.audience.localCopyToCounterparty?.checkedAgainst, SRV)
  })

  it('jwks-kid self id: reverse direction needs counterpartyRecipientId, else it is not evaluated', () => {
    const KID_SELF = 'jwks-kid:aeoess-2026-07'
    const KID_CP = 'jwks-kid:agentlair-2026-05'
    const local = mk({ aud: bindAudience([KID_SELF, KID_CP]) })
    const counterparty = mk({ aud: bindAudience([KID_SELF, KID_CP]) })
    // Without the explicit counterparty id the reverse direction cannot be
    // derived from agent DIDs (self id matches neither agent id): no trace
    // entry, no invented failure. The forward direction still runs.
    const without = reconcileBilateralPair(local, counterparty, {
      selfRecipientId: KID_SELF,
      requireAudience: true,
    })
    assert.equal(without.audience.localCopyToCounterparty, undefined)
    assert.equal(without.audience.counterpartyCopyToSelf?.status, 'pass')
    assert.equal(without.status, 'reconciled')
    // With the explicit counterparty id both directions run and pass.
    const withId = reconcileBilateralPair(local, counterparty, {
      selfRecipientId: KID_SELF,
      requireAudience: true,
      counterpartyRecipientId: KID_CP,
    })
    assert.equal(withId.audience.localCopyToCounterparty?.status, 'pass')
    assert.equal(withId.status, 'reconciled')
  })

  it('expectedActionRef pairs legacy slot-free receipts without penalizing absence', () => {
    const ref = 'c'.repeat(64)
    const local = mk() // no action_ref slot
    const counterparty = mk()
    const verdict = reconcileBilateralPair(local, counterparty, {
      ...policy,
      expectedActionRef: ref,
    })
    // Absence never mismatches (the slot is additive, F1).
    assert.equal(verdict.status, 'reconciled')
  })

  it('expectedActionRef against a copy carrying a different ref is action_ref_mismatch', () => {
    const local = mk({ action_ref: 'c'.repeat(64) })
    const counterparty = mk({ action_ref: 'c'.repeat(64) })
    const verdict = reconcileBilateralPair(local, counterparty, {
      ...policy,
      expectedActionRef: 'd'.repeat(64),
    })
    assert.deepEqual(verdict.mismatches, ['action_ref_mismatch'])
  })

  it('unilateral non-success local copy is unilateral with no unilateral_success finding', () => {
    const local = mk({ outcome: { ...outcome, status: 'failure' } })
    const verdict = reconcileBilateralPair(local, null, policy)
    assert.equal(verdict.status, 'unilateral')
    assert.ok(!verdict.mismatches.includes('unilateral_success'))
  })

  it('pair with success on one side and failure on the other is unilateral_success', () => {
    const local = mk()
    const counterparty = mk({ outcome: { ...outcome, status: 'failure' } })
    const verdict = reconcileBilateralPair(local, counterparty, policy)
    assert.ok(verdict.mismatches.includes('unilateral_success'))
    // The status divergence also changes the signed body but NOT the payload
    // hashes, so payload_changed is not implied.
    assert.ok(!verdict.mismatches.includes('payload_changed'))
    assert.equal(verdict.status, 'mismatch')
  })

  it('multiple classes accumulate without duplication', () => {
    const local = mk({ action_ref: 'c'.repeat(64) })
    const counterparty = mk({
      servingAgentId: 'did:aps:zEvil',
      action_ref: 'd'.repeat(64),
      outcome: { ...outcome, responseHash: 'x'.repeat(64) },
      aud: bindAudience(['did:aps:zSomeoneElse']),
    })
    const verdict = reconcileBilateralPair(local, counterparty, policy)
    assert.equal(verdict.status, 'mismatch')
    assert.deepEqual(
      [...verdict.mismatches].sort(),
      ['action_ref_mismatch', 'payload_changed', 'recipient_changed', 'wrong_audience'],
    )
    assert.equal(new Set(verdict.mismatches).size, verdict.mismatches.length)
  })

  it('does not mutate its inputs', () => {
    const local = mk()
    const counterparty = mk({ aud: bindAudience(['did:aps:zSomeoneElse']) })
    const localSnap = JSON.stringify(local)
    const cpSnap = JSON.stringify(counterparty)
    reconcileBilateralPair(local, counterparty, policy)
    assert.equal(JSON.stringify(local), localSnap)
    assert.equal(JSON.stringify(counterparty), cpSnap)
  })
})
