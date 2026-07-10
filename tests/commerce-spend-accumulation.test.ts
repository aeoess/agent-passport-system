// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Regression: spend accumulation (recordSpend)
// ══════════════════════════════════════════════════════════════════
// Guards the read-but-never-written spentAmount bug: checkSpendGate reads
// delegation.spentAmount, which was created at 0 and never incremented, so
// one delegation passed unlimited purchases against its cap. recordSpend is
// the stateless write primitive that closes the loop. The cumulative-overspend
// test FAILS before the fix (recordSpend did not exist; the second purchase
// passed when it should be denied) and passes after.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createCommerceDelegation, recordSpend, checkSpendGate } from '../src/index.js'

describe('commerce spend accumulation (recordSpend)', () => {
  it('denies a second purchase that, with the first recorded, exceeds the cap', () => {
    const d0 = createCommerceDelegation({ agentId: 'a', delegationId: 'del_1', spendLimit: 100 })
    // First purchase of 60 is within the full budget.
    assert.equal(checkSpendGate(d0, { amount: 60, currency: 'usd' }).passed, true)
    // Record it. Without recordSpend, spentAmount stayed 0 and the next check passed (the bug).
    const d1 = recordSpend(d0, 60)
    assert.equal(d1.spentAmount, 60)
    // Second purchase of 60 now exceeds the remaining 40 and is denied.
    assert.equal(checkSpendGate(d1, { amount: 60, currency: 'usd' }).passed, false)
  })

  it('is pure: the input delegation is not mutated', () => {
    const d0 = createCommerceDelegation({ agentId: 'a', delegationId: 'del_2', spendLimit: 100 })
    recordSpend(d0, 25)
    assert.equal(d0.spentAmount, 0)
  })

  it('refuses a spend that would exceed the limit', () => {
    const d0 = createCommerceDelegation({ agentId: 'a', delegationId: 'del_3', spendLimit: 100 })
    const d1 = recordSpend(d0, 80)
    assert.throws(() => recordSpend(d1, 30), /would exceed the spend limit/)
  })

  it('refuses invalid amounts (negative, NaN, Infinity)', () => {
    const d0 = createCommerceDelegation({ agentId: 'a', delegationId: 'del_4', spendLimit: 100 })
    for (const bad of [-1, NaN, Infinity, -Infinity]) {
      assert.throws(() => recordSpend(d0, bad), /non-negative finite number/)
    }
  })

  it('accumulates across several recorded purchases', () => {
    let d = createCommerceDelegation({ agentId: 'a', delegationId: 'del_5', spendLimit: 100 })
    d = recordSpend(d, 30)
    d = recordSpend(d, 30)
    d = recordSpend(d, 40)
    assert.equal(d.spentAmount, 100)
    assert.equal(checkSpendGate(d, { amount: 1, currency: 'usd' }).passed, false)
  })
})
