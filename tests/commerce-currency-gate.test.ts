// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Regression (round-3): the commerce spend gate must check currency
// ══════════════════════════════════════════════════════════════════
// checkSpendGate compared amounts without checking currency, so a EUR purchase
// passed a USD budget (the SDK does no conversion). It now denies a declared
// currency mismatch. Fails before the fix.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createCommerceDelegation, checkSpendGate } from '../src/index.js'

describe('checkSpendGate currency match', () => {
  const d = createCommerceDelegation({ agentId: 'a', delegationId: 'd', spendLimit: 100, currency: 'usd' })

  it('denies a foreign-currency purchase', () => {
    assert.equal(checkSpendGate(d, { amount: 10, currency: 'eur' }).passed, false)
  })
  it('allows the same currency (case-insensitive)', () => {
    assert.equal(checkSpendGate(d, { amount: 10, currency: 'usd' }).passed, true)
    assert.equal(checkSpendGate(d, { amount: 10, currency: 'USD' }).passed, true)
  })
  it('still enforces the amount within a matching currency', () => {
    assert.equal(checkSpendGate(d, { amount: 200, currency: 'usd' }).passed, false)
  })
})
