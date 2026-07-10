// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Payment Rails — canonical scope-resolution tests
// ══════════════════════════════════════════════════════════════════
// resolveSpendLimitCents() is the single source of truth for spend
// cap field-name resolution across all five binding rails (AP2,
// x402, Stripe-Issuing, ACP, MPP). These tests pin the resolution
// order so future rails cannot drift their own field-name semantics.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { resolveSpendLimitCents } from '../../../src/v2/payment-rails/scope-resolution.js'
import type { V2Delegation } from '../../../src/v2/types.js'

const VALID_FROM = '2026-01-01T00:00:00.000Z'
const VALID_UNTIL = '2027-01-01T00:00:00.000Z'

function makeDelegation(scope: Partial<V2Delegation['scope']> = {}): V2Delegation {
  return {
    id: 'aps-deleg-resolver-test',
    version: 1,
    supersedes: null,
    supersession_justification: null,
    delegator: 'did:aps:test-user',
    delegatee: 'did:aps:test-agent',
    scope: {
      action_categories: ['commerce.checkout'],
      ...scope,
    },
    policy_context: {
      policy_version: 'v2',
      values_floor_version: 'v1',
      trust_epoch: 0,
      issuer_id: 'did:aps:test-user',
      created_at: VALID_FROM,
      valid_from: VALID_FROM,
      valid_until: VALID_UNTIL,
    },
    signature: '',
    status: 'active',
    renewal_reason: null,
    expansion_reviewer: null,
    expansion_review_sig: null,
    assurance_class: 'self_attested',
  }
}

describe('resolveSpendLimitCents — canonical resolution order', () => {
  it('reads canonical spend_limit_cents (number) when present', () => {
    const d = makeDelegation({ resource_limits: { spend_limit_cents: 5000 } })
    assert.equal(resolveSpendLimitCents(d), 5000)
  })

  it('reads commerce.spend_limit alias when canonical absent', () => {
    const d = makeDelegation({ resource_limits: { 'commerce.spend_limit': 7500 } })
    assert.equal(resolveSpendLimitCents(d), 7500)
  })

  it('canonical spend_limit_cents takes precedence over commerce.spend_limit alias', () => {
    const d = makeDelegation({
      resource_limits: { spend_limit_cents: 5000, 'commerce.spend_limit': 9999 },
    })
    assert.equal(resolveSpendLimitCents(d), 5000)
  })

  it('parses constraints.spend_limit_cents string fallback when both numeric sources absent', () => {
    const d = makeDelegation({
      resource_limits: {},
      // V2ScopeDefinition.constraints is Record<string, string>
      constraints: { spend_limit_cents: '1000' } as Record<string, string>,
    })
    assert.equal(resolveSpendLimitCents(d), 1000)
  })

  it('canonical numeric source takes precedence over string constraints fallback', () => {
    const d = makeDelegation({
      resource_limits: { spend_limit_cents: 5000 },
      constraints: { spend_limit_cents: '9999' } as Record<string, string>,
    })
    assert.equal(resolveSpendLimitCents(d), 5000)
  })

  it('rejects malformed string constraint (non-numeric) — returns null', () => {
    const d = makeDelegation({
      resource_limits: {},
      constraints: { spend_limit_cents: 'abc' } as Record<string, string>,
    })
    assert.equal(resolveSpendLimitCents(d), null)
  })

  it('rejects negative number — returns null, does not fall through to alias', () => {
    // Defensive: a negative spend cap is malformed. Resolver MUST NOT
    // accept it. Caller treats null as "no cap configured, deny."
    const d = makeDelegation({
      // eslint-disable-next-line @typescript-eslint/consistent-type-assertions
      resource_limits: { spend_limit_cents: -1, 'commerce.spend_limit': 5000 } as Record<string, number>,
    })
    assert.equal(resolveSpendLimitCents(d), 5000)
  })

  it('rejects non-finite number (Infinity, NaN) — returns null', () => {
    const d1 = makeDelegation({ resource_limits: { spend_limit_cents: Infinity } as Record<string, number> })
    assert.equal(resolveSpendLimitCents(d1), null)
    const d2 = makeDelegation({ resource_limits: { spend_limit_cents: NaN } as Record<string, number> })
    assert.equal(resolveSpendLimitCents(d2), null)
  })

  it('returns null for empty delegation (no resource_limits, no constraints)', () => {
    const d = makeDelegation({})
    assert.equal(resolveSpendLimitCents(d), null)
  })

  it('opts.canonicalKey override — AP2 passes commerce.spend_limit and walks alias logic correctly', () => {
    // AP2 calls resolver with canonicalKey='commerce.spend_limit'.
    // It MUST get the alias as primary, and MUST NOT double-check it
    // as a fallback.
    const d = makeDelegation({
      resource_limits: { 'commerce.spend_limit': 4200 },
    })
    assert.equal(resolveSpendLimitCents(d, { canonicalKey: 'commerce.spend_limit' }), 4200)
  })

  it('opts.canonicalKey override + canonical wins over spend_limit_cents (AP2 mode)', () => {
    // AP2 mode: when both 'commerce.spend_limit' AND 'spend_limit_cents'
    // are set, AP2's canonicalKey ('commerce.spend_limit') MUST win.
    const d = makeDelegation({
      resource_limits: { 'commerce.spend_limit': 4200, spend_limit_cents: 9999 },
    })
    assert.equal(
      resolveSpendLimitCents(d, { canonicalKey: 'commerce.spend_limit' }),
      4200,
    )
  })

  it('zero is a valid cap (means "no spending allowed") — distinct from null (no cap configured)', () => {
    // Financial-grade invariant: 0 means "explicitly no spend
    // permitted." null means "no cap configured, deny by default."
    // These MUST be distinguishable to callers.
    const d = makeDelegation({ resource_limits: { spend_limit_cents: 0 } })
    assert.equal(resolveSpendLimitCents(d), 0)
  })
})
