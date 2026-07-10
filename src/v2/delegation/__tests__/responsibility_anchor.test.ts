// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// responsibility_anchor: cascade and chain composition validator tests for
// matrix v2 candidate C-II-3.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { cascadePrincipal } from '../responsibility.js'
import type { DelegationChain } from '../responsibility.js'
import { validateChainComposition } from '../validateChainComposition.js'
import type {
  V2Delegation,
  V2ScopeDefinition,
  PolicyContext,
  ResponsibilityAnchor,
} from '../../types.js'

// ══════════════════════════════════════════════════════════════
// FIXTURES
// ══════════════════════════════════════════════════════════════

const PRIN_A = 'a'.repeat(64)
const PRIN_B = 'b'.repeat(64)
const PRIN_H = 'c'.repeat(64)
const AGENT_X = 'd'.repeat(64)
const AGENT_Y = 'e'.repeat(64)
const SIG = '0'.repeat(128)
const NOW = '2026-04-30T00:00:00.000Z'
const LATER = '2027-04-30T00:00:00.000Z'

function baseScope(): V2ScopeDefinition {
  return { action_categories: ['read'] }
}

function basePolicyContext(): PolicyContext {
  return {
    policy_version: '1.0.0',
    values_floor_version: '1.0.0',
    trust_epoch: 1,
    issuer_id: 'issuer:test',
    created_at: NOW,
    valid_from: NOW,
    valid_until: LATER,
  }
}

interface MakeDelegationInput {
  id: string
  delegator: string
  delegatee: string
  supersedes?: string | null
  anchor?: ResponsibilityAnchor
}

function makeDelegation(input: MakeDelegationInput): V2Delegation {
  const d: V2Delegation = {
    id: input.id,
    version: 1,
    supersedes: input.supersedes ?? null,
    supersession_justification: null,
    delegator: input.delegator,
    delegatee: input.delegatee,
    scope: baseScope(),
    policy_context: basePolicyContext(),
    signature: SIG,
    status: 'active',
    renewal_reason: null,
    expansion_reviewer: null,
    expansion_review_sig: null,
    assurance_class: 'mechanically_enforceable',
  }
  if (input.anchor) {
    d.responsibility_anchor = input.anchor
  }
  return d
}

// ══════════════════════════════════════════════════════════════
// CASCADE TESTS
// ══════════════════════════════════════════════════════════════

describe('cascadePrincipal', () => {
  it('test 1: single-principal chain returns one principal', () => {
    const chain: DelegationChain = [
      makeDelegation({
        id: 'd1',
        delegator: PRIN_A,
        delegatee: AGENT_X,
        anchor: { principal_id: PRIN_A, principal_kind: 'human' },
      }),
      makeDelegation({
        id: 'd2',
        delegator: AGENT_X,
        delegatee: AGENT_Y,
        anchor: { principal_id: PRIN_A, principal_kind: 'human' },
      }),
      makeDelegation({
        id: 'd3',
        delegator: AGENT_Y,
        delegatee: 'agent:Z',
        anchor: { principal_id: PRIN_A, principal_kind: 'human' },
      }),
      makeDelegation({
        id: 'd4',
        delegator: 'agent:Z',
        delegatee: 'agent:leaf',
        anchor: { principal_id: PRIN_A, principal_kind: 'human' },
      }),
    ]
    const result = cascadePrincipal(chain)
    assert.equal(result.chain_integrity, 'ok')
    assert.equal(result.principals.length, 1)
    assert.equal(result.principals[0].principal_id, PRIN_A)
    assert.equal(result.principals[0].principal_kind, 'human')
  })

  it('test 2: multi-principal convergent chain returns both root principals', () => {
    const chain: DelegationChain = [
      makeDelegation({
        id: 'd1',
        delegator: PRIN_A,
        delegatee: AGENT_X,
        anchor: { principal_id: PRIN_A, principal_kind: 'human' },
      }),
      makeDelegation({
        id: 'd2',
        delegator: PRIN_B,
        delegatee: AGENT_X,
        anchor: { principal_id: PRIN_B, principal_kind: 'human' },
      }),
    ]
    const result = cascadePrincipal(chain)
    assert.equal(result.chain_integrity, 'ok')
    assert.equal(result.principals.length, 2)
    const ids = result.principals.map((p) => p.principal_id).sort()
    assert.deepEqual(ids, [PRIN_A, PRIN_B].sort())
  })

  it('test 3: agent-acting-for-principal chain returns the human root', () => {
    const chain: DelegationChain = [
      makeDelegation({
        id: 'd1',
        delegator: PRIN_H,
        delegatee: AGENT_X,
        anchor: { principal_id: PRIN_H, principal_kind: 'human' },
      }),
      makeDelegation({
        id: 'd2',
        delegator: AGENT_X,
        delegatee: AGENT_Y,
        anchor: {
          principal_id: AGENT_X,
          principal_kind: 'agent_acting_for_principal',
          acting_agent_id: PRIN_H,
        },
      }),
      makeDelegation({
        id: 'd3',
        delegator: AGENT_Y,
        delegatee: 'agent:leaf',
        anchor: {
          principal_id: AGENT_Y,
          principal_kind: 'agent_acting_for_principal',
          acting_agent_id: AGENT_X,
        },
      }),
    ]
    const result = cascadePrincipal(chain)
    assert.equal(result.chain_integrity, 'ok')
    assert.equal(result.principals.length, 1)
    assert.equal(result.principals[0].principal_id, PRIN_H)
    assert.equal(result.principals[0].principal_kind, 'human')
  })

  it('test 4: chain with only agent_acting_for_principal anchors reports missing_root_anchor', () => {
    const chain: DelegationChain = [
      makeDelegation({
        id: 'd1',
        delegator: AGENT_X,
        delegatee: AGENT_Y,
        anchor: {
          principal_id: AGENT_X,
          principal_kind: 'agent_acting_for_principal',
          acting_agent_id: 'agent:dangling',
        },
      }),
      makeDelegation({
        id: 'd2',
        delegator: AGENT_Y,
        delegatee: 'agent:leaf',
        anchor: {
          principal_id: AGENT_Y,
          principal_kind: 'agent_acting_for_principal',
          acting_agent_id: AGENT_X,
        },
      }),
    ]
    const result = cascadePrincipal(chain)
    assert.equal(result.chain_integrity, 'missing_root_anchor')
    assert.equal(result.principals.length, 0)
  })

  it('test 5: circular acting_agent_id reports circular', () => {
    const chain: DelegationChain = [
      makeDelegation({
        id: 'd1',
        delegator: AGENT_X,
        delegatee: AGENT_Y,
        anchor: {
          principal_id: AGENT_X,
          principal_kind: 'agent_acting_for_principal',
          acting_agent_id: AGENT_Y,
        },
      }),
      makeDelegation({
        id: 'd2',
        delegator: AGENT_Y,
        delegatee: AGENT_X,
        anchor: {
          principal_id: AGENT_Y,
          principal_kind: 'agent_acting_for_principal',
          acting_agent_id: AGENT_X,
        },
      }),
    ]
    const result = cascadePrincipal(chain)
    assert.equal(result.chain_integrity, 'circular')
    assert.equal(result.principals.length, 0)
  })

  it('test 6: legacy chain with no anchors falls back to root delegator', () => {
    const chain: DelegationChain = [
      makeDelegation({ id: 'd1', delegator: PRIN_A, delegatee: AGENT_X }),
      makeDelegation({ id: 'd2', delegator: AGENT_X, delegatee: AGENT_Y }),
      makeDelegation({ id: 'd3', delegator: AGENT_Y, delegatee: 'agent:leaf' }),
    ]
    const result = cascadePrincipal(chain)
    assert.equal(result.chain_integrity, 'ok')
    assert.equal(result.principals.length, 1)
    assert.equal(result.principals[0].principal_id, PRIN_A)
    assert.equal(result.principals[0].principal_kind, 'human')
  })
})

// ══════════════════════════════════════════════════════════════
// VALIDATOR TESTS
// ══════════════════════════════════════════════════════════════

describe('validateChainComposition', () => {
  it('test 7: catches missing acting_agent_id when kind is agent_acting_for_principal', () => {
    const chain: DelegationChain = [
      makeDelegation({
        id: 'd1',
        delegator: PRIN_H,
        delegatee: AGENT_X,
        anchor: { principal_id: PRIN_H, principal_kind: 'human' },
      }),
      makeDelegation({
        id: 'd2',
        delegator: AGENT_X,
        delegatee: 'agent:leaf',
        anchor: {
          principal_id: AGENT_X,
          principal_kind: 'agent_acting_for_principal',
          // acting_agent_id intentionally omitted
        },
      }),
    ]
    const result = validateChainComposition(chain)
    assert.equal(result.valid, false)
    assert.equal(
      result.failures.some((f) => f.includes('acting_agent_id')),
      true,
      `expected an acting_agent_id failure, got: ${result.failures.join(' | ')}`,
    )
  })

  it('test 8: catches infinite-agent chain with no human or org anchor', () => {
    const chain: DelegationChain = [
      makeDelegation({
        id: 'd1',
        delegator: AGENT_X,
        delegatee: AGENT_Y,
        anchor: {
          principal_id: AGENT_X,
          principal_kind: 'agent_acting_for_principal',
          acting_agent_id: 'agent:dangling',
        },
      }),
      makeDelegation({
        id: 'd2',
        delegator: AGENT_Y,
        delegatee: 'agent:leaf',
        anchor: {
          principal_id: AGENT_Y,
          principal_kind: 'agent_acting_for_principal',
          acting_agent_id: AGENT_X,
        },
      }),
    ]
    const result = validateChainComposition(chain)
    assert.equal(result.valid, false)
    assert.equal(
      result.failures.some((f) => f.includes('Infinite-agent chain')),
      true,
      `expected an infinite-agent failure, got: ${result.failures.join(' | ')}`,
    )
  })
})
