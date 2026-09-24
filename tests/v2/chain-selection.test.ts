// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// src/v2/chain-selection: draft-03 section 3.3 lines 594-596, "Each action selects one
// root-to-leaf authority chain.  A verifier MUST NOT union scopes or budgets from
// multiple chains.  Cross-principal composition requires a separate profile."
//
// Two files cover this module. This one runs the recorded parity vectors, which are the
// same bytes the Python SDK runs, and then the properties a vector table cannot state:
// that no second chain is reachable from a decision, and that the module never throws.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { createHash } from 'node:crypto'
import { publicKeyFromPrivate } from '../../src/crypto/keys.js'
import {
  InMemoryAuthorityBudgetLedger,
  issueAuthorityDelegation,
} from '../../src/v2/authority-delegation/index.js'
import type {
  AuthorityDelegationV1,
  RevocationResolution,
} from '../../src/v2/authority-delegation/index.js'
import {
  CHAIN_SELECTION_EVALUATION_CODES,
  CHAIN_SELECTION_FAILURE_CODES,
  selectChainForAction,
  selectWithFallback,
} from '../../src/v2/chain-selection/index.js'
import type { HeldChain, SelectionOutcome } from '../../src/v2/chain-selection/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const VECTORS = JSON.parse(
  readFileSync(join(here, '../../fixtures/chain-selection/chain-selection-vectors-v0.json'), 'utf8'),
) as VectorFile

interface VectorFile {
  now: string
  verification_keys: Record<string, string>
  records: Record<string, AuthorityDelegationV1>
  delegation_ids: Record<string, string>
  chains: Record<string, string[]>
  cases: VectorCase[]
}

interface VectorCase {
  id: string
  api: 'selectChainForAction' | 'selectWithFallback'
  held: string[]
  preferred_chain_id: string | null
  fallback: { authorization_ref: string } | null
  required_grants: string[]
  required_spend: { unit: string; amount: string; action_ref: string } | null
  ledger: 'none' | 'fresh_in_memory'
  revocation: Record<string, RevocationResolution>
  expected: Record<string, unknown>
}

const LABEL_BY_ID: Record<string, string> = Object.fromEntries(
  Object.entries(VECTORS.delegation_ids).map(([label, id]) => [id, label]),
)

function heldFor(vector: VectorCase): HeldChain[] {
  return vector.held.map(name => ({
    chain_id: name,
    chain: VECTORS.chains[name].map(label => VECTORS.records[label]),
  }))
}

function optionsFor(vector: VectorCase) {
  return {
    now: VECTORS.now,
    resolveVerificationKey: (_issuer: string, method: string) => VECTORS.verification_keys[method] ?? null,
    trustRoot: () => true,
    resolveRevocation: (delegation: AuthorityDelegationV1): RevocationResolution => {
      const label = LABEL_BY_ID[delegation.delegation_id]
      const answer = label === undefined ? undefined : vector.revocation[label]
      // Fail loud: a case with no declared answer must not read as active.
      if (answer === undefined) throw new Error(`no revocation answer for ${label ?? 'an unknown record'}`)
      return answer
    },
  }
}

function runVector(vector: VectorCase): SelectionOutcome {
  const shared = {
    held: heldFor(vector),
    requiredGrants: vector.required_grants,
    requiredSpend: vector.required_spend,
    options: optionsFor(vector),
    reserveBudget: vector.ledger === 'none' ? null : new InMemoryAuthorityBudgetLedger(),
  }
  return vector.api === 'selectChainForAction'
    ? selectChainForAction(shared)
    : selectWithFallback({
        ...shared,
        preferred_chain_id: vector.preferred_chain_id as string,
        fallback: vector.fallback,
      })
}

function flatten(outcome: SelectionOutcome): Record<string, unknown> {
  const flat: Record<string, unknown> = {
    selected: outcome.selected,
    evaluations: outcome.evaluations.map(item => ({
      chain_id: item.chain_id,
      outcome: item.outcome,
      code: item.code,
      chain_state: item.chain_state,
    })),
  }
  if (outcome.selected) {
    flat.chain_id = outcome.chain_id
    flat.state = outcome.result.state
    if (outcome.switched_from !== undefined) flat.switched_from = outcome.switched_from
    if (outcome.fallback_ref !== undefined) flat.fallback_ref = outcome.fallback_ref
  } else {
    flat.code = outcome.code
  }
  if (outcome.fallback_considered !== undefined) flat.fallback_considered = outcome.fallback_considered
  return flat
}

test('the selection surface is reachable from the package root', async () => {
  // Release check, not a unit test. A symbol implemented under src but absent from
  // src/index.ts is not reachable through the package root consumers install.
  const api = await import('../../src/index.js')
  assert.equal(typeof api.selectChainForAction, 'function')
  assert.equal(typeof api.selectWithFallback, 'function')
  assert.ok(Array.isArray(api.CHAIN_SELECTION_FAILURE_CODES))
  assert.ok(Array.isArray(api.CHAIN_SELECTION_EVALUATION_CODES))
  assert.equal(api.HELD_SET_CEILING, 256)
})

test('the recorded chain-selection vectors reproduce', () => {
  assert.equal(VECTORS.cases.length, 19)
  for (const vector of VECTORS.cases) {
    assert.deepEqual(flatten(runVector(vector)), vector.expected, vector.id)
  }
})

test('every recorded code is a declared code of this module or of a component it calls', () => {
  const own = new Set<string>([...CHAIN_SELECTION_EVALUATION_CODES, ...CHAIN_SELECTION_FAILURE_CODES])
  // Codes the chain verifier and the ledger produce are passed through unchanged, so this
  // list is the set of pass-throughs the vectors exercise, not a second vocabulary.
  const passthrough = new Set(['REVOKED', 'REVOCATION_UNKNOWN', 'PER_ACTION_EXCEEDED', 'RESERVED'])
  for (const vector of VECTORS.cases) {
    const expected = vector.expected as { code?: string; evaluations: { code: string }[] }
    if (expected.code) assert.ok(own.has(expected.code), `${vector.id}: ${expected.code}`)
    for (const evaluation of expected.evaluations) {
      assert.ok(own.has(evaluation.code) || passthrough.has(evaluation.code), `${vector.id}: ${evaluation.code}`)
    }
  }
})

// ── properties a vector table cannot state ────────────────────────────────────

const SEED = createHash('sha256').update('agent-passport-system:chain-selection-test:p', 'utf8').digest('hex')
const ISSUER = 'did:example:chain-selection-test-root'
const VM = `${ISSUER}#key-1`

function mint(grants: string[], ceiling: string, nonce: string): AuthorityDelegationV1 {
  return issueAuthorityDelegation(
    {
      record_type: 'aps:authority-delegation:v1',
      version: '1.0',
      parent_delegation_id: null,
      issuer: ISSUER,
      subject: 'did:example:chain-selection-test-leaf',
      verification_method: VM,
      issued_at: '2026-03-01T00:00:00.000Z',
      nonce,
      authority: {
        scope: { profile: 'aps-hierarchical-v1', grants },
        spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: ceiling, cumulative: ceiling },
        depth: { remaining: 1 },
        time: { not_before: '2026-03-01T00:00:00.000Z', not_after: '2026-04-01T00:00:00.000Z' },
        reputation: { profile: 'aps-score-0-100-v1', ceiling: 100 },
        values: { profile: 'aps-values-identifiers-v1', required: [] },
        reversibility: { profile: 'aps-tci-v1', ceiling: 'irreversible' },
      },
    },
    SEED,
  )
}

const PUBLIC_KEY = publicKeyFromPrivate(SEED)

const OPTIONS = {
  now: '2026-03-15T00:00:00.000Z',
  resolveVerificationKey: (_issuer: string, method: string) => (method === VM ? PUBLIC_KEY : null),
  trustRoot: () => true,
  resolveRevocation: (): RevocationResolution => 'active',
}

test('a refused selection reserves nothing against any chain', () => {
  const a = mint(['resource1:read'], '5', '00000000000000000000000000000001')
  const b = mint(['resource1:read'], '5', '00000000000000000000000000000002')
  const ledger = new InMemoryAuthorityBudgetLedger()
  const outcome = selectChainForAction({
    held: [{ chain_id: 'a', chain: [a] }, { chain_id: 'b', chain: [b] }],
    requiredGrants: ['resource1:read'],
    requiredSpend: { unit: 'iso4217:USD:minor', amount: '8', action_ref: 'a'.repeat(64) },
    options: OPTIONS,
    reserveBudget: ledger,
  })
  assert.equal(outcome.selected, false)
  // Neither chain's counter moved: a refusal is not a partial reservation, and the
  // second chain was never reached, so its ceiling could not have been added to the first.
  assert.deepEqual(ledger.counter(a.delegation_id), { reserved: '0', committed: '0' })
  assert.deepEqual(ledger.counter(b.delegation_id), { reserved: '0', committed: '0' })
})

test('a selection reserves against exactly one chain, never both', () => {
  const a = mint(['resource1:read'], '5', '00000000000000000000000000000003')
  const b = mint(['resource1:read'], '5', '00000000000000000000000000000004')
  const ledger = new InMemoryAuthorityBudgetLedger()
  const outcome = selectChainForAction({
    held: [{ chain_id: 'a', chain: [a] }, { chain_id: 'b', chain: [b] }],
    requiredGrants: ['resource1:read'],
    requiredSpend: { unit: 'iso4217:USD:minor', amount: '4', action_ref: 'b'.repeat(64) },
    options: OPTIONS,
    reserveBudget: ledger,
  })
  assert.equal(outcome.selected, true)
  assert.equal(outcome.selected && outcome.chain_id, 'a')
  assert.deepEqual(ledger.counter(a.delegation_id), { reserved: '4', committed: '0' })
  assert.deepEqual(ledger.counter(b.delegation_id), { reserved: '0', committed: '0' })
})

test('fallback null never hands a second chain to any callback', () => {
  const a = mint(['resource1:read'], '5', '00000000000000000000000000000005')
  const b = mint(['resource1:read'], '5', '00000000000000000000000000000006')
  const seenByRevocation: string[] = []
  const outcome = selectWithFallback({
    held: [{ chain_id: 'a', chain: [a] }, { chain_id: 'b', chain: [b] }],
    requiredGrants: ['resource1:read'],
    requiredSpend: null,
    options: {
      ...OPTIONS,
      resolveRevocation: (delegation: AuthorityDelegationV1): RevocationResolution => {
        seenByRevocation.push(delegation.delegation_id)
        return 'revoked'
      },
    },
    preferred_chain_id: 'a',
    fallback: null,
  })
  assert.equal(outcome.selected, false)
  assert.equal(outcome.selected === false && outcome.code, 'no_valid_chain')
  assert.equal(outcome.fallback_considered, false)
  assert.deepEqual(seenByRevocation, [a.delegation_id])
  assert.equal(outcome.evaluations.length, 1)
})

test('an authorized fallback names what it switched from and the reference it was given', () => {
  const a = mint(['resource1:read'], '5', '00000000000000000000000000000007')
  const b = mint(['resource1:read'], '5', '00000000000000000000000000000008')
  const outcome = selectWithFallback({
    held: [{ chain_id: 'a', chain: [a] }, { chain_id: 'b', chain: [b] }],
    requiredGrants: ['resource1:read'],
    requiredSpend: null,
    options: {
      ...OPTIONS,
      resolveRevocation: (delegation: AuthorityDelegationV1): RevocationResolution =>
        delegation.delegation_id === a.delegation_id ? 'revoked' : 'active',
    },
    preferred_chain_id: 'a',
    fallback: { authorization_ref: 'opaque-ref' },
  })
  assert.equal(outcome.selected, true)
  assert.equal(outcome.selected && outcome.chain_id, 'b')
  assert.equal(outcome.selected && outcome.switched_from, 'a')
  assert.equal(outcome.selected && outcome.fallback_ref, 'opaque-ref')
  // The reason the action left its selected chain stays in the record even though the
  // fallback succeeded. A later finding does not rewrite an earlier one.
  assert.equal(outcome.evaluations[0].chain_id, 'a')
  assert.equal(outcome.evaluations[0].code, 'REVOKED')
})

test('an authorization object with no usable reference does not switch', () => {
  const a = mint(['resource1:read'], '5', '00000000000000000000000000000009')
  const b = mint(['resource1:read'], '5', '0000000000000000000000000000000a')
  const outcome = selectWithFallback({
    held: [{ chain_id: 'a', chain: [a] }, { chain_id: 'b', chain: [b] }],
    requiredGrants: ['resource1:read'],
    requiredSpend: null,
    options: { ...OPTIONS, resolveRevocation: (): RevocationResolution => 'revoked' },
    preferred_chain_id: 'a',
    fallback: { authorization_ref: '' },
  })
  assert.equal(outcome.selected, false)
  assert.equal(outcome.selected === false && outcome.code, 'invalid_action_requirement')
})

test('neither entry point throws on hostile input', () => {
  const hostile: unknown[] = [
    undefined,
    null,
    {},
    { held: 'not-an-array', requiredGrants: [], options: OPTIONS },
    { held: [{ chain_id: 'a' }], requiredGrants: [], options: OPTIONS },
    { held: [{ get chain_id() { throw new Error('boom') }, chain: [] }], requiredGrants: [], options: OPTIONS },
    { held: [{ chain_id: 'a', chain: [] }], requiredGrants: [], options: OPTIONS },
    { held: [{ chain_id: 'a', chain: [{}] }], requiredGrants: ['x:y'], options: OPTIONS },
    { held: new Array(300).fill({ chain_id: 'a', chain: [] }), requiredGrants: [], options: OPTIONS },
  ]
  for (const input of hostile) {
    const first = selectChainForAction(input as never)
    assert.equal(typeof first.selected, 'boolean')
    const second = selectWithFallback({ ...(input as object), preferred_chain_id: 'a', fallback: null } as never)
    assert.equal(typeof second.selected, 'boolean')
  }
})

test('a caller mutating its own chain after the call cannot change what was decided', () => {
  const a = mint(['resource1:read'], '5', '0000000000000000000000000000000b')
  const chain = [{ ...a }]
  const outcome = selectChainForAction({
    held: [{ chain_id: 'a', chain }],
    requiredGrants: ['resource1:read'],
    requiredSpend: null,
    options: OPTIONS,
  })
  assert.equal(outcome.selected, true)
  chain[0].subject = 'did:example:someone-else'
  assert.equal(outcome.selected && outcome.chain_id, 'a')
  assert.equal(outcome.selected && outcome.result.state, 'valid')
})
