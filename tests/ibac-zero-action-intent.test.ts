// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// An expired delegation never yields a success receipt.
// ══════════════════════════════════════════════════════════════════
// governIBACIntent checks the delegation's expiry inside the per-tuple map, so
// with zero tuples the check never runs. `[].every(...)` is vacuously true, and
// the adapter signs a receipt reading `success` / "All 0 IBAC tuples
// authorized" against a delegation that expired, or whose expiry it cannot
// read at all.
//
// That is contract-neutral to fix: the adapter's own per-tuple path already
// denies on both conditions, so hoisting the check changes no answer that was
// ever computed. It only supplies one where none was.
//
// Whether a zero-action intent is valid input, and what a receipt for one
// should say when the delegation IS good, is a separate question and is not
// decided here. See the session 1b report, item 3(b).
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import { createPassport, signPassport } from '../src/core/passport.js'
import { createDelegation } from '../src/core/delegation.js'
import { governIBACIntent, evaluateIBACTuples } from '../src/adapters/ibac.js'
import type { Delegation } from '../src/types/passport.js'
import type { IBACIntent } from '../src/adapters/ibac.js'

const principal = generateKeyPair()

function fixture() {
  const { signedPassport, keyPair } = createPassport({
    agentId: 'ibac-agent-1',
    agentName: 'ibac-agent', ownerAlias: 'owner', mission: 'm',
    capabilities: ['read'], runtime: { platform: 'node', models: ['m'], toolsCount: 0, memoryType: 'none' },
  })
  return { passport: signPassport(signedPassport.passport, keyPair.privateKey), agent: keyPair }
}

function delegationWith(expiresAt: string, agentKey: string): Delegation {
  const good = createDelegation({
    delegatedTo: agentKey, delegatedBy: principal.publicKey,
    scope: ['data:read:*'], privateKey: principal.privateKey,
  })
  return { ...good, expiresAt }
}

const PAST = '2020-01-01T00:00:00.000Z'
const FUTURE = '2099-01-01T00:00:00.000Z'

function intent(actions: IBACIntent['actions']): IBACIntent {
  return {
    task: 'read the thing',
    subject: { id: 'agent-1' },
    actions,
    timestamp: '2026-01-01T00:00:00.000Z',
  }
}

describe('governIBACIntent: the expiry check runs whatever the action count', () => {
  for (const [label, expiresAt] of [
    ['an expired delegation', PAST],
    ['a delegation whose expiry cannot be read', 'not-a-date'],
  ] as const) {
    it(`refuses a zero-action intent against ${label}`, () => {
      const { passport, agent } = fixture()
      const result = governIBACIntent(intent([]), {
        passport,
        delegation: delegationWith(expiresAt, agent.publicKey),
        privateKey: agent.privateKey,
      })
      assert.equal(result.receipt.result.status, 'failure',
        'a receipt signed against an unusable delegation must not read success')
    })

    it(`refuses a one-action intent against ${label}, as it always did`, () => {
      const { passport, agent } = fixture()
      const result = governIBACIntent(intent([{ verb: 'read', resource: 'doc' }]), {
        passport,
        delegation: delegationWith(expiresAt, agent.publicKey),
        privateKey: agent.privateKey,
      })
      assert.equal(result.receipt.result.status, 'failure')
    })
  }

  it('still authorizes a one-action intent against a live delegation', () => {
    const { passport, agent } = fixture()
    const result = governIBACIntent(intent([{ verb: 'read', resource: 'doc' }]), {
      passport,
      delegation: delegationWith(FUTURE, agent.publicKey),
      privateKey: agent.privateKey,
    })
    assert.equal(result.receipt.result.status, 'success')
    assert.equal(result.tupleResults.length, 1)
    assert.equal(result.tupleResults[0].authorized, true)
  })

  it('still denies an action outside the delegated scope', () => {
    const { passport, agent } = fixture()
    const result = governIBACIntent(intent([{ verb: 'delete', resource: 'doc' }]), {
      passport,
      delegation: delegationWith(FUTURE, agent.publicKey),
      privateKey: agent.privateKey,
    })
    assert.equal(result.receipt.result.status, 'failure')
  })

  it('evaluateIBACTuples is unchanged: the per-tuple path already denied on both', () => {
    // The hoist must not alter the answer this function was already giving,
    // which is what makes it contract-neutral.
    const { agent } = fixture()
    const tuples = [{ principal: 'agent:a', action: 'tool:read', resource: 'doc' }]
    for (const expiresAt of [PAST, 'not-a-date']) {
      const { tupleResults } = evaluateIBACTuples(tuples, delegationWith(expiresAt, agent.publicKey))
      assert.equal(tupleResults[0].authorized, false)
    }
    const live = evaluateIBACTuples(tuples, delegationWith(FUTURE, agent.publicKey))
    assert.equal(live.tupleResults[0].authorized, true)
  })
})
