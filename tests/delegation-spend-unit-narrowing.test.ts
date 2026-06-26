// ══════════════════════════════════════════════════════════════════
// Regression: subDelegate must carry the parent's spend unit forward
// ══════════════════════════════════════════════════════════════════
// subDelegate signed the raw opts.spendLimitUnit (undefined when the caller
// omitted it), silently dropping the parent's unit from the signed child. With
// the unit-resolution fallback treating a unit-less spendLimit as 'currency',
// an 'invocations' budget became a 'currency' budget two hops down: a unit
// change the narrowing guard is meant to forbid, invisible in the signed bytes.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, createDelegation, subDelegate } from '../src/index.js'

describe('subDelegate spend-unit narrowing', () => {
  it('carries the parent invocations unit into the signed child when the caller omits it', () => {
    const granter = generateKeyPair()
    const agent = generateKeyPair()
    const sub = generateKeyPair()

    const parent = createDelegation({
      delegatedBy: granter.publicKey, delegatedTo: agent.publicKey,
      scope: ['consult'], spendLimit: 5, spendLimitUnit: 'invocations',
      maxDepth: 3, privateKey: granter.privateKey,
    })

    // Caller omits spendLimitUnit on the child.
    const child = subDelegate({
      parentDelegation: parent, delegatedTo: sub.publicKey, scope: ['consult'],
      privateKey: agent.privateKey,
    })

    assert.equal(child.spendLimitUnit, 'invocations', 'child must inherit the parent unit, not drop it')
  })

  it('does not let the unit flip to currency across two hops', () => {
    const granter = generateKeyPair()
    const agent = generateKeyPair()
    const sub = generateKeyPair()
    const sub2 = generateKeyPair()

    const parent = createDelegation({
      delegatedBy: granter.publicKey, delegatedTo: agent.publicKey,
      scope: ['consult'], spendLimit: 5, spendLimitUnit: 'invocations',
      maxDepth: 3, privateKey: granter.privateKey,
    })
    const child = subDelegate({ parentDelegation: parent, delegatedTo: sub.publicKey, scope: ['consult'], privateKey: agent.privateKey })
    const grandchild = subDelegate({ parentDelegation: child, delegatedTo: sub2.publicKey, scope: ['consult'], privateKey: sub.privateKey })
    assert.equal(grandchild.spendLimitUnit, 'invocations', 'unit must stay invocations across hops')
  })
})
