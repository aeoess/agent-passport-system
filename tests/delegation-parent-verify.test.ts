// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Regression (round-2 sweep): subDelegate must verify the parent
// ══════════════════════════════════════════════════════════════════
// subDelegate checked only the parent's expiry timestamp, not its signature,
// so a parent with a forged signature could still mint an authority-bearing
// child. It now runs verifyDelegation(parent) first (parity with Python).
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, createDelegation, subDelegate } from '../src/index.js'

describe('subDelegate parent verification', () => {
  it('rejects a parent whose signature was tampered', () => {
    const granter = generateKeyPair()
    const agent = generateKeyPair()
    const sub = generateKeyPair()
    const parent = createDelegation({
      delegatedBy: granter.publicKey, delegatedTo: agent.publicKey,
      scope: ['data:read'], spendLimit: 100, maxDepth: 3, privateKey: granter.privateKey,
    })
    const tampered = {
      ...parent,
      signature: (parent.signature.startsWith('00') ? 'ff' : '00') + parent.signature.slice(2),
    }
    assert.throws(
      () => subDelegate({ parentDelegation: tampered, delegatedTo: sub.publicKey, scope: ['data:read'], privateKey: agent.privateKey }),
      /invalid parent/,
    )
  })

  it('still allows a legitimate sub-delegation from a valid parent', () => {
    const granter = generateKeyPair()
    const agent = generateKeyPair()
    const sub = generateKeyPair()
    const parent = createDelegation({
      delegatedBy: granter.publicKey, delegatedTo: agent.publicKey,
      scope: ['data:read'], spendLimit: 100, maxDepth: 3, privateKey: granter.privateKey,
    })
    const child = subDelegate({ parentDelegation: parent, delegatedTo: sub.publicKey, scope: ['data:read'], privateKey: agent.privateKey })
    assert.equal(child.delegatedBy, agent.publicKey)
  })
})
