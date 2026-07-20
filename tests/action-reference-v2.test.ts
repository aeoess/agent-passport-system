// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  computeActionRefV2,
  computePayloadRefV1,
  createActionReferenceInputV2,
} from '../src/v2/action-reference/v2.js'

describe('action_ref v2', () => {
  const base = () => createActionReferenceInputV2({
    agent_id: 'did:example:agent',
    action_type: 'mcp:tools/call',
    target: 'https://mcp.example#tool=checkout',
    payload_ref: computePayloadRefV1({ cart: ['sku-1'] }),
    scope_required: ['commerce:write'],
    issued_at: '2026-07-17T00:00:00.000Z',
    nonce: '11'.repeat(16),
  })

  it('is deterministic and domain-shaped', () => {
    assert.match(computeActionRefV2(base()), /^[0-9a-f]{64}$/)
    assert.equal(computeActionRefV2(base()), computeActionRefV2(base()))
  })

  it('binds target, payload, and nonce so same-second calls do not collide', () => {
    const original = base()
    assert.notEqual(computeActionRefV2(original), computeActionRefV2({ ...original, target: 'https://mcp.example#tool=refund' }))
    assert.notEqual(computeActionRefV2(original), computeActionRefV2({ ...original, payload_ref: computePayloadRefV1({ cart: ['sku-2'] }) }))
    assert.notEqual(computeActionRefV2(original), computeActionRefV2({ ...original, nonce: '12'.repeat(16) }))
  })

  it('normalizes and sorts scopes before hashing', () => {
    const first = createActionReferenceInputV2({
      ...base(),
      scope_required: ['repo:write', 'cafe\u0301:read'],
    })
    const second = createActionReferenceInputV2({
      ...base(),
      scope_required: ['caf\u00e9:read', 'repo:write'],
    })
    assert.equal(computeActionRefV2(first), computeActionRefV2(second))
  })
})
