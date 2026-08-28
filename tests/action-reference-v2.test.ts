// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  computeActionRefV2,
  computeActionRefV2FromJson,
  computePayloadRefV1,
  createActionReferenceInputV2,
  parseActionReferenceInputV2,
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

describe('action_ref v2 serialized input, strict duplicate-member parsing', () => {
  // A well-formed document, written out as the bytes a peer would send.
  const doc = {
    profile: 'aps-action-ref-v2',
    agent_id: 'did:example:agent',
    action_type: 'mcp:tools/call',
    target: 'https://mcp.example#tool=checkout',
    payload_ref: computePayloadRefV1({ cart: ['sku-1'] }),
    scope_required: ['commerce:write'],
    issued_at: '2026-07-17T00:00:00.000Z',
    nonce: '11'.repeat(16),
  }
  const clean = JSON.stringify(doc)
  // JSON.stringify cannot emit a duplicate member, so the duplicate is spliced
  // in textually. That is the point: the fact only exists in the byte stream.
  const withDuplicate = clean.replace(
    '"agent_id":"did:example:agent"',
    '"agent_id":"did:example:agent","agent_id":"did:example:attacker"',
  )
  // Same member name reached through an escape alias rather than a literal
  // repeat, so this is rejected only if names are compared AFTER decoding.
  const withEscapedDuplicate = clean.replace(
    '"agent_id":"did:example:agent"',
    '"agent_id":"did:example:agent","\\u0061gent_id":"did:example:attacker"',
  )

  it('the duplicate is genuinely present in the raw bytes', () => {
    // Guards the fixture itself: if the splice silently failed, the rejection
    // tests below would pass for the wrong reason.
    assert.notEqual(withDuplicate, clean)
    assert.notEqual(withEscapedDuplicate, clean)
    assert.equal(withDuplicate.match(/"agent_id":/g)?.length, 2)
    // And a permissive parser really does lose it, which is why validation
    // downstream of JSON.parse can never see this.
    assert.equal((JSON.parse(withDuplicate) as { agent_id: string }).agent_id, 'did:example:attacker')
  })

  it('rejects a duplicated member name at parseActionReferenceInputV2', () => {
    assert.throws(() => parseActionReferenceInputV2(withDuplicate), /duplicate object member/)
  })

  it('rejects a duplicated member name at computeActionRefV2FromJson', () => {
    assert.throws(() => computeActionRefV2FromJson(withDuplicate), /duplicate object member/)
  })

  it('rejects an escape-aliased duplicate at both entry points', () => {
    assert.throws(() => parseActionReferenceInputV2(withEscapedDuplicate), /duplicate object member/)
    assert.throws(() => computeActionRefV2FromJson(withEscapedDuplicate), /duplicate object member/)
  })

  it('accepts the same document without the duplicate', () => {
    const parsed = parseActionReferenceInputV2(clean)
    assert.equal(parsed.agent_id, 'did:example:agent')
    assert.match(computeActionRefV2FromJson(clean), /^[0-9a-f]{64}$/)
  })

  it('agrees digest-for-digest with the already-parsed path', () => {
    // Proves the serialized path is the existing path plus parsing, not a
    // second implementation that could drift.
    assert.equal(computeActionRefV2FromJson(clean), computeActionRefV2(parseActionReferenceInputV2(clean)))
    assert.equal(computeActionRefV2FromJson(clean), computeActionRefV2(createActionReferenceInputV2({
      agent_id: doc.agent_id,
      action_type: doc.action_type,
      target: doc.target,
      payload_ref: doc.payload_ref,
      scope_required: doc.scope_required,
      issued_at: doc.issued_at,
      nonce: doc.nonce,
    })))
  })

  it('does not weaken the existing validation it wraps', () => {
    const wrongProfile = clean.replace('"aps-action-ref-v2"', '"aps-action-ref-v1"')
    assert.throws(() => parseActionReferenceInputV2(wrongProfile), /action reference profile/)
    const badNonce = clean.replace(doc.nonce, 'zz'.repeat(16))
    assert.throws(() => parseActionReferenceInputV2(badNonce))
    const extraKey = clean.replace('"profile":', '"unexpected":1,"profile":')
    assert.throws(() => parseActionReferenceInputV2(extraKey))
  })
})
