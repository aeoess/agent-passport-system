// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { computeActionRef, actionRefsMatch } from '../src/core/action-ref.js'
import { canonicalHashJCS } from '../src/core/canonical-jcs.js'
import { createActionIntent, createPolicyReceipt, verifyActionIntent } from '../src/core/policy.js'
import { generateKeyPair } from '../src/crypto/keys.js'
import type { ActionIntent, PolicyDecision } from '../src/types/policy.js'
import type { ActionReceipt } from '../src/types/passport.js'

describe('action_ref — Content-Addressed Request Identity (A2A#1672)', () => {
  const baseIntent = {
    agentId: 'agent_abc',
    action: { type: 'code_execution', target: 'repo/file.ts', scopeRequired: 'repo:write' },
    createdAt: '2026-04-05T03:39:31.000Z'
  }

  it('returns the same ref for identical inputs', () => {
    assert.equal(computeActionRef(baseIntent), computeActionRef(baseIntent))
  })

  it('returns 64-char lowercase hex', () => {
    const ref = computeActionRef(baseIntent)
    assert.match(ref, /^[0-9a-f]{64}$/)
  })

  it('is invariant to sub-second timestamp drift (second precision)', () => {
    const a = { ...baseIntent, createdAt: '2026-04-05T03:39:31.001Z' }
    const b = { ...baseIntent, createdAt: '2026-04-05T03:39:31.999Z' }
    assert.equal(computeActionRef(a), computeActionRef(b))
  })

  it('differs when timestamps are in different seconds', () => {
    const a = { ...baseIntent, createdAt: '2026-04-05T03:39:31.000Z' }
    const b = { ...baseIntent, createdAt: '2026-04-05T03:39:32.000Z' }
    assert.notEqual(computeActionRef(a), computeActionRef(b))
  })

  it('differs when agentId differs', () => {
    assert.notEqual(
      computeActionRef(baseIntent),
      computeActionRef({ ...baseIntent, agentId: 'agent_xyz' })
    )
  })

  it('differs when action.type differs', () => {
    assert.notEqual(
      computeActionRef(baseIntent),
      computeActionRef({ ...baseIntent, action: { ...baseIntent.action, type: 'web_search' } })
    )
  })

  it('differs when scopeRequired differs', () => {
    assert.notEqual(
      computeActionRef(baseIntent),
      computeActionRef({ ...baseIntent, action: { ...baseIntent.action, scopeRequired: 'repo:read' } })
    )
  })

  it('actionRefsMatch returns true for equal non-empty strings, false otherwise', () => {
    const ref = computeActionRef(baseIntent)
    assert.ok(actionRefsMatch(ref, ref))
    assert.ok(!actionRefsMatch(ref, 'different'))
    assert.ok(!actionRefsMatch('', ''))
  })

  it('action_ref preserves null-valued keys per RFC 8785', () => {
    // Strict-JCS conformance pin per draft-pidlisnyi-aps-01 §4.1. Null
    // scopeRequired (or any null pre-image field) MUST be preserved in
    // the canonical bytes — not stripped — so the action_ref byte-matches
    // any other strict-JCS implementation (x402 ecosystem, AgentGraph CTEF,
    // Nobulex). The expected hash below is the SHA-256 of the strict
    // canonical form, independently reproduced by canonicalize@3.0.0
    // (erdtman, RFC 8785 author) and rfc8785@0.1.4 (PyPI).
    const intent = {
      agentId: 'a',
      action: { type: 't', target: '-', scopeRequired: null as unknown as string },
      createdAt: '2026-05-21T00:00:00Z',
    }
    const expected = '0c7573a9f120b37bda5648bea097181bf3261c0739c2f465fb878879c21c4c47'
    assert.equal(computeActionRef(intent), expected)
  })
})

describe('action_ref integration — createActionIntent + createPolicyReceipt', () => {
  it('createActionIntent auto-populates actionRef', () => {
    const kp = generateKeyPair()
    const intent = createActionIntent({
      agentId: 'agent_int',
      agentPublicKey: kp.publicKey,
      delegationId: 'del_1',
      action: { type: 'web_search', target: 'example.com', scopeRequired: 'web:read' },
      privateKey: kp.privateKey,
    })
    assert.ok(intent.actionRef)
    assert.equal(intent.actionRef!.length, 64)
    // actionRef matches what computeActionRef would produce
    assert.equal(intent.actionRef, computeActionRef(intent))
  })

  it('signed intent verifies (signature covers the actionRef field)', () => {
    const kp = generateKeyPair()
    const intent = createActionIntent({
      agentId: 'agent_sig',
      agentPublicKey: kp.publicKey,
      delegationId: 'del_2',
      action: { type: 'code_execution', target: 't', scopeRequired: 'repo:write' },
      privateKey: kp.privateKey,
    })
    // canonicalize+verify is called from verifyActionIntent; prove round-trip works
    const result = verifyActionIntent(intent)
    assert.ok(result.valid, `verifyActionIntent failed: ${result.errors.join(', ')}`)
  })

  it('PolicyReceipt carries actionRef (request identity) separate from compoundDigest', () => {
    const agentKp = generateKeyPair()
    const verifierKp = generateKeyPair()
    const intent = createActionIntent({
      agentId: 'agent_pr',
      agentPublicKey: agentKp.publicKey,
      delegationId: 'del_3',
      action: { type: 'code_execution', target: 't', scopeRequired: 'repo:write' },
      privateKey: agentKp.privateKey,
    })
    const decision: PolicyDecision = {
      decisionId: 'pdec_x',
      intentId: intent.intentId,
      evaluatorId: 'eval_1',
      evaluatorPublicKey: verifierKp.publicKey,
      verdict: 'permit',
      principlesEvaluated: [],
      reason: 'ok',
      floorVersion: '0.1',
      evaluatedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60000).toISOString(),
      signature: 'fakesig'
    }
    const receipt: ActionReceipt = {
      receiptId: 'rcpt_x',
      version: '1.0',
      timestamp: new Date().toISOString(),
      agentId: intent.agentId,
      delegationId: intent.delegationId,
      action: { type: intent.action.type, target: intent.action.target, scopeUsed: intent.action.scopeRequired },
      result: { status: 'success', summary: 'ok' },
      delegationChain: [],
      signature: 'fakesig2'
    }
    const pr = createPolicyReceipt({
      intent, decision, receipt,
      verifierPrivateKey: verifierKp.privateKey
    })
    assert.equal(pr.actionRef, intent.actionRef)
    // compoundDigest is undefined by default; actionRef is independently populated
    assert.notEqual(pr.actionRef, pr.compoundDigest)
  })
})

describe('action_ref scopeRequired canonicalization (draft-pidlisnyi-aps-03 section 4.1)', () => {
  const at = '2026-07-10T00:00:00Z'
  const mk = (scopeRequired: string | readonly string[]) => ({
    agentId: 'agent_canon',
    action: { type: 'code_execution', target: 't', scopeRequired },
    createdAt: at,
  })

  it('multi-scope: unsorted input hashes identically to sorted input, caller array untouched', () => {
    const unsorted = ['repo:write', 'admin:keys', 'commerce:read']
    const sorted = ['admin:keys', 'commerce:read', 'repo:write']
    assert.equal(computeActionRef(mk(unsorted)), computeActionRef(mk(sorted)))
    // never mutate caller input
    assert.deepEqual(unsorted, ['repo:write', 'admin:keys', 'commerce:read'])
  })

  it('NFD and NFC forms of the same scope hash identically', () => {
    const nfd = 'cafe\u0301:read' // e followed by U+0301 combining acute
    const nfc = 'caf\u00e9:read' // precomposed U+00E9
    assert.notEqual(nfd, nfc) // different code points before normalization
    assert.equal(computeActionRef(mk([nfd])), computeActionRef(mk([nfc])))
    // the single-string form (current ActionIntent type) is normalized too
    assert.equal(computeActionRef(mk(nfd)), computeActionRef(mk(nfc)))
  })

  it('sorts by code point: astral-plane scope orders AFTER a U+E000..U+FFFF scope', () => {
    const bmpHigh = 'scope:\uFF21' // U+FF21 FULLWIDTH LATIN CAPITAL A, inside U+E000..U+FFFF
    const astral = 'scope:\u{10400}' // U+10400, UTF-16 surrogate pair 0xD801 0xDC00
    // Default JS sort compares UTF-16 code units and puts the astral scope
    // FIRST (0xD801 < 0xFF21); pin that hazard, then pin the correct order.
    assert.equal([astral, bmpHigh].sort()[0], astral)
    const correctOrder = canonicalHashJCS({
      agentId: 'agent_canon',
      actionType: 'code_execution',
      scopeRequired: [bmpHigh, astral], // code-point order: U+FF21 < U+10400
      timestamp: at,
    })
    const utf16Order = canonicalHashJCS({
      agentId: 'agent_canon',
      actionType: 'code_execution',
      scopeRequired: [astral, bmpHigh],
      timestamp: at,
    })
    assert.equal(computeActionRef(mk([astral, bmpHigh])), correctOrder)
    assert.notEqual(computeActionRef(mk([astral, bmpHigh])), utf16Order)
  })

  it('pre-existing single-scope ASCII refs are unchanged (recorded on main at 61cd79c before this change)', () => {
    const base = {
      agentId: 'agent_abc',
      action: { type: 'code_execution', target: 'repo/file.ts', scopeRequired: 'repo:write' },
      createdAt: '2026-04-05T03:39:31.000Z',
    }
    const pinned: Array<[string, () => string]> = [
      ['ca07f48910323ed98bab9fed8e3c64d4e1ae7ae670b5b5e9a0e915569daf1fe6', () => computeActionRef(base)],
      ['ca07f48910323ed98bab9fed8e3c64d4e1ae7ae670b5b5e9a0e915569daf1fe6', () => computeActionRef({ ...base, createdAt: '2026-04-05T03:39:31.001Z' })],
      ['9653f1d133ebfa650f731cc156bfd6f59bf7a8d2a0fc862208b0954b86f62199', () => computeActionRef({ ...base, createdAt: '2026-04-05T03:39:32.000Z' })],
      ['0eda4ac4154f3498b42829cd110295fbd30a59ce010619319f1cf577a7d5e641', () => computeActionRef({ ...base, agentId: 'agent_xyz' })],
      ['ce6baea251d3638bbadb99639cfe6d330c580a45d8403e867cb055fbdf28260d', () => computeActionRef({ ...base, action: { ...base.action, type: 'web_search' } })],
      ['acf66c590d870e1ebe906321be0195d84468814ac702ba6645cefb36340de32b', () => computeActionRef({ ...base, action: { ...base.action, scopeRequired: 'repo:read' } })],
      ['0c7573a9f120b37bda5648bea097181bf3261c0739c2f465fb878879c21c4c47', () => computeActionRef({ agentId: 'a', action: { type: 't', target: '-', scopeRequired: null as unknown as string }, createdAt: '2026-05-21T00:00:00Z' })],
    ]
    for (const [expected, compute] of pinned) {
      assert.equal(compute(), expected)
    }
  })
})

describe('action_ref canonical vectors fixture (consumed by the Go port, T2)', () => {
  const fixture = JSON.parse(
    readFileSync(new URL('./fixtures/actionref-canonical-vectors.json', import.meta.url), 'utf-8'),
  )
  for (const v of fixture.vectors) {
    it(`vector: ${v.name}`, () => {
      const ref = computeActionRef({
        agentId: v.input.agentId,
        action: { type: v.input.actionType, target: '-', scopeRequired: v.input.scopeRequired },
        createdAt: v.input.timestamp,
      })
      assert.equal(ref, v.action_ref)
    })
  }
})
