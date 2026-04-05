import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { computeActionRef, actionRefsMatch } from '../src/core/action-ref.js'
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
