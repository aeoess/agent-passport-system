// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createPassport, createDelegation, verify, canonicalize,
  governLangChainTool, createLangGraphGovernance, langchainToolToScope,
} from '../src/index.js'
import type { ActionReceipt, LangChainToolCall } from '../src/index.js'

const pk = generateKeyPair()
const ak = generateKeyPair()
const { signedPassport } = createPassport({
  agentId: 'agent-lc-test', agentName: 'LC Test', ownerAlias: 'tima',
  mission: 'test', capabilities: ['tools'], runtime: { platform: 'node', version: process.version },
})
function mkDel(scopes: string[]) {
  return createDelegation({ delegatedTo: ak.publicKey, delegatedBy: pk.publicKey, scope: scopes, privateKey: pk.privateKey })
}
const mockExec = async (args: Record<string, unknown>) => ({ ok: true, ...args })

describe('LangChain Adapter v2', () => {
  it('authorized tool call produces receipt', async () => {
    const receipts: ActionReceipt[] = []
    const r = await governLangChainTool(
      { name: 'search', args: { q: 'test' } },
      mockExec,
      { passport: signedPassport, delegation: mkDel(['tools:search']), privateKey: ak.privateKey, onReceipt: r => receipts.push(r) },
    )
    assert.ok('output' in r && !('denied' in r))
    assert.deepStrictEqual(r.output, { ok: true, q: 'test' })
    assert.equal(receipts.length, 1)
    assert.ok(receipts[0].receiptId.startsWith('rcpt_lc_'))
  })

  it('denied tool call (scope) produces denial receipt', async () => {
    const r = await governLangChainTool(
      { name: 'admin_delete', args: {} },
      mockExec,
      { passport: signedPassport, delegation: mkDel(['tools:search']), privateKey: ak.privateKey },
    )
    assert.ok('denied' in r && r.denied === true)
    assert.ok(r.reason.includes('not covered'))
  })

  it('denied tool call (expired delegation)', async () => {
    const del = mkDel(['tools:search'])
    del.expiresAt = new Date(Date.now() - 1000).toISOString()
    const r = await governLangChainTool(
      { name: 'search', args: {} }, mockExec,
      { passport: signedPassport, delegation: del, privateKey: ak.privateKey },
    )
    assert.ok('denied' in r && r.denied === true)
  })

  it('custom scope mapping', () => {
    assert.equal(langchainToolToScope('search_google', { search_google: 'web:search' }), 'web:search')
  })

  it('default scope derivation', () => {
    assert.equal(langchainToolToScope('my_tool'), 'tools:my_tool')
  })

  it('LangGraph middleware creation', async () => {
    const middleware = createLangGraphGovernance({
      passport: signedPassport, delegation: mkDel(['tools:fetch']), privateKey: ak.privateKey,
    })
    const r = await middleware({ name: 'fetch', args: { url: 'x' } }, mockExec)
    assert.ok('output' in r)
  })

  it('receipt signature verifies', async () => {
    const r = await governLangChainTool(
      { name: 'search', args: {} }, mockExec,
      { passport: signedPassport, delegation: mkDel(['tools:search']), privateKey: ak.privateKey },
    )
    assert.ok('receipt' in r)
    const { signature, ...rest } = r.receipt
    assert.ok(verify(canonicalize(rest), signature, ak.publicKey))
  })

  it('onDenied callback fires', async () => {
    let called = false
    await governLangChainTool(
      { name: 'nope', args: {} }, mockExec,
      { passport: signedPassport, delegation: mkDel(['tools:other']), privateKey: ak.privateKey, onDenied: () => { called = true } },
    )
    assert.ok(called)
  })

  it('onReceipt callback fires on success', async () => {
    let called = false
    await governLangChainTool(
      { name: 'search', args: {} }, mockExec,
      { passport: signedPassport, delegation: mkDel(['tools:search']), privateKey: ak.privateKey, onReceipt: () => { called = true } },
    )
    assert.ok(called)
  })

  it('empty args handling', async () => {
    const r = await governLangChainTool(
      { name: 'ping', args: {} }, mockExec,
      { passport: signedPassport, delegation: mkDel(['tools:ping']), privateKey: ak.privateKey },
    )
    assert.ok('output' in r)
  })

  it('tool name with special chars', () => {
    assert.equal(langchainToolToScope('my-tool_v2.0'), 'tools:my-tool_v2.0')
  })

  it('batch sequential tool calls', async () => {
    const cfg = { passport: signedPassport, delegation: mkDel(['tools:a', 'tools:b']), privateKey: ak.privateKey }
    const r1 = await governLangChainTool({ name: 'a', args: {} }, mockExec, cfg)
    const r2 = await governLangChainTool({ name: 'b', args: {} }, mockExec, cfg)
    assert.ok('output' in r1 && 'output' in r2)
  })
})
