// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createPassport, createDelegation, verify, canonicalize,
  governMCPToolCall, createMCPGovernanceInterceptor, mcpToolToScope,
} from '../src/index.js'
import type { ActionReceipt, MCPToolCall } from '../src/index.js'

const pk = generateKeyPair()
const ak = generateKeyPair()
const { signedPassport } = createPassport({
  agentId: 'agent-mcp-test', agentName: 'MCP Test', ownerAlias: 'tima',
  mission: 'test', capabilities: ['mcp'], runtime: { platform: 'node', version: process.version },
})
function mkDel(scopes: string[]) {
  return createDelegation({ delegatedTo: ak.publicKey, delegatedBy: pk.publicKey, scope: scopes, privateKey: pk.privateKey })
}
const mockExec = async (args: Record<string, unknown>) => ({ ok: true, ...args })

describe('MCP Adapter', () => {
  it('authorized tool call produces receipt', async () => {
    const receipts: ActionReceipt[] = []
    const r = await governMCPToolCall(
      { name: 'read_file', arguments: { path: '/tmp/x' } },
      mockExec,
      { passport: signedPassport, delegation: mkDel(['tools:read_file']), privateKey: ak.privateKey, onReceipt: r => receipts.push(r) },
    )
    assert.ok('result' in r && !('denied' in r))
    assert.equal(receipts.length, 1)
    assert.ok(receipts[0].receiptId.startsWith('rcpt_mcp_'))
  })

  it('denied tool call produces denial receipt', async () => {
    const r = await governMCPToolCall(
      { name: 'write_file', arguments: {} },
      mockExec,
      { passport: signedPassport, delegation: mkDel(['tools:read_file']), privateKey: ak.privateKey },
    )
    assert.ok('denied' in r && r.denied === true)
    assert.ok(r.reason.includes('not covered'))
  })

  it('server-namespaced scope derivation', () => {
    assert.equal(mcpToolToScope({ name: 'query', arguments: {}, server: 'postgres' }, {}), 'mcp:postgres:query')
  })

  it('no-server scope derivation', () => {
    assert.equal(mcpToolToScope({ name: 'fetch', arguments: {} }, {}), 'tools:fetch')
  })

  it('destructive tool detection (delete)', () => {
    assert.equal(mcpToolToScope({ name: 'delete_row', arguments: {} }, {}), 'admin:delete_row')
  })

  it('destructive tool detection (drop)', () => {
    assert.equal(mcpToolToScope({ name: 'drop_table', arguments: {}, server: 'db' }, {}), 'admin:db:drop_table')
  })

  it('destructive tool detection (remove)', () => {
    assert.ok(mcpToolToScope({ name: 'remove_item', arguments: {} }, {}).startsWith('admin:'))
  })

  it('custom destructive tools list', () => {
    assert.equal(mcpToolToScope({ name: 'nuke', arguments: {} }, { destructiveTools: ['nuke'] }), 'admin:nuke')
    assert.equal(mcpToolToScope({ name: 'delete_row', arguments: {} }, { destructiveTools: ['nuke'] }), 'tools:delete_row')
  })

  it('custom scope prefix', () => {
    assert.equal(mcpToolToScope({ name: 'fetch', arguments: {} }, { scopePrefix: 'custom' }), 'custom:fetch')
  })

  it('interceptor creation and use', async () => {
    const interceptor = createMCPGovernanceInterceptor({
      passport: signedPassport, delegation: mkDel(['tools:ping']), privateKey: ak.privateKey,
    })
    const r = await interceptor({ name: 'ping', arguments: {} }, mockExec)
    assert.ok('result' in r)
  })

  it('receipt signature verifies', async () => {
    const r = await governMCPToolCall(
      { name: 'read', arguments: {} }, mockExec,
      { passport: signedPassport, delegation: mkDel(['tools:read']), privateKey: ak.privateKey },
    )
    assert.ok('receipt' in r)
    const { signature, ...rest } = r.receipt
    assert.ok(verify(canonicalize(rest), signature, ak.publicKey))
  })

  it('expired delegation denial', async () => {
    const del = mkDel(['tools:read'])
    del.expiresAt = new Date(Date.now() - 1000).toISOString()
    const r = await governMCPToolCall(
      { name: 'read', arguments: {} }, mockExec,
      { passport: signedPassport, delegation: del, privateKey: ak.privateKey },
    )
    assert.ok('denied' in r)
  })

  it('empty arguments handling', async () => {
    const r = await governMCPToolCall(
      { name: 'ping', arguments: {} }, mockExec,
      { passport: signedPassport, delegation: mkDel(['tools:ping']), privateKey: ak.privateKey },
    )
    assert.ok('result' in r)
  })
})
