// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createPassport, createDelegation,
  reportReceipt, reportEvaluation,
  governLangChainTool, governMCPToolCall, governCrewTask,
} from '../src/index.js'
import type { ActionReceipt, GatewayReporterConfig } from '../src/index.js'

const pk = generateKeyPair()
const ak = generateKeyPair()
const { signedPassport } = createPassport({
  agentId: 'agent-reporter-test', agentName: 'Reporter Test', ownerAlias: 'tima',
  mission: 'test', capabilities: ['tools'], runtime: { platform: 'node', version: process.version },
})
function mkDel(scopes: string[]) {
  return createDelegation({ delegatedTo: ak.publicKey, delegatedBy: pk.publicKey, scope: scopes, privateKey: pk.privateKey })
}

// Mock fetch tracking
let fetchCalls: Array<{ url: string; body: string; headers: Record<string, string> }> = []
const originalFetch = globalThis.fetch

function mockFetch(status = 201) {
  fetchCalls = []
  globalThis.fetch = async (url: any, opts: any) => {
    fetchCalls.push({ url: String(url), body: opts?.body || '', headers: opts?.headers || {} })
    return { ok: status < 400, status, text: async () => 'ok', json: async () => ({}) } as Response
  }
}

function restoreFetch() { globalThis.fetch = originalFetch }

const gwConfig: GatewayReporterConfig = { gatewayUrl: 'https://gateway.test', apiKey: 'aps_live_test123' }

describe('Gateway Receipt Reporter', () => {
  beforeEach(() => mockFetch())
  afterEach(() => restoreFetch())

  it('reportReceipt builds correct request body', async () => {
    const receipt: ActionReceipt = {
      receiptId: 'rcpt_test', version: '1.1', timestamp: new Date().toISOString(),
      agentId: 'agent-001', delegationId: 'del-001',
      action: { type: 'test', target: 'tool', scopeUsed: 'tools:test' },
      result: { status: 'success', summary: 'ok' },
      delegationChain: [], signature: 'sig123',
    }
    const r = await reportReceipt(receipt, gwConfig)
    assert.equal(r.ok, true)
    assert.equal(fetchCalls.length, 1)
    const body = JSON.parse(fetchCalls[0].body)
    assert.equal(body.agent_id, 'agent-001')
    assert.equal(body.verdict, 'permit')
    assert.equal(body.signature, 'sig123')
  })

  it('reportReceipt handles network error gracefully', async () => {
    globalThis.fetch = async () => { throw new Error('ECONNREFUSED') }
    const receipt: ActionReceipt = {
      receiptId: 'rcpt_fail', version: '1.1', timestamp: new Date().toISOString(),
      agentId: 'agent-001', delegationId: 'del-001',
      action: { type: 'test', target: 'tool', scopeUsed: 'x' },
      result: { status: 'failure', summary: 'denied' },
      delegationChain: [], signature: 'sig',
    }
    const r = await reportReceipt(receipt, gwConfig)
    assert.equal(r.ok, false)
    assert.ok(r.error?.includes('ECONNREFUSED'))
  })

  it('reportReceipt includes Authorization header', async () => {
    const receipt: ActionReceipt = {
      receiptId: 'rcpt_auth', version: '1.1', timestamp: new Date().toISOString(),
      agentId: 'a', delegationId: 'd',
      action: { type: 't', target: 't', scopeUsed: 's' },
      result: { status: 'success', summary: 'ok' },
      delegationChain: [], signature: 's',
    }
    await reportReceipt(receipt, gwConfig)
    assert.equal(fetchCalls[0].headers['Authorization'], 'Bearer aps_live_test123')
  })

  it('reportEvaluation sends correct payload', async () => {
    const r = await reportEvaluation('agent-001', 'tool_call', 'tools:read', 'permit', 'ok', gwConfig)
    assert.equal(r.ok, true)
    assert.equal(fetchCalls.length, 1)
    assert.ok(fetchCalls[0].url.includes('/api/v1/evaluate'))
    const body = JSON.parse(fetchCalls[0].body)
    assert.equal(body.agent_id, 'agent-001')
    assert.equal(body.scope_required, 'tools:read')
  })

  it('without gateway config, no fetch calls happen', async () => {
    await governLangChainTool(
      { name: 'search', args: {} },
      async () => ({ ok: true }),
      { passport: signedPassport, delegation: mkDel(['tools:search']), privateKey: ak.privateKey },
    )
    assert.equal(fetchCalls.length, 0)
  })

  it('governLangChainTool with gateway config fires fetch', async () => {
    await governLangChainTool(
      { name: 'search', args: {} },
      async () => ({ ok: true }),
      { passport: signedPassport, delegation: mkDel(['tools:search']), privateKey: ak.privateKey, gateway: gwConfig },
    )
    assert.ok(fetchCalls.length >= 1)
    assert.ok(fetchCalls[0].url.includes('/api/v1/receipt'))
  })

  it('governLangChainTool with gateway config does not throw when gateway unreachable', async () => {
    globalThis.fetch = async () => { throw new Error('ECONNREFUSED') }
    const r = await governLangChainTool(
      { name: 'search', args: {} },
      async () => ({ ok: true }),
      { passport: signedPassport, delegation: mkDel(['tools:search']), privateKey: ak.privateKey, gateway: gwConfig },
    )
    assert.ok('output' in r)
  })

  it('governMCPToolCall with gateway config does not throw when gateway unreachable', async () => {
    globalThis.fetch = async () => { throw new Error('ECONNREFUSED') }
    const r = await governMCPToolCall(
      { name: 'read', arguments: {} },
      async () => ({ ok: true }),
      { passport: signedPassport, delegation: mkDel(['tools:read']), privateKey: ak.privateKey, gateway: gwConfig },
    )
    assert.ok('result' in r)
  })

  it('governCrewTask with gateway config does not throw when gateway unreachable', async () => {
    globalThis.fetch = async () => { throw new Error('ECONNREFUSED') }
    const r = await governCrewTask(
      { description: 'test', agent: 'worker' },
      async () => ({ ok: true }),
      { passport: signedPassport, delegation: mkDel(['crew:execute:worker']), privateKey: ak.privateKey, gateway: gwConfig },
    )
    assert.ok('output' in r || 'denied' in r)
  })

  it('denial receipt is also reported to gateway', async () => {
    await governLangChainTool(
      { name: 'forbidden', args: {} },
      async () => ({ ok: true }),
      { passport: signedPassport, delegation: mkDel(['tools:other']), privateKey: ak.privateKey, gateway: gwConfig },
    )
    assert.ok(fetchCalls.length >= 1)
    const body = JSON.parse(fetchCalls[0].body)
    assert.equal(body.verdict, 'deny')
  })

  it('receipt payload matches gateway schema', async () => {
    await governMCPToolCall(
      { name: 'fetch', arguments: { url: 'x' } },
      async () => ({ data: 'ok' }),
      { passport: signedPassport, delegation: mkDel(['tools:fetch']), privateKey: ak.privateKey, gateway: gwConfig },
    )
    const body = JSON.parse(fetchCalls[0].body)
    assert.ok(body.agent_id, 'has agent_id')
    assert.ok(body.action_type, 'has action_type')
    assert.ok(body.verdict, 'has verdict')
    assert.ok(body.signature, 'has signature')
    assert.ok(body.payload, 'has payload')
  })
})
