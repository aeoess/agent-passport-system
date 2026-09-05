// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { generateKeyPair } from '../src/crypto/keys.js'
import {
  APS_MCP_AUTHORIZATION_META,
  APS_MCP_RECEIPT_META,
  ApsMcpAuthorizationError,
  createApsMcpUseMiddleware,
  issueApsMcpAuthorizationV1,
} from '../src/profiles/mcp/index.js'
import type { McpToolCallResult } from '../src/profiles/mcp/index.js'

// mcp-use@2.0.0 declares engines.node >=22.22.2. The adapter itself is pure
// TypeScript and runs anywhere the SDK runs, so the unit tests below are
// unconditional. The two checks that need the devDependency loaded, the
// compile-time conformance assertion and the real-server integration, are
// gated here and print why they were skipped rather than vanishing.
const NODE_MAJOR = Number(process.versions.node.split('.')[0])
const MCP_USE_RUNS_HERE = NODE_MAJOR >= 22
const SKIP_REASON =
  `mcp-use@2.0.0 requires Node >=22.22.2; this leg runs Node ${process.versions.node}`

const MCP_SERVER = 'https://mcp.example'
const TOOL = 'search'

function setup(overrides: { toolArguments?: Record<string, unknown> } = {}) {
  const agent = generateKeyPair()
  const toolArguments = overrides.toolArguments ?? { query: 'aps' }
  const issuedAt = new Date().toISOString()
  const expiresAt = new Date(Date.now() + 60_000).toISOString()
  const authorization = issueApsMcpAuthorizationV1({
    agent_id: 'did:key:zTestAgent',
    verification_method: 'did:key:zTestAgent#key-1',
    delegation_ref: 'aa'.repeat(32),
    mcp_server: MCP_SERVER,
    tool_name: TOOL,
    arguments: toolArguments,
    scope_required: ['mcp:tools/call'],
    nonce: 'bb'.repeat(16),
    issued_at: issuedAt,
    expires_at: expiresAt,
    private_key_hex: agent.privateKey,
  })
  const ctx = {
    method: 'tools/call' as const,
    params: {
      name: TOOL,
      arguments: toolArguments,
      _meta: {
        [APS_MCP_AUTHORIZATION_META]: authorization,
        'host.example/trace': 'keep-me',
      },
    },
    auth: { token: 'opaque' },
  }
  return { agent, authorization, ctx, toolArguments }
}

function baseOptions(agentPublicKey: string) {
  const seen = new Set<string>()
  return {
    mcp_server: MCP_SERVER,
    resolve_key: () => ({ state: 'resolved' as const, public_key_hex: agentPublicKey }),
    consume_action_ref: (ref: string) => seen.has(ref) ? false : (seen.add(ref), true),
    evaluate_authority: () => ({ state: 'permit' as const, code: 'OK' }),
    emit_receipt: () => ({ receipt_id: 'r1' }),
  }
}

describe('mcp-use adapter, ctx mapping', () => {
  it('maps ctx.params onto the profile request and passes _meta through untouched', async () => {
    const { agent, ctx, toolArguments } = setup()
    let seenRequest: unknown
    const middleware = createApsMcpUseMiddleware({
      ...baseOptions(agent.publicKey),
      evaluate_authority: (_authorization, request) => {
        seenRequest = request
        return { state: 'permit', code: 'OK' }
      },
    })
    const result = await middleware(ctx, async () => ({ content: [{ type: 'text', text: 'ok' }] }))

    assert.deepEqual(seenRequest, {
      method: 'tools/call',
      params: { name: TOOL, arguments: toolArguments, _meta: ctx.params._meta },
    })
    assert.equal((seenRequest as { params: { _meta: Record<string, unknown> } })
      .params._meta['host.example/trace'], 'keep-me')
    assert.ok(result._meta?.[APS_MCP_RECEIPT_META])
  })

  it('omits arguments and _meta from the request when the context has none', async () => {
    const { agent } = setup()
    let seenRequest: unknown
    const middleware = createApsMcpUseMiddleware({
      ...baseOptions(agent.publicKey),
      evaluate_authority: (_a, request) => { seenRequest = request; return { state: 'permit', code: 'OK' } },
    })
    await assert.rejects(
      () => middleware({ method: 'tools/call', params: { name: TOOL }, auth: {} }, async () => ({})),
      (error: unknown) => error instanceof ApsMcpAuthorizationError,
    )
    assert.equal(seenRequest, undefined)
  })
})

describe('mcp-use adapter, transport authentication', () => {
  it('rejects with MCP_TRANSPORT_UNAUTHENTICATED before next() when ctx.auth is absent', async () => {
    const { agent, ctx } = setup()
    let dispatched = 0
    const middleware = createApsMcpUseMiddleware(baseOptions(agent.publicKey))
    const { auth: _auth, ...ctxWithoutAuth } = ctx
    await assert.rejects(
      () => middleware(ctxWithoutAuth, async () => { dispatched++; return {} }),
      (error: unknown) =>
        error instanceof ApsMcpAuthorizationError && error.code === 'MCP_TRANSPORT_UNAUTHENTICATED',
    )
    assert.equal(dispatched, 0, 'the tool must not dispatch when the transport is unauthenticated')
  })

  it('uses the transport_authenticated override instead of ctx.auth when supplied', async () => {
    const { agent, ctx } = setup()
    const { auth: _auth, ...ctxWithoutAuth } = ctx
    let sawCtx: unknown
    const middleware = createApsMcpUseMiddleware({
      ...baseOptions(agent.publicKey),
      transport_authenticated: (c) => { sawCtx = c; return true },
    })
    const result = await middleware(ctxWithoutAuth, async () => ({ content: [] }))
    assert.equal(sawCtx, ctxWithoutAuth)
    assert.ok(result._meta?.[APS_MCP_RECEIPT_META])
  })
})

describe('mcp-use adapter, authorization outcomes', () => {
  it('rejects replay on the second call and dispatches exactly once', async () => {
    const { agent, ctx } = setup()
    let dispatched = 0
    const middleware = createApsMcpUseMiddleware(baseOptions(agent.publicKey))
    const first = await middleware(ctx, async () => { dispatched++; return { content: [] } })
    assert.ok(first._meta?.[APS_MCP_RECEIPT_META])
    await assert.rejects(
      () => middleware(ctx, async () => { dispatched++; return { content: [] } }),
      (error: unknown) =>
        error instanceof ApsMcpAuthorizationError && error.code === 'MCP_ACTION_REPLAY',
    )
    assert.equal(dispatched, 1)
  })

  it('does not dispatch when evaluate_authority denies', async () => {
    const { agent, ctx } = setup()
    let dispatched = 0
    const middleware = createApsMcpUseMiddleware({
      ...baseOptions(agent.publicKey),
      evaluate_authority: () => ({ state: 'deny', code: 'MCP_AUTHORITY_DENIED' }),
    })
    await assert.rejects(
      () => middleware(ctx, async () => { dispatched++; return {} }),
      (error: unknown) =>
        error instanceof ApsMcpAuthorizationError && error.code === 'MCP_AUTHORITY_DENIED',
    )
    assert.equal(dispatched, 0)
  })
})

describe('mcp-use adapter, conformance against the real package', () => {
  it('satisfies McpMiddlewareFnFor<"mcp:tools/call"> at compile time', { skip: MCP_USE_RUNS_HERE ? false : SKIP_REASON }, () => {
    if (!MCP_USE_RUNS_HERE) return
    // Compiles tests/typecheck-fixtures/mcp-use-conformance.ts against the real
    // mcp-use types. tsconfig.json excludes tests/, so this is the only run that
    // sees the assertion; without it the structural interface is asserted only
    // against itself.
    const out = execFileSync('npx', ['tsc', '-p', 'tsconfig.mcp-use.json'], {
      cwd: new URL('..', import.meta.url).pathname,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    assert.equal(out.trim(), '')
  })

  it('runs inside a real mcp-use server and attaches the receipt', { skip: MCP_USE_RUNS_HERE ? false : SKIP_REASON }, async () => {
    if (!MCP_USE_RUNS_HERE) return
    const { MCPServer } = await import('mcp-use')
    const { z } = await import('zod')
    const { agent, ctx } = setup()
    let dispatched = 0

    // `skills: false` keeps this harness about the middleware. mcp-use 2.1.0 gave
    // MCPServer.fetch() a conventional skills/ discovery pass, and this repository
    // has a skills/ directory; without this the server refuses to serve on a file
    // the adapter never touches. The option does not exist in 2.0.0, which ignores
    // it, so the block runs on both pins.
    const server = new MCPServer({ name: 'aps-adapter-test', version: '0.0.0', skills: false })
    server.tool(
      { name: TOOL, inputSchema: z.object({ query: z.string() }) },
      async () => { dispatched++; return { content: [{ type: 'text', text: 'ok' }] } },
    )
    // Registered exactly as a host would. The `use` overload resolves the
    // handler to McpMiddlewareFnFor<'mcp:tools/call'>, so this line is itself a
    // type check against the real package.
    server.use('mcp:tools/call', createApsMcpUseMiddleware({
      ...baseOptions(agent.publicKey),
      // No OAuth in this harness, so the fail-closed default would refuse.
      // Overriding here is what a host terminating auth elsewhere must do; the
      // default is proved separately above.
      transport_authenticated: () => true,
    }))

    const response = await server.fetch(new Request('http://local/mcp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: TOOL, arguments: ctx.params.arguments, _meta: ctx.params._meta },
      }),
    }))

    assert.equal(response.status, 200)
    const text = await response.text()
    const payload = JSON.parse(text.slice(text.indexOf('{'), text.lastIndexOf('}') + 1)) as {
      result?: McpToolCallResult
      error?: unknown
    }
    assert.equal(payload.error, undefined, `server returned an error: ${text}`)
    assert.equal(dispatched, 1, 'the tool must dispatch exactly once')
    assert.ok(
      payload.result?._meta?.[APS_MCP_RECEIPT_META],
      `receipt missing from the server result: ${text}`,
    )
    await server.close()
  })

  it('surfaces a refusal to the client as an MCP tool error, not a JSON-RPC error', { skip: MCP_USE_RUNS_HERE ? false : SKIP_REASON }, async () => {
    if (!MCP_USE_RUNS_HERE) return
    const { MCPServer } = await import('mcp-use')
    const { z } = await import('zod')
    const { agent } = setup()
    let dispatched = 0

    const server = new MCPServer({ name: 'aps-adapter-reject-test', version: '0.0.0', skills: false })
    server.tool(
      { name: TOOL, inputSchema: z.object({ query: z.string() }) },
      async () => { dispatched++; return { content: [{ type: 'text', text: 'ok' }] } },
    )
    // No transport_authenticated override, so the fail-closed default refuses.
    server.use('mcp:tools/call', createApsMcpUseMiddleware(baseOptions(agent.publicKey)))

    const response = await server.fetch(new Request('http://local/mcp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({
        jsonrpc: '2.0', id: 7, method: 'tools/call',
        params: { name: TOOL, arguments: { query: 'x' } },
      }),
    }))
    const text = await response.text()
    const payload = JSON.parse(text.slice(text.indexOf('{'), text.lastIndexOf('}') + 1)) as {
      result?: { isError?: boolean, content?: { type: string, text: string }[] }
      error?: { code: number }
    }

    // mcp-use turns a thrown middleware error into a tool result carrying
    // isError, at HTTP 200. It does NOT become a JSON-RPC protocol error, so a
    // host matching on error.code will not see this.
    assert.equal(response.status, 200)
    assert.equal(payload.error, undefined)
    assert.equal(payload.result?.isError, true)
    assert.equal(payload.result?.content?.[0]?.text, 'MCP_TRANSPORT_UNAUTHENTICATED')
    assert.equal(dispatched, 0, 'the tool must not dispatch when authorization refuses')
    await server.close()
  })
})
