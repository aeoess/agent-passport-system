// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto'
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import { didKeyFromPublicKey } from '../src/v2/identity-binding/did-aps.js'
import {
  APS_A2A_IDENTITY_EXTENSION,
  attachApsIdentityExtensionV1,
  signA2AAgentCardV1,
  verifyApsA2AAgentCardV1,
} from '../src/profiles/a2a/identity-v1.js'
import {
  APS_MCP_AUTHORIZATION_META,
  APS_MCP_RECEIPT_META,
  ApsMcpAuthorizationError,
  createApsMcpToolCallMiddleware,
  issueApsMcpAuthorizationV1,
} from '../src/profiles/mcp/authorization-v1.js'

describe('A2A APS identity extension', () => {
  it('uses native Agent Card extensions and JWS signatures', async () => {
    const agent = generateKeyPair()
    const agentId = didKeyFromPublicKey(agent.publicKey)
    const kid = `${agentId}#${agentId.slice('did:key:'.length)}`
    const passportBytes = Buffer.from('{"passport":"v2"}', 'utf8')
    const base = {
      name: 'Checkout Agent',
      description: 'Runs governed checkout actions',
      supportedInterfaces: [{ url: 'https://agent.example/a2a', protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
      version: '1.0.0',
      capabilities: { streaming: false },
      defaultInputModes: ['application/json'],
      defaultOutputModes: ['application/json'],
      skills: [],
    }
    const extended = attachApsIdentityExtensionV1(base, {
      agent_id: agentId,
      passport_uri: 'https://agent.example/.well-known/aps-passport.json',
      passport_sha256: createHash('sha256').update(passportBytes).digest('hex'),
      issued_at: '2026-07-16T00:00:00.000Z',
      expires_at: '2026-07-19T00:00:00.000Z',
    })
    assert.equal((extended.capabilities.extensions![0] as Record<string, unknown>).uri, APS_A2A_IDENTITY_EXTENSION)
    const signed = signA2AAgentCardV1(extended, agent.privateKey, kid)
    const verified = await verifyApsA2AAgentCardV1(signed, {
      now: '2026-07-17T00:00:00.000Z',
      resolve_key: () => ({ state: 'resolved', public_key_hex: agent.publicKey }),
      resolve_artifact: async () => passportBytes,
    })
    assert.equal(verified.state, 'valid')
    assert.equal(verified.card_signature, 'verified')
    assert.equal(verified.passport, 'resolved')

    const tampered = { ...signed, name: 'Refund Agent' }
    assert.equal((await verifyApsA2AAgentCardV1(tampered, {
      now: '2026-07-17T00:00:00.000Z',
      resolve_key: () => ({ state: 'resolved', public_key_hex: agent.publicKey }),
      resolve_artifact: async () => passportBytes,
    })).state, 'invalid')
  })
})

describe('MCP aps-mcp-1 pre-dispatch middleware', () => {
  function setup() {
    const agent = generateKeyPair()
    const agentId = didKeyFromPublicKey(agent.publicKey)
    const authorization = issueApsMcpAuthorizationV1({
      agent_id: agentId,
      verification_method: `${agentId}#${agentId.slice('did:key:'.length)}`,
      delegation_ref: 'sha256:' + 'aa'.repeat(32),
      mcp_server: 'https://mcp.example',
      tool_name: 'checkout',
      arguments: { cart_id: 'cart-1' },
      scope_required: ['commerce:checkout'],
      spend: { unit: 'iso4217:USD:minor', amount: '5000' },
      nonce: '22'.repeat(16),
      issued_at: '2026-01-01T00:00:00.000Z',
      expires_at: '2027-01-01T00:00:00.000Z',
      private_key_hex: agent.privateKey,
    })
    const request = {
      method: 'tools/call' as const,
      params: {
        name: 'checkout',
        arguments: { cart_id: 'cart-1' },
        _meta: { [APS_MCP_AUTHORIZATION_META]: authorization },
      },
    }
    return { agent, authorization, request }
  }

  it('denies before dispatch when transport authentication is absent', async () => {
    const { agent, request } = setup()
    let dispatched = false
    const middleware = createApsMcpToolCallMiddleware({
      mcp_server: 'https://mcp.example',
      resolve_key: () => ({ state: 'resolved', public_key_hex: agent.publicKey }),
      consume_action_ref: () => true,
      evaluate_authority: () => ({ state: 'permit', code: 'OK' }),
      emit_receipt: () => ({ receipt_id: 'r1' }),
    })
    await assert.rejects(
      () => middleware(request, { transport_authenticated: false }, async () => {
        dispatched = true
        return { content: [] }
      }),
      (error: unknown) => error instanceof ApsMcpAuthorizationError && error.code === 'MCP_TRANSPORT_UNAUTHENTICATED',
    )
    assert.equal(dispatched, false)
  })

  it('authorizes, dispatches once, returns a receipt, and rejects replay', async () => {
    const { agent, request } = setup()
    const seen = new Set<string>()
    let dispatches = 0
    const middleware = createApsMcpToolCallMiddleware({
      mcp_server: 'https://mcp.example',
      resolve_key: () => ({ state: 'resolved', public_key_hex: agent.publicKey }),
      consume_action_ref: (ref) => seen.has(ref) ? false : (seen.add(ref), true),
      evaluate_authority: () => ({ state: 'permit', code: 'OK', decision_ref: 'bb'.repeat(32) }),
      emit_receipt: (authorization) => ({ action_ref: authorization.action_ref }),
    })
    const response = await middleware(request, { transport_authenticated: true }, async () => {
      dispatches++
      return { content: [{ type: 'text', text: 'ok' }] }
    })
    assert.equal(dispatches, 1)
    assert.ok(response._meta?.[APS_MCP_RECEIPT_META])
    await assert.rejects(
      () => middleware(request, { transport_authenticated: true }, async () => {
        dispatches++
        return { content: [] }
      }),
      (error: unknown) => error instanceof ApsMcpAuthorizationError && error.code === 'MCP_ACTION_REPLAY',
    )
    assert.equal(dispatches, 1)
  })
})
