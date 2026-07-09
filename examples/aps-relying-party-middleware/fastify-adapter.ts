// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Fastify adapter - reference relying-party gate
// ══════════════════════════════════════════════════════════════════
// A thin Fastify preHandler hook that drops unauthorized traffic before
// your route handlers run. All the decision logic lives in the SDK's
// framework-agnostic gate (evaluateRequest); this file only knows how to
// pull a passport off a Fastify request and how to send a deny reply.
//
// Reference only. This folder has its own package.json; the SDK repo does
// not install fastify. Copy it into your project, npm install, and hook in.
//
// Usage:
//   import Fastify from 'fastify'
//   import { apsGateHook } from './fastify-adapter.js'
//
//   const app = Fastify()
//   app.addHook('preHandler', apsGateHook({
//     requiredScopes: ['data:read'],
//     trustedIssuers: [MY_ISSUER_PUBKEY_HEX],
//   }))
//   app.get('/protected', async () => ({ ok: true }))
//
// The passport is read, in order, from:
//   1. request.body.passport         (a JSON body carrying the SignedPassport)
//   2. the x-aps-passport header      (base64url-encoded SignedPassport JSON)
// Override extractPassport to source it from a verified session instead.
// ══════════════════════════════════════════════════════════════════

import type { FastifyReply, FastifyRequest } from 'fastify'
import {
  evaluateRequest,
  type GateOptions,
  type SignedPassport,
} from 'agent-passport-system'

/** Pull a SignedPassport off a Fastify request. Returns undefined when no
 *  credential is present or it does not parse; the gate turns that into a
 *  clean 401 rather than a 500. */
export function extractPassport(request: FastifyRequest): SignedPassport | undefined {
  // 1. JSON body.
  const fromBody = (request.body as { passport?: unknown } | undefined)?.passport
  if (fromBody && typeof fromBody === 'object') {
    return fromBody as SignedPassport
  }
  // 2. Header (base64url-encoded JSON).
  const header = request.headers['x-aps-passport']
  const headerValue = Array.isArray(header) ? header[0] : header
  if (typeof headerValue === 'string' && headerValue.length > 0) {
    try {
      const json = Buffer.from(headerValue, 'base64url').toString('utf-8')
      const parsed = JSON.parse(json)
      if (parsed && typeof parsed === 'object') return parsed as SignedPassport
    } catch {
      return undefined
    }
  }
  return undefined
}

/**
 * Build a Fastify preHandler hook that admits authorized requests and
 * drops everything else. On admit it decorates the request with the
 * verified passport and returns (letting the request proceed); on deny it
 * sends the status the gate chose and does NOT let the route handler run,
 * so application logic never runs for unauthorized traffic.
 */
export function apsGateHook(opts: GateOptions = {}) {
  return async function preHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> {
    const presented = extractPassport(request)
    const decision = evaluateRequest(presented, opts)
    if (decision.admit) {
      ;(request as unknown as Record<string, unknown>).apsPassport = presented
      return
    }
    await reply.code(decision.status ?? 401).send({
      error: decision.reason,
      detail: decision.detail,
    })
  }
}
