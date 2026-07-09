// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Express adapter - reference relying-party gate
// ══════════════════════════════════════════════════════════════════
// A thin Express middleware that drops unauthorized traffic before your
// route handlers run. All the decision logic lives in the SDK's
// framework-agnostic gate (evaluateRequest); this file only knows how to
// pull a passport off an Express request and how to send a deny response.
//
// Reference only. This folder has its own package.json; the SDK repo does
// not install express. Copy it into your project, npm install, and mount.
//
// Usage:
//   import express from 'express'
//   import { apsGate } from './express-adapter.js'
//
//   const app = express()
//   app.use(express.json())
//   app.use(apsGate({
//     requiredScopes: ['data:read'],
//     trustedIssuers: [MY_ISSUER_PUBKEY_HEX],
//   }))
//   app.get('/protected', (_req, res) => res.json({ ok: true }))
//
// The passport is read, in order, from:
//   1. req.body.passport         (a JSON body carrying the SignedPassport)
//   2. the X-APS-Passport header (base64url-encoded SignedPassport JSON)
// Override extractPassport to source it from a verified session instead.
// ══════════════════════════════════════════════════════════════════

import type { Request, Response, NextFunction, RequestHandler } from 'express'
import {
  evaluateRequest,
  type GateOptions,
  type SignedPassport,
} from 'agent-passport-system'

/** Pull a SignedPassport off an Express request. Returns undefined when
 *  no credential is present or it does not parse; the gate turns that into
 *  a clean 401 rather than a 500. */
export function extractPassport(req: Request): SignedPassport | undefined {
  // 1. JSON body.
  const fromBody = (req.body as { passport?: unknown } | undefined)?.passport
  if (fromBody && typeof fromBody === 'object') {
    return fromBody as SignedPassport
  }
  // 2. Header (base64url-encoded JSON).
  const header = req.header('X-APS-Passport')
  if (header) {
    try {
      const json = Buffer.from(header, 'base64url').toString('utf-8')
      const parsed = JSON.parse(json)
      if (parsed && typeof parsed === 'object') return parsed as SignedPassport
    } catch {
      return undefined
    }
  }
  return undefined
}

/**
 * Build an Express middleware that admits authorized requests and drops
 * everything else. On admit it attaches the verified passport to
 * res.locals.apsPassport and calls next(); on deny it sends the status the
 * gate chose (401 for credential problems, 403 for missing scope) and does
 * NOT call next, so application logic never runs for unauthorized traffic.
 */
export function apsGate(opts: GateOptions = {}): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    const presented = extractPassport(req)
    const decision = evaluateRequest(presented, opts)
    if (decision.admit) {
      ;(res.locals as Record<string, unknown>).apsPassport = presented
      next()
      return
    }
    res.status(decision.status ?? 401).json({
      error: decision.reason,
      detail: decision.detail,
    })
  }
}
