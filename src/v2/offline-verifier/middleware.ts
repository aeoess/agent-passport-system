// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Relying-party middleware core - framework-agnostic
// ══════════════════════════════════════════════════════════════════
// A reference relying-party gate: it verifies an agent's passport and its
// scope, and DROPS unauthorized traffic before any application logic runs.
//
// This module is framework-agnostic on purpose. The decision logic lives
// in a single pure function, evaluateRequest, which takes the presented
// passport and the required scope and returns an admit/deny decision. The
// Express and Fastify adapters (examples/aps-relying-party-middleware) are
// thin shells that extract the passport from the request, call this
// function, and either call next() or send the deny response. Keeping the
// core here means the gate is tested in the main suite with no web
// framework installed, and an integrator can wire it into any server.
//
// Reuse: the passport signature/expiry check is the existing
// verifyPassport (src/verification/verify.ts), with its established
// { trustedIssuers, clock } options surface. The scope check reads the
// passport's capabilities[] (the existing capability vocabulary). Nothing
// new is invented for identity or expiry.
//
// PUBLIC/PRIVATE boundary: this is the SLOT and the HOOK, not a service.
// It does not ship identity bridges, policy-template libraries,
// dashboards, rate limiting, or session stores. It admits or denies one
// request against a presented passport. An integrator supplies the
// trust anchors, the required scope, and the transport binding.
//
// SCOPE OF CLAIM (dogfooded language, no receipt here so no ScopeOfClaim
// object): this gate decides admission from a passport's signature,
// validity window, and declared capabilities. It is SPECIFIED and TESTED
// to drop a request whose passport fails to verify or lacks the required
// scope. It does NOT prove the agent will behave within scope after
// admission, only that the presented credential authorizes the request at
// the gate.
// ══════════════════════════════════════════════════════════════════

import { verifyPassport } from '../../verification/verify.js'
import type { SignedPassport } from '../../types/passport.js'
import type { CoreVerifyClockOptions } from '../../types/policy.js'

/** Why a request was denied at the gate. Closed set, ordered: a missing
 *  passport is reported before signature, signature before scope. */
export type GateDenyReason =
  | 'NO_PASSPORT' // no passport presented on the request
  | 'PASSPORT_INVALID' // signature, expiry, or issuer-trust check failed
  | 'MISSING_SCOPE' // passport is valid but lacks a required capability

export interface GateDecision {
  /** True iff the request is authorized to proceed to application logic. */
  admit: boolean
  /** Set iff admit is false. */
  reason?: GateDenyReason
  /** Suggested HTTP status for the deny response. 401 for credential
   *  problems, 403 for an authenticated agent lacking scope. Undefined on
   *  admit. The adapter is free to override. */
  status?: 401 | 403
  /** Human-readable detail for logs and the deny body. Never leaks key
   *  material; names the failing check only. */
  detail?: string
  /** Verifier errors from the passport check, when applicable. Useful for
   *  audit logs; not sent to the caller by default. */
  errors?: string[]
}

export interface GateOptions {
  /** Trust anchors. When provided, the passport MUST carry a valid issuer
   *  countersignature from one of these. When omitted, self-signed
   *  passports verify (signature + expiry only) - documented and weaker. */
  trustedIssuers?: string[]
  /** Uniform clock-skew option, threaded into verifyPassport. Reuses the
   *  one millisecond-based skew option the SDK exposes. */
  clock?: CoreVerifyClockOptions
  /** Scopes the request requires. ALL listed scopes must be present in the
   *  passport's capabilities[] for admission (logical AND). Empty or
   *  omitted means "any valid passport admits" (authentication only). */
  requiredScopes?: string[]
  /** When true, a required scope is satisfied if the passport carries ANY
   *  one of requiredScopes (logical OR) instead of all. Default false. */
  anyScope?: boolean
}

/**
 * The gate decision. Pure and offline: it runs verifyPassport (signature,
 * validity window, optional issuer-trust) and then the scope check, in
 * that order, and returns admit/deny. No network, no mutation, no I/O.
 *
 * `presented` is whatever the transport adapter extracted. `undefined` or
 * a malformed value denies with NO_PASSPORT rather than throwing, so a
 * missing credential is a clean 401, not a 500.
 */
export function evaluateRequest(
  presented: SignedPassport | undefined | null,
  opts: GateOptions = {},
): GateDecision {
  // 1. No passport presented.
  if (presented === undefined || presented === null || typeof presented !== 'object') {
    return {
      admit: false,
      reason: 'NO_PASSPORT',
      status: 401,
      detail: 'no passport presented on the request',
    }
  }

  // 2. Passport signature / expiry / issuer trust.
  const result = verifyPassport(presented, {
    trustedIssuers: opts.trustedIssuers,
    clock: opts.clock,
  })
  if (!result.valid) {
    return {
      admit: false,
      reason: 'PASSPORT_INVALID',
      status: 401,
      detail: 'passport failed verification',
      errors: result.errors,
    }
  }

  // 3. Scope check against the passport's declared capabilities.
  const required = opts.requiredScopes ?? []
  if (required.length > 0) {
    const held = new Set(presented.passport.capabilities ?? [])
    const ok = opts.anyScope
      ? required.some((s) => held.has(s))
      : required.every((s) => held.has(s))
    if (!ok) {
      const missing = required.filter((s) => !held.has(s))
      return {
        admit: false,
        reason: 'MISSING_SCOPE',
        status: 403,
        detail: opts.anyScope
          ? `passport holds none of the required scopes: ${required.join(', ')}`
          : `passport is missing required scope(s): ${missing.join(', ')}`,
      }
    }
  }

  return { admit: true }
}

// ── Minimal structural transport types ──────────────────────────────
// These mirror the shape of an Express/Fastify request/response WITHOUT
// importing either framework, so the core ships no web dependency. The
// adapters in the examples package satisfy these structurally.

/** Minimal request surface the gate reads. The adapter supplies a
 *  getPassport that knows where the credential lives on the transport
 *  (a header, the parsed body, a verified session). */
export interface GateRequestLike {
  getPassport: () => SignedPassport | undefined | null
}

/** Minimal response surface the gate writes on deny. */
export interface GateResponseLike {
  /** Send a deny response with the given status and JSON body, then end. */
  deny: (status: number, body: { error: GateDenyReason; detail?: string }) => void
}

/**
 * Run the gate against a transport-shaped request/response. On admit,
 * calls `proceed()` (the framework's next()/handler). On deny, writes the
 * deny response and does NOT call proceed - unauthorized traffic is
 * dropped before application logic.
 *
 * Returns the decision so an adapter or test can assert on it.
 */
export function runGate(
  req: GateRequestLike,
  res: GateResponseLike,
  proceed: () => void,
  opts: GateOptions = {},
): GateDecision {
  const presented = req.getPassport()
  const decision = evaluateRequest(presented, opts)
  if (decision.admit) {
    proceed()
    return decision
  }
  res.deny(decision.status ?? 401, {
    error: decision.reason ?? 'PASSPORT_INVALID',
    detail: decision.detail,
  })
  return decision
}
