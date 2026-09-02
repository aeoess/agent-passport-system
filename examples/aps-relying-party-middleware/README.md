# APS relying-party middleware (reference)

Reference Express and Fastify middleware that verifies an agent's APS
passport and scope and drops unauthorized traffic before your application
logic runs.

The decision logic is not in this folder. It lives in the SDK as a
framework-agnostic gate:

- `evaluateRequest(presented, opts)` returns an admit/deny decision.
- `runGate(req, res, proceed, opts)` runs the gate against a transport.

Both are exported from `agent-passport-system`. The adapters here are thin
shells: they know how to pull a passport off an Express or Fastify request
and how to send a deny reply, and they delegate every decision to the SDK.

## Reference only

This folder has its own `package.json` with `express` and `fastify` as
dependencies. The SDK repository does not install them. Copy this folder
into your project, run `npm install`, and wire the adapter into your
server.

## Express

```ts
import express from 'express'
import { apsGate } from './express-adapter.js'

const app = express()
app.use(express.json())
app.use(apsGate({ requiredScopes: ['data:read'], trustedIssuers: [ISSUER] }))
app.get('/protected', (_req, res) => res.json({ ok: true }))
```

## Fastify

```ts
import Fastify from 'fastify'
import { apsGateHook } from './fastify-adapter.js'

const app = Fastify()
app.addHook('preHandler', apsGateHook({ requiredScopes: ['data:read'], trustedIssuers: [ISSUER] }))
app.get('/protected', async () => ({ ok: true }))
```

## Where the passport comes from

Both adapters read the passport, in order, from:

1. `req.body.passport` (a JSON body carrying the `SignedPassport`)
2. the `X-APS-Passport` header (base64url-encoded `SignedPassport` JSON)

Override `extractPassport` to read it from a verified session instead.

## Deny semantics

| Reason             | Status | Meaning                                              |
| ------------------ | ------ | ---------------------------------------------------- |
| `NO_PASSPORT`      | 401    | No passport presented on the request.                |
| `PASSPORT_INVALID` | 401    | Signature, validity window, or issuer-trust failed.  |
| `UNTRUSTED_ISSUER` | 401    | The gate holds no trust anchor for this passport.    |
| `MISSING_SCOPE`    | 403    | Passport is valid but lacks a required capability.    |

Scope is checked against the passport's `capabilities[]`. All
`requiredScopes` must be present by default (logical AND); set
`anyScope: true` for logical OR.

## Trust anchors

A passport signature verifies under the public key inside the passport, so
on its own it proves only that whoever holds that key wrote the passport,
capabilities included. The gate will not treat that as an authorization by
anyone you trust, so it needs one of two postures, stated explicitly:

- `trustedIssuers: [issuerPublicKeyHex, ...]` — the passport must carry a
  valid countersignature from one of those issuers.
- `allowSelfSigned: true` — self-signed passports are accepted. Every
  admit made this way carries a warning on the decision saying so.

Neither one, or `trustedIssuers: []`, denies with `UNTRUSTED_ISSUER`. An
empty anchor list is an empty anchor list, not a wildcard.

## Proof box

Proves: the gate drops a request whose passport fails to verify or lacks
the required scope, and admits a request whose passport verifies and holds
the scope. The check runs offline against the presented credential.

Does NOT prove: that an admitted agent will behave within scope after
admission. The gate authorizes the request at the boundary; it does not
observe what happens downstream. It does not prevent collusion and makes
no claim about the truth of any effect the agent later produces.
