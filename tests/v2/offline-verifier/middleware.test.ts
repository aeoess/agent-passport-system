// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Relying-party middleware tests
// ══════════════════════════════════════════════════════════════════
// Pins the headline behavior: the gate DROPS unauthorized traffic and
// ADMITS authorized traffic, before application logic runs. Covers a
// missing passport, a tampered passport, a valid passport lacking scope,
// and a valid passport with scope.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createPassport, signPassport } from '../../../src/core/passport.js'
import type { SignedPassport } from '../../../src/types/passport.js'
import {
  evaluateRequest,
  runGate,
  type GateDenyReason,
  type GateRequestLike,
  type GateResponseLike,
} from '../../../src/v2/offline-verifier/middleware.js'

const RUNTIME = { platform: 'node', models: ['test'], toolsCount: 0, memoryType: 'none' }

function makePassport(capabilities: string[]): { signed: SignedPassport; priv: string } {
  const { signedPassport, keyPair } = createPassport({
    agentId: 'agent-mw-001',
    agentName: 'gate-test',
    ownerAlias: 'owner',
    mission: 'middleware test',
    capabilities,
    runtime: RUNTIME,
    expiresInDays: 30,
  })
  // Re-sign with the returned private key so we hold the key for tamper tests.
  const resigned = signPassport(signedPassport.passport, keyPair.privateKey)
  return { signed: resigned, priv: keyPair.privateKey }
}

// These cases exercise signature, expiry and scope on self-signed
// passports, so they now declare that posture explicitly: the gate no
// longer admits a self-signed credential just because no trust anchor was
// configured. SELF_SIGNED is that declaration, and the trust-anchor suite
// further down pins what happens without it.
const SELF_SIGNED = { allowSelfSigned: true } as const

describe('relying-party gate: evaluateRequest', () => {
  it('admits a valid passport that holds the required scope', () => {
    const { signed } = makePassport(['data:read', 'commerce:checkout'])
    const decision = evaluateRequest(signed, { ...SELF_SIGNED, requiredScopes: ['data:read'] })
    assert.equal(decision.admit, true)
    assert.equal(decision.reason, undefined)
  })

  it('admits authentication-only when no scope is required', () => {
    const { signed } = makePassport(['data:read'])
    const decision = evaluateRequest(signed, { ...SELF_SIGNED })
    assert.equal(decision.admit, true)
  })

  it('denies a request with no passport (NO_PASSPORT, 401)', () => {
    const decision = evaluateRequest(undefined, { ...SELF_SIGNED, requiredScopes: ['data:read'] })
    assert.equal(decision.admit, false)
    assert.equal(decision.reason, 'NO_PASSPORT')
    assert.equal(decision.status, 401)
  })

  it('denies a tampered passport (PASSPORT_INVALID, 401)', () => {
    const { signed } = makePassport(['data:read'])
    // Mutate a signed field without re-signing: signature no longer covers it.
    const tampered: SignedPassport = {
      ...signed,
      passport: { ...signed.passport, mission: 'tampered mission' },
    }
    const decision = evaluateRequest(tampered, { ...SELF_SIGNED, requiredScopes: ['data:read'] })
    assert.equal(decision.admit, false)
    assert.equal(decision.reason, 'PASSPORT_INVALID')
    assert.equal(decision.status, 401)
  })

  it('denies a valid passport that lacks the required scope (MISSING_SCOPE, 403)', () => {
    const { signed } = makePassport(['data:read'])
    const decision = evaluateRequest(signed, { ...SELF_SIGNED, requiredScopes: ['commerce:checkout'] })
    assert.equal(decision.admit, false)
    assert.equal(decision.reason, 'MISSING_SCOPE')
    assert.equal(decision.status, 403)
    assert.ok(decision.detail?.includes('commerce:checkout'))
  })

  it('requires ALL scopes by default (logical AND)', () => {
    const { signed } = makePassport(['data:read'])
    const decision = evaluateRequest(signed, {
      ...SELF_SIGNED,
      requiredScopes: ['data:read', 'commerce:checkout'],
    })
    assert.equal(decision.admit, false)
    assert.equal(decision.reason, 'MISSING_SCOPE')
  })

  it('admits on ANY scope when anyScope is set (logical OR)', () => {
    const { signed } = makePassport(['data:read'])
    const decision = evaluateRequest(signed, {
      ...SELF_SIGNED,
      requiredScopes: ['data:read', 'commerce:checkout'],
      anyScope: true,
    })
    assert.equal(decision.admit, true)
  })
})

// ── Transport adapter behavior via the framework-agnostic runGate ────

interface FakeResponse extends GateResponseLike {
  sent?: { status: number; body: { error: GateDenyReason; detail?: string } }
}

function fakeReq(p: SignedPassport | undefined): GateRequestLike {
  return { getPassport: () => p }
}

function fakeRes(): FakeResponse {
  const res: FakeResponse = {
    deny(status, body) {
      res.sent = { status, body }
    },
  }
  return res
}

describe('relying-party gate: runGate drops vs passes', () => {
  it('PASSES an authorized call to the application handler', () => {
    const { signed } = makePassport(['data:read'])
    const res = fakeRes()
    let proceeded = false
    const decision = runGate(
      fakeReq(signed),
      res,
      () => {
        proceeded = true
      },
      { ...SELF_SIGNED, requiredScopes: ['data:read'] },
    )
    assert.equal(decision.admit, true)
    assert.equal(proceeded, true, 'authorized traffic reaches application logic')
    assert.equal(res.sent, undefined, 'no deny response sent on admit')
  })

  it('DROPS an unauthorized call before application logic', () => {
    const { signed } = makePassport(['data:read'])
    const res = fakeRes()
    let proceeded = false
    const decision = runGate(
      fakeReq(signed),
      res,
      () => {
        proceeded = true
      },
      { ...SELF_SIGNED, requiredScopes: ['admin:write'] },
    )
    assert.equal(decision.admit, false)
    assert.equal(proceeded, false, 'unauthorized traffic never reaches application logic')
    assert.ok(res.sent, 'a deny response was sent')
    assert.equal(res.sent!.status, 403)
    assert.equal(res.sent!.body.error, 'MISSING_SCOPE')
  })

  it('DROPS a no-passport call with 401', () => {
    const res = fakeRes()
    let proceeded = false
    runGate(
      fakeReq(undefined),
      res,
      () => {
        proceeded = true
      },
      { ...SELF_SIGNED, requiredScopes: ['data:read'] },
    )
    assert.equal(proceeded, false)
    assert.equal(res.sent!.status, 401)
    assert.equal(res.sent!.body.error, 'NO_PASSPORT')
  })
})

// ══════════════════════════════════════════════════════════════════
// Invariant: a signature valid under an issuer the passport supplied
// itself is not a trusted-issuer authorization.
// ══════════════════════════════════════════════════════════════════
// evaluateRequest admitted an attacker's self-signed passport that
// declared admin:everything, returning {"admit":true}. verifyPassport
// does emit a 'No trustedIssuers provided — self-signed passports are
// accepted' warning, but GateDecision had no warnings field so the gate
// discarded it, and trustedIssuers: [] took the same silent path as
// omitting the option. An empty trust-anchor set now means what it says:
// no anchors, nothing to trust. Wildcard trust is available, but only by
// asking for it by name.

import { countersignPassport, generateKeyPair } from '../../../src/index.js'

describe('relying-party gate: trust anchors are not optional by accident', () => {
  function attackerPassport(): SignedPassport {
    return makePassport(['admin:everything', 'data:read']).signed
  }

  it('a self-signed passport claiming admin:everything is NOT admitted by default', () => {
    const decision = evaluateRequest(attackerPassport(), {
      requiredScopes: ['admin:everything'],
    })
    assert.equal(decision.admit, false)
    assert.equal(decision.reason, 'UNTRUSTED_ISSUER')
    assert.equal(decision.status, 401)
  })

  it('an empty trustedIssuers list does not mean "trust anyone"', () => {
    const decision = evaluateRequest(attackerPassport(), {
      trustedIssuers: [],
      requiredScopes: ['admin:everything'],
    })
    assert.equal(decision.admit, false)
    assert.equal(decision.reason, 'UNTRUSTED_ISSUER')
  })

  it('runGate DROPS the self-signed admin request before application logic', () => {
    const res = fakeRes()
    let proceeded = false
    const decision = runGate(
      fakeReq(attackerPassport()),
      res,
      () => {
        proceeded = true
      },
      { requiredScopes: ['admin:everything'] },
    )
    assert.equal(decision.admit, false)
    assert.equal(proceeded, false, 'unauthorized traffic never reaches application logic')
    assert.equal(res.sent!.status, 401)
    assert.equal(res.sent!.body.error, 'UNTRUSTED_ISSUER')
  })

  it('wildcard trust is available, but only by name', () => {
    const decision = evaluateRequest(attackerPassport(), {
      allowSelfSigned: true,
      requiredScopes: ['admin:everything'],
    })
    assert.equal(decision.admit, true)
    assert.ok(
      decision.warnings?.some((w) => w.toLowerCase().includes('self-signed')),
      `expected a self-signed warning on the decision, got ${JSON.stringify(decision.warnings)}`,
    )
  })

  it('a countersignature from a trusted issuer admits', () => {
    const issuer = generateKeyPair()
    const { signed } = makePassport(['data:read'])
    const countersigned = countersignPassport(signed, issuer.privateKey, 'test-ca')
    const decision = evaluateRequest(countersigned, {
      trustedIssuers: [issuer.publicKey],
      requiredScopes: ['data:read'],
    })
    assert.equal(decision.admit, true, JSON.stringify(decision.errors))
  })

  it('a countersignature from an issuer outside the allowlist is denied', () => {
    const trusted = generateKeyPair()
    const rogue = generateKeyPair()
    const { signed } = makePassport(['data:read'])
    const countersigned = countersignPassport(signed, rogue.privateKey, 'rogue-ca')
    const decision = evaluateRequest(countersigned, {
      trustedIssuers: [trusted.publicKey],
      requiredScopes: ['data:read'],
    })
    assert.equal(decision.admit, false)
    assert.equal(decision.reason, 'PASSPORT_INVALID')
  })

  it('a non-empty trustedIssuers list still requires a countersignature even with allowSelfSigned', () => {
    const issuer = generateKeyPair()
    const decision = evaluateRequest(attackerPassport(), {
      trustedIssuers: [issuer.publicKey],
      allowSelfSigned: true,
      requiredScopes: ['admin:everything'],
    })
    assert.equal(decision.admit, false)
    assert.equal(decision.reason, 'PASSPORT_INVALID')
  })

  it('the verifier warnings reach the decision instead of being discarded', () => {
    const decision = evaluateRequest(attackerPassport(), {
      allowSelfSigned: true,
      requiredScopes: ['data:read'],
    })
    assert.ok(Array.isArray(decision.warnings))
    assert.ok(decision.warnings!.length > 0)
  })

  it('scope is still checked after the trust anchor is satisfied', () => {
    const decision = evaluateRequest(makePassport(['data:read']).signed, {
      allowSelfSigned: true,
      requiredScopes: ['admin:everything'],
    })
    assert.equal(decision.admit, false)
    assert.equal(decision.reason, 'MISSING_SCOPE')
    assert.equal(decision.status, 403)
  })
})
