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

describe('relying-party gate: evaluateRequest', () => {
  it('admits a valid passport that holds the required scope', () => {
    const { signed } = makePassport(['data:read', 'commerce:checkout'])
    const decision = evaluateRequest(signed, { requiredScopes: ['data:read'] })
    assert.equal(decision.admit, true)
    assert.equal(decision.reason, undefined)
  })

  it('admits authentication-only when no scope is required', () => {
    const { signed } = makePassport(['data:read'])
    const decision = evaluateRequest(signed, {})
    assert.equal(decision.admit, true)
  })

  it('denies a request with no passport (NO_PASSPORT, 401)', () => {
    const decision = evaluateRequest(undefined, { requiredScopes: ['data:read'] })
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
    const decision = evaluateRequest(tampered, { requiredScopes: ['data:read'] })
    assert.equal(decision.admit, false)
    assert.equal(decision.reason, 'PASSPORT_INVALID')
    assert.equal(decision.status, 401)
  })

  it('denies a valid passport that lacks the required scope (MISSING_SCOPE, 403)', () => {
    const { signed } = makePassport(['data:read'])
    const decision = evaluateRequest(signed, { requiredScopes: ['commerce:checkout'] })
    assert.equal(decision.admit, false)
    assert.equal(decision.reason, 'MISSING_SCOPE')
    assert.equal(decision.status, 403)
    assert.ok(decision.detail?.includes('commerce:checkout'))
  })

  it('requires ALL scopes by default (logical AND)', () => {
    const { signed } = makePassport(['data:read'])
    const decision = evaluateRequest(signed, {
      requiredScopes: ['data:read', 'commerce:checkout'],
    })
    assert.equal(decision.admit, false)
    assert.equal(decision.reason, 'MISSING_SCOPE')
  })

  it('admits on ANY scope when anyScope is set (logical OR)', () => {
    const { signed } = makePassport(['data:read'])
    const decision = evaluateRequest(signed, {
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
      { requiredScopes: ['data:read'] },
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
      { requiredScopes: ['admin:write'] },
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
      { requiredScopes: ['data:read'] },
    )
    assert.equal(proceeded, false)
    assert.equal(res.sent!.status, 401)
    assert.equal(res.sent!.body.error, 'NO_PASSPORT')
  })
})
