// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Tests for the OAuth 2.1 / RFC 8693 Token Exchange delegation-token bridge.
//
// Covers: APS chain -> RFC 8693 act/may_act and back with authority preserved;
// narrowing preserved across the mapping (recovered chain is no broader);
// SPIFFE SVID resolves as a did-method identity input. Negative-path fixtures
// are explicit (widening rejection, impersonation token, malformed SPIFFE,
// non-conforming JWT-SVID).

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  TOKEN_EXCHANGE_GRANT_TYPE,
  TOKEN_TYPE_URN,
  bridgeScopeOfClaim,
  isNarrowing,
  assertChainNarrows,
  effectiveScope,
  chainToTokenExchangeClaims,
  tokenExchangeClaimsToChain,
  assertRoundTripNarrows,
  actorSatisfiesMayAct,
  currentActor,
  parseScope,
  validateSpiffeId,
  spiffeIdToDidInput,
  jwtSvidToDidInput,
} from '../src/index.js'
import type {
  DelegationChainView,
  TokenExchangeClaims,
  JwtSvidView,
} from '../src/index.js'

// ── Fixtures ──

/** Two-hop APS chain: principal -> service77 (read,write) -> service16 (read). */
function twoHopChain(): DelegationChainView {
  return {
    principal: 'user@example.com',
    principalIss: 'https://issuer.example.com',
    hops: [
      {
        delegatedBy: 'user@example.com',
        delegatedTo: 'https://service77.example.com',
        scope: ['read', 'write', 'admin'],
      },
      {
        delegatedBy: 'https://service77.example.com',
        delegatedTo: 'https://service16.example.com',
        scope: ['read', 'write'],
      },
    ],
  }
}

// ── act / may_act mapping ──

describe('RFC 8693 act claim mapping', () => {
  it('maps a single-hop chain to a top-level sub + outermost act', () => {
    const chain: DelegationChainView = {
      principal: 'user@example.com',
      hops: [
        {
          delegatedBy: 'user@example.com',
          delegatedTo: 'admin@example.com',
          scope: ['read'],
        },
      ],
    }
    const claims = chainToTokenExchangeClaims(chain)
    assert.equal(claims.sub, 'user@example.com')
    assert.ok(claims.act)
    assert.equal(claims.act?.sub, 'admin@example.com')
    // single actor → no nested act
    assert.equal(claims.act?.act, undefined)
  })

  it('nests prior actors so the OUTERMOST act is the current actor', () => {
    const chain = twoHopChain()
    const claims = chainToTokenExchangeClaims(chain)
    // current actor (most recent hop delegatee) is outermost
    assert.equal(claims.act?.sub, 'https://service16.example.com')
    // prior actor nested inside
    assert.equal(claims.act?.act?.sub, 'https://service77.example.com')
    // principal is top-level sub, never an actor
    assert.equal(claims.sub, 'user@example.com')
    assert.equal(claims.act?.act?.act, undefined)
  })

  it('emits act (delegation), never an impersonation-shaped token', () => {
    const claims = chainToTokenExchangeClaims(twoHopChain())
    assert.ok(claims.act, 'delegation token must carry act')
  })

  it('carries narrowed effective scope as the space-delimited scope member', () => {
    const claims = chainToTokenExchangeClaims(twoHopChain())
    // effective = intersection of [read,write,admin] and [read,write] = read write
    assert.deepEqual(parseScope(claims.scope).sort(), ['read', 'write'])
  })

  it('emits may_act as a forward authorization when supplied', () => {
    const claims = chainToTokenExchangeClaims(twoHopChain(), {
      mayActBecome: { sub: 'https://service26.example.com' },
    })
    assert.equal(claims.may_act?.sub, 'https://service26.example.com')
    // may_act is distinct from act (permission vs proof)
    assert.notEqual(claims.may_act?.sub, claims.act?.sub)
  })

  it('passes through audience, resource, iss, exp, nbf options', () => {
    const claims = chainToTokenExchangeClaims(twoHopChain(), {
      audience: 'https://service26.example.com',
      resource: 'https://backend.example.com/api',
      iss: 'https://issuer.example.com',
      exp: 1443904100,
      nbf: 1443904000,
    })
    assert.equal(claims.aud, 'https://service26.example.com')
    assert.equal(claims.resource, 'https://backend.example.com/api')
    assert.equal(claims.iss, 'https://issuer.example.com')
    assert.equal(claims.exp, 1443904100)
    assert.equal(claims.nbf, 1443904000)
  })
})

// ── Round-trip: chain -> claims -> chain with authority preserved ──

describe('RFC 8693 round-trip preserves authority', () => {
  it('recovers principal, actor order, and effective scope', () => {
    const original = twoHopChain()
    const claims = chainToTokenExchangeClaims(original)
    const recovered = tokenExchangeClaimsToChain(claims)

    assert.equal(recovered.principal, original.principal)
    // actor order preserved: root-first
    assert.deepEqual(
      recovered.hops.map((h) => h.delegatedTo),
      ['https://service77.example.com', 'https://service16.example.com'],
    )
    // first hop is delegated by the principal
    assert.equal(recovered.hops[0].delegatedBy, 'user@example.com')
    // chain links: second hop delegated by first actor
    assert.equal(recovered.hops[1].delegatedBy, 'https://service77.example.com')
    // effective authority preserved
    assert.deepEqual(
      (recovered.effectiveScope ?? []).sort(),
      effectiveScope(original).sort(),
    )
  })

  it('assertRoundTripNarrows passes for a faithful round-trip', () => {
    const original = twoHopChain()
    const recovered = tokenExchangeClaimsToChain(
      chainToTokenExchangeClaims(original),
    )
    assert.doesNotThrow(() => assertRoundTripNarrows(original, recovered))
  })

  it('three-hop chain round-trips with order preserved', () => {
    const original: DelegationChainView = {
      principal: 'owner@example.com',
      hops: [
        { delegatedBy: 'owner@example.com', delegatedTo: 'a', scope: ['x', 'y', 'z'] },
        { delegatedBy: 'a', delegatedTo: 'b', scope: ['x', 'y'] },
        { delegatedBy: 'b', delegatedTo: 'c', scope: ['x'] },
      ],
    }
    const recovered = tokenExchangeClaimsToChain(
      chainToTokenExchangeClaims(original),
    )
    assert.deepEqual(recovered.hops.map((h) => h.delegatedTo), ['a', 'b', 'c'])
    assert.deepEqual((recovered.effectiveScope ?? []).sort(), ['x'])
    assert.doesNotThrow(() => assertRoundTripNarrows(original, recovered))
  })
})

// ── Narrowing preserved across the mapping ──

describe('narrowing is preserved across the mapping', () => {
  it('recovered effective scope is no broader than the original', () => {
    const original = twoHopChain()
    const recovered = tokenExchangeClaimsToChain(
      chainToTokenExchangeClaims(original),
    )
    assert.ok(
      isNarrowing(effectiveScope(original), recovered.effectiveScope ?? []),
      'recovered scope must be a subset of original effective scope',
    )
  })

  it('recovered hops never exceed the token effective scope ceiling', () => {
    const original = twoHopChain()
    const claims = chainToTokenExchangeClaims(original)
    const recovered = tokenExchangeClaimsToChain(claims)
    const ceiling = recovered.effectiveScope ?? []
    for (const hop of recovered.hops) {
      assert.ok(
        isNarrowing(ceiling, hop.scope),
        `hop ${hop.delegatedTo} must not exceed the effective ceiling`,
      )
    }
  })

  it('NEGATIVE: rejects a chain that widens authority before mapping', () => {
    const widening: DelegationChainView = {
      principal: 'user@example.com',
      hops: [
        { delegatedBy: 'user@example.com', delegatedTo: 'a', scope: ['read'] },
        // child widens to add 'write', must be rejected
        { delegatedBy: 'a', delegatedTo: 'b', scope: ['read', 'write'] },
      ],
    }
    assert.throws(() => assertChainNarrows(widening), /widens authority/)
    assert.throws(() => chainToTokenExchangeClaims(widening), /widens authority/)
  })

  it('NEGATIVE: assertRoundTripNarrows throws if recovered scope is broader', () => {
    const original: DelegationChainView = {
      principal: 'user@example.com',
      hops: [{ delegatedBy: 'user@example.com', delegatedTo: 'a', scope: ['read'] }],
    }
    // hand-craft a recovered chain that widened (simulating a tampered token)
    const tampered = {
      principal: 'user@example.com',
      hops: [{ delegatedBy: 'user@example.com', delegatedTo: 'a', scope: ['read', 'write'] }],
      effectiveScope: ['read', 'write'],
    }
    assert.throws(() => assertRoundTripNarrows(original, tampered), /widened authority/)
  })

  it('NEGATIVE: assertRoundTripNarrows throws if the principal changed', () => {
    const original = twoHopChain()
    const tampered = { ...tokenExchangeClaimsToChain(chainToTokenExchangeClaims(original)) }
    tampered.principal = 'attacker@example.com'
    assert.throws(() => assertRoundTripNarrows(original, tampered), /changed principal/)
  })

  it('NEGATIVE: assertRoundTripNarrows throws if actors were reordered', () => {
    const original = twoHopChain()
    const recovered = tokenExchangeClaimsToChain(chainToTokenExchangeClaims(original))
    const reordered = {
      ...recovered,
      hops: [recovered.hops[1], recovered.hops[0]],
    }
    assert.throws(() => assertRoundTripNarrows(original, reordered), /reordered actors/)
  })
})

// ── may_act enforcement and current-actor reading ──

describe('may_act enforcement (RFC 8693 Section 4.4)', () => {
  it('actorSatisfiesMayAct matches the permitted actor', () => {
    const claims = chainToTokenExchangeClaims(twoHopChain(), {
      mayActBecome: { sub: 'https://service26.example.com' },
    })
    assert.equal(
      actorSatisfiesMayAct(claims.may_act, { sub: 'https://service26.example.com' }),
      true,
    )
  })

  it('NEGATIVE: rejects an actor not named by may_act', () => {
    const claims = chainToTokenExchangeClaims(twoHopChain(), {
      mayActBecome: { sub: 'https://service26.example.com' },
    })
    assert.equal(
      actorSatisfiesMayAct(claims.may_act, { sub: 'https://attacker.example.com' }),
      false,
    )
  })

  it('NEGATIVE: rejects when may_act pins an issuer and the actor issuer differs', () => {
    const ok = actorSatisfiesMayAct(
      { sub: 'svc', iss: 'https://issuer.example.com' },
      { sub: 'svc', iss: 'https://other.example.com' },
    )
    assert.equal(ok, false)
  })

  it('NEGATIVE: rejects when may_act is absent (permission, not default-allow)', () => {
    assert.equal(actorSatisfiesMayAct(undefined, { sub: 'svc' }), false)
  })

  it('currentActor returns the OUTERMOST actor only', () => {
    const claims = chainToTokenExchangeClaims(twoHopChain())
    assert.deepEqual(currentActor(claims), { sub: 'https://service16.example.com' })
  })
})

// ── Impersonation vs delegation ──

describe('impersonation-shaped tokens', () => {
  it('an impersonation token (no act) recovers a zero-hop chain', () => {
    const impersonation: TokenExchangeClaims = {
      sub: 'user@example.com',
      scope: 'read write',
    }
    const recovered = tokenExchangeClaimsToChain(impersonation)
    assert.equal(recovered.hops.length, 0)
    assert.equal(recovered.principal, 'user@example.com')
    assert.deepEqual((recovered.effectiveScope ?? []).sort(), ['read', 'write'])
    assert.equal(currentActor(impersonation), undefined)
  })

  it('NEGATIVE: claims with no sub are rejected on recovery', () => {
    assert.throws(
      () => tokenExchangeClaimsToChain({ scope: 'read' } as unknown as TokenExchangeClaims),
      /non-empty top-level sub/,
    )
  })
})

// ── Constants and verbatim wire vector ──

describe('RFC 8693 constants and wire vector', () => {
  it('uses the exact grant_type and token-type URNs', () => {
    assert.equal(
      TOKEN_EXCHANGE_GRANT_TYPE,
      'urn:ietf:params:oauth:grant-type:token-exchange',
    )
    assert.equal(
      TOKEN_TYPE_URN.access_token,
      'urn:ietf:params:oauth:token-type:access_token',
    )
    assert.equal(TOKEN_TYPE_URN.jwt, 'urn:ietf:params:oauth:token-type:jwt')
  })

  it('reads the RFC 8693 two-hop verbatim example as a delegation chain', () => {
    // From RFC 8693: service16 currently acting, service77 prior, on behalf of user.
    const wire: TokenExchangeClaims = {
      aud: 'https://service26.example.com',
      iss: 'https://issuer.example.com',
      exp: 1443904100,
      nbf: 1443904000,
      sub: 'user@example.com',
      act: {
        sub: 'https://service16.example.com',
        act: { sub: 'https://service77.example.com' },
      },
    }
    const recovered = tokenExchangeClaimsToChain(wire)
    assert.equal(recovered.principal, 'user@example.com')
    // root-first order: service77 then service16
    assert.deepEqual(
      recovered.hops.map((h) => h.delegatedTo),
      ['https://service77.example.com', 'https://service16.example.com'],
    )
    // current actor is the outermost act
    assert.deepEqual(currentActor(wire), { sub: 'https://service16.example.com' })
  })
})

// ── SPIFFE SVID → DID-method identity input ──

describe('SPIFFE SVID resolves as a did-method identity input', () => {
  it('validates and splits a well-formed SPIFFE ID', () => {
    const parts = validateSpiffeId('spiffe://staging.example.com/payments/mysql')
    assert.equal(parts.trustDomain, 'staging.example.com')
    assert.deepEqual(parts.pathSegments, ['payments', 'mysql'])
  })

  it('maps a SPIFFE ID to a did:<method> input losslessly', () => {
    const input = spiffeIdToDidInput('spiffe://staging.example.com/payments/mysql')
    assert.equal(input.trustDomain, 'staging.example.com')
    assert.deepEqual(input.pathSegments, ['payments', 'mysql'])
    assert.equal(input.did, 'did:spiffe:staging.example.com:payments:mysql')
  })

  it('honors a custom method and enforces a trust-domain match', () => {
    const input = spiffeIdToDidInput('spiffe://td.example.com/workload', {
      method: 'web',
      expectedTrustDomain: 'td.example.com',
    })
    assert.equal(input.did, 'did:web:td.example.com:workload')
  })

  it('NEGATIVE: rejects a trust-domain mismatch against the expected root', () => {
    assert.throws(
      () =>
        spiffeIdToDidInput('spiffe://other.example.com/workload', {
          expectedTrustDomain: 'td.example.com',
        }),
      /trust-domain mismatch/,
    )
  })

  it('NEGATIVE: rejects a non-spiffe scheme', () => {
    assert.throws(() => validateSpiffeId('https://example.com/x'), /scheme must be spiffe/)
  })

  it('NEGATIVE: rejects query, fragment, percent-encoding, port, userinfo', () => {
    assert.throws(() => validateSpiffeId('spiffe://td.example.com/x?y=1'), /query/)
    assert.throws(() => validateSpiffeId('spiffe://td.example.com/x#frag'), /fragment/)
    assert.throws(() => validateSpiffeId('spiffe://td.example.com/x%2Fy'), /percent-encoding/)
    assert.throws(() => validateSpiffeId('spiffe://td.example.com:8443/x'), /port/)
    assert.throws(() => validateSpiffeId('spiffe://user@td.example.com/x'), /userinfo/)
  })

  it('NEGATIVE: rejects empty, dot, and dot-dot path segments and trailing slash', () => {
    assert.throws(() => validateSpiffeId('spiffe://td.example.com/a//b'), /empty segment/)
    assert.throws(() => validateSpiffeId('spiffe://td.example.com/./b'), /'\.' segment/)
    assert.throws(() => validateSpiffeId('spiffe://td.example.com/a/..'), /'\.\.' segment/)
    assert.throws(() => validateSpiffeId('spiffe://td.example.com/a/'), /trailing slash/)
  })

  it('NEGATIVE: rejects an uppercase trust domain (lowercase charset only)', () => {
    assert.throws(
      () => validateSpiffeId('spiffe://TD.example.com/x'),
      /invalid characters/,
    )
  })

  it('NEGATIVE: rejects an oversized SPIFFE ID', () => {
    const big = 'spiffe://td.example.com/' + 'a'.repeat(2100)
    assert.throws(() => validateSpiffeId(big), /exceeds 2048 bytes/)
  })
})

// ── JWT-SVID → DID-method input ──

describe('JWT-SVID validation and DID mapping', () => {
  function validSvid(): JwtSvidView {
    return {
      header: { alg: 'ES256', typ: 'JWT', kid: 'abc' },
      claims: {
        sub: 'spiffe://staging.example.com/payments/mysql',
        aud: ['https://validator.example.com'],
        exp: 1443904100,
      },
    }
  }

  it('maps a conforming JWT-SVID sub to a did input', () => {
    const input = jwtSvidToDidInput(validSvid(), {
      expectedAudience: 'https://validator.example.com',
    })
    assert.equal(input.did, 'did:spiffe:staging.example.com:payments:mysql')
  })

  it('NEGATIVE: rejects alg:none', () => {
    const svid = validSvid()
    svid.header.alg = 'none'
    assert.throws(() => jwtSvidToDidInput(svid), /alg:none is forbidden/)
  })

  it('NEGATIVE: rejects a symmetric / unapproved alg', () => {
    const svid = validSvid()
    svid.header.alg = 'HS256'
    assert.throws(() => jwtSvidToDidInput(svid), /not in approved asymmetric set/)
  })

  it('NEGATIVE: rejects a JWT-SVID missing exp', () => {
    const svid = validSvid()
    delete (svid.claims as { exp?: number }).exp
    assert.throws(() => jwtSvidToDidInput(svid), /must carry exp/)
  })

  it('NEGATIVE: rejects a JWT-SVID missing aud', () => {
    const svid = validSvid()
    delete (svid.claims as { aud?: unknown }).aud
    assert.throws(() => jwtSvidToDidInput(svid), /must carry aud/)
  })

  it('NEGATIVE: rejects when the validator id is not among aud', () => {
    assert.throws(
      () => jwtSvidToDidInput(validSvid(), { expectedAudience: 'https://other.example.com' }),
      /does not include validator id/,
    )
  })

  it('NEGATIVE: rejects a typ header that is neither JWT nor JOSE', () => {
    const svid = validSvid()
    svid.header.typ = 'at+jwt'
    assert.throws(() => jwtSvidToDidInput(svid), /typ header must be JWT or JOSE/)
  })

  it('NEGATIVE: rejects a sub that is not a valid SPIFFE ID', () => {
    const svid = validSvid()
    svid.claims.sub = 'not-a-spiffe-id'
    assert.throws(() => jwtSvidToDidInput(svid), /scheme must be spiffe/)
  })
})

// ── Scope-of-claim dogfooding ──

describe('scope-of-claim (honest scope declaration)', () => {
  it('declares what the bridge proves and what it does not', () => {
    const soc = bridgeScopeOfClaim()
    assert.match(soc.asserts, /RFC 8693/)
    assert.ok(soc.does_not_assert.length >= 3)
    assert.ok(
      soc.does_not_assert.some((s) => /authorization server/i.test(s)),
      'must disclaim that the AS honored the claims',
    )
    assert.equal(soc.self_attested, true)
    assert.equal(soc.completeness, 'complete')
  })
})
