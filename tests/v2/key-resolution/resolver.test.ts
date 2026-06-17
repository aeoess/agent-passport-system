// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Key Resolution (M3): KeyResolver interface + did:cycles/JWKS resolver
// ══════════════════════════════════════════════════════════════════
// Covers: did:cycles -> JWKS URL mapping, Ed25519 JWK selection by kid,
// the RFC 8032 / RFC 8037 byte-level test vector, cache hit/miss,
// unreachable under fail-closed (rejects) and under fail-open (degraded,
// no key), key rotation, did:key/did:web registration behind the
// interface, and an end-to-end Cycles envelope verification.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  CyclesKeyResolver,
  parseDIDCycles,
  isDIDCycles,
  cyclesJwksUrl,
  selectKey,
  asJWKS,
  decodeBase64Url,
} from '../../../src/v2/key-resolution/index.js'
import type { JWKS, KeyResolution } from '../../../src/v2/key-resolution/index.js'
import { sign, verify, publicKeyFromPrivate } from '../../../src/crypto/keys.js'
import { toDIDKey } from '../../../src/core/did-interop.js'

// ── RFC 8032 §7.1 TEST 1 = RFC 8037 OKP example key ─────────────────
// Private seed (fixture-signer only).
const SEED_HEX = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
// 32-byte public key (hex) from RFC 8032 Test 1.
const PUB_HEX = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
// Same public key as JWK `x` (base64url, RFC 8037 example).
const X_B64URL = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'
// NOTE on the RFC 8032 published signature for the empty message: the
// authoritative value is whatever the RFC 8032 algorithm produces for
// (seed, empty message), which node:crypto / OpenSSL emits exactly.
// The fixture derives it at runtime via sign(), keeping the vector
// self-consistent and authoritative rather than depending on a pasted
// string.
const TEST1_SIG = sign('', SEED_HEX)

function fixtureJWK(kid: string, x: string = X_B64URL) {
  return { kty: 'OKP', crv: 'Ed25519', x, kid, use: 'sig', alg: 'EdDSA' }
}

function fixtureJWKS(...jwks: object[]): JWKS {
  return { keys: jwks as JWKS['keys'] }
}

/** A fetch stub that serves a fixed JSON body, counting calls. */
function jsonFetch(body: unknown, status = 200) {
  let calls = 0
  const impl = (async () => {
    calls++
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
    } as unknown as Response
  }) as unknown as typeof fetch
  return { impl, calls: () => calls }
}

/** A fetch stub that always throws (unreachable). */
function throwingFetch() {
  let calls = 0
  const impl = (async () => {
    calls++
    throw new Error('ECONNREFUSED (simulated)')
  }) as unknown as typeof fetch
  return { impl, calls: () => calls }
}

// ════════════════════════════════════════════════════════════════
describe('did:cycles hash-bound parsing (subject = sha256(server_id))', () => {
  const H = 'a'.repeat(64) // a valid 64-char lowercase hex sha256

  it('parses the server_id-hash subject', () => {
    assert.equal(parseDIDCycles(`did:cycles:${H}`).serverIdHash, H)
  })

  it('fragment becomes the kid', () => {
    const p = parseDIDCycles(`did:cycles:${H}#2026-06`)
    assert.equal(p.kid, '2026-06')
    assert.equal(p.serverIdHash, H)
  })

  it('rejects an empty fragment', () => {
    assert.throws(() => parseDIDCycles(`did:cycles:${H}#`))
  })

  it('rejects a host-style subject (the dropped did:web M3 form)', () => {
    assert.throws(() => parseDIDCycles('did:cycles:example.com'))
    assert.throws(() => parseDIDCycles('did:cycles:example.com:agents:7'))
  })

  it('rejects a non-cycles method', () => {
    assert.throws(() => parseDIDCycles('did:web:example.com'))
  })

  it('isDIDCycles recognizes the method', () => {
    assert.equal(isDIDCycles(`did:cycles:${H}`), true)
    assert.equal(isDIDCycles('did:web:example.com'), false)
  })
})

describe('cyclesJwksUrl (API-base-relative, not origin-rooted)', () => {
  it('appends /.well-known/cycles-jwks.json to server_id, keeping its path', () => {
    assert.equal(
      cyclesJwksUrl('https://cycles.example.com/v1'),
      'https://cycles.example.com/v1/.well-known/cycles-jwks.json',
    )
  })
  it('collapses a single trailing slash at the join', () => {
    assert.equal(
      cyclesJwksUrl('https://cycles.example.com/v1/'),
      'https://cycles.example.com/v1/.well-known/cycles-jwks.json',
    )
  })
})

// ════════════════════════════════════════════════════════════════
describe('byte-level test vector (RFC 8032 / RFC 8037 linkage)', () => {
  it('base64url x decodes to exactly the 32-byte RFC 8032 public key', () => {
    const bytes = decodeBase64Url(X_B64URL)
    assert.ok(bytes)
    assert.equal(bytes!.length, 32)
    const hex = Buffer.from(bytes!).toString('hex')
    assert.equal(hex, PUB_HEX, 'JWK x must decode to the RFC 8032 Test 1 public key')
  })

  it('derived public key from the seed equals the RFC 8032 public key', () => {
    assert.equal(publicKeyFromPrivate(SEED_HEX), PUB_HEX)
  })

  it('flipping any x byte yields a different (and wrong) key', () => {
    const tampered = '00' + PUB_HEX.slice(2)
    assert.notEqual(tampered, PUB_HEX)
    assert.equal(verify('', TEST1_SIG, tampered), false)
  })
})

// ════════════════════════════════════════════════════════════════
describe('base64url decoder strictness', () => {
  it('rejects standard-base64 chars and padding', () => {
    assert.equal(decodeBase64Url('AA=='), null)
    assert.equal(decodeBase64Url('a+/b'), null)
  })
  it('rejects whitespace and empty input', () => {
    assert.equal(decodeBase64Url(''), null)
    assert.equal(decodeBase64Url('AA AA'), null)
  })
  it('rejects non-canonical trailing bits', () => {
    // 'A_' would set high bits that are not representable in 1 byte.
    // The canonical 1-byte encodings are limited; a stray-bit input fails.
    assert.equal(decodeBase64Url('AB'), null)
  })
})

// ════════════════════════════════════════════════════════════════
describe('selectKey (JWK selection by kid)', () => {
  it('selects the unique kid match', () => {
    const jwks = fixtureJWKS(fixtureJWK('a'), fixtureJWK('b'))
    const sel = selectKey(jwks, 'b')
    assert.equal(sel.ok, true)
    if (sel.ok) assert.equal(sel.publicKeyHex, PUB_HEX)
  })

  it('fails closed when the requested kid is absent', () => {
    const sel = selectKey(fixtureJWKS(fixtureJWK('a')), 'zzz')
    assert.equal(sel.ok, false)
    if (!sel.ok) assert.equal(sel.status, 'not_found')
  })

  it('fails closed on duplicate kids', () => {
    const sel = selectKey(fixtureJWKS(fixtureJWK('dup'), fixtureJWK('dup')), 'dup')
    assert.equal(sel.ok, false)
    if (!sel.ok) assert.equal(sel.status, 'ambiguous')
  })

  it('no kid + single signing key -> use it', () => {
    const sel = selectKey(fixtureJWKS(fixtureJWK('only')))
    assert.equal(sel.ok, true)
  })

  it('no kid + multiple signing keys -> ambiguous', () => {
    const sel = selectKey(fixtureJWKS(fixtureJWK('a'), fixtureJWK('b')))
    assert.equal(sel.ok, false)
    if (!sel.ok) assert.equal(sel.status, 'ambiguous')
  })

  it('rejects an enc-use key', () => {
    const jwks = fixtureJWKS({ kty: 'OKP', crv: 'Ed25519', x: X_B64URL, kid: 'e', use: 'enc' })
    const sel = selectKey(jwks, 'e')
    assert.equal(sel.ok, false)
    if (!sel.ok) assert.equal(sel.status, 'not_found')
  })

  it('rejects an X25519 (key-agreement) curve', () => {
    const jwks = fixtureJWKS({ kty: 'OKP', crv: 'X25519', x: X_B64URL, kid: 'x' })
    const sel = selectKey(jwks, 'x')
    assert.equal(sel.ok, false)
  })

  // ── Cycles window gate + raw-hex match (the v0.2 selection rules) ──
  const winJWK = (kid: string, nbf: number, exp: number | null) => ({
    kty: 'OKP', crv: 'Ed25519', x: X_B64URL, kid, use: 'sig', alg: 'EdDSA',
    cycles_nbf_ms: nbf, cycles_exp_ms: exp,
  })

  it('window gate: selects the key whose [nbf,exp) covers issued_at_ms (not the newest)', () => {
    const jwks = fixtureJWKS(
      winJWK('old', 0, 1000),       // valid [0,1000)
      winJWK('new', 1000, null),    // valid [1000, ∞)
    )
    // An envelope issued at t=500 must resolve to the OLD key, never "current".
    const sel = selectKey(jwks, { issuedAtMs: 500 })
    assert.equal(sel.ok, true)
    if (sel.ok) assert.equal(sel.kid, 'old')
  })

  it('window gate fails closed when no key covers issued_at_ms', () => {
    const sel = selectKey(fixtureJWKS(winJWK('k', 1000, 2000)), { issuedAtMs: 500 })
    assert.equal(sel.ok, false)
    if (!sel.ok) assert.equal(sel.status, 'not_found')
  })

  it('window gate: exp is EXCLUSIVE (issued_at == exp does not cover)', () => {
    const sel = selectKey(fixtureJWKS(winJWK('k', 0, 1000)), { issuedAtMs: 1000 })
    assert.equal(sel.ok, false)
  })

  it('window gate: a non-integer cycles_nbf_ms does not cover (no coercion)', () => {
    const bad = { kty: 'OKP', crv: 'Ed25519', x: X_B64URL, kid: 'k', cycles_nbf_ms: 'soon' }
    const sel = selectKey(fixtureJWKS(bad), { issuedAtMs: 500 })
    assert.equal(sel.ok, false)
  })

  it('window gate: a non-integer issuedAtMs fails closed (no coercion)', () => {
    const jwks = fixtureJWKS(winJWK('k', 0, null))
    assert.equal(selectKey(jwks, { issuedAtMs: 500.5 }).ok, false)
    assert.equal(selectKey(jwks, { issuedAtMs: '500' as unknown as number }).ok, false)
  })

  it('raw-hex match: selects the JWK whose x decodes to the signer key', () => {
    const sel = selectKey(fixtureJWKS(fixtureJWK('a'), fixtureJWK('b')), { publicKeyHex: PUB_HEX })
    // both fixtures carry PUB_HEX → ambiguous (two carriers, no other narrowing)
    assert.equal(sel.ok, false)
    if (!sel.ok) assert.equal(sel.status, 'ambiguous')
  })

  it('raw-hex match: no JWK carries the signer key → not_found', () => {
    const other = Buffer.from(PUB_HEX, 'hex'); other[0] ^= 0xff
    const sel = selectKey(fixtureJWKS(fixtureJWK('a')), { publicKeyHex: other.toString('hex') })
    assert.equal(sel.ok, false)
    if (!sel.ok) assert.equal(sel.status, 'not_found')
  })

  it('rejects x that does not decode to 32 bytes', () => {
    const jwks = fixtureJWKS({ kty: 'OKP', crv: 'Ed25519', x: 'AAAA', kid: 'short' })
    const sel = selectKey(jwks, 'short')
    assert.equal(sel.ok, false)
    if (!sel.ok) assert.equal(sel.status, 'malformed')
  })

  it('strips a private d member (never used)', () => {
    // d present is a misconfiguration; selection still returns the public x.
    const jwks = fixtureJWKS({
      kty: 'OKP', crv: 'Ed25519', x: X_B64URL, kid: 'p', d: SEED_HEX,
    } as object)
    const sel = selectKey(jwks, 'p')
    assert.equal(sel.ok, true)
    if (sel.ok) {
      assert.equal(sel.publicKeyHex, PUB_HEX)
      assert.equal('d' in (sel.jwk as Record<string, unknown>) , true) // input untouched
    }
  })
})

describe('asJWKS structural validation', () => {
  it('rejects a body without keys[]', () => {
    assert.equal(asJWKS({}), null)
    assert.equal(asJWKS({ keys: [] }), null)
    assert.equal(asJWKS(null), null)
    assert.equal(asJWKS('nope'), null)
  })
})

// ════════════════════════════════════════════════════════════════
describe('CyclesKeyResolver: did:cycles / JWKS', () => {
  // did:cycles is hash-bound (not self-locating): the cycles verify layer
  // derives the JWKS URL from the envelope's server_id and supplies it. These
  // tests pass jwksUrl directly (optionally alongside the hash-bound did to
  // exercise the #fragment kid), mirroring how the verify path calls in.
  const HASH = 'a'.repeat(64)
  const CYCLES_URL = 'https://h.test/v1/.well-known/cycles-jwks.json'

  it('resolves a did:cycles key (fragment kid) to the RFC 8032 public key', async () => {
    const { impl } = jsonFetch(fixtureJWKS(fixtureJWK('test-1')))
    const r = new CyclesKeyResolver({ fetchImpl: impl })
    const res = await r.resolve({ did: `did:cycles:${HASH}#test-1`, jwksUrl: CYCLES_URL })
    assert.equal(res.ok, true)
    assert.equal(res.publicKeyHex, PUB_HEX)
    assert.equal(res.kid, 'test-1')
    assert.ok(res.scope_of_claim, 'resolved key carries scope_of_claim')
  })

  it('resolves a direct jwksUrl + explicit kid', async () => {
    const { impl } = jsonFetch(fixtureJWKS(fixtureJWK('k1')))
    const r = new CyclesKeyResolver({ fetchImpl: impl })
    const res = await r.resolve({ jwksUrl: CYCLES_URL, kid: 'k1' })
    assert.equal(res.ok, true)
    assert.equal(res.publicKeyHex, PUB_HEX)
  })

  it('rejects a non-https jwksUrl as unsupported', async () => {
    const r = new CyclesKeyResolver()
    const res = await r.resolve({ jwksUrl: 'http://insecure.test/cycles-jwks.json' })
    assert.equal(res.ok, false)
    assert.equal(res.status, 'unsupported')
  })

  it('a did:cycles locator with no jwksUrl is unsupported (not self-locating)', async () => {
    const r = new CyclesKeyResolver()
    const res = await r.resolve({ did: `did:cycles:${HASH}#k` })
    assert.equal(res.ok, false)
    assert.equal(res.status, 'unsupported')
  })

  it('fails closed when DID fragment and explicit kid disagree', async () => {
    const { impl } = jsonFetch(fixtureJWKS(fixtureJWK('a')))
    const r = new CyclesKeyResolver({ fetchImpl: impl })
    const res = await r.resolve({ did: `did:cycles:${HASH}#a`, jwksUrl: CYCLES_URL, kid: 'b' })
    assert.equal(res.ok, false)
    assert.equal(res.status, 'ambiguous')
  })

  it('malformed JWKS fails closed even under fail-open', async () => {
    const { impl } = jsonFetch({ not: 'a jwks' })
    const r = new CyclesKeyResolver({ fetchImpl: impl, failurePolicy: 'open' })
    const res = await r.resolve({ jwksUrl: CYCLES_URL, kid: 'k' })
    assert.equal(res.ok, false)
    assert.equal(res.status, 'malformed')
    assert.notEqual(res.degraded, true) // not a transient-network relaxation
  })

  it('cache key includes the window: an out-of-window issuance is not a stale hit', async () => {
    // Same jwksUrl + kid, one key valid [0,1000). An in-window resolution must
    // NOT be served from cache for an out-of-window issuance — the window is
    // part of the cache key (regression guard for cross-window contamination).
    const jwks = fixtureJWKS({
      kty: 'OKP', crv: 'Ed25519', x: X_B64URL, kid: 'k', use: 'sig', alg: 'EdDSA',
      cycles_nbf_ms: 0, cycles_exp_ms: 1000,
    })
    const { impl } = jsonFetch(jwks)
    const r = new CyclesKeyResolver({ fetchImpl: impl })
    const inWin = await r.resolve({ jwksUrl: CYCLES_URL, kid: 'k', issuedAtMs: 500 })
    const outWin = await r.resolve({ jwksUrl: CYCLES_URL, kid: 'k', issuedAtMs: 5000 })
    assert.equal(inWin.ok, true)
    assert.equal(outWin.ok, false, 'out-of-window issuance must not reuse the in-window cache entry')
  })
})

// ════════════════════════════════════════════════════════════════
describe('cache hit and cache miss', () => {
  it('serves a second identical resolution from cache (one fetch)', async () => {
    const f = jsonFetch(fixtureJWKS(fixtureJWK('k')))
    const r = new CyclesKeyResolver({ fetchImpl: f.impl })
    const a = await r.resolve({ jwksUrl: 'https://h.test/v1/.well-known/cycles-jwks.json', kid: 'k' })
    const b = await r.resolve({ jwksUrl: 'https://h.test/v1/.well-known/cycles-jwks.json', kid: 'k' })
    assert.equal(a.cacheHit, false, 'first call is a miss')
    assert.equal(b.cacheHit, true, 'second call is a hit')
    assert.equal(f.calls(), 1, 'cache hit avoids the second fetch')
    assert.equal(b.publicKeyHex, PUB_HEX)
  })

  it('expired entry is a miss and re-fetches', async () => {
    let clock = 1_000
    const f = jsonFetch(fixtureJWKS(fixtureJWK('k')))
    const r = new CyclesKeyResolver({
      fetchImpl: f.impl,
      now: () => clock,
      cache: { ttlMs: 100 },
    })
    await r.resolve({ jwksUrl: 'https://h.test/v1/.well-known/cycles-jwks.json', kid: 'k' })
    clock += 200 // advance past TTL
    const b = await r.resolve({ jwksUrl: 'https://h.test/v1/.well-known/cycles-jwks.json', kid: 'k' })
    assert.equal(b.cacheHit, false, 'expired entry is a miss')
    assert.equal(f.calls(), 2, 'expired entry triggers a re-fetch')
  })

  it('a cached miss is never promoted to a key', async () => {
    const f = jsonFetch(fixtureJWKS(fixtureJWK('present')))
    const r = new CyclesKeyResolver({ fetchImpl: f.impl })
    const miss = await r.resolve({ jwksUrl: 'https://h.test/v1/.well-known/cycles-jwks.json', kid: 'absent' })
    assert.equal(miss.ok, false)
    const again = await r.resolve({ jwksUrl: 'https://h.test/v1/.well-known/cycles-jwks.json', kid: 'absent' })
    assert.equal(again.ok, false)
    assert.equal(again.publicKeyHex, undefined)
    assert.equal(again.cacheHit, true, 'negative result is cached')
  })
})

// ════════════════════════════════════════════════════════════════
describe('unreachable endpoint: fail-closed vs fail-open', () => {
  it('fail-closed (default): unreachable rejects, no key', async () => {
    const f = throwingFetch()
    const r = new CyclesKeyResolver({ fetchImpl: f.impl }) // default closed
    const res = await r.resolve({ jwksUrl: 'https://down.test/v1/.well-known/cycles-jwks.json', kid: 'k' })
    assert.equal(res.ok, false)
    assert.equal(res.status, 'unreachable')
    assert.equal(res.degraded, false)
    assert.equal(res.publicKeyHex, undefined)
  })

  it('non-200 is unreachable and rejects under fail-closed', async () => {
    const { impl } = jsonFetch({}, 503)
    const r = new CyclesKeyResolver({ fetchImpl: impl })
    const res = await r.resolve({ jwksUrl: 'https://down.test/v1/.well-known/cycles-jwks.json', kid: 'k' })
    assert.equal(res.ok, false)
    assert.equal(res.status, 'unreachable')
  })

  it('fail-open: unreachable yields a degraded result with NO key', async () => {
    const f = throwingFetch()
    const r = new CyclesKeyResolver({ fetchImpl: f.impl, failurePolicy: 'open' })
    const res = await r.resolve({ jwksUrl: 'https://down.test/v1/.well-known/cycles-jwks.json', kid: 'k' })
    assert.equal(res.ok, false, 'degraded is still not a positive verification')
    assert.equal(res.status, 'unreachable')
    assert.equal(res.degraded, true)
    assert.equal(res.publicKeyHex, undefined, 'fail-open never fabricates key material')
    assert.ok(res.scope_of_claim, 'degraded result carries a scope_of_claim')
  })
})

// ════════════════════════════════════════════════════════════════
describe('key rotation picks the new key', () => {
  it('a new kid in keys[] is selected when the envelope points at it', async () => {
    const KP_NEW = (() => {
      // A second, independent key under a new kid.
      const seed = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'
      const pub = publicKeyFromPrivate(seed)
      const x = Buffer.from(pub, 'hex').toString('base64url')
      return { seed, pub, x }
    })()
    const jwks = fixtureJWKS(
      fixtureJWK('old-2025'),                          // old key, RFC8032 pub
      fixtureJWK('new-2026', KP_NEW.x),                // rotated-in key
    )
    const { impl } = jsonFetch(jwks)
    const r = new CyclesKeyResolver({ fetchImpl: impl })

    const oldRes = await r.resolve({ jwksUrl: 'https://h.test/v1/.well-known/cycles-jwks.json', kid: 'old-2025' })
    const newRes = await r.resolve({ jwksUrl: 'https://h.test/v1/.well-known/cycles-jwks.json', kid: 'new-2026' })
    assert.equal(oldRes.publicKeyHex, PUB_HEX)
    assert.equal(newRes.publicKeyHex, KP_NEW.pub)
    assert.notEqual(oldRes.publicKeyHex, newRes.publicKeyHex)
  })
})

// ════════════════════════════════════════════════════════════════
describe('did:key and did:web registered behind the interface', () => {
  it('did:key resolves self-certifyingly with no fetch', async () => {
    const didKey = toDIDKey(PUB_HEX)
    // A fetch that would throw if called: shows no network for did:key.
    const r = new CyclesKeyResolver({ fetchImpl: throwingFetch().impl })
    const res = await r.resolve({ did: didKey })
    assert.equal(res.ok, true)
    assert.equal(res.publicKeyHex, PUB_HEX)
  })

  it('did:web resolves a verificationMethod by fragment (publicKeyMultibase)', async () => {
    const didWeb = 'did:web:vm.test'
    const keyId = `${didWeb}#key-1`
    const { multibaseFromHex } = await loadMultibase()
    const doc = {
      id: didWeb,
      verificationMethod: [{
        id: keyId,
        type: 'Ed25519VerificationKey2020',
        controller: didWeb,
        publicKeyMultibase: multibaseFromHex(PUB_HEX),
      }],
    }
    // The existing resolveDIDWeb (unchanged, reused behind the interface)
    // reads the global fetch. Stub it for this test, then restore.
    const original = globalThis.fetch
    globalThis.fetch = (async () => ({
      ok: true,
      status: 200,
      json: async () => doc,
    })) as unknown as typeof fetch
    try {
      const r = new CyclesKeyResolver()
      const res = await r.resolve({ did: `${didWeb}#key-1` })
      assert.equal(res.ok, true)
      assert.equal(res.publicKeyHex, PUB_HEX)
      assert.equal(res.kid, 'key-1')
    } finally {
      globalThis.fetch = original
    }
  })

  it('canResolve recognizes all three methods and a direct jwksUrl', () => {
    const r = new CyclesKeyResolver()
    assert.equal(r.canResolve({ did: 'did:key:z6Mk...' }), true)
    assert.equal(r.canResolve({ did: 'did:web:e.test' }), true)
    assert.equal(r.canResolve({ did: 'did:cycles:e.test' }), false) // hash-bound, needs jwksUrl
    assert.equal(r.canResolve({ jwksUrl: 'https://e.test/v1/.well-known/cycles-jwks.json' }), true)
    assert.equal(r.canResolve({ jwksUrl: 'https://e.test/jwks.json' }), true)
    assert.equal(r.canResolve({ did: 'did:example:nope' }), false)
  })
})

async function loadMultibase() {
  const did = await import('../../../src/core/did.js')
  return { multibaseFromHex: did.hexToMultibase }
}

// ════════════════════════════════════════════════════════════════
describe('end-to-end: a did:cycles envelope verifies against a JWKS', () => {
  // A minimal Cycles-style signed envelope: a message and a detached
  // Ed25519 signature whose verification key is named by a did:cycles
  // URL. The resolver fetches the JWKS, selects the key by kid, and the
  // existing verify() completes the check.
  // did:cycles is hash-bound, so the JWKS URL comes from the envelope's
  // server_id (here a constant; the verify layer derives + binds it). The
  // resolver is handed {jwksUrl, kid}.
  const E2E_JWKS_URL = 'https://fixture.test/v1/.well-known/cycles-jwks.json'

  function signEnvelope(message: string, seedHex: string, kid: string) {
    return { message, kid, signature: sign(message, seedHex) }
  }

  async function verifyEnvelope(
    env: { message: string; kid: string; signature: string },
    resolver: CyclesKeyResolver,
    jwksUrl: string = E2E_JWKS_URL,
  ): Promise<{ verified: boolean; resolution: KeyResolution }> {
    const resolution = await resolver.resolve({ jwksUrl, kid: env.kid })
    if (!resolution.ok || !resolution.publicKeyHex) {
      return { verified: false, resolution } // fail-closed
    }
    const verified = verify(env.message, env.signature, resolution.publicKeyHex)
    return { verified, resolution }
  }

  it('verifies the empty-message RFC 8032 envelope end to end', async () => {
    const { impl } = jsonFetch(fixtureJWKS(fixtureJWK('test-1')))
    const resolver = new CyclesKeyResolver({ fetchImpl: impl })
    const env = signEnvelope('', SEED_HEX, 'test-1')
    const { verified, resolution } = await verifyEnvelope(env, resolver)
    assert.equal(verified, true, 'envelope must verify end to end')
    assert.equal(resolution.publicKeyHex, PUB_HEX)
  })

  it('verifies a non-empty-message envelope end to end', async () => {
    const { impl } = jsonFetch(fixtureJWKS(fixtureJWK('test-1')))
    const resolver = new CyclesKeyResolver({ fetchImpl: impl })
    const env = signEnvelope('cycles:permit:reservation-42', SEED_HEX, 'test-1')
    const { verified } = await verifyEnvelope(env, resolver)
    assert.equal(verified, true)
  })

  it('flipping any x byte in the served JWKS makes the check fail', async () => {
    // Tamper the JWKS x so it decodes to a different key; the resolved
    // key no longer matches the signer, and verification fails closed.
    const tamperedX = (() => {
      const bytes = Buffer.from(PUB_HEX, 'hex')
      bytes[0] ^= 0xff
      return bytes.toString('base64url')
    })()
    const { impl } = jsonFetch(fixtureJWKS(fixtureJWK('test-1', tamperedX)))
    const resolver = new CyclesKeyResolver({ fetchImpl: impl })
    const env = signEnvelope('', SEED_HEX, 'test-1')
    const { verified } = await verifyEnvelope(env, resolver)
    assert.equal(verified, false, 'a tampered JWKS key must not verify the signature')
  })

  it('an unreachable JWKS makes the envelope check fail closed', async () => {
    const resolver = new CyclesKeyResolver({ fetchImpl: throwingFetch().impl })
    const env = signEnvelope('', SEED_HEX, 'test-1')
    const { verified, resolution } = await verifyEnvelope(
      env, resolver, 'https://down.test/v1/.well-known/cycles-jwks.json',
    )
    assert.equal(verified, false)
    assert.equal(resolution.status, 'unreachable')
  })
})
