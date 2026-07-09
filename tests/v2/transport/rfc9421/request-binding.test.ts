// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Tests for the RFC 9421 + RFC 9530 request-binding profile.
 *
 * Conformance vectors are byte-matched against the authoritative RFC text:
 *   - RFC 9530 Appendix B.1: sha-256 Content-Digest of {"hello": "world"}\n
 *   - RFC 9421 Appendix B.2.6: Ed25519 signed request (deterministic, so the
 *     signature value is byte-reproducible).
 *
 * Negative paths are explicit: wrong method, swapped path, body substitution
 * (content-digest mismatch), stale created (outside skew), and replayed nonce.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  buildSignatureBase,
  computeContentDigest,
  deriveAuthority,
  derivePath,
  signRequest,
  verifyRequest,
  InMemoryNonceStore,
  APS_REQUEST_BINDING_TAG,
  DEFAULT_COVERED,
} from '../../../../src/v2/transport/rfc9421/index.js'
import { sign as ed25519Sign } from '../../../../src/crypto/keys.js'
import type {
  RequestContext,
  SignatureParams,
  SignerKey,
  VerifierKey,
  VerifyPolicy,
  RequestBindingProfile,
} from '../../../../src/v2/transport/rfc9421/index.js'

// ── RFC 9421 Appendix B.2.6 test key (test-key-ed25519), as JWK ──
const B26_JWK = {
  d: 'n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU',
  x: 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs',
}

function b64urlToHex(s: string): string {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('hex')
}

const B26_PRIV_HEX = b64urlToHex(B26_JWK.d)
const B26_PUB_HEX = b64urlToHex(B26_JWK.x)

// ── RFC 9530 Appendix B.1 ──────────────────────────────────────────
test('RFC 9530 B.1: content-digest of {"hello": "world"}\\n byte-matches', () => {
  const body = Buffer.from('{"hello": "world"}\n', 'utf8')
  assert.equal(body.length, 19)
  const digest = computeContentDigest(new Uint8Array(body), 'sha-256')
  assert.equal(
    digest,
    'sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:',
  )
})

test('content-digest rejects an unsupported algorithm', () => {
  const body = new Uint8Array([1, 2, 3])
  assert.throws(
    () => computeContentDigest(body, 'sha-512' as 'sha-256'),
    /unsupported content-digest algorithm/,
  )
})

// ── RFC 9421 §2.2 derived-component helpers ────────────────────────
test('@authority lowercases host and omits default ports', () => {
  assert.equal(deriveAuthority(new URL('https://Example.com/foo')), 'example.com')
  assert.equal(deriveAuthority(new URL('https://example.com:443/foo')), 'example.com')
  assert.equal(deriveAuthority(new URL('http://example.com:80/foo')), 'example.com')
})

test('@authority keeps a non-default port', () => {
  assert.equal(deriveAuthority(new URL('https://example.com:8443/foo')), 'example.com:8443')
})

test('@path returns absolute path and normalizes empty to /', () => {
  assert.equal(derivePath(new URL('https://example.com/foo?x=1')), '/foo')
  assert.equal(derivePath(new URL('https://example.com')), '/')
})

// ── RFC 9421 Appendix B.2.6: byte-matchable Ed25519 signature ──────
// Build the exact B.2.6 signature base directly (the published vector covers
// date/@method/@path/@authority/content-type/content-length, which is broader
// than this profile's default set) and confirm our signing reproduces the
// published signature value byte-for-byte. This validates the line format,
// the ": " separator, LF joining, lowercasing, and the @signature-params
// trailer that the profile's buildSignatureBase relies on.
test('RFC 9421 B.2.6: Ed25519 signature over the published base byte-matches', () => {
  const base = [
    '"date": Tue, 20 Apr 2021 02:07:55 GMT',
    '"@method": POST',
    '"@path": /foo',
    '"@authority": example.com',
    '"content-type": application/json',
    '"content-length": 18',
    '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
  ].join('\n')

  const sigHex = ed25519Sign(base, B26_PRIV_HEX)
  const sigB64 = Buffer.from(sigHex, 'hex').toString('base64')
  assert.equal(
    sigB64,
    'wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==',
  )
})

// ── Signature-base construction for the request-binding profile ────
test('buildSignatureBase produces the exact line format for @method/@authority/@path', () => {
  const ctx: RequestContext = {
    method: 'post',
    url: 'https://example.com/foo?param=Value&Pet=dog',
  }
  const params: SignatureParams = {
    created: 1618884473,
    keyid: 'did:key:zTest#zTest',
    nonce: 'nonce-1',
    tag: APS_REQUEST_BINDING_TAG,
  }
  const { base } = buildSignatureBase(['@method', '@authority', '@path'], ctx, params)
  const expected = [
    '"@method": POST',
    '"@authority": example.com',
    '"@path": /foo',
    `"@signature-params": ("@method" "@authority" "@path");created=1618884473;keyid="did:key:zTest#zTest";nonce="nonce-1";tag="${APS_REQUEST_BINDING_TAG}"`,
  ].join('\n')
  assert.equal(base, expected)
  // No trailing newline after @signature-params.
  assert.ok(!base.endsWith('\n'))
})

test('buildSignatureBase includes content-digest line when body is covered', () => {
  const body = Buffer.from('{"hello": "world"}\n', 'utf8')
  const ctx: RequestContext = {
    method: 'POST',
    url: 'https://example.com/foo',
    body: new Uint8Array(body),
  }
  const params: SignatureParams = {
    created: 1618884473,
    keyid: 'did:key:zTest#zTest',
    nonce: 'n',
    tag: APS_REQUEST_BINDING_TAG,
  }
  const { base, contentDigest } = buildSignatureBase(
    ['@method', '@authority', '@path', 'content-digest'],
    ctx,
    params,
  )
  assert.equal(contentDigest, 'sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:')
  assert.ok(
    base.includes(
      '"content-digest": sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:',
    ),
  )
})

// ── Helpers for round-trip and negative tests ──────────────────────
const SIGNER: SignerKey = {
  privateKeyHex: B26_PRIV_HEX,
  verificationMethod: 'did:key:zB26#zB26',
}
const VERIFIER_KEY: VerifierKey = {
  publicKeyHex: B26_PUB_HEX,
  verificationMethod: 'did:key:zB26#zB26',
}
const NOW = 1618884473

function basePolicy(overrides: Partial<VerifyPolicy> = {}): VerifyPolicy {
  return {
    expectedTag: APS_REQUEST_BINDING_TAG,
    maxSkewSeconds: 300,
    nowSeconds: NOW,
    ...overrides,
  }
}

function signSample(body?: Uint8Array, covered = DEFAULT_COVERED): RequestBindingProfile {
  const ctx: RequestContext = {
    method: 'POST',
    url: 'https://example.com/foo?param=Value',
    ...(body !== undefined ? { body } : {}),
  }
  return signRequest({
    request: ctx,
    signer: SIGNER,
    params: { created: NOW, nonce: 'nonce-abc' },
    covered,
    receiptHash: 'a'.repeat(64),
  })
}

// ── Positive: full sign/verify round-trip ──────────────────────────
test('round-trip: a valid request-binding profile verifies', () => {
  const profile = signSample()
  const ctx: RequestContext = { method: 'POST', url: 'https://example.com/foo?param=Value' }
  const result = verifyRequest({
    profile,
    request: ctx,
    keys: [VERIFIER_KEY],
    policy: basePolicy(),
  })
  assert.equal(result.valid, true)
  assert.equal(result.verificationMethod, 'did:key:zB26#zB26')
})

// Regression (round-3): a declared `expires` must be enforced. `created` freshness alone does not
// cover a short-lived signature presented late within the broader skew window.
test('a signature past its declared expires is rejected even within the created skew window', () => {
  const ctx: RequestContext = { method: 'POST', url: 'https://example.com/foo?param=Value' }
  const profile = signRequest({
    request: ctx,
    signer: SIGNER,
    params: { created: NOW, nonce: 'nonce-exp', expires: NOW + 30 },
    covered: DEFAULT_COVERED,
    receiptHash: 'a'.repeat(64),
  })
  // created (NOW) is within +/-300 of NOW+60, but expires (NOW+30) has already passed.
  const expired = verifyRequest({ profile, request: ctx, keys: [VERIFIER_KEY], policy: basePolicy({ nowSeconds: NOW + 60 }) })
  assert.equal(expired.valid, false)
  assert.equal(expired.reason, 'expired')
  // Before expiry the same signature still verifies.
  const fresh = verifyRequest({ profile, request: ctx, keys: [VERIFIER_KEY], policy: basePolicy({ nowSeconds: NOW + 10 }) })
  assert.equal(fresh.valid, true)
})

test('round-trip with a covered body verifies, and the receipt link is carried', () => {
  const body = new Uint8Array(Buffer.from('{"hello": "world"}\n', 'utf8'))
  const profile = signSample(body, ['@method', '@authority', '@path', 'content-digest'])
  assert.equal(profile.receiptHash, 'a'.repeat(64))
  assert.equal(profile.inner.contentDigest, 'sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:')
  const ctx: RequestContext = {
    method: 'POST',
    url: 'https://example.com/foo?param=Value',
    body,
  }
  const result = verifyRequest({
    profile,
    request: ctx,
    keys: [VERIFIER_KEY],
    policy: basePolicy({ requiredComponents: ['@method', '@authority', '@path', 'content-digest'] }),
  })
  assert.equal(result.valid, true)
})

test('the Signature-Input RHS byte-matches the @signature-params line in the base', () => {
  const profile = signSample()
  const rhs = profile.inner.signatureInput.replace(/^aps=/, '')
  const trailerLine = profile.inner.signatureBase.split('\n').at(-1) ?? ''
  const trailerValue = trailerLine.replace('"@signature-params": ', '')
  assert.equal(rhs, trailerValue)
})

test('signRequest refuses an empty covered set', () => {
  assert.throws(
    () =>
      signRequest({
        request: { method: 'GET', url: 'https://example.com/' },
        signer: SIGNER,
        params: { created: NOW, nonce: 'n' },
        covered: [],
      }),
    /empty covered set/,
  )
})

// ── Negative: wrong method ─────────────────────────────────────────
test('reject: wrong method (received GET, signed POST)', () => {
  const profile = signSample()
  const ctx: RequestContext = { method: 'GET', url: 'https://example.com/foo?param=Value' }
  const result = verifyRequest({
    profile,
    request: ctx,
    keys: [VERIFIER_KEY],
    policy: basePolicy(),
  })
  assert.equal(result.valid, false)
  assert.equal(result.reason, 'base_reconstruction_mismatch')
})

// ── Negative: swapped path ─────────────────────────────────────────
test('reject: swapped path (received /bar, signed /foo)', () => {
  const profile = signSample()
  const ctx: RequestContext = { method: 'POST', url: 'https://example.com/bar?param=Value' }
  const result = verifyRequest({
    profile,
    request: ctx,
    keys: [VERIFIER_KEY],
    policy: basePolicy(),
  })
  assert.equal(result.valid, false)
  assert.equal(result.reason, 'base_reconstruction_mismatch')
})

// ── Negative: swapped authority ────────────────────────────────────
test('reject: swapped authority (received evil.com, signed example.com)', () => {
  const profile = signSample()
  const ctx: RequestContext = { method: 'POST', url: 'https://evil.com/foo?param=Value' }
  const result = verifyRequest({
    profile,
    request: ctx,
    keys: [VERIFIER_KEY],
    policy: basePolicy(),
  })
  assert.equal(result.valid, false)
  assert.equal(result.reason, 'base_reconstruction_mismatch')
})

// ── Negative: body substitution (content-digest mismatch) ──────────
test('reject: body substitution fails content-digest recomputation', () => {
  const signedBody = new Uint8Array(Buffer.from('{"hello": "world"}\n', 'utf8'))
  const profile = signSample(signedBody, ['@method', '@authority', '@path', 'content-digest'])
  const tamperedBody = new Uint8Array(Buffer.from('{"hello": "evil"}\n', 'utf8'))
  const ctx: RequestContext = {
    method: 'POST',
    url: 'https://example.com/foo?param=Value',
    body: tamperedBody,
  }
  const result = verifyRequest({
    profile,
    request: ctx,
    keys: [VERIFIER_KEY],
    policy: basePolicy({ requiredComponents: ['@method', '@authority', '@path', 'content-digest'] }),
  })
  assert.equal(result.valid, false)
  assert.equal(result.reason, 'content_digest_mismatch')
})

// ── Negative: stale created (outside skew) ─────────────────────────
test('reject: stale created outside the skew window', () => {
  const profile = signSample()
  const ctx: RequestContext = { method: 'POST', url: 'https://example.com/foo?param=Value' }
  const result = verifyRequest({
    profile,
    request: ctx,
    keys: [VERIFIER_KEY],
    policy: basePolicy({ nowSeconds: NOW + 1000, maxSkewSeconds: 300 }),
  })
  assert.equal(result.valid, false)
  assert.equal(result.reason, 'stale_created')
})

test('reject: future-dated created outside the skew window', () => {
  const profile = signSample()
  const ctx: RequestContext = { method: 'POST', url: 'https://example.com/foo?param=Value' }
  const result = verifyRequest({
    profile,
    request: ctx,
    keys: [VERIFIER_KEY],
    policy: basePolicy({ nowSeconds: NOW - 1000, maxSkewSeconds: 300 }),
  })
  assert.equal(result.valid, false)
  assert.equal(result.reason, 'stale_created')
})

// ── Negative: replayed nonce ───────────────────────────────────────
test('reject: a replayed nonce on second verify', () => {
  const profile = signSample()
  const ctx: RequestContext = { method: 'POST', url: 'https://example.com/foo?param=Value' }
  const store = new InMemoryNonceStore()
  const first = verifyRequest({
    profile,
    request: ctx,
    keys: [VERIFIER_KEY],
    policy: basePolicy(),
    nonceStore: store,
  })
  assert.equal(first.valid, true)
  const second = verifyRequest({
    profile,
    request: ctx,
    keys: [VERIFIER_KEY],
    policy: basePolicy(),
    nonceStore: store,
  })
  assert.equal(second.valid, false)
  assert.equal(second.reason, 'replayed_nonce')
})

test('a failed verify does not consume the nonce', () => {
  const profile = signSample()
  const store = new InMemoryNonceStore()
  // First attempt fails on tag mismatch, must not record the nonce.
  const bad = verifyRequest({
    profile,
    request: { method: 'POST', url: 'https://example.com/foo?param=Value' },
    keys: [VERIFIER_KEY],
    policy: basePolicy({ expectedTag: 'some-other-tag' }),
    nonceStore: store,
  })
  assert.equal(bad.valid, false)
  assert.equal(bad.reason, 'tag_mismatch')
  // The valid request should now still succeed because the nonce was untouched.
  const good = verifyRequest({
    profile,
    request: { method: 'POST', url: 'https://example.com/foo?param=Value' },
    keys: [VERIFIER_KEY],
    policy: basePolicy(),
    nonceStore: store,
  })
  assert.equal(good.valid, true)
})

// ── Negative: tag mismatch (cross-protocol reuse) ──────────────────
test('reject: tag mismatch (cross-protocol reuse defense)', () => {
  const profile = signSample()
  const result = verifyRequest({
    profile,
    request: { method: 'POST', url: 'https://example.com/foo?param=Value' },
    keys: [VERIFIER_KEY],
    policy: basePolicy({ expectedTag: 'unexpected' }),
  })
  assert.equal(result.valid, false)
  assert.equal(result.reason, 'tag_mismatch')
})

// ── Negative: empty / missing required component ───────────────────
test('reject: covered set missing a required component', () => {
  // Sign covering only @method/@authority, then require @path.
  const profile = signSample(undefined, ['@method', '@authority'])
  const result = verifyRequest({
    profile,
    request: { method: 'POST', url: 'https://example.com/foo?param=Value' },
    keys: [VERIFIER_KEY],
    policy: basePolicy(),
  })
  assert.equal(result.valid, false)
  assert.equal(result.reason, 'missing_required_component')
})

test('reject: an empty covered set in a hand-built profile', () => {
  const profile = signSample()
  const tampered: RequestBindingProfile = { ...profile, covered: [] }
  const result = verifyRequest({
    profile: tampered,
    request: { method: 'POST', url: 'https://example.com/foo?param=Value' },
    keys: [VERIFIER_KEY],
    policy: basePolicy(),
  })
  assert.equal(result.valid, false)
  assert.equal(result.reason, 'empty_covered_set')
})

// ── Negative: unknown verification method ──────────────────────────
test('reject: unknown verification method (no key)', () => {
  const profile = signSample()
  const result = verifyRequest({
    profile,
    request: { method: 'POST', url: 'https://example.com/foo?param=Value' },
    keys: [{ publicKeyHex: VERIFIER_KEY.publicKeyHex, verificationMethod: 'did:key:zOther#zOther' }],
    policy: basePolicy(),
  })
  assert.equal(result.valid, false)
  assert.equal(result.reason, 'unknown_verification_method')
})

// ── Negative: tampered signature ───────────────────────────────────
test('reject: a tampered signature fails the Ed25519 check', () => {
  const profile = signSample()
  // Re-sign a DIFFERENT base with the same key to get a valid-but-wrong sig.
  // This keeps the byte-sequence well formed (so it passes parsing) yet the
  // signature does not match the reconstructed base.
  const wrongSigHex = ed25519Sign('not-the-base', SIGNER.privateKeyHex)
  const wrongByteSeq = `:${Buffer.from(wrongSigHex, 'hex').toString('base64')}:`
  const tampered: RequestBindingProfile = {
    ...profile,
    inner: { ...profile.inner, signature: `${profile.inner.label}=${wrongByteSeq}` },
  }
  const result = verifyRequest({
    profile: tampered,
    request: { method: 'POST', url: 'https://example.com/foo?param=Value' },
    keys: [VERIFIER_KEY],
    policy: basePolicy(),
  })
  assert.equal(result.valid, false)
  assert.equal(result.reason, 'signature_invalid')
})

// ── Scope-of-claim is carried and honest ───────────────────────────
test('profile carries an honest scope-of-claim that disclaims action_ref binding', () => {
  const profile = signSample()
  assert.equal(profile.scopeOfClaim.self_attested, true)
  const joined = profile.scopeOfClaim.does_not_assert.join(' ').toLowerCase()
  assert.ok(joined.includes('action_ref'))
  assert.ok(joined.includes('authority'))
})
