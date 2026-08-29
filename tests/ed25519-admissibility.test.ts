// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Ed25519 admissibility. A public key or an R that decodes to a small-order
// point, a non-canonically encoded public key or R, and a scalar S that is not
// reduced modulo the group order are all inadmissible, so the artifact that
// carries them is refused before it is believed.
//
// tests/fixtures/ed25519-admissibility-v1.json records the behaviour on which
// the two strict reference implementations agree: libsodium through PyNaCl
// (agent-passport-python) and ed25519-dalek verify_strict
// (crates/aps-verifier-core). The same file is used by the Rust, Go and Python
// suites, so the four implementations answer every vector the same way by
// construction.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { verify, sign, generateKeyPair } from '../src/crypto/keys.js'
import { isAdmissiblePoint } from '../src/crypto/ed25519-admissibility.js'
import {
  canonicalizeEnvelope,
  sha256Hex,
  verifyInstructionProvenanceReceipt,
} from '../src/v2/instruction-provenance/index.js'

interface Vector {
  id: string
  group: string
  note: string
  message_utf8: string
  public_key_hex: string
  signature_hex: string
  expected_verification: boolean
}

const doc = JSON.parse(
  readFileSync(new URL('./fixtures/ed25519-admissibility-v1.json', import.meta.url), 'utf-8'),
) as {
  version: string
  count: number
  vectors: Vector[]
  artifact_vectors: {
    note: string
    public_key_hex: string
    canonical_preimage: string
    delegation: Record<string, unknown>
  }
}

/** The Edwards identity point as a public key. */
const IDENTITY_KEY = '0100000000000000000000000000000000000000000000000000000000000000'
/** R = the identity encoding, S = 0. The RFC 8032 equation degenerates to
 *  identity = identity, so this verifies under every message unless
 *  admissibility is checked. */
const DEGENERATE_SIG =
  '0100000000000000000000000000000000000000000000000000000000000000' +
  '0000000000000000000000000000000000000000000000000000000000000000'

test('the fixture is the one this suite was written against', () => {
  assert.equal(doc.version, 'ed25519-admissibility-v1')
  assert.equal(doc.vectors.length, doc.count)
})

test('admissibility vectors match the strict reference', () => {
  const wrong: string[] = []
  for (const v of doc.vectors) {
    const got = verify(v.message_utf8, v.signature_hex, v.public_key_hex)
    if (got !== v.expected_verification) {
      wrong.push(`${v.id} [${v.group}] expected ${v.expected_verification} got ${got} :: ${v.note}`)
    }
  }
  assert.equal(
    wrong.length,
    0,
    `${wrong.length} of ${doc.vectors.length} vectors disagree with the strict reference:\n${wrong
      .slice(0, 12)
      .join('\n')}`,
  )
})

test('a small-order public key is rejected', () => {
  assert.equal(verify('APS admissibility probe', DEGENERATE_SIG, IDENTITY_KEY), false)
  assert.equal(verify('a completely different message', DEGENERATE_SIG, IDENTITY_KEY), false)
})

test('every small-order encoding is rejected', () => {
  const groups = ['small_order_pk', 'small_order_pk_message_independence']
  const vectors = doc.vectors.filter(v => groups.includes(v.group))
  assert.equal(vectors.length, 28, 'all eight small-order points in every encoding')
  for (const v of vectors) {
    assert.equal(
      verify(v.message_utf8, v.signature_hex, v.public_key_hex),
      false,
      `${v.id} accepted a small-order public key: ${v.note}`,
    )
  }
})

test('a small-order R under an honest key is rejected', () => {
  // R is the identity and S = k*a mod L, so the cofactorless equation holds
  // exactly under a genuine prime-order public key. Only an admissibility test
  // on R refuses it.
  const vectors = doc.vectors.filter(
    v => v.group === 'small_order_R_honest_key' && v.id.startsWith('smallR-honest-'),
  )
  assert.ok(vectors.length >= 8, `expected the honest-key small-order R vectors, got ${vectors.length}`)
  for (const v of vectors) {
    assert.equal(
      verify(v.message_utf8, v.signature_hex, v.public_key_hex),
      false,
      `${v.id} accepted a small-order R: ${v.note}`,
    )
  }
})

test('a non-canonically encoded public key is rejected', () => {
  const vectors = doc.vectors.filter(v => v.group === 'non_canonical_A')
  assert.equal(vectors.length, 39)
  for (const v of vectors) {
    assert.equal(
      verify(v.message_utf8, v.signature_hex, v.public_key_hex),
      false,
      `${v.id} accepted a non-canonical public key encoding: ${v.note}`,
    )
  }
  // The identity point has two spellings; only one may be admissible, and the
  // identity is small-order so neither is.
  assert.equal(isAdmissiblePoint(Buffer.from(IDENTITY_KEY, 'hex')), false)
  assert.equal(
    isAdmissiblePoint(Buffer.from('eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'hex')),
    false,
  )
})

test('a non-reduced scalar S is rejected', () => {
  const vectors = doc.vectors.filter(v => v.group === 's_ge_L')
  assert.equal(vectors.length, 34)
  for (const v of vectors) {
    assert.equal(
      verify(v.message_utf8, v.signature_hex, v.public_key_hex),
      false,
      `${v.id} accepted a non-reduced scalar: ${v.note}`,
    )
  }
})

test('ordinary keys and signatures are unaffected', () => {
  const vectors = doc.vectors.filter(v => v.group === 'normal')
  assert.equal(vectors.length, 128)
  for (const v of vectors) {
    assert.equal(
      verify(v.message_utf8, v.signature_hex, v.public_key_hex),
      true,
      `${v.id} is an ordinary valid signature and must still verify`,
    )
  }
})

test('freshly generated keys still round-trip', () => {
  for (let i = 0; i < 64; i++) {
    const kp = generateKeyPair()
    const message = `APS neighbour probe ${i}`
    const signature = sign(message, kp.privateKey)
    assert.equal(verify(message, signature, kp.publicKey), true)
    assert.equal(verify(`${message} tampered`, signature, kp.publicKey), false)
    assert.equal(isAdmissiblePoint(Buffer.from(kp.publicKey, 'hex')), true)
  }
})

test('the degenerate signature is message-independent and still refused', () => {
  for (let i = 0; i < 256; i++) {
    assert.equal(
      verify(`unrelated APS artifact body ${i}`, DEGENERATE_SIG, IDENTITY_KEY),
      false,
      `message ${i} accepted the message-independent signature`,
    )
  }
})

// The instruction-provenance receipt verifier carried its own copy of the
// Ed25519 primitive. It is a second way into the same decision and must reach
// the same answer. The envelope below is a real positive fixture with the
// signer swapped for the identity point and the degenerate signature; the
// receipt id is recomputed so the check reaches the signature step rather than
// stopping at a schema or digest error.
test('the instruction-provenance receipt verifier refuses an inadmissible signer', () => {
  const iprFixture = JSON.parse(
    readFileSync(
      new URL('../fixtures/instruction-provenance/canonicalize-fixture-v1.json', import.meta.url),
      'utf-8',
    ),
  ) as { vectors: Array<{ name: string; expected_verification: boolean; envelope?: Record<string, unknown> }> }
  const positive = iprFixture.vectors.find(v => v.expected_verification === true && v.envelope)
  assert.ok(positive?.envelope, 'the fixture must carry a positive envelope')

  const envelope = { ...(positive.envelope as Record<string, unknown>) }
  envelope.signing_key_id = `ed25519:${IDENTITY_KEY.slice(0, 16)}`
  envelope.signature = DEGENERATE_SIG
  envelope.receipt_id = sha256Hex(canonicalizeEnvelope(envelope as never))

  const result = verifyInstructionProvenanceReceipt({
    envelope: envelope as never,
    publicKeyHex: IDENTITY_KEY,
  } as never)
  assert.equal(result.valid, false, 'an inadmissible signer key must not produce a valid receipt')
  assert.ok(
    result.errors.some(e => e.includes('signature')),
    `the refusal must name the signature, got: ${JSON.stringify(result.errors)}`,
  )
})

test('the unmodified positive instruction-provenance envelope still verifies', () => {
  const iprFixture = JSON.parse(
    readFileSync(
      new URL('../fixtures/instruction-provenance/canonicalize-fixture-v1.json', import.meta.url),
      'utf-8',
    ),
  ) as {
    keypair: { publicKeyHex: string }
    vectors: Array<{ name: string; expected_verification: boolean; envelope?: Record<string, unknown> }>
  }
  const positives = iprFixture.vectors.filter(v => v.expected_verification === true && v.envelope)
  assert.ok(positives.length > 0)
  for (const v of positives) {
    const result = verifyInstructionProvenanceReceipt({
      envelope: v.envelope as never,
      publicKeyHex: iprFixture.keypair.publicKeyHex,
    } as never)
    assert.equal(result.valid, true, `${v.name} must still verify: ${JSON.stringify(result.errors)}`)
  }
})

// The point check is the normative implementation. This test cross-checks it
// against a second, completely different argument: edwards25519 has exactly
// eight points of order dividing 8, a canonical encoding names exactly one
// point, and therefore the inadmissible canonical encodings are exactly those
// eight byte strings and no others. If the arithmetic in
// ed25519-admissibility.ts ever drifts, the two answers stop agreeing.
const CANONICAL_SMALL_ORDER = [
  '0100000000000000000000000000000000000000000000000000000000000000',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0000000000000000000000000000000000000000000000000000000000000080',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
]

test('the point check agrees with the exhaustive small-order enumeration', () => {
  const small = new Set(CANONICAL_SMALL_ORDER)
  for (const hex of CANONICAL_SMALL_ORDER) {
    assert.equal(isAdmissiblePoint(Buffer.from(hex, 'hex')), false, `${hex} has small order`)
  }
  // Every public key and every R in the fixture, plus fresh keys: a canonical
  // encoding is inadmissible only when it is one of the eight.
  const candidates = new Set<string>()
  for (const v of doc.vectors) {
    candidates.add(v.public_key_hex)
    candidates.add(v.signature_hex.slice(0, 64))
  }
  for (let i = 0; i < 128; i++) candidates.add(generateKeyPair().publicKey)

  // An independent on-curve test, so the assertion below is not the module
  // checking itself. x exists for this y exactly when (y^2 - 1)/(d*y^2 + 1) is
  // a square in the field.
  const FIELD_P = (1n << 255n) - 19n
  const CURVE_D =
    37095705934669439343138083508754565189542113879843219016388785533085940283555n
  const powm = (b: bigint, e: bigint): bigint => {
    let result = 1n
    let base = ((b % FIELD_P) + FIELD_P) % FIELD_P
    let exp = e
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % FIELD_P
      base = (base * base) % FIELD_P
      exp >>= 1n
    }
    return result
  }
  const decodesToACurvePoint = (bytes: Buffer): boolean => {
    const n = BigInt(`0x${Buffer.from(bytes).reverse().toString('hex')}`)
    const y = (n & ((1n << 255n) - 1n)) % FIELD_P
    const yy = (y * y) % FIELD_P
    const u = (yy - 1n + FIELD_P) % FIELD_P
    const v = (CURVE_D * yy + 1n) % FIELD_P
    if (v === 0n) return false
    const xx = (u * powm(v, FIELD_P - 2n)) % FIELD_P
    if (xx === 0n) return true
    // xx is a square exactly when xx^((p-1)/2) == 1
    return powm(xx, (FIELD_P - 1n) / 2n) === 1n
  }

  let checked = 0
  let onCurveNotSmall = 0
  for (const hex of candidates) {
    const bytes = Buffer.from(hex, 'hex')
    if (bytes.length !== 32) continue
    // Restrict the claim to canonical encodings, which is where the
    // enumeration argument applies. Canonical means two things, not one: the
    // y coordinate is reduced modulo p, AND the sign bit is clear when x is
    // zero. x is zero exactly for y = 1 and y = p - 1, so those two y values
    // with the sign bit set are the second family of non-canonical spellings.
    const raw = BigInt(`0x${Buffer.from(bytes).reverse().toString('hex')}`)
    const y = raw & ((1n << 255n) - 1n)
    const signBit = raw >> 255n
    if (y >= FIELD_P) continue
    if (signBit === 1n && (y === 1n || y === FIELD_P - 1n)) continue
    const admissible = isAdmissiblePoint(bytes)
    if (small.has(hex)) {
      assert.equal(admissible, false, `${hex} is one of the eight and must be inadmissible`)
    } else if (decodesToACurvePoint(bytes)) {
      // The whole claim: a canonical encoding of a curve point that is not one
      // of the eight has order greater than 8 and must be admissible.
      assert.equal(
        admissible,
        true,
        `${hex} is a canonical curve point and is not one of the eight small-order points, so it must be admissible`,
      )
      onCurveNotSmall++
    } else {
      // Not a point encoding at all.
      assert.equal(
        admissible,
        false,
        `${hex} does not decode to a curve point and must be inadmissible`,
      )
    }
    checked++
  }
  assert.ok(checked > 200, `expected a broad sample, checked ${checked}`)
  assert.ok(
    onCurveNotSmall > 200,
    `the claim must actually bite on real points, it bit on ${onCurveNotSmall}`,
  )
})

// ---------------------------------------------------------------------------
// High-level paths. The primitive is not the surface an attacker meets; the
// artifact verifiers are. Each of these hands a verifier the degenerate
// identity-key signature, which satisfies the RFC 8032 equation for every
// message, so a permissive primitive would accept the artifact whatever its
// contents. Inadmissible key material must stop the artifact.
// ---------------------------------------------------------------------------

test('a delegation signed with an inadmissible key is refused', async () => {
  const { verifyDelegation } = await import('../src/core/delegation.js')
  const status = verifyDelegation({
    delegationId: 'del_smallorder',
    delegatedBy: IDENTITY_KEY,
    delegatedTo: 'agent-b',
    scope: ['*'],
    issuedAt: '2026-01-01T00:00:00Z',
    expiresAt: '2099-01-01T00:00:00Z',
    signature: DEGENERATE_SIG,
  } as never)
  assert.equal(status.valid, false, JSON.stringify(status))
})

test('a passport issuer countersignature under an inadmissible key is refused', async () => {
  const { verifyIssuerSignature } = await import('../src/core/passport.js')
  assert.equal(
    verifyIssuerSignature(
      {
        passport: { agentId: 'agent-a' },
        signature: 'ff'.repeat(64),
        signedAt: '2026-01-01T00:00:00Z',
        issuerSignature: {
          issuerPublicKey: IDENTITY_KEY,
          signature: DEGENERATE_SIG,
          issuedAt: '2026-01-01T00:00:00Z',
        },
      } as never,
      IDENTITY_KEY,
    ),
    false,
  )
})

test('an Agora message from an inadmissible author key is refused', async () => {
  const { verifyAgoraMessage } = await import('../src/core/agora.js')
  const result = verifyAgoraMessage({
    id: 'msg_smallorder',
    topic: 'aps.security',
    body: 'inadmissible signer',
    author: { agentId: 'agent-a', publicKey: IDENTITY_KEY },
    signature: DEGENERATE_SIG,
  } as never)
  assert.equal(result.valid, false, JSON.stringify(result))
})

// A did:key is self-certifying: the key is the identifier. That makes an
// inadmissible key expressible as a well-formed DID, so the refusal has to
// happen at verification rather than at parsing.
test('a did:key naming a small-order point cannot authenticate a document', async () => {
  const { createDID, publicKeyFromDID, verifyWithDID } = await import('../src/core/did.js')
  const did = createDID(IDENTITY_KEY)
  assert.equal(
    publicKeyFromDID(did),
    IDENTITY_KEY,
    'the DID round-trips, so parsing alone does not stop it',
  )
  const signatureBase64url = Buffer.from(DEGENERATE_SIG, 'hex').toString('base64url')
  assert.equal(
    await verifyWithDID({ claim: 'anything at all' }, signatureBase64url, did),
    false,
    'the document must be refused at verification',
  )
  assert.equal(
    await verifyWithDID({ claim: 'a totally different document' }, signatureBase64url, did),
    false,
  )
})

// ---------------------------------------------------------------------------
// The public-key half of admissibility, isolated.
//
// Every vector that carries a small-order public key also carries R = the
// identity, so the test on R alone refuses it and the test on A is never
// exercised. Dropping the check on A would leave all of those tests green.
//
// These vectors close that. Take a canonical order-8 public key, pick any r,
// set R = [r]B, and grind the message until k = H(R||A||M) mod L is divisible
// by 8. Then [k]A is the identity and [S]B = R + [k]A holds with S = r. R is a
// full-order, canonically encoded point and S < L, so the R half passes it and
// only the test on A refuses it.
// ---------------------------------------------------------------------------

test('a small-order public key carrying an ordinary R is rejected', () => {
  const vectors = doc.vectors.filter(v => v.group === 'small_order_A_full_order_R')
  assert.equal(vectors.length, 28)
  for (const v of vectors) {
    assert.equal(
      verify(v.message_utf8, v.signature_hex, v.public_key_hex),
      false,
      `${v.id} accepted a small-order public key carrying an ordinary R: ${v.note}`,
    )
  }
})

test('both halves of the admissibility check are independently forced', () => {
  const aOnly = doc.vectors.filter(v => v.group === 'small_order_A_full_order_R')
  const rOnly = doc.vectors.filter(
    v => v.group === 'small_order_R_honest_key' && v.id.startsWith('smallR-honest-'),
  )
  assert.ok(aOnly.length > 0, 'no vector isolates the public-key half of the check')
  assert.ok(rOnly.length > 0, 'no vector isolates the R half of the check')
  // The isolating vectors must really isolate: R admissible, A not.
  for (const v of aOnly) {
    assert.equal(
      isAdmissiblePoint(Buffer.from(v.signature_hex.slice(0, 64), 'hex')),
      true,
      `${v.id}: R must pass the R half, or the vector does not isolate A`,
    )
    assert.equal(
      isAdmissiblePoint(Buffer.from(v.public_key_hex, 'hex')),
      false,
      `${v.id}: A must fail the A half`,
    )
  }
  for (const v of rOnly) {
    assert.equal(
      isAdmissiblePoint(Buffer.from(v.public_key_hex, 'hex')),
      true,
      `${v.id}: A must pass the A half, or the vector does not isolate R`,
    )
    assert.equal(
      isAdmissiblePoint(Buffer.from(v.signature_hex.slice(0, 64), 'hex')),
      false,
      `${v.id}: R must fail the R half`,
    )
  }
})

// Artifact path for the same class. This delegation grants payments:transfer
// and admin:*, and it was minted with no private key at all.
test('a delegation with a small-order signer and an ordinary R is refused', async () => {
  const { verifyDelegation } = await import('../src/core/delegation.js')
  const { canonicalize } = await import('../src/core/canonical.js')
  const av = doc.artifact_vectors
  assert.ok(av?.public_key_hex, 'the fixture must carry an artifact vector')

  // The canonical bytes this SDK computes must be the ones the signature was
  // ground against, otherwise the test would pass for the wrong reason.
  const { signature: _sig, ...unsigned } = av.delegation as Record<string, unknown>
  assert.equal(
    canonicalize(unsigned),
    av.canonical_preimage,
    'canonical bytes differ from the fixture preimage',
  )

  const status = verifyDelegation(av.delegation as never)
  assert.equal(
    status.valid,
    false,
    `a delegation granting payments:transfer and admin:*, minted with no private key, was accepted: ${JSON.stringify(status)}`,
  )
})
