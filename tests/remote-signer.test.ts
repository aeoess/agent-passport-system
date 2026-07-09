// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// W2-B2 Remote Signer adapters - tests (additive).
// Proves a KMS-mock-signed receipt verifies IDENTICALLY to the Ed25519 path and
// that the raw private key never materializes in the consuming process. Includes
// explicit negative-path fixtures.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { generateKeyPair, sign, verify, publicKeyFromPrivate } from '../src/crypto/keys.js'
import {
  LocalEd25519Signer,
  createLocalSigner,
  HandleSigner,
  createHandleSigner,
  verifyWithSigner,
  defaultKeyId,
  assertRawEd25519SignatureHex,
  RemoteSignerError,
  buildRemoteSignerScopeOfClaim,
  type Signer,
  type SignerHandle,
} from '../src/adapters/remote-signer/index.js'
import {
  createBilateralReceipt,
  verifyBilateralReceipt,
} from '../src/core/bilateral-receipt.js'
import { canonicalize } from '../src/core/canonical.js'

// ──────────────────────────────────────────────────────────────────
// A mock KMS/HSM backend. The raw private key lives ONLY inside this
// closure. It hands out a HandleSigner whose callbacks reach the key, but the
// returned object exposes no path to the raw key. This models "the adapter only
// ever holds a handle": the consuming code below never receives privateKeyHex.
// ──────────────────────────────────────────────────────────────────
interface MockKms {
  signer: Signer
  publicKeyHex: string
  /** number of backend sign round-trips, to prove the consumer never signs locally */
  signCalls: () => number
}

function makeMockKms(keyRef = 'arn:mock:kms:key/ed25519-1'): MockKms {
  // Key material is sealed here. Nothing outside this function returns it.
  const { privateKey, publicKey } = generateKeyPair()
  let calls = 0

  const handle: SignerHandle = { kind: 'aws-kms', keyRef }

  const signer = createHandleSigner({
    handle,
    signRemote: async (messageUtf8: string) => {
      calls++
      // The backend signs with the sealed key and returns ONLY the signature.
      return sign(messageUtf8, privateKey)
    },
    getPublicKeyHex: async () => publicKey,
  })

  return { signer, publicKeyHex: publicKey, signCalls: () => calls }
}

describe('W2-B2 remote signer - byte-identical to Ed25519 default', () => {
  it('HandleSigner signature equals the direct sign() output over the same bytes', async () => {
    const { privateKey, publicKey } = generateKeyPair()
    const message = 'aps:test:' + JSON.stringify({ a: 1, b: [2, 3], z: 'x' })

    // Direct Ed25519 path (what every builder callsite does today).
    const direct = sign(message, privateKey)

    // Same key, but exercised through the remote-signer abstraction.
    const signer = createHandleSigner({
      handle: { kind: 'vault-transit', keyRef: 'k1' },
      signRemote: async (m) => sign(m, privateKey),
      getPublicKeyHex: async () => publicKey,
    })
    const viaSigner = await signer.sign(message)

    assert.equal(viaSigner, direct, 'remote signer must produce byte-identical signature')
    assert.equal(viaSigner.length, 128, 'raw 64-byte Ed25519 signature hex')
    assert.ok(verify(message, viaSigner, publicKey), 'verifies under unchanged verify()')
    assert.ok(await verifyWithSigner(message, viaSigner, signer))
  })

  it('LocalEd25519Signer default delegates to the unchanged sign()', async () => {
    const { privateKey, publicKey } = generateKeyPair()
    const message = 'aps:local:default'
    const local: Signer = createLocalSigner({ privateKeyHex: privateKey })

    assert.equal(await local.sign(message), sign(message, privateKey))
    assert.equal(await local.publicKeyHex(), publicKey)
    assert.equal(await local.keyId(), defaultKeyId(publicKey))
    assert.deepEqual(local.handle, { kind: 'local', keyRef: 'in-process' })
  })

  it('a KMS-mock-signed bilateral receipt verifies identically to the Ed25519 path', async () => {
    // Two parties: requesting agent signs locally; serving agent signs via KMS.
    const requesting = generateKeyPair()
    const kms = makeMockKms()
    const servingPub = kms.publicKeyHex

    // 1) Reference receipt: both parties via the default Ed25519 path. To do
    //    that for the serving party we need its raw key, so use a separate local
    //    keypair for the equality baseline of the body/signature relation.
    const requestedAt = '2026-05-31T10:00:00.000Z'
    const completedAt = '2026-05-31T10:05:00.000Z'

    // Build a receipt with the requesting agent's local key and a PLACEHOLDER
    // serving signature, then replace the serving signature with the KMS one.
    const receipt = createBilateralReceipt({
      requestingAgentId: 'did:aps:requester',
      servingAgentId: 'did:aps:server',
      outcome: {
        toolName: 'kms.sign',
        requestHash: 'a'.repeat(64),
        responseHash: 'b'.repeat(64),
        status: 'success',
        summary: 'ok',
      },
      requestedAt,
      completedAt,
      requestingAgentPrivateKey: requesting.privateKey,
      // placeholder: immediately overwritten by the KMS signature below
      servingAgentPrivateKey: requesting.privateKey,
    })

    // Recompute the canonical body the verifier reconstructs, sign it via KMS.
    const { requestingAgentSignature, servingAgentSignature, gatewaySignature, ...body } = receipt
    const canonical = canonicalize(body)
    const kmsServingSig = await kms.signer.sign(canonical)

    // The KMS signature over the canonical body equals a direct Ed25519 sign
    // would, and verifies under the unchanged verify().
    assert.equal(kmsServingSig.length, 128)
    assert.ok(verify(canonical, kmsServingSig, servingPub))

    const kmsReceipt = { ...receipt, servingAgentSignature: kmsServingSig }
    const result = verifyBilateralReceipt(
      kmsReceipt,
      requesting.publicKey,
      servingPub,
    )

    assert.equal(result.valid, true, 'KMS-signed receipt verifies as valid')
    assert.equal(result.servingAgentSignatureValid, true)
    assert.equal(result.requestingAgentSignatureValid, true)
    assert.equal(result.outcomeConsistent, true)
    assert.ok(kms.signCalls() >= 1, 'signature came from the backend round-trip')
  })

  it('key non-materialization: the consumer holds only a handle, never the raw key', async () => {
    const kms = makeMockKms('arn:mock:kms:key/sealed')
    const signer = kms.signer

    // The signer exposes a custody handle and async accessors only.
    assert.deepEqual(signer.handle, { kind: 'aws-kms', keyRef: 'arn:mock:kms:key/sealed' })

    // No own enumerable property of the signer carries a 64-hex private key.
    const ownValues = Object.values(signer as unknown as Record<string, unknown>)
    for (const v of ownValues) {
      assert.notEqual(
        typeof v === 'string' && v.length === 64 && /^[0-9a-f]+$/i.test(v),
        true,
        'no raw private key on the signer surface',
      )
    }
    // The handle keyRef is an identifier, not the key.
    assert.equal(/^[0-9a-f]{64}$/i.test(signer.handle.keyRef), false)

    // It still produces a verifiable signature without ever returning the key.
    const m = 'aps:sealed:message'
    const sig = await signer.sign(m)
    assert.ok(await verifyWithSigner(m, sig, signer))
  })

  it('keyId defaults to ed25519:<first-16-hex> and can be overridden', async () => {
    const { privateKey } = generateKeyPair()
    const pub = publicKeyFromPrivate(privateKey)

    const def = createHandleSigner({
      handle: { kind: 'pkcs11', keyRef: 'token:label' },
      signRemote: async (m) => sign(m, privateKey),
      getPublicKeyHex: async () => pub,
    })
    assert.equal(await def.keyId(), `ed25519:${pub.slice(0, 16)}`)

    const overridden = createHandleSigner({
      handle: { kind: 'aws-kms', keyRef: 'arn:x' },
      signRemote: async (m) => sign(m, privateKey),
      getPublicKeyHex: async () => pub,
      keyId: 'arn:x',
    })
    assert.equal(await overridden.keyId(), 'arn:x')
  })

  it('proof box ScopeOfClaim reports the signature relation, not backend trust', () => {
    const soc = buildRemoteSignerScopeOfClaim('aws-kms')
    assert.match(soc.asserts, /verifies under the unchanged verify\(\)/)
    assert.match(soc.asserts, /aws-kms/)
    assert.equal(soc.self_attested, false)
    assert.ok(
      soc.does_not_assert.some((s) => /HSM\/KMS backend itself is uncompromised/.test(s)),
      'does not claim the backend is uncompromised',
    )
  })
})

describe('W2-B2 remote signer - negative-path fixtures', () => {
  it('rejects a DER-wrapped (non-raw) signature from the backend', async () => {
    const { privateKey, publicKey } = generateKeyPair()
    // 70-byte ASN.1/DER-looking blob: 140 hex chars, not the raw 128.
    const derLike = '30' + '44'.padEnd(138, 'a')
    const bad = createHandleSigner({
      handle: { kind: 'aws-kms', keyRef: 'k' },
      signRemote: async () => derLike,
      getPublicKeyHex: async () => publicKey,
    })
    await assert.rejects(() => bad.sign('m'), (e: unknown) => {
      assert.ok(e instanceof RemoteSignerError)
      assert.match((e as Error).message, /non-raw-Ed25519 signature/)
      return true
    })
  })

  it('rejects a too-short signature from the backend', async () => {
    const { publicKey } = generateKeyPair()
    const bad = createHandleSigner({
      handle: { kind: 'vault-transit', keyRef: 'k' },
      signRemote: async () => 'deadbeef',
      getPublicKeyHex: async () => publicKey,
    })
    await assert.rejects(() => bad.sign('m'), RemoteSignerError)
  })

  it('rejects a non-raw public key from the backend', async () => {
    const { privateKey } = generateKeyPair()
    const bad = createHandleSigner({
      handle: { kind: 'azure-kv', keyRef: 'k' },
      signRemote: async (m) => sign(m, privateKey),
      // SPKI-DER-length public key (88 hex), not the raw 64.
      getPublicKeyHex: async () => '30'.padEnd(88, 'a'),
    })
    await assert.rejects(() => bad.publicKeyHex(), RemoteSignerError)
  })

  it('a tampered message fails verification against a genuine signature', async () => {
    const { privateKey, publicKey } = generateKeyPair()
    const signer = createHandleSigner({
      handle: { kind: 'pkcs11', keyRef: 'k' },
      signRemote: async (m) => sign(m, privateKey),
      getPublicKeyHex: async () => publicKey,
    })
    const sig = await signer.sign('original message')
    assert.equal(await verifyWithSigner('tampered message', sig, signer), false)
    assert.equal(verify('tampered message', sig, publicKey), false)
  })

  it('a signature from a different key does not verify against this signer', async () => {
    const a = generateKeyPair()
    const b = generateKeyPair()
    const signerA = createHandleSigner({
      handle: { kind: 'aws-kms', keyRef: 'a' },
      signRemote: async (m) => sign(m, a.privateKey),
      getPublicKeyHex: async () => a.publicKey,
    })
    const sigFromB = sign('m', b.privateKey)
    assert.equal(await verifyWithSigner('m', sigFromB, signerA), false)
  })

  it('LocalEd25519Signer rejects a malformed private key', () => {
    assert.throws(() => new LocalEd25519Signer({ privateKeyHex: 'tooshort' }), RemoteSignerError)
    assert.throws(
      () => new LocalEd25519Signer({ privateKeyHex: 'zz'.repeat(32) as unknown as string }),
      /requires a 64-hex-char/,
    )
  })

  it('HandleSigner rejects missing callbacks or handle', () => {
    assert.throws(
      () =>
        new HandleSigner({
          handle: { kind: 'aws-kms', keyRef: 'k' },
          // @ts-expect-error intentionally bad
          signRemote: undefined,
          getPublicKeyHex: async () => '',
        }),
      RemoteSignerError,
    )
    assert.throws(
      () =>
        new HandleSigner({
          // @ts-expect-error intentionally bad
          handle: null,
          signRemote: async () => '',
          getPublicKeyHex: async () => '',
        }),
      RemoteSignerError,
    )
  })

  it('assertRawEd25519SignatureHex guard accepts valid and rejects invalid', () => {
    const { privateKey } = generateKeyPair()
    const good = sign('m', privateKey)
    assert.equal(assertRawEd25519SignatureHex(good), good)
    assert.throws(() => assertRawEd25519SignatureHex('xyz'), RemoteSignerError)
    assert.throws(() => assertRawEd25519SignatureHex(123 as unknown as string), RemoteSignerError)
    assert.throws(() => assertRawEd25519SignatureHex('g'.repeat(128)), RemoteSignerError)
  })
})
