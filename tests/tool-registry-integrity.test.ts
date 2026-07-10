// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Tool Registry & Discovery Integrity — tests
// Covers: Part 0 hash fix, signed manifests + metadata hash, publisher
// identity verification, namespace governance, metadata-change re-approval,
// and the cross-language conformance vectors.
// Maps to CoSAI control `controlToolRegistryandDiscoveryIntegrity`.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { generateKeyPair, verify } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { toDIDKey } from '../src/core/did-interop.js'
import {
  createToolRegistryEntry,
  verifyToolIntegrity,
  createToolManifest,
  verifyToolManifest,
  createNamespaceClaim,
  verifyNamespaceClaim,
  reviseToolManifest,
  reapproveToolManifest,
  type ToolMetadata,
} from '../src/core/tool-integrity.js'

const META: ToolMetadata = {
  description: 'Search the public web.',
  schema: { input: { query: 'string' } },
  permissions: ['net:read'],
}

/** A fake did:web resolver returning a DID doc that carries `pubHex`. */
function fakeDidWeb(pubHex: string) {
  return async (_did: string) => ({
    id: 'did:web:acme.example',
    verificationMethod: [{
      id: 'did:web:acme.example#k1',
      type: 'Ed25519VerificationKey2020',
      controller: 'did:web:acme.example',
      publicKeyHex: pubHex,
    }],
  })
}

// ══════════════════════════════════════════════════════════════════
// Part 0 — Buffer/string hashing fix
// ══════════════════════════════════════════════════════════════════
describe('Part 0 — implementation hashing (Buffer + string)', () => {
  it('hashes a utf-8 string and its equivalent Buffer to the same hash', () => {
    const kp = generateKeyPair()
    const strEntry = createToolRegistryEntry({
      toolName: 'web_search', implementation: 'tool-source-v1',
      attestorId: 'did:key:attestor', attestorPrivateKey: kp.privateKey,
    })
    const bufEntry = createToolRegistryEntry({
      toolName: 'web_search', implementation: Buffer.from('tool-source-v1', 'utf8'),
      attestorId: 'did:key:attestor', attestorPrivateKey: kp.privateKey,
    })
    // Canonical behaviour: string -> utf-8 bytes, Buffer -> raw bytes.
    // An equivalent utf-8 Buffer therefore produces the SAME implementationHash.
    assert.equal(strEntry.implementationHash, bufEntry.implementationHash)
  })

  it('verifyToolIntegrity cross-checks a string entry against an equivalent Buffer', () => {
    const kp = generateKeyPair()
    const entry = createToolRegistryEntry({
      toolName: 'web_search', implementation: 'tool-source-v1',
      attestorId: 'did:key:attestor', attestorPrivateKey: kp.privateKey,
    })
    const r = verifyToolIntegrity({
      registryEntry: entry,
      currentImplementation: Buffer.from('tool-source-v1', 'utf8'),
      attestorPublicKey: kp.publicKey,
    })
    assert.equal(r.implementationVerified, true)
    assert.equal(r.attestorSignatureValid, true)
    assert.equal(r.valid, true)
  })

  it('hashes raw (non-utf8) Buffer bytes as-is', () => {
    const kp = generateKeyPair()
    const raw = Buffer.from([0xff, 0x00, 0xfe, 0x01, 0x80])
    const entry = createToolRegistryEntry({
      toolName: 'binary_tool', implementation: raw,
      attestorId: 'did:key:attestor', attestorPrivateKey: kp.privateKey,
    })
    const expected = 'sha256:' + createHash('sha256').update(raw).digest('hex')
    assert.equal(entry.implementationHash, expected)
  })

  it('detects a swapped implementation (tool-swap attack)', () => {
    const kp = generateKeyPair()
    const entry = createToolRegistryEntry({
      toolName: 'web_search', implementation: 'tool-source-v1',
      attestorId: 'did:key:attestor', attestorPrivateKey: kp.privateKey,
    })
    const r = verifyToolIntegrity({
      registryEntry: entry,
      currentImplementation: Buffer.from('malicious-source', 'utf8'),
      attestorPublicKey: kp.publicKey,
    })
    assert.equal(r.implementationVerified, false)
    assert.equal(r.valid, false)
  })
})

// ══════════════════════════════════════════════════════════════════
// Part 1a — signed manifest + metadata hash
// ══════════════════════════════════════════════════════════════════
describe('Part 1a — signed tool manifest + metadata hash', () => {
  it('creates and verifies a signed manifest', async () => {
    const kp = generateKeyPair()
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: kp.privateKey,
    })
    const r = await verifyToolManifest({ manifest: m, attestorPublicKey: kp.publicKey })
    assert.equal(r.attestorSignatureValid, true)
    assert.equal(r.valid, true)
    assert.equal(m.metadataVersion, 1)
    assert.equal(m.approvalState, 'approved')
  })

  it('metadataHash is distinct from implementationHash', () => {
    const kp = generateKeyPair()
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: kp.privateKey,
    })
    assert.notEqual(m.metadataHash, m.implementationHash)
    assert.match(m.metadataHash, /^sha256:[0-9a-f]{64}$/)
  })

  it('rejects a manifest signed by the wrong attestor key', async () => {
    const kp = generateKeyPair()
    const other = generateKeyPair()
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: kp.privateKey,
    })
    const r = await verifyToolManifest({ manifest: m, attestorPublicKey: other.publicKey })
    assert.equal(r.attestorSignatureValid, false)
    assert.equal(r.valid, false)
  })

  it('detects a metadata-only change even when the implementation is byte-identical', async () => {
    const kp = generateKeyPair()
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: kp.privateKey,
    })
    // same implementation, different metadata block
    const changedMeta: ToolMetadata = { ...META, permissions: ['net:read', 'fs:write'] }
    const r = await verifyToolManifest({
      manifest: m, attestorPublicKey: kp.publicKey,
      currentImplementation: 'src-v1',          // unchanged -> verifies
      currentMetadata: changedMeta,             // changed   -> mismatch
    })
    assert.equal(r.implementationVerified, true)
    assert.equal(r.metadataVerified, false)
    assert.equal(r.valid, false)
  })

  it('verifies matching current implementation and metadata', async () => {
    const kp = generateKeyPair()
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: kp.privateKey,
    })
    const r = await verifyToolManifest({
      manifest: m, attestorPublicKey: kp.publicKey,
      currentImplementation: 'src-v1', currentMetadata: META,
    })
    assert.equal(r.implementationVerified, true)
    assert.equal(r.metadataVerified, true)
    assert.equal(r.valid, true)
  })
})

// ══════════════════════════════════════════════════════════════════
// Part 1b — publisher identity verification (D1 trust roots)
// ══════════════════════════════════════════════════════════════════
describe('Part 1b — publisher identity verification', () => {
  it('aps-native DID: publisher co-signature verifies', async () => {
    const att = generateKeyPair()
    const pub = generateKeyPair()
    const did = toDIDKey(pub.publicKey)
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
      publisherDid: did, trustRoot: { type: 'aps', ref: did },
      publisherPrivateKey: pub.privateKey,
    })
    const r = await verifyToolManifest({ manifest: m, attestorPublicKey: att.publicKey })
    assert.equal(r.publisherVerified, true)
    assert.equal(r.publisherResolutionMethod, 'aps-native-did')
    assert.equal(r.valid, true)
  })

  it('aps-native DID: a forged publisher signature fails', async () => {
    const att = generateKeyPair()
    const pub = generateKeyPair()
    const wrong = generateKeyPair()
    const did = toDIDKey(pub.publicKey)
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
      publisherDid: did, trustRoot: { type: 'aps', ref: did },
      publisherPrivateKey: wrong.privateKey,   // not the key behind `did`
    })
    const r = await verifyToolManifest({ manifest: m, attestorPublicKey: att.publicKey })
    assert.equal(r.publisherVerified, false)
    assert.equal(r.valid, false)
  })

  it('raw-key trust root verifies the publisher signature', async () => {
    const att = generateKeyPair()
    const pub = generateKeyPair()
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
      publisherDid: 'did:example:acme',
      trustRoot: { type: 'raw-key', ref: pub.publicKey },
      publisherPrivateKey: pub.privateKey,
    })
    const r = await verifyToolManifest({ manifest: m, attestorPublicKey: att.publicKey })
    assert.equal(r.publisherVerified, true)
    assert.equal(r.publisherResolutionMethod, 'raw-key')
  })

  it('raw-key trust root rejects a malformed key', async () => {
    const att = generateKeyPair()
    const pub = generateKeyPair()
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
      publisherDid: 'did:example:acme',
      trustRoot: { type: 'raw-key', ref: 'not-a-key' },
      publisherPrivateKey: pub.privateKey,
    })
    const r = await verifyToolManifest({ manifest: m, attestorPublicKey: att.publicKey })
    assert.equal(r.publisherVerified, false)
    assert.equal(r.valid, false)
  })

  it('did:web trust root verifies via an injected resolver', async () => {
    const att = generateKeyPair()
    const pub = generateKeyPair()
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
      publisherDid: 'did:web:acme.example',
      trustRoot: { type: 'did:web', ref: 'did:web:acme.example' },
      publisherPrivateKey: pub.privateKey,
    })
    const r = await verifyToolManifest({
      manifest: m, attestorPublicKey: att.publicKey,
      didWebResolver: fakeDidWeb(pub.publicKey),
    })
    assert.equal(r.publisherVerified, true)
    assert.equal(r.publisherResolutionMethod, 'did:web')
  })

  it('did:web trust root fails when the document carries a different key', async () => {
    const att = generateKeyPair()
    const pub = generateKeyPair()
    const other = generateKeyPair()
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
      publisherDid: 'did:web:acme.example',
      trustRoot: { type: 'did:web', ref: 'did:web:acme.example' },
      publisherPrivateKey: pub.privateKey,
    })
    const r = await verifyToolManifest({
      manifest: m, attestorPublicKey: att.publicKey,
      didWebResolver: fakeDidWeb(other.publicKey),   // wrong key in the doc
    })
    assert.equal(r.publisherVerified, false)
    assert.equal(r.valid, false)
  })

  it('no publisherDid: publisher check is skipped, not failed', async () => {
    const att = generateKeyPair()
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
    })
    const r = await verifyToolManifest({ manifest: m, attestorPublicKey: att.publicKey })
    assert.equal(r.publisherResolutionMethod, 'not-asserted')
    assert.equal(r.publisherVerified, false)
    assert.equal(r.valid, true)             // skipped, not failed
  })

  it('publisherDid asserted with no publisherSignature is an error', async () => {
    const att = generateKeyPair()
    const pub = generateKeyPair()
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
      publisherDid: toDIDKey(pub.publicKey),
      // no publisherPrivateKey -> no publisherSignature
    })
    const r = await verifyToolManifest({ manifest: m, attestorPublicKey: att.publicKey })
    assert.equal(r.publisherVerified, false)
    assert.equal(r.valid, false)
  })
})

// ══════════════════════════════════════════════════════════════════
// Part 2 — namespace governance (anti-typosquat / anti-shadowing)
// ══════════════════════════════════════════════════════════════════
describe('Part 2 — namespace governance', () => {
  it('creates and verifies a namespace claim', async () => {
    const owner = generateKeyPair()
    const did = toDIDKey(owner.publicKey)
    const claim = createNamespaceClaim({
      namespace: 'acme/*', ownerDid: did,
      trustRoot: { type: 'aps', ref: did }, ownerPrivateKey: owner.privateKey,
    })
    const r = await verifyNamespaceClaim(claim)
    assert.equal(r.ownerVerified, true)
    assert.equal(r.valid, true)
  })

  it('rejects a namespace claim with a forged owner signature', async () => {
    const owner = generateKeyPair()
    const forger = generateKeyPair()
    const did = toDIDKey(owner.publicKey)
    const claim = createNamespaceClaim({
      namespace: 'acme/*', ownerDid: did,
      trustRoot: { type: 'aps', ref: did }, ownerPrivateKey: forger.privateKey,
    })
    const r = await verifyNamespaceClaim(claim)
    assert.equal(r.ownerVerified, false)
    assert.equal(r.valid, false)
  })

  it('passes a manifest whose publisher owns the claimed namespace', async () => {
    const att = generateKeyPair()
    const owner = generateKeyPair()
    const did = toDIDKey(owner.publicKey)
    const claim = createNamespaceClaim({
      namespace: 'acme/*', ownerDid: did,
      trustRoot: { type: 'aps', ref: did }, ownerPrivateKey: owner.privateKey,
    })
    const m = createToolManifest({
      toolName: 'acme/web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
      publisherDid: did, trustRoot: { type: 'aps', ref: did },
      publisherPrivateKey: owner.privateKey,
    })
    const r = await verifyToolManifest({
      manifest: m, attestorPublicKey: att.publicKey, namespaceClaims: [claim],
    })
    assert.equal(r.namespaceVerified, true)
    assert.equal(r.namespaceViolation, false)
    assert.equal(r.valid, true)
  })

  it('denies a typosquat — tool under a claimed namespace, different publisher', async () => {
    const att = generateKeyPair()
    const owner = generateKeyPair()
    const squatter = generateKeyPair()
    const ownerDid = toDIDKey(owner.publicKey)
    const squatDid = toDIDKey(squatter.publicKey)
    const claim = createNamespaceClaim({
      namespace: 'acme/*', ownerDid,
      trustRoot: { type: 'aps', ref: ownerDid }, ownerPrivateKey: owner.privateKey,
    })
    const m = createToolManifest({
      toolName: 'acme/web_search',          // shadows the acme/* namespace
      implementation: 'malicious', metadata: META,
      attestorPrivateKey: att.privateKey,
      publisherDid: squatDid, trustRoot: { type: 'aps', ref: squatDid },
      publisherPrivateKey: squatter.privateKey,
    })
    const r = await verifyToolManifest({
      manifest: m, attestorPublicKey: att.publicKey, namespaceClaims: [claim],
    })
    assert.equal(r.namespaceViolation, true)
    assert.equal(r.namespaceVerified, false)
    assert.equal(r.valid, false)
    assert.ok(r.errors.some(e => e.includes('acme/*')))
  })

  it('passes a tool not under any claimed namespace (open by default)', async () => {
    const att = generateKeyPair()
    const owner = generateKeyPair()
    const ownerDid = toDIDKey(owner.publicKey)
    const claim = createNamespaceClaim({
      namespace: 'acme/*', ownerDid,
      trustRoot: { type: 'aps', ref: ownerDid }, ownerPrivateKey: owner.privateKey,
    })
    const m = createToolManifest({
      toolName: 'globex/web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
    })
    const r = await verifyToolManifest({
      manifest: m, attestorPublicKey: att.publicKey, namespaceClaims: [claim],
    })
    assert.equal(r.namespaceVerified, true)
    assert.equal(r.namespaceViolation, false)
    assert.equal(r.valid, true)
  })
})

// ══════════════════════════════════════════════════════════════════
// Part 3 — re-approval workflow on metadata change
// ══════════════════════════════════════════════════════════════════
describe('Part 3 — re-approval on metadata change', () => {
  it('a metadata change moves the manifest to pending-reapproval, version + 1', () => {
    const att = generateKeyPair()
    const m1 = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
    })
    const m2 = reviseToolManifest(
      m1, { metadata: { ...META, description: 'edited description' } }, att.privateKey,
    )
    assert.equal(m2.approvalState, 'pending-reapproval')
    assert.equal(m2.metadataVersion, 2)
    assert.notEqual(m2.metadataHash, m1.metadataHash)
  })

  it('an implementation change also triggers pending-reapproval', () => {
    const att = generateKeyPair()
    const m1 = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
    })
    const m2 = reviseToolManifest(m1, { implementation: 'src-v2' }, att.privateKey)
    assert.equal(m2.approvalState, 'pending-reapproval')
    assert.equal(m2.metadataVersion, 2)
  })

  it('a no-op revision (no hash delta) does NOT change version or state', () => {
    const att = generateKeyPair()
    const m1 = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
    })
    const m2 = reviseToolManifest(m1, { metadata: META }, att.privateKey)  // identical metadata
    assert.equal(m2.approvalState, 'approved')
    assert.equal(m2.metadataVersion, 1)
  })

  it('verifyToolManifest denies a manifest pending re-approval', async () => {
    const att = generateKeyPair()
    const m1 = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
    })
    const m2 = reviseToolManifest(m1, { implementation: 'src-v2' }, att.privateKey)
    const r = await verifyToolManifest({ manifest: m2, attestorPublicKey: att.publicKey })
    assert.equal(r.reapprovalRequired, true)
    assert.equal(r.valid, false)
    assert.deepEqual(r.errors, ['tool metadata changed, awaiting re-approval'])
  })

  it('full state machine: create -> revise -> denied -> reapprove -> pass', async () => {
    const att = generateKeyPair()
    const m1 = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
    })
    assert.equal((await verifyToolManifest({ manifest: m1, attestorPublicKey: att.publicKey })).valid, true)

    const m2 = reviseToolManifest(m1, { implementation: 'src-v2' }, att.privateKey)
    assert.equal((await verifyToolManifest({ manifest: m2, attestorPublicKey: att.publicKey })).valid, false)

    const m3 = reapproveToolManifest(m2, { attestorPrivateKey: att.privateKey })
    assert.equal(m3.approvalState, 'approved')
    const r = await verifyToolManifest({ manifest: m3, attestorPublicKey: att.publicKey })
    assert.equal(r.reapprovalRequired, false)
    assert.equal(r.attestorSignatureValid, true)
    assert.equal(r.valid, true)
  })

  it('reapproveToolManifest throws if the manifest is not pending re-approval', () => {
    const att = generateKeyPair()
    const m1 = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
    })
    assert.throws(() => reapproveToolManifest(m1, { attestorPrivateKey: att.privateKey }), /not pending re-approval/)
  })
})

// ══════════════════════════════════════════════════════════════════
// Part 4 — cross-language conformance vectors
// ══════════════════════════════════════════════════════════════════
describe('Part 4 — conformance vectors', () => {
  const fixture = JSON.parse(readFileSync(
    new URL('../fixtures/tool-registry-integrity/conformance-vectors-v1.json', import.meta.url),
    'utf8',
  )) as {
    vectors: Array<{
      name: string
      input: unknown
      canonical_bytes_hex: string
      canonical_sha256: string
      metadata_hash?: string
      ed25519_pubkey_hex?: string
      ed25519_signature_over_canonical_hex?: string
      expected_verification?: boolean
    }>
  }

  it('the fixture has vectors', () => {
    assert.ok(fixture.vectors.length >= 4, `expected >= 4 vectors, got ${fixture.vectors.length}`)
  })

  for (const v of fixture.vectors) {
    it(`vector "${v.name}" — canonical bytes + sha256 reproduce`, () => {
      const canon = canonicalize(v.input)
      assert.equal(Buffer.from(canon, 'utf8').toString('hex'), v.canonical_bytes_hex,
        `canonical bytes mismatch for ${v.name}`)
      assert.equal(createHash('sha256').update(canon).digest('hex'), v.canonical_sha256,
        `canonical sha256 mismatch for ${v.name}`)
      if (v.metadata_hash) {
        assert.equal('sha256:' + v.canonical_sha256, v.metadata_hash)
      }
    })

    if (v.ed25519_signature_over_canonical_hex && v.ed25519_pubkey_hex) {
      it(`vector "${v.name}" — signature verifies to ${v.expected_verification}`, () => {
        const canon = canonicalize(v.input)
        const ok = verify(canon, v.ed25519_signature_over_canonical_hex!, v.ed25519_pubkey_hex!)
        assert.equal(ok, v.expected_verification,
          `signature verification mismatch for ${v.name}`)
      })
    }
  }
})

// ══════════════════════════════════════════════════════════════════
// Pass 2 — attestor identity binding (close the attestor-binding gap)
// ══════════════════════════════════════════════════════════════════
describe('Attestor binding — DID-resolved attestor identity', () => {
  it('a manifest with attestorDid verifies against the RESOLVED key (no attestorPublicKey needed)', async () => {
    const att = generateKeyPair()
    const did = toDIDKey(att.publicKey)
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
      attestorDid: did, attestorTrustRoot: { type: 'aps', ref: did },
    })
    const r = await verifyToolManifest({ manifest: m })   // no attestorPublicKey supplied
    assert.equal(r.attestorVerified, true)
    assert.equal(r.attestorSignatureValid, true)
    assert.equal(r.attestorResolutionMethod, 'aps-native-did')
    assert.equal(r.valid, true)
  })

  // G2 — the named adversarial test: the precise hole pass 1 left open.
  it('attestor binding: signature by wrong key fails even if that key is passed as attestorPublicKey', async () => {
    const att = generateKeyPair()       // the identity the manifest claims
    const attacker = generateKeyPair()  // whoever actually holds a key
    const did = toDIDKey(att.publicKey)
    // Manifest claims attestorDid = att, but m.signature is the attacker's.
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: attacker.privateKey,           // forged signer
      attestorDid: did, attestorTrustRoot: { type: 'aps', ref: did },
    })
    // The verifier is handed the attacker's OWN public key — pass-1 would go green.
    const r = await verifyToolManifest({ manifest: m, attestorPublicKey: attacker.publicKey })
    assert.equal(r.attestorVerified, false)
    assert.equal(r.attestorSignatureValid, false)
    assert.equal(r.valid, false)
    assert.equal(r.attestorResolutionMethod, 'aps-native-did')   // resolved path was used
  })

  it('G1: a caller-supplied attestorPublicKey cannot override or substitute for attestorDid', async () => {
    const att = generateKeyPair()
    const attacker = generateKeyPair()
    const did = toDIDKey(att.publicKey)
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: attacker.privateKey,
      attestorDid: did, attestorTrustRoot: { type: 'aps', ref: did },
    })
    // the key that DOES match m.signature must not satisfy verification
    assert.equal((await verifyToolManifest({ manifest: m, attestorPublicKey: attacker.publicKey })).valid, false)
    // the legitimate key cannot rescue a forged signature either
    assert.equal((await verifyToolManifest({ manifest: m, attestorPublicKey: att.publicKey })).valid, false)
  })

  it('G1: no attestorDid keeps pass-1 behaviour (caller-supplied key path)', async () => {
    const att = generateKeyPair()
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,                 // no attestorDid asserted
    })
    const r = await verifyToolManifest({ manifest: m, attestorPublicKey: att.publicKey })
    assert.equal(r.valid, true)
    assert.equal(r.attestorSignatureValid, true)
    assert.equal(r.attestorVerified, false)               // no DID binding to verify
    assert.equal(r.attestorResolutionMethod, 'caller-supplied-key')
  })

  it('raw-key attestor trust root: ref is the trusted key and is used as the resolved key', async () => {
    const att = generateKeyPair()
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
      attestorDid: 'did:example:registry-attestor',
      attestorTrustRoot: { type: 'raw-key', ref: att.publicKey },
    })
    const r = await verifyToolManifest({ manifest: m })
    assert.equal(r.attestorVerified, true)
    assert.equal(r.attestorResolutionMethod, 'raw-key')
    assert.equal(r.valid, true)
  })

  it('wrong attestor trust root (raw-key holds a different key) fails', async () => {
    const att = generateKeyPair()
    const other = generateKeyPair()
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
      attestorDid: 'did:example:registry-attestor',
      attestorTrustRoot: { type: 'raw-key', ref: other.publicKey },   // wrong key
    })
    const r = await verifyToolManifest({ manifest: m })
    assert.equal(r.attestorVerified, false)
    assert.equal(r.valid, false)
  })

  it('attestorDid present but trust root cannot resolve: clean fail, not a throw, not a silent pass', async () => {
    const att = generateKeyPair()
    const m = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey,
      attestorDid: 'did:web:attestor.example',
      attestorTrustRoot: { type: 'did:web', ref: 'did:web:attestor.example' },
    })
    const r = await verifyToolManifest({
      manifest: m,
      didWebResolver: async () => { throw new Error('network down') },
    })
    assert.equal(r.attestorVerified, false)
    assert.equal(r.attestorResolutionMethod, 'did:web')
    assert.equal(r.valid, false)
    assert.ok(r.errors.some(e => e.includes('Attestor key resolution failed')))
  })

  it('valid attestor re-approval passes; a random attestor re-approval fails', async () => {
    const att = generateKeyPair()
    const did = toDIDKey(att.publicKey)
    const trustRoot = { type: 'aps' as const, ref: did }
    const m1 = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey, attestorDid: did, attestorTrustRoot: trustRoot,
    })
    const m2 = reviseToolManifest(m1, { implementation: 'src-v2' }, att.privateKey)
    assert.equal(m2.approvalState, 'pending-reapproval')

    // pending-reapproval still fails before approval
    assert.equal((await verifyToolManifest({ manifest: m2 })).valid, false)

    const good = reapproveToolManifest(m2, {
      attestorPrivateKey: att.privateKey, attestorDid: did, attestorTrustRoot: trustRoot,
    })
    const rGood = await verifyToolManifest({ manifest: good })
    assert.equal(rGood.attestorVerified, true)
    assert.equal(rGood.reapprovalRequired, false)
    assert.equal(rGood.valid, true)

    // random attestor: re-approves with a stranger key while still claiming
    // attestorDid = att -> the resolved (att) key rejects the stranger signature
    const stranger = generateKeyPair()
    const forged = reapproveToolManifest(m2, {
      attestorPrivateKey: stranger.privateKey, attestorDid: did, attestorTrustRoot: trustRoot,
    })
    const rForged = await verifyToolManifest({ manifest: forged })
    assert.equal(rForged.attestorVerified, false)
    assert.equal(rForged.valid, false)
  })

  it('publisher + reapproval compose end-to-end — both identities verify', async () => {
    const att = generateKeyPair()
    const pub = generateKeyPair()
    const attDid = toDIDKey(att.publicKey)
    const pubDid = toDIDKey(pub.publicKey)
    const attRoot = { type: 'aps' as const, ref: attDid }
    const pubRoot = { type: 'aps' as const, ref: pubDid }

    const m1 = createToolManifest({
      toolName: 'web_search', implementation: 'src-v1', metadata: META,
      attestorPrivateKey: att.privateKey, attestorDid: attDid, attestorTrustRoot: attRoot,
      publisherDid: pubDid, trustRoot: pubRoot, publisherPrivateKey: pub.privateKey,
    })

    // revising a publisher-bearing manifest WITHOUT a publisher key must throw
    assert.throws(
      () => reviseToolManifest(m1, { implementation: 'src-v2' }, att.privateKey),
      /publisherPrivateKey is required/,
    )
    const m2 = reviseToolManifest(m1, { implementation: 'src-v2' }, att.privateKey, {
      publisherPrivateKey: pub.privateKey,
    })
    assert.equal(m2.approvalState, 'pending-reapproval')

    // re-approving a publisher-bearing manifest WITHOUT a publisher key must throw
    assert.throws(
      () => reapproveToolManifest(m2, { attestorPrivateKey: att.privateKey }),
      /publisherPrivateKey is required/,
    )
    const m3 = reapproveToolManifest(m2, {
      attestorPrivateKey: att.privateKey, attestorDid: attDid, attestorTrustRoot: attRoot,
      publisherPrivateKey: pub.privateKey,
    })
    const r = await verifyToolManifest({ manifest: m3 })
    assert.equal(r.publisherVerified, true)
    assert.equal(r.attestorVerified, true)
    assert.equal(r.reapprovalRequired, false)
    assert.equal(r.valid, true)
  })
})
