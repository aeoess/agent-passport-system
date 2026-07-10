// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Signed content-addressed policy-bundle format and verifier tests.
// Covers: round-trip sign/verify, tampered manifest rejected, tampered tar
// rejected, a weakening changeType flagged, and a revoked bundle rejected
// via an aps.txt fixture.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

import {
  createPolicyBundle,
  verifyPolicyBundle,
  manifestHash,
  serializePolicyBundle,
  parsePolicyBundle,
  bundleTarBytes,
  packTar,
  unpackTar,
  defaultPolicyBundleScope,
} from '../../../src/v2/policy-bundle/index.js'
import type { PolicyBundleEnvelope } from '../../../src/v2/policy-bundle/index.js'
import { generateKeyPair } from '../../../src/crypto/keys.js'
import { generateApsTxt } from '../../../src/core/aps-txt.js'
import type { ApsTxt } from '../../../src/core/aps-txt.js'
import type { GovernanceTerms } from '../../../src/core/governance-block.js'

// ── helpers ──

function sampleFiles() {
  return [
    { path: 'policy.json', content: JSON.stringify({ rule: 'deny-by-default', version: 1 }) },
    { path: 'rules/allow.txt', content: 'allow: data:read\n' },
    { path: 'README.md', content: '# Policy set\nGoverns data access.\n' },
  ]
}

function makeBundle(overrides: Partial<Parameters<typeof createPolicyBundle>[0]> = {}) {
  const signer = generateKeyPair()
  const envelope = createPolicyBundle({
    bundleId: 'acme-data-policy',
    files: sampleFiles(),
    signerPrivateKey: signer.privateKey,
    signerPublicKey: signer.publicKey,
    createdAt: '2026-05-31T00:00:00.000Z',
    ...overrides,
  })
  return { signer, envelope }
}

const PROHIBIT_ALL: GovernanceTerms = {
  inference: 'prohibited',
  training: 'prohibited',
  redistribution: 'prohibited',
  derivative: 'prohibited',
  caching: 'prohibited',
}

const ALLOW_ALL: GovernanceTerms = {
  inference: 'permitted',
  training: 'permitted',
  redistribution: 'permitted',
  derivative: 'permitted',
  caching: 'permitted',
}

/** Build an aps.txt fixture whose path override revokes one bundle id. */
function makeApsTxtRevoking(bundleId: string): ApsTxt {
  const publisher = generateKeyPair()
  return generateApsTxt({
    domain: 'policies.example.com',
    publisherName: 'Example Policy Publisher',
    publicKey: publisher.publicKey,
    privateKey: publisher.privateKey,
    defaultTerms: ALLOW_ALL,
    pathOverrides: [
      { pattern: `/${bundleId}`, terms: PROHIBIT_ALL },
    ],
  })
}

/** Build an aps.txt fixture that does not revoke the bundle (allow-all default). */
function makeApsTxtAllowing(): ApsTxt {
  const publisher = generateKeyPair()
  return generateApsTxt({
    domain: 'policies.example.com',
    publisherName: 'Example Policy Publisher',
    publicKey: publisher.publicKey,
    privateKey: publisher.privateKey,
    defaultTerms: ALLOW_ALL,
  })
}

// ─────────────────────────────────────────────────────────────────────────
// Deterministic tar
// ─────────────────────────────────────────────────────────────────────────

describe('policy-bundle: deterministic tar', () => {
  it('packs and unpacks regular files round-trip', () => {
    const entries = [
      { name: 'a.txt', data: new TextEncoder().encode('alpha') },
      { name: 'dir/b.txt', data: new TextEncoder().encode('beta beta') },
    ]
    const packed = packTar(entries)
    const out = unpackTar(packed)
    assert.equal(out.length, 2)
    const byName = new Map(out.map(e => [e.name, new TextDecoder().decode(e.data)]))
    assert.equal(byName.get('a.txt'), 'alpha')
    assert.equal(byName.get('dir/b.txt'), 'beta beta')
  })

  it('is deterministic: same files yield identical bytes regardless of input order', () => {
    const a = [
      { name: 'z.txt', data: new TextEncoder().encode('zeta') },
      { name: 'a.txt', data: new TextEncoder().encode('alpha') },
    ]
    const b = [
      { name: 'a.txt', data: new TextEncoder().encode('alpha') },
      { name: 'z.txt', data: new TextEncoder().encode('zeta') },
    ]
    const ha = createHash('sha256').update(packTar(a)).digest('hex')
    const hb = createHash('sha256').update(packTar(b)).digest('hex')
    assert.equal(ha, hb)
  })

  it('rejects a corrupted archive at read time (checksum mismatch)', () => {
    const packed = packTar([{ name: 'a.txt', data: new TextEncoder().encode('alpha') }])
    // Flip a byte in the name field of the first header.
    packed[0] ^= 0xff
    assert.throws(() => unpackTar(packed), /checksum mismatch|corrupted/)
  })

  it('rejects duplicate entry names', () => {
    assert.throws(
      () => packTar([
        { name: 'dup.txt', data: new Uint8Array([1]) },
        { name: 'dup.txt', data: new Uint8Array([2]) },
      ]),
      /duplicate entry/,
    )
  })
})

// ─────────────────────────────────────────────────────────────────────────
// Round-trip sign and verify (happy path)
// ─────────────────────────────────────────────────────────────────────────

describe('policy-bundle: round-trip sign and verify', () => {
  it('a freshly created bundle verifies as valid', () => {
    const { envelope } = makeBundle()
    const result = verifyPolicyBundle(envelope)
    assert.equal(result.valid, true, JSON.stringify(result.reasons))
    assert.equal(result.signatureValid, true)
    assert.equal(result.tarHashMatches, true)
    assert.equal(result.fileHashesMatch, true)
    assert.equal(result.signerDidConsistent, true)
    assert.equal(result.revoked, false)
    assert.deepEqual(result.reasons, [])
  })

  it('manifest hash is content-addressed and stable across recreation', () => {
    const signer = generateKeyPair()
    const opts = {
      bundleId: 'stable-id',
      files: sampleFiles(),
      signerPrivateKey: signer.privateKey,
      signerPublicKey: signer.publicKey,
      createdAt: '2026-05-31T00:00:00.000Z',
    }
    const e1 = createPolicyBundle(opts)
    const e2 = createPolicyBundle(opts)
    assert.equal(manifestHash(e1.manifest), manifestHash(e2.manifest))
    assert.equal(e1.signature, e2.signature)
    assert.equal(e1.tarHex, e2.tarHex)
  })

  it('serializes and parses an envelope without losing integrity', () => {
    const { envelope } = makeBundle()
    const json = serializePolicyBundle(envelope)
    const parsed = parsePolicyBundle(json)
    assert.ok(parsed)
    const result = verifyPolicyBundle(parsed as PolicyBundleEnvelope)
    assert.equal(result.valid, true)
  })

  it('verifies when raw tar bytes are supplied directly', () => {
    const { envelope } = makeBundle()
    const bytes = bundleTarBytes(envelope)
    const result = verifyPolicyBundle(envelope, { tarBytes: bytes })
    assert.equal(result.valid, true)
  })

  it('default scope-of-claim is dogfooded onto the manifest', () => {
    const { envelope } = makeBundle()
    assert.deepEqual(envelope.manifest.scopeOfClaim, defaultPolicyBundleScope())
    assert.equal(envelope.manifest.scopeOfClaim.self_attested, true)
    assert.ok(envelope.manifest.scopeOfClaim.does_not_assert.length >= 1)
  })

  it('parsePolicyBundle returns null on malformed input', () => {
    assert.equal(parsePolicyBundle('not json'), null)
    assert.equal(parsePolicyBundle(JSON.stringify({ manifest: { format: 'other' } })), null)
  })
})

// ─────────────────────────────────────────────────────────────────────────
// NEGATIVE: tampered manifest rejected
// ─────────────────────────────────────────────────────────────────────────

describe('policy-bundle: tampered manifest rejected', () => {
  it('rejects when a manifest field is altered after signing (signature breaks)', () => {
    const { envelope } = makeBundle()
    const tampered: PolicyBundleEnvelope = {
      ...envelope,
      manifest: { ...envelope.manifest, bundleId: 'attacker-renamed' },
    }
    const result = verifyPolicyBundle(tampered)
    assert.equal(result.valid, false)
    assert.equal(result.signatureValid, false)
    assert.ok(result.reasons.includes('SIGNATURE_INVALID'))
  })

  it('rejects when a manifest file pin is altered (signature breaks)', () => {
    const { envelope } = makeBundle()
    const files = envelope.manifest.files.map((f, i) =>
      i === 0 ? { ...f, sha256: 'deadbeef'.repeat(8) } : f,
    )
    const tampered: PolicyBundleEnvelope = {
      ...envelope,
      manifest: { ...envelope.manifest, files },
    }
    const result = verifyPolicyBundle(tampered)
    assert.equal(result.valid, false)
    assert.ok(result.reasons.includes('SIGNATURE_INVALID'))
  })

  it('rejects when signerPublicKey is swapped to an attacker key', () => {
    const { envelope } = makeBundle()
    const attacker = generateKeyPair()
    const tampered: PolicyBundleEnvelope = {
      ...envelope,
      manifest: { ...envelope.manifest, signerPublicKey: attacker.publicKey },
    }
    const result = verifyPolicyBundle(tampered)
    assert.equal(result.valid, false)
    // signer key no longer matches the did and the signature no longer verifies
    assert.ok(result.reasons.includes('SIGNATURE_INVALID') || result.reasons.includes('SIGNER_DID_MISMATCH'))
  })

  it('rejects when signerDid is inconsistent with signerPublicKey', () => {
    const { signer, envelope } = makeBundle()
    // Re-sign a manifest whose did is wrong, so the signature is valid but the
    // did does not match the key.
    const badManifest = { ...envelope.manifest, signerDid: 'did:aps:zNOTACONSISTENTDID' }
    // Signature is over the original manifest, so this also breaks the signature;
    // the did-consistency check is the explicit assertion here.
    const tampered: PolicyBundleEnvelope = { ...envelope, manifest: badManifest }
    const result = verifyPolicyBundle(tampered)
    assert.equal(result.signerDidConsistent, false)
    assert.equal(result.valid, false)
    assert.ok(result.reasons.includes('SIGNER_DID_MISMATCH'))
    // keep signer referenced
    assert.equal(typeof signer.publicKey, 'string')
  })
})

// ─────────────────────────────────────────────────────────────────────────
// NEGATIVE: tampered tar / file contents rejected
// ─────────────────────────────────────────────────────────────────────────

describe('policy-bundle: tampered tar rejected', () => {
  it('rejects when tar bytes are altered so the tar hash no longer matches', () => {
    const { envelope } = makeBundle()
    const bytes = bundleTarBytes(envelope)
    // Flip a byte inside the first file's data region (past the 512-byte header).
    const mutated = Uint8Array.from(bytes)
    mutated[520] ^= 0x01
    const result = verifyPolicyBundle(envelope, { tarBytes: mutated })
    assert.equal(result.valid, false)
    assert.equal(result.tarHashMatches, false)
    assert.ok(result.reasons.includes('TAR_HASH_MISMATCH'))
  })

  it('rejects when a file is swapped for different content of the same length', () => {
    // Build a bundle, then rebuild a tar with one file's bytes changed but the
    // manifest left intact. tarSha256 will mismatch and so will the file pin.
    const { envelope } = makeBundle()
    const original = unpackTar(bundleTarBytes(envelope))
    const swapped = original.map(e =>
      e.name === 'policy.json'
        ? { name: e.name, data: new TextEncoder().encode(JSON.stringify({ rule: 'allow-all', version: 1 })) }
        : e,
    )
    const forgedTar = packTar(swapped)
    const result = verifyPolicyBundle(envelope, { tarBytes: forgedTar })
    assert.equal(result.valid, false)
    assert.equal(result.tarHashMatches, false)
    // file content no longer matches the manifest pin either
    assert.equal(result.fileHashesMatch, false)
  })

  it('rejects when an extra file is smuggled into the tar', () => {
    const { envelope } = makeBundle()
    const original = unpackTar(bundleTarBytes(envelope))
    const withExtra = [...original, { name: 'backdoor.sh', data: new TextEncoder().encode('rm -rf') }]
    const forgedTar = packTar(withExtra)
    const result = verifyPolicyBundle(envelope, { tarBytes: forgedTar })
    assert.equal(result.valid, false)
    assert.ok(result.reasons.includes('FILE_COUNT_MISMATCH') || result.reasons.some(r => r.startsWith('FILE_NOT_IN_MANIFEST')))
  })
})

// ─────────────────────────────────────────────────────────────────────────
// NEGATIVE/ADVISORY: weakening changeType flagged
// ─────────────────────────────────────────────────────────────────────────

describe('policy-bundle: weakening changeType flagged', () => {
  it('flags a bundle whose governance changeType is weakening', () => {
    const { envelope } = makeBundle({
      governance: {
        changeType: 'weakening',
        previousManifestHash: 'a'.repeat(64),
        removals: ['rule:require-mfa'],
      },
    })
    const result = verifyPolicyBundle(envelope)
    assert.equal(result.weakeningFlagged, true)
    assert.ok(result.reasons.includes('GOVERNANCE_WEAKENING'))
    // Weakening is advisory: a well-formed, signed weakening bundle still
    // verifies structurally so the caller can apply its own approval policy.
    assert.equal(result.valid, true)
  })

  it('infers weakening when removals are present without an explicit changeType', () => {
    const { envelope } = makeBundle({
      governance: {
        previousManifestHash: 'b'.repeat(64),
        removals: ['rule:audit-log'],
      },
    })
    assert.equal(envelope.manifest.governance.changeType, 'weakening')
    const result = verifyPolicyBundle(envelope)
    assert.equal(result.weakeningFlagged, true)
  })

  it('flags mixed change as weakening too', () => {
    const { envelope } = makeBundle({
      governance: {
        changeType: 'mixed',
        previousManifestHash: 'c'.repeat(64),
        additions: ['rule:rate-limit'],
        removals: ['rule:require-mfa'],
      },
    })
    const result = verifyPolicyBundle(envelope)
    assert.equal(result.weakeningFlagged, true)
  })

  it('does not flag a strengthening or initial bundle', () => {
    const strengthen = makeBundle({
      governance: { changeType: 'strengthening', previousManifestHash: 'd'.repeat(64), additions: ['rule:new'] },
    })
    assert.equal(verifyPolicyBundle(strengthen.envelope).weakeningFlagged, false)

    const initial = makeBundle()
    assert.equal(initial.envelope.manifest.governance.changeType, 'initial')
    assert.equal(verifyPolicyBundle(initial.envelope).weakeningFlagged, false)
  })
})

// ─────────────────────────────────────────────────────────────────────────
// NEGATIVE: revoked bundle rejected via aps.txt fixture
// ─────────────────────────────────────────────────────────────────────────

describe('policy-bundle: revocation via aps.txt fixture', () => {
  it('rejects a bundle revoked by an aps.txt path override', () => {
    const { envelope } = makeBundle({ bundleId: 'revoked-policy' })
    const apsTxt = makeApsTxtRevoking('revoked-policy')
    const result = verifyPolicyBundle(envelope, { apsTxt })
    assert.equal(result.revoked, true)
    assert.equal(result.valid, false)
    assert.ok(result.reasons.includes('REVOKED'))
  })

  it('accepts a structurally valid bundle when aps.txt does not revoke it', () => {
    const { envelope } = makeBundle({ bundleId: 'live-policy' })
    const apsTxt = makeApsTxtAllowing()
    const result = verifyPolicyBundle(envelope, { apsTxt })
    assert.equal(result.revoked, false)
    assert.equal(result.valid, true)
  })

  it('honors an explicit revocationPath override', () => {
    const { envelope } = makeBundle({ bundleId: 'whatever' })
    const publisher = generateKeyPair()
    const apsTxt = generateApsTxt({
      domain: 'policies.example.com',
      publisherName: 'Example',
      publicKey: publisher.publicKey,
      privateKey: publisher.privateKey,
      defaultTerms: ALLOW_ALL,
      pathOverrides: [{ pattern: '/revoked/here', terms: PROHIBIT_ALL }],
    })
    const result = verifyPolicyBundle(envelope, { apsTxt, revocationPath: '/revoked/here' })
    assert.equal(result.revoked, true)
    assert.equal(result.valid, false)
  })

  it('a revoked-but-otherwise-valid bundle still reports its other checks as passing', () => {
    const { envelope } = makeBundle({ bundleId: 'revoked-policy-2' })
    const apsTxt = makeApsTxtRevoking('revoked-policy-2')
    const result = verifyPolicyBundle(envelope, { apsTxt })
    // structural integrity is intact; only revocation fails the verdict
    assert.equal(result.signatureValid, true)
    assert.equal(result.tarHashMatches, true)
    assert.equal(result.fileHashesMatch, true)
    assert.equal(result.revoked, true)
    assert.equal(result.valid, false)
  })
})
