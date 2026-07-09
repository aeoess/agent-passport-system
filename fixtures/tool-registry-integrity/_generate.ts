// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Deterministic generator for the Tool Registry & Discovery Integrity
// conformance vectors. Fixed keypairs + fixed timestamp -> reproducible
// output (Ed25519 is deterministic, RFC 8032). Run:
//
//   npx tsx fixtures/tool-registry-integrity/_generate.ts
//
// The emitted conformance-vectors-v1.json is language-agnostic: any
// implementation can re-canonicalize each `input`, hash it, and verify the
// Ed25519 signature against the published key. That cross-language check is
// what makes "reference implementation" a source-verifiable claim.

import { createHash } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { canonicalize } from '../../src/core/canonical.js'
import { publicKeyFromPrivate } from '../../src/crypto/keys.js'
import { toDIDKey } from '../../src/core/did-interop.js'
import {
  createToolManifest, createNamespaceClaim, type ToolManifest, type ToolMetadata,
} from '../../src/core/tool-integrity.js'

// ── fixed test keys (32-byte hex; any 32 bytes is a valid Ed25519 seed) ──
const ATTESTOR_PRIV = 'a1'.repeat(32)
const PUBLISHER_PRIV = 'b2'.repeat(32)
const ATTESTOR_PUB = publicKeyFromPrivate(ATTESTOR_PRIV)
const PUBLISHER_PUB = publicKeyFromPrivate(PUBLISHER_PRIV)
const VERIFIED_AT = '2026-05-16T00:00:00Z'

const hex = (s: string) => Buffer.from(s, 'utf8').toString('hex')
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex')
const bodyOf = (m: ToolManifest) => {
  const { signature: _s, publisherSignature: _p, ...body } = m
  return body
}

interface Vector {
  name: string
  description: string
  input: unknown
  canonical_bytes_hex: string
  canonical_sha256: string
  metadata_hash?: string
  signer?: string
  ed25519_pubkey_hex?: string
  ed25519_signature_over_canonical_hex?: string
  expected_verification?: boolean
}

const vectors: Vector[] = []

const metadata: ToolMetadata = {
  description: 'Search the public web and return ranked results.',
  schema: { input: { query: 'string' }, output: { results: 'array' } },
  permissions: ['net:read', 'cache:write'],
}

// 1 — metadata block hash (distinct from implementation hash)
{
  const canon = canonicalize(metadata)
  vectors.push({
    name: 'metadata-block-hash',
    description: 'Canonicalized metadata block; metadataHash = sha256: of these bytes.',
    input: metadata,
    canonical_bytes_hex: hex(canon),
    canonical_sha256: sha256(canon),
    metadata_hash: 'sha256:' + sha256(canon),
  })
}

// 2 — attestor-signed manifest body (APS-native publisher, co-signed)
const manifest = createToolManifest({
  toolName: 'acme/web_search',
  namespace: 'acme/*',
  implementation: 'web-search-tool-source-v1',
  metadata,
  attestorPrivateKey: ATTESTOR_PRIV,
  publisherDid: toDIDKey(PUBLISHER_PUB),
  trustRoot: { type: 'aps', ref: toDIDKey(PUBLISHER_PUB) },
  publisherPrivateKey: PUBLISHER_PRIV,
  verifiedAt: VERIFIED_AT,
})
{
  const canon = canonicalize(bodyOf(manifest))
  vectors.push({
    name: 'manifest-body-attestor-signed',
    description: 'Canonical manifest body (manifest minus both signatures), attestor Ed25519 signature.',
    input: bodyOf(manifest),
    canonical_bytes_hex: hex(canon),
    canonical_sha256: sha256(canon),
    signer: 'attestor',
    ed25519_pubkey_hex: ATTESTOR_PUB,
    ed25519_signature_over_canonical_hex: manifest.signature,
    expected_verification: true,
  })
  vectors.push({
    name: 'manifest-body-publisher-cosigned',
    description: 'Same canonical manifest body, publisher Ed25519 co-signature over identical bytes.',
    input: bodyOf(manifest),
    canonical_bytes_hex: hex(canon),
    canonical_sha256: sha256(canon),
    signer: 'publisher',
    ed25519_pubkey_hex: PUBLISHER_PUB,
    ed25519_signature_over_canonical_hex: manifest.publisherSignature!,
    expected_verification: true,
  })
}

// 3 — namespace ownership claim body
const claim = createNamespaceClaim({
  namespace: 'acme/*',
  ownerDid: toDIDKey(PUBLISHER_PUB),
  trustRoot: { type: 'aps', ref: toDIDKey(PUBLISHER_PUB) },
  ownerPrivateKey: PUBLISHER_PRIV,
})
{
  const claimBody = { namespace: claim.namespace, ownerDid: claim.ownerDid }
  const canon = canonicalize(claimBody)
  vectors.push({
    name: 'namespace-claim-body',
    description: 'Canonical namespace-claim body {namespace, ownerDid}, owner Ed25519 signature.',
    input: claimBody,
    canonical_bytes_hex: hex(canon),
    canonical_sha256: sha256(canon),
    signer: 'namespaceOwner-is-publisher',
    ed25519_pubkey_hex: PUBLISHER_PUB,
    ed25519_signature_over_canonical_hex: claim.signature,
    expected_verification: true,
  })
}

// 4 — tampered manifest body: signature is over the ORIGINAL body, the
//     input here has a mutated implementationHash -> verification MUST fail.
{
  const tampered = { ...bodyOf(manifest), implementationHash: 'sha256:' + '0'.repeat(64) }
  const canon = canonicalize(tampered)
  vectors.push({
    name: 'manifest-body-tampered-impl-hash',
    description: 'Manifest body with a swapped implementationHash; the attestor signature is over the untampered body, so verification MUST fail.',
    input: tampered,
    canonical_bytes_hex: hex(canon),
    canonical_sha256: sha256(canon),
    signer: 'attestor',
    ed25519_pubkey_hex: ATTESTOR_PUB,
    ed25519_signature_over_canonical_hex: manifest.signature,
    expected_verification: false,
  })
}


const out = {
  version: 'v1',
  spec: 'CoSAI controlToolRegistryandDiscoveryIntegrity — APS reference conformance vectors',
  control_ref: 'cosai-oasis/secure-ai-tooling#162',
  canonicalization: 'APS SDK canonicalize() — src/core/canonical.ts (sorted keys, null-stripped)',
  signature: 'Ed25519 (RFC 8032), deterministic; signs the utf-8 canonical bytes',
  module: 'src/core/tool-integrity.ts',
  generated_at: '2026-05-16',
  note: 'Deterministic — fixed keypairs + fixed verifiedAt. Regenerate with fixtures/tool-registry-integrity/_generate.ts',
  keys: {
    attestor: { publicKeyHex: ATTESTOR_PUB },
    publisher: { publicKeyHex: PUBLISHER_PUB },
  },
  vectors,
}

const dir = dirname(fileURLToPath(import.meta.url))
const path = join(dir, 'conformance-vectors-v1.json')
writeFileSync(path, JSON.stringify(out, null, 2) + '\n')
console.log(`wrote ${vectors.length} vectors -> ${path}`)
