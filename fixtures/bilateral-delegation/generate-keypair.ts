// Deterministic Ed25519 keypair derivation + fixture regeneration.
//
// The keypair seed is SHA-256("aps-canonicalize-fixture-v1") — any
// implementation can reproduce it and verify our signatures match.
//
// Run as: tsx generate-keypair.ts
// Exports: deriveKeypair(), sign(), SEED_INPUT.

import crypto from 'node:crypto'
import { writeFileSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalizeJCS } from '../../src/core/canonical-jcs.js'

export const SEED_INPUT = 'aps-canonicalize-fixture-v1'

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')

export interface Keypair {
  seedHex: string
  privateKeyHex: string
  publicKeyHex: string
}

export function deriveKeypair(seedInput: string = SEED_INPUT): Keypair {
  const seed = crypto.createHash('sha256').update(seedInput, 'utf-8').digest()
  const derKey = Buffer.concat([PKCS8_ED25519_PREFIX, seed])
  const keyObj = crypto.createPrivateKey({ key: derKey, format: 'der', type: 'pkcs8' })
  const pubKey = crypto.createPublicKey(keyObj)
  const pubDer = pubKey.export({ type: 'spki', format: 'der' })
  const publicKeyHex = Buffer.from(pubDer.slice(-32)).toString('hex')
  return { seedHex: seed.toString('hex'), privateKeyHex: seed.toString('hex'), publicKeyHex }
}

export function signBytes(message: Uint8Array, privateKeyHex: string): string {
  const priv = Buffer.from(privateKeyHex, 'hex')
  const derKey = Buffer.concat([PKCS8_ED25519_PREFIX, priv])
  const keyObj = crypto.createPrivateKey({ key: derKey, format: 'der', type: 'pkcs8' })
  const sig = crypto.sign(null, Buffer.from(message), keyObj)
  return Buffer.from(sig).toString('hex')
}

interface Vector {
  name: string
  description: string
  input: unknown
}

const VECTORS: Vector[] = [
  {
    name: 'nested-null-preservation',
    description: 'JCS preserves null values at every nesting depth (legacy canonicalize strips them).',
    input: { a: null, b: { c: null } },
  },
  {
    name: 'key-ordering-unicode',
    description: 'Keys sort by Unicode code point: a(0x61) < m(0x6D) < z(0x7A) < é(0xE9).',
    input: { z: 1, a: 2, 'é': 3, m: { z: 1, a: 2 } },
  },
  {
    name: 'empty-containers',
    description: 'Empty object and empty array serialize as {} and [] respectively; both are valid.',
    input: { a: {}, b: [], c: { d: [] } },
  },
  {
    name: 'deeply-nested',
    description: 'Five levels of mixed object/array nesting. Tests recursive canonicalization and key ordering at depth.',
    input: {
      l1: {
        l2: {
          l3: [
            { l4: { l5: { value: 42, tag: 'leaf' } } },
            { l4: { l5: { value: 7, tag: 'leaf-sibling' } } },
          ],
        },
      },
    },
  },
  {
    name: 'string-escape-tab',
    description: 'Tab (U+0009) and newline (U+000A) must be escaped as \\t and \\n per RFC 8785 §3.2.2.2.',
    input: { tab: 'a\tb', nl: 'a\nb' },
  },
  {
    name: 'string-escape-unicode',
    description: 'Non-ASCII characters above U+001F emit as literal UTF-8 bytes (snowman U+2603, thumbs-up U+1F44D).',
    input: { snowman: '☃', emoji: '👍' },
  },
  {
    name: 'numeric-edge-cases',
    description: 'Number formatting per ECMA-262: -0 serializes as "0"; integers have no fractional part; floats round-trip.',
    input: { neg_zero: -0, int: 42, float: 3.14 },
  },
  {
    name: 'array-of-objects',
    description: 'Array preserves element order; each object inside is independently canonicalized with sorted keys.',
    input: [{ a: 1 }, { a: 2, b: 3 }, {}],
  },
  {
    name: 'bilateral-receipt-shape',
    description: 'Realistic in-toto Statement v1 envelope wrapping an AEOESS bilateral delegation receipt predicate (v0.1). Tracks in-toto/attestation#549.',
    input: {
      _type: 'https://in-toto.io/Statement/v1',
      predicateType: 'https://aeoess.com/predicates/bilateral-delegation-receipt/v0.1',
      subject: [
        {
          name: 'delegation:del_abc123',
          digest: { sha256: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae' },
        },
      ],
      predicate: {
        delegation_chain_root: '4f3d8defea1e82c1705c35d97ee4db046c6313ba83855a7d0de04a44f04c834a',
        delegated_by: 'did:aps:principal-001',
        delegated_to: 'did:aps:agent-002',
        scope: ['data:read', 'commerce:checkout'],
        spend_limit: 500,
        issued_at: '2026-04-22T12:00:00Z',
        expires_at: '2026-04-29T12:00:00Z',
        max_depth: 3,
        current_depth: 1,
        obligation_bundle_hash: null,
        revoked_at: null,
      },
    },
  },
  {
    name: 'migration-attestation-shape',
    description: 'Realistic SINT migrationAttestation envelope (reference sint-ai/sint-protocol PR #178). Tests bilateral interop on a non-APS predicate shape.',
    input: {
      _type: 'https://in-toto.io/Statement/v1',
      predicateType: 'https://sint.ai/predicates/migration-attestation/v0.1',
      subject: [
        {
          name: 'migration:mig_789',
          digest: { sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8' },
        },
      ],
      predicate: {
        migration_id: 'mig_789',
        source_chain: 'ethereum',
        target_chain: 'polygon',
        asset_locator: 'erc20:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
        amount: '1000000000',
        recipient: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7',
        attested_by: 'did:sint:attestor-001',
        attested_at: '2026-04-22T12:00:00Z',
        proof_refs: [
          { type: 'merkle', root: 'abc123' },
          { type: 'signature', alg: 'ed25519' },
        ],
        recovery_hint: null,
      },
    },
  },
]

interface FixtureEntry {
  name: string
  description: string
  input: unknown
  canonical_bytes_hex: string
  canonical_sha256: string
  ed25519_pubkey_hex: string
  ed25519_signature_over_canonical_hex: string
  expected_verification: boolean
}

interface Fixture {
  version: string
  spec: string
  canonicalization: string
  seed_input: string
  seed_sha256_hex: string
  keypair: { publicKeyHex: string }
  generated_at: string
  vectors: FixtureEntry[]
}

export function buildFixture(): Fixture {
  const kp = deriveKeypair()
  const entries: FixtureEntry[] = VECTORS.map(v => {
    const canonical = canonicalizeJCS(v.input)
    const canonicalBytes = Buffer.from(canonical, 'utf-8')
    const canonicalHex = canonicalBytes.toString('hex')
    const sha256 = crypto.createHash('sha256').update(canonicalBytes).digest('hex')
    const signature = signBytes(canonicalBytes, kp.privateKeyHex)
    return {
      name: v.name,
      description: v.description,
      input: v.input,
      canonical_bytes_hex: canonicalHex,
      canonical_sha256: sha256,
      ed25519_pubkey_hex: kp.publicKeyHex,
      ed25519_signature_over_canonical_hex: signature,
      expected_verification: true,
    }
  })
  return {
    version: 'v1',
    spec: 'JCS — RFC 8785',
    canonicalization: 'APS SDK canonicalizeJCS (src/core/canonical-jcs.ts)',
    seed_input: SEED_INPUT,
    seed_sha256_hex: kp.seedHex,
    keypair: { publicKeyHex: kp.publicKeyHex },
    generated_at: '2026-04-22',
    vectors: entries,
  }
}

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

function isMain(): boolean {
  const argv1 = process.argv[1]
  if (!argv1) return false
  return argv1 === __filename || argv1.endsWith('generate-keypair.ts') || argv1.endsWith('generate-keypair.js')
}

if (isMain()) {
  const fixture = buildFixture()
  const outPath = join(__dirname, 'canonicalize-fixture-v1.json')
  const json = JSON.stringify(fixture, null, 2) + '\n'
  writeFileSync(outPath, json, 'utf-8')
  console.log(`[generate-keypair] wrote ${fixture.vectors.length} vectors to ${outPath}`)
  console.log(`[generate-keypair] pubkey: ${fixture.keypair.publicKeyHex}`)
  const roundtrip = JSON.parse(readFileSync(outPath, 'utf-8'))
  if (roundtrip.vectors.length !== fixture.vectors.length) {
    console.error('[generate-keypair] roundtrip mismatch')
    process.exit(1)
  }
}
