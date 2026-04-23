// Verify canonicalize-fixture-v1.json against the APS SDK canonicalizer.
//
// For each vector:
//   1. Run input through canonicalizeJCS.
//   2. Assert UTF-8 hex of canonical string equals canonical_bytes_hex.
//   3. Assert SHA-256 of canonical bytes equals canonical_sha256.
//   4. Verify the Ed25519 signature over canonical bytes against
//      the fixture's pubkey.
//
// Run: npm run test:fixtures

import crypto from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalizeJCS } from '../../src/core/canonical-jcs.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_PATH = join(__dirname, 'canonicalize-fixture-v1.json')

const PKCS8_ED25519_PUB_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

interface Vector {
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
  seed_input: string
  keypair: { publicKeyHex: string }
  vectors: Vector[]
}

function verifyEd25519(message: Uint8Array, signatureHex: string, publicKeyHex: string): boolean {
  const pub = Buffer.from(publicKeyHex, 'hex')
  const derKey = Buffer.concat([PKCS8_ED25519_PUB_PREFIX, pub])
  const keyObj = crypto.createPublicKey({ key: derKey, format: 'der', type: 'spki' })
  return crypto.verify(null, Buffer.from(message), keyObj, Buffer.from(signatureHex, 'hex'))
}

interface Failure {
  vector: string
  check: string
  expected: string
  actual: string
}

function runVector(v: Vector): Failure[] {
  const failures: Failure[] = []
  const canonical = canonicalizeJCS(v.input)
  const canonicalBytes = Buffer.from(canonical, 'utf-8')
  const actualHex = canonicalBytes.toString('hex')
  if (actualHex !== v.canonical_bytes_hex) {
    failures.push({
      vector: v.name,
      check: 'canonical_bytes_hex',
      expected: v.canonical_bytes_hex,
      actual: actualHex,
    })
  }
  const actualSha = crypto.createHash('sha256').update(canonicalBytes).digest('hex')
  if (actualSha !== v.canonical_sha256) {
    failures.push({
      vector: v.name,
      check: 'canonical_sha256',
      expected: v.canonical_sha256,
      actual: actualSha,
    })
  }
  const sigValid = verifyEd25519(
    canonicalBytes,
    v.ed25519_signature_over_canonical_hex,
    v.ed25519_pubkey_hex,
  )
  if (sigValid !== v.expected_verification) {
    failures.push({
      vector: v.name,
      check: 'ed25519_verification',
      expected: String(v.expected_verification),
      actual: String(sigValid),
    })
  }
  return failures
}

function main(): void {
  const fixture: Fixture = JSON.parse(readFileSync(FIXTURE_PATH, 'utf-8'))
  const allFailures: Failure[] = []
  let passed = 0
  for (const v of fixture.vectors) {
    const fails = runVector(v)
    if (fails.length === 0) {
      passed++
      console.log(`  ok  ${v.name}`)
    } else {
      console.log(`  FAIL ${v.name}`)
      for (const f of fails) {
        console.log(`       ${f.check}`)
        console.log(`         expected: ${f.expected}`)
        console.log(`         actual:   ${f.actual}`)
      }
      allFailures.push(...fails)
    }
  }
  console.log('')
  console.log(`${passed}/${fixture.vectors.length} vectors passed`)
  if (allFailures.length > 0) {
    console.log(`${allFailures.length} check(s) failed — DO NOT modify canonicalizer; see README.md step "On failure".`)
    process.exit(1)
  }
}

main()
