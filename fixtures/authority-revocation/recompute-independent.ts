// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Independent recompute of the `aps:authority-revocation:v1` valid case.
//
//   npx tsx fixtures/authority-revocation/recompute-independent.ts
//
// THIS FILE IMPORTS NOTHING FROM src/. Its only imports are node:crypto and
// node:fs. Everything the SDK would have supplied is re-stated here from the
// specification:
//
//   - RFC 8785 JCS, written out below for the string-only objects this record
//     is made of (every member of a revocation is a JSON string).
//   - The three domain tags, re-typed as literals and then checked against the
//     hex the vector publishes, so a tag that drifted would be caught here
//     rather than silently agreed with.
//   - SHA-256 and Ed25519 from the platform.
//
// What it checks, from the vector file alone:
//
//   1. cascade_transaction_id preimage bytes and the identity they hash to
//   2. revocation_id preimage bytes and the identity they hash to
//   3. signature preimage bytes, and an Ed25519 verification over them with the
//      published public key
//
// Nothing in the valid case had to be skipped for want of the SDK. Note one
// deliberate difference in scope: src/crypto/keys.ts additionally refuses
// small-order ("inadmissible") key material before calling the platform
// primitive. This script does not reimplement that check — it is a property of
// the SDK's verifier, not of the vector's bytes, and asserting it here would be
// asserting something these bytes do not carry.
//
// Exits non-zero on the first disagreement.

import { createHash, createPublicKey, verify as ed25519Verify } from 'node:crypto'
import { readFileSync } from 'node:fs'

// ── the frozen domain tags, each terminated by one NUL byte ───────────────────
const ID_DOMAIN = 'APS-AUTHORITY-REVOCATION-ID-V1\u0000'
const SIGNATURE_DOMAIN = 'APS-AUTHORITY-REVOCATION-SIGNATURE-V1\u0000'
const CASCADE_TRANSACTION_DOMAIN = 'APS-AUTHORITY-REVOCATION-CASCADE-TRANSACTION-ID-V1\u0000'

// ── RFC 8785, the part this record needs ──────────────────────────────────────

/**
 * RFC 8785 section 3.2.2.2 string serialization.
 *
 * The seven short escapes, \u00xx for the remaining C0 controls, every other
 * code point emitted literally (the output is UTF-8, so no \u escaping of
 * non-ASCII), and an unpaired surrogate refused rather than escaped: a lone
 * surrogate is not a Unicode scalar and has no UTF-8 encoding.
 */
function jcsString(value: string): string {
  let out = '"'
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code === 0x22) out += '\\"'
    else if (code === 0x5c) out += '\\\\'
    else if (code === 0x08) out += '\\b'
    else if (code === 0x0c) out += '\\f'
    else if (code === 0x0a) out += '\\n'
    else if (code === 0x0d) out += '\\r'
    else if (code === 0x09) out += '\\t'
    else if (code < 0x20) out += `\\u${code.toString(16).padStart(4, '0')}`
    else if (code >= 0xd800 && code <= 0xdbff) {
      const next = i + 1 < value.length ? value.charCodeAt(i + 1) : 0
      if (next < 0xdc00 || next > 0xdfff) {
        throw new Error('unpaired UTF-16 high surrogate has no UTF-8 encoding')
      }
      out += value[i] + value[i + 1]
      i += 1
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error('unpaired UTF-16 low surrogate has no UTF-8 encoding')
    } else out += value[i]
  }
  return `${out}"`
}

/**
 * RFC 8785 serialization of a flat object whose every member is a string.
 *
 * Keys are sorted as UTF-16 code unit sequences, which is what the default
 * Array.prototype.sort comparison does. This function deliberately refuses any
 * value that is not a string rather than growing a general JSON emitter: every
 * member of an AuthorityRevocationV1 is a string, and a narrow function that
 * refuses everything else cannot quietly agree with the SDK for the wrong
 * reason.
 */
function jcsStringOnlyObject(value: Record<string, unknown>, where: string): string {
  const keys = Object.keys(value).sort()
  const pairs = keys.map(key => {
    const member = value[key]
    if (typeof member !== 'string') {
      throw new Error(`${where}.${key} is ${typeof member}; this recompute handles string-only objects`)
    }
    return `${jcsString(key)}:${jcsString(member)}`
  })
  return `{${pairs.join(',')}}`
}

// ── helpers ───────────────────────────────────────────────────────────────────
const utf8Hex = (value: string): string => Buffer.from(value, 'utf8').toString('hex')

const sha256Id = (preimage: string): string =>
  `sha256:${createHash('sha256').update(Buffer.from(preimage, 'utf8')).digest('hex')}`

function without(value: Record<string, unknown>, drop: string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const key of Object.keys(value)) {
    if (!drop.includes(key)) out[key] = value[key]
  }
  return out
}

/** Ed25519 over the UTF-8 bytes of `preimage`, raw 32-byte key, raw 64-byte signature. */
function ed25519VerifyRaw(preimage: string, signatureHex: string, publicKeyHex: string): boolean {
  const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex')
  const key = createPublicKey({
    key: Buffer.concat([spkiPrefix, Buffer.from(publicKeyHex, 'hex')]),
    format: 'der',
    type: 'spki',
  })
  return ed25519Verify(null, Buffer.from(preimage, 'utf8'), key, Buffer.from(signatureHex, 'hex'))
}

const failures: string[] = []
let checks = 0

function check(label: string, actual: unknown, expected: unknown): void {
  checks += 1
  if (actual === expected) {
    process.stdout.write(`  ok    ${label}\n`)
    return
  }
  process.stdout.write(`  FAIL  ${label}\n        expected ${String(expected)}\n        actual   ${String(actual)}\n`)
  failures.push(label)
}

// ── the vector ────────────────────────────────────────────────────────────────
interface Preimages {
  cascade_transaction_id_preimage_hex: string
  revocation_id_preimage_hex: string
  signature_preimage_hex: string
}

interface Vector {
  sdk_reference: { commit: string }
  domain_tags: Record<'revocation_id' | 'signature' | 'cascade_transaction_id', { hex: string }>
  valid_case: {
    name: string
    revocation: Record<string, unknown>
    preimages: Preimages
    derived: {
      cascade_transaction_id: string
      revocation_id: string
      signature: string
      public_key_hex: string
    }
    verification: { state: string; valid: boolean }
  }
}

const vectorPath = new URL('./authority-revocation-vectors-v1.json', import.meta.url)
const vector = JSON.parse(readFileSync(vectorPath, 'utf8')) as Vector
const valid = vector.valid_case

process.stdout.write(
  `independent recompute — no SDK imports\n` +
  `vector:      ${valid.name}\n` +
  `sdk commit:  ${vector.sdk_reference.commit}\n\n`,
)

process.stdout.write('domain tags\n')
check('revocation_id tag bytes', utf8Hex(ID_DOMAIN), vector.domain_tags.revocation_id.hex)
check('signature tag bytes', utf8Hex(SIGNATURE_DOMAIN), vector.domain_tags.signature.hex)
check(
  'cascade_transaction_id tag bytes',
  utf8Hex(CASCADE_TRANSACTION_DOMAIN),
  vector.domain_tags.cascade_transaction_id.hex,
)

const revocation = valid.revocation
const body = without(revocation, ['revocation_id', 'signature'])
const origin = without(body, ['cascade_transaction_id'])
const unsigned = without(revocation, ['signature'])

process.stdout.write('\ncascade transaction identity\n')
const cascadePreimage = CASCADE_TRANSACTION_DOMAIN + jcsStringOnlyObject(origin, 'cascade_origin')
check(
  'preimage bytes',
  utf8Hex(cascadePreimage),
  valid.preimages.cascade_transaction_id_preimage_hex,
)
check('cascade_transaction_id', sha256Id(cascadePreimage), valid.derived.cascade_transaction_id)
check(
  'cascade_transaction_id matches the record member',
  sha256Id(cascadePreimage),
  revocation.cascade_transaction_id,
)

process.stdout.write('\nrecord identifier\n')
const idPreimage = ID_DOMAIN + jcsStringOnlyObject(body, 'body')
check('preimage bytes', utf8Hex(idPreimage), valid.preimages.revocation_id_preimage_hex)
check('revocation_id', sha256Id(idPreimage), valid.derived.revocation_id)
check('revocation_id matches the record member', sha256Id(idPreimage), revocation.revocation_id)

process.stdout.write('\nsignature\n')
const signaturePreimage = SIGNATURE_DOMAIN + jcsStringOnlyObject(unsigned, 'unsigned')
check('preimage bytes', utf8Hex(signaturePreimage), valid.preimages.signature_preimage_hex)
check(
  'Ed25519 verifies under the published public key',
  ed25519VerifyRaw(signaturePreimage, valid.derived.signature, valid.derived.public_key_hex),
  true,
)
check('recorded TS verification state', valid.verification.state, 'valid')

process.stdout.write(`\n${checks} checks, ${failures.length} failed\n`)
if (failures.length > 0) {
  process.stdout.write(`disagreement with the TypeScript reference: ${failures.join(', ')}\n`)
  process.exitCode = 1
} else {
  process.stdout.write('byte-for-byte agreement with the TypeScript reference\n')
}
