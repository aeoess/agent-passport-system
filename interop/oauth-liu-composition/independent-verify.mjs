// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Independent verifier: no SDK imports. Recomputes the strict JCS (RFC 8785)
// canonical form, the tagged digests, and the Ed25519 signatures for all three
// committed vectors using node builtins only, and prints PASS or FAIL per
// check. A third party holding record.json and the public key can reproduce
// exactly this.
//
// Payload constructions mirrored here (from the SDK's published tags):
//   receipt id:   sha256("APS-RECEIPT-ID-V1" \0 JCS(receipt minus receipt_id, signatures))
//   receipt sig:  Ed25519 over "APS-RECEIPT-SIG-V1" \0 JCS({receipt: minus signatures, signer: descriptor})
//   observation:  Ed25519 over JCS(record minus signature)

import { createHash, verify as cryptoVerify, createPublicKey } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const load = (...p) => JSON.parse(readFileSync(join(HERE, ...p), 'utf8'))

// Minimal RFC 8785 JCS: sorted keys by UTF-16 code units, JSON.stringify
// number/string semantics. Rejects non-finite numbers and undefined.
function jcs(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('jcs: non-finite number')
    return JSON.stringify(value)
  }
  if (typeof value === 'string') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort()
    return `{${keys.map(k => `${JSON.stringify(k)}:${jcs(value[k])}`).join(',')}}`
  }
  throw new Error(`jcs: unsupported type ${typeof value}`)
}

const sha256Hex = s => createHash('sha256').update(s, 'utf8').digest('hex')

// Raw 32-byte Ed25519 public key hex to a KeyObject via SPKI DER framing.
function ed25519Key(publicKeyHex) {
  const raw = Buffer.from(publicKeyHex, 'hex')
  if (raw.length !== 32) throw new Error('public key must be 32 bytes')
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw])
  return createPublicKey({ key: spki, format: 'der', type: 'spki' })
}

function ed25519Verify(message, signatureHex, publicKeyHex) {
  return cryptoVerify(null, Buffer.from(message, 'utf8'), ed25519Key(publicKeyHex), Buffer.from(signatureHex, 'hex'))
}

let failures = 0
function report(name, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` (${detail})` : ''}`)
  if (!ok) failures++
}

for (const vector of ['v1-permit', 'v2-denial']) {
  const receipt = load('vectors', vector, 'record.json')
  const keys = load('vectors', vector, 'keys.json')

  const { receipt_id, signatures, ...idBody } = receipt
  const idPayload = `APS-RECEIPT-ID-V1\0${jcs(idBody)}`
  report(`${vector} receipt_id recomputes`, sha256Hex(idPayload) === receipt_id)

  const { signatures: _s, ...sigBody } = receipt
  for (const proof of signatures) {
    const { value, ...descriptor } = proof
    const payload = `APS-RECEIPT-SIG-V1\0${jcs({ receipt: sigBody, signer: descriptor })}`
    const keyOk = proof.signer === keys.signer && proof.key_id === keys.key_id
    report(`${vector} signature by ${proof.key_id}`, keyOk && ed25519Verify(payload, value, keys.public_key_hex))
  }
}

{
  const record = load('vectors', 'v3-observation', 'record.json')
  const { signature, ...body } = record
  report('v3-observation signature', ed25519Verify(jcs(body), signature, record.observer_key),
    `observer ${record.observer_key_id}`)
  report('v3-observation status_source is a SET reference',
    record.status_source && record.status_source.kind === 'set' && typeof record.status_source.jti === 'string')
}

process.exit(failures === 0 ? 0 : 1)
