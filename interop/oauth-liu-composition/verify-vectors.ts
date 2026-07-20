// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Re-verifies every committed record.json through the SDK verify path, as a
// third party would: the receipt vectors via verifyReceiptV1 with the key from
// the keys.json sidecar, the observation via verifyRevocationObservation with
// the record's own bound observer key. Also re-checks that each receipt's
// evidence_refs digests match the input.json artifacts they claim to tie to,
// so a vector whose record and input drift apart fails loud.

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { strictJCS } from '../../src/v2/receipt-core/jcs.js'
import { verifyReceiptV1 } from '../../src/v2/receipt-core/receipt.js'
import type { JsonValue, ReceiptV1 } from '../../src/v2/receipt-core/types.js'
import { verifyRevocationObservation } from '../../src/v2/revocation-enforcement/observation.js'
import type { SignedRevocationObservation } from '../../src/v2/revocation-enforcement/types.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const sha256Hex = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex')
const digestOf = (value: JsonValue): string => sha256Hex(strictJCS(value))
const load = (...p: string[]): unknown => JSON.parse(readFileSync(join(HERE, ...p), 'utf8'))

export interface VectorResult {
  vector: string
  valid: boolean
  detail: string
}

export function verifyReceiptVector(vector: 'v1-permit' | 'v2-denial'): VectorResult {
  const receipt = load('vectors', vector, 'record.json') as ReceiptV1
  const keys = load('vectors', vector, 'keys.json') as { signer: string; key_id: string; public_key_hex: string }
  const input = load('vectors', vector, 'input.json') as Record<string, JsonValue>

  const verification = verifyReceiptV1(receipt, (signer, keyId) =>
    signer === keys.signer && keyId === keys.key_id ? keys.public_key_hex : undefined)
  if (!verification.valid) {
    return { vector, valid: false, detail: `sdk verify failed: ${verification.errors.join(', ')}` }
  }

  // Tie-back: the receipt's evidence digests must equal the digests of the Liu
  // artifacts in the input fixture.
  const wantEvidence = digestOf(input.authorization_details as JsonValue)
  const wantChain = digestOf({ delegation_chain: input.delegation_chain } as unknown as JsonValue)
  const byType = new Map(receipt.evidence_refs.map(r => [r.artifact_type, r.sha256]))
  if (byType.get('liu-oauth-authorization-evidence-01/authorization_details') !== wantEvidence) {
    return { vector, valid: false, detail: 'authorization_evidence digest does not tie back to input.json' }
  }
  if (byType.get('liu-oauth-chain-delegation-00/delegation_chain') !== wantChain) {
    return { vector, valid: false, detail: 'delegation_chain digest does not tie back to input.json' }
  }
  if (!receipt.decision_ref) {
    return { vector, valid: false, detail: 'decision_ref missing on a policy-decision receipt' }
  }
  return { vector, valid: true, detail: `receipt_id ${receipt.receipt_id} verified, evidence ties back` }
}

export function verifyObservationVector(): VectorResult {
  const record = load('vectors', 'v3-observation', 'record.json') as SignedRevocationObservation
  const result = verifyRevocationObservation(record, { expectedObserverKey: record.observer_key })
  if (!result.valid) return { vector: 'v3-observation', valid: false, detail: `sdk verify failed: ${result.reason}` }
  if (record.status_source.kind !== 'set') {
    return { vector: 'v3-observation', valid: false, detail: 'status_source is not a SET reference' }
  }
  const input = load('vectors', 'v3-observation', 'input.json') as { revocation_signal: { set_jti: string } }
  if (record.status_source.jti !== input.revocation_signal.set_jti) {
    return { vector: 'v3-observation', valid: false, detail: 'SET jti does not tie back to input.json' }
  }
  return { vector: 'v3-observation', valid: true, detail: `observation verified, jti ${record.status_source.jti}` }
}

export function verifyAll(): VectorResult[] {
  return [verifyReceiptVector('v1-permit'), verifyReceiptVector('v2-denial'), verifyObservationVector()]
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const results = verifyAll()
  for (const r of results) console.log(`${r.valid ? 'PASS' : 'FAIL'} ${r.vector}: ${r.detail}`)
  if (results.some(r => !r.valid)) process.exit(1)
}
