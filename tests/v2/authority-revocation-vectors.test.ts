// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// The committed `aps:authority-revocation:v1` vector family, run against the
// merged verifier.
//
// Source of the vectors: fixtures/authority-revocation/. Nothing is minted here.
// Every record, identifier, preimage and signature is read out of the JSON, and
// the assertions are that the SDK still produces exactly what the file records.
//
// This is the TypeScript half of a two-language claim: the Python port consumes
// the same file and must reach the same outcomes. A change in this suite that is
// "fixed" by regenerating the vector is a change to the wire format, and the
// vector's sdk_reference.commit is what says which implementation the recorded
// outcomes came from.

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import {
  authorityRevocationBody,
  authorityRevocationCascadeOrigin,
  authorityRevocationCascadeTransactionInput,
  authorityRevocationIdInput,
  authorityRevocationSignatureInput,
  verifyAuthorityRevocation,
} from '../../src/v2/authority-revocation/index.js'
import type {
  AuthorityRevocationV1,
  AuthorityRevocationVerificationResult,
} from '../../src/v2/authority-revocation/index.js'
import type {
  AuthorityDelegationV1,
  KeyResolutionFailure,
} from '../../src/v2/authority-delegation/index.js'

interface ResolverEntry {
  controller: string
  verification_method: string
  key_valid_from: string
  public_key_hex: string
  key_label: string
}

interface RecordedVerification {
  state: AuthorityRevocationVerificationResult['state']
  valid: boolean
  failures: Array<{ code: string; message: string }>
}

interface VectorFile {
  record_type: string
  sdk_reference: { commit: string }
  key_resolver: { entries: ResolverEntry[] }
  valid_case: {
    name: string
    target_delegation: AuthorityDelegationV1
    revocation: AuthorityRevocationV1
    preimages: {
      cascade_transaction_id_preimage_hex: string
      revocation_id_preimage_hex: string
      signature_preimage_hex: string
    }
    derived: {
      cascade_transaction_id: string
      revocation_id: string
      signature: string
      public_key_hex: string
      signing_key_label: string
    }
    verification: RecordedVerification
  }
  negative_cases: Array<{
    name: string
    defect: string
    record: unknown
    verification: RecordedVerification
  }>
}

const vector = JSON.parse(readFileSync(
  new URL('../../fixtures/authority-revocation/authority-revocation-vectors-v1.json', import.meta.url),
  'utf8',
)) as VectorFile

const delegation = vector.valid_case.target_delegation

/** The resolver the vector file describes, rebuilt from its own committed table. */
function resolveVerificationKey(
  controller: string,
  verificationMethod: string,
  at: string,
): string | KeyResolutionFailure {
  const entry = vector.key_resolver.entries.find(
    item => item.controller === controller && item.verification_method === verificationMethod,
  )
  if (!entry) return { outcome: 'not_found' }
  if (at < entry.key_valid_from) return { outcome: 'not_found' }
  return entry.public_key_hex
}

const verifyCandidate = (candidate: unknown): AuthorityRevocationVerificationResult =>
  verifyAuthorityRevocation(candidate, delegation, { resolveVerificationKey })

const utf8Hex = (value: string): string => Buffer.from(value, 'utf8').toString('hex')

function assertOutcome(
  observed: AuthorityRevocationVerificationResult,
  recorded: RecordedVerification,
  name: string,
): void {
  assert.equal(observed.state, recorded.state, `${name}: state`)
  assert.equal(observed.valid, recorded.valid, `${name}: valid`)
  assert.deepEqual(
    observed.failures.map(item => item.code),
    recorded.failures.map(item => item.code),
    `${name}: failure codes`,
  )
  assert.deepEqual(observed.failures, recorded.failures, `${name}: failures`)
}

test('the vector family is the one this suite claims to run', () => {
  assert.equal(vector.record_type, 'aps:authority-revocation:v1')
  assert.match(vector.sdk_reference.commit, /^[0-9a-f]{40}$/)
  assert.ok(vector.negative_cases.length >= 7,
    `expected at least 7 negative cases, got ${vector.negative_cases.length}`)
  const names = vector.negative_cases.map(item => item.name)
  assert.equal(new Set(names).size, names.length, 'negative case names must be unique')
})

test('valid case — the recorded preimage bytes are the ones the SDK builds', () => {
  const revocation = vector.valid_case.revocation
  const body = authorityRevocationBody(revocation)
  const origin = authorityRevocationCascadeOrigin(body)
  const { signature: _signature, ...unsigned } = revocation

  assert.equal(
    utf8Hex(authorityRevocationCascadeTransactionInput(origin)),
    vector.valid_case.preimages.cascade_transaction_id_preimage_hex,
    'cascade transaction preimage',
  )
  assert.equal(
    utf8Hex(authorityRevocationIdInput(body)),
    vector.valid_case.preimages.revocation_id_preimage_hex,
    'revocation_id preimage',
  )
  assert.equal(
    utf8Hex(authorityRevocationSignatureInput(unsigned)),
    vector.valid_case.preimages.signature_preimage_hex,
    'signature preimage',
  )
})

test('valid case — the record carries the identifiers and signature the file derives', () => {
  const revocation = vector.valid_case.revocation
  const derived = vector.valid_case.derived
  assert.equal(revocation.cascade_transaction_id, derived.cascade_transaction_id)
  assert.equal(revocation.revocation_id, derived.revocation_id)
  assert.equal(revocation.signature, derived.signature)
})

test('valid case — the merged verifier returns the recorded outcome', () => {
  assertOutcome(
    verifyCandidate(vector.valid_case.revocation),
    vector.valid_case.verification,
    vector.valid_case.name,
  )
  assert.equal(vector.valid_case.verification.state, 'valid')
})

for (const negative of vector.negative_cases) {
  test(`negative case "${negative.name}" — the merged verifier returns the recorded outcome`, () => {
    const observed = verifyCandidate(negative.record)
    assertOutcome(observed, negative.verification, negative.name)
    assert.notEqual(observed.state, 'valid', `${negative.name} must not verify`)
    assert.ok(negative.defect.length > 0, `${negative.name} must name its defect`)
  })
}
