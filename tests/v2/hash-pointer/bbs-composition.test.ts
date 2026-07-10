// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════════
// Hash-and-Pointer - BBS composition test.
//
// The field-disclosure profile can carry a BBS selective-disclosure proof by
// reference. The BBS implementation lives in @aeoess/aps-bbs-credentials, an
// EXPERIMENTAL, ISOLATED package that is NOT imported by core, with its own
// runtime crypto dependency (@grottonetworking/bbs-signatures) that is NOT
// installed in the shared core node_modules.
//
// This suite therefore has two layers:
//
//   1. Bridge round-trip (always runs): exercises the structural bridge with a
//      synthetic proof shape. No BBS dependency. This is what verifies the slot
//      and format this module owns.
//
//   2. Real BBS composition (runs only where the optional dep is installed):
//      imports the real package by source path and re-verifies a bridged proof
//      with the real verifier. When the optional dependency is absent, this
//      layer is SKIPPED, not failed, so the core suite stays green. The
//      composition is wired against the real interface, never faked.
// ══════════════════════════════════════════════════════════════════════
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  bbsProofToFieldDisclosureRef,
  fieldDisclosureRefToBbsProof,
  buildFieldDisclosureProfile,
} from '../../../src/v2/hash-pointer/index.js'
import type { BbsDisclosureProofShape } from '../../../src/v2/hash-pointer/index.js'
import { canonicalize } from '../../../src/core/canonical.js'

// ── Layer 1: bridge round-trip (no BBS dependency) ──

function syntheticProof(): BbsDisclosureProofShape {
  return {
    publicKey: new Uint8Array(96).fill(3),
    header: new TextEncoder().encode('aps:bbs-scope-credential:v0'),
    presentationHeader: new TextEncoder().encode('verifier-challenge'),
    disclosedScopes: ['diagnosis_code', 'visible_note'],
    disclosedIndexes: [2, 3],
    proof: new Uint8Array(304).fill(9),
    totalScopes: 4,
    ciphersuite: 'SHA-256',
  }
}

test('bridge converts a BBS proof shape to a JSON-canonicalizable reference', () => {
  const ref = bbsProofToFieldDisclosureRef(syntheticProof())
  assert.equal(ref.format, 'bbs-2023')
  assert.equal(ref.ciphersuite, 'SHA-256')
  assert.deepEqual(ref.disclosed_fields, ['diagnosis_code', 'visible_note'])
  assert.deepEqual(ref.disclosed_indexes, [2, 3])
  assert.equal(ref.total_fields, 4)
  // No Uint8Array leaks into the receipt body; everything is a base64 string.
  const serialized = canonicalize(ref as unknown as Record<string, unknown>)
  assert.ok(serialized.includes('bbs-2023'))
  // Undisclosed field names never appear in the disclosed list.
  assert.ok(!ref.disclosed_fields.includes('ssn'))
  assert.ok(!ref.disclosed_fields.includes('patient_name'))
})

test('bridge round-trips byte-for-byte', () => {
  const original = syntheticProof()
  const ref = bbsProofToFieldDisclosureRef(original)
  const rebuilt = fieldDisclosureRefToBbsProof(ref)
  assert.deepEqual(Array.from(rebuilt.publicKey), Array.from(original.publicKey))
  assert.deepEqual(Array.from(rebuilt.header), Array.from(original.header))
  assert.deepEqual(
    Array.from(rebuilt.presentationHeader),
    Array.from(original.presentationHeader)
  )
  assert.deepEqual(Array.from(rebuilt.proof), Array.from(original.proof))
  assert.deepEqual(rebuilt.disclosedScopes, original.disclosedScopes)
  assert.deepEqual(rebuilt.disclosedIndexes, original.disclosedIndexes)
  assert.equal(rebuilt.totalScopes, original.totalScopes)
  assert.equal(rebuilt.ciphersuite, original.ciphersuite)
})

test('a bridged BBS reference attaches to a field-disclosure profile without leaking raw values', () => {
  const ref = bbsProofToFieldDisclosureRef(syntheticProof())
  const profile = buildFieldDisclosureProfile({
    payload: {
      patient_name: 'Jane Roe',
      ssn: '000-00-0000',
      diagnosis_code: 'Z99',
      visible_note: 'follow up',
    },
    policies: {
      patient_name: 'hash_only',
      ssn: 'redacted',
      diagnosis_code: 'hash_only',
      visible_note: 'public',
    },
    sensitive_fields: ['patient_name', 'ssn', 'diagnosis_code'],
    bbs_proof: ref,
  })
  assert.ok(profile.bbs_proof)
  assert.equal(profile.bbs_proof!.format, 'bbs-2023')
  const serialized = canonicalize(profile as unknown as Record<string, unknown>)
  assert.ok(!serialized.includes('Jane Roe'))
  assert.ok(!serialized.includes('000-00-0000'))
})

// ── Layer 2: real BBS composition (skips when the optional dep is absent) ──

// Probe whether the isolated package's runtime crypto dependency is installed.
// It is NOT part of the shared core node_modules, so in the core suite this
// layer skips. Where the package's own deps are installed, it runs for real.
let bbsAvailable = false
try {
  await import('@grottonetworking/bbs-signatures')
  bbsAvailable = true
} catch {
  bbsAvailable = false
}

const KEY_MATERIAL = new Uint8Array(32).fill(11)
const PH = new TextEncoder().encode('aps:field-disclosure:challenge:0001')
const FIELDS = ['patient_name', 'ssn', 'diagnosis_code', 'visible_note']

test('real BBS: a bridged subset proof re-verifies with the real verifier', { skip: !bbsAvailable }, async () => {
  const {
    generateKeyPair: bbsGenerateKeyPair,
    issueScopeCredential,
    deriveDisclosureProof,
    verifyDisclosureProof,
  } = await import('../../../packages/aps-bbs-credentials/src/index.js')

  const keyPair = await bbsGenerateKeyPair(KEY_MATERIAL)
  const credential = await issueScopeCredential(keyPair, FIELDS)
  const proof = await deriveDisclosureProof(
    credential,
    ['diagnosis_code', 'visible_note'],
    PH
  )
  assert.equal(await verifyDisclosureProof(proof), true)

  // Bridge to the receipt reference and back, then re-verify with the real
  // verifier. This is the out-of-band path a holder of the package would run.
  const ref = bbsProofToFieldDisclosureRef(proof)
  const rebuilt = fieldDisclosureRefToBbsProof(ref)
  const reverified = await verifyDisclosureProof({
    ...rebuilt,
    scopeOfClaim: proof.scopeOfClaim,
  })
  assert.equal(reverified, true)
})

test('real BBS NEGATIVE: a tampered bridged proof fails re-verification', { skip: !bbsAvailable }, async () => {
  const {
    generateKeyPair: bbsGenerateKeyPair,
    issueScopeCredential,
    deriveDisclosureProof,
    verifyDisclosureProof,
  } = await import('../../../packages/aps-bbs-credentials/src/index.js')

  const keyPair = await bbsGenerateKeyPair(KEY_MATERIAL)
  const credential = await issueScopeCredential(keyPair, FIELDS)
  const proof = await deriveDisclosureProof(credential, ['diagnosis_code'], PH)
  const ref = bbsProofToFieldDisclosureRef(proof)

  const raw = Buffer.from(ref.proof_b64, 'base64')
  raw[Math.floor(raw.length / 2)] ^= 0xff
  const tamperedRef = { ...ref, proof_b64: raw.toString('base64') }
  const rebuilt = fieldDisclosureRefToBbsProof(tamperedRef)
  const reverified = await verifyDisclosureProof({
    ...rebuilt,
    scopeOfClaim: proof.scopeOfClaim,
  })
  assert.equal(reverified, false)
})
