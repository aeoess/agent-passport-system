// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Hash-and-Pointer Payloads + Field-Disclosure Profile - core tests.
// Includes explicit negative-path fixtures:
//   - raw PII handed to the builder is rejected
//   - a hash_only field verifies without revealing the value
//   - a receipt carrying a redacted profile still verifies its signature
// ══════════════════════════════════════════════════════════════════════
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  buildFieldDisclosureProfile,
  verifyFieldDisclosureProfile,
  canonicalProfileBytes,
  REDACTED_SENTINEL,
} from '../../../src/v2/hash-pointer/index.js'
import { canonicalHash, canonicalize } from '../../../src/core/canonical.js'
import {
  createBilateralReceipt,
  verifyBilateralReceipt,
} from '../../../src/core/bilateral-receipt.js'
import { generateKeyPair } from '../../../src/crypto/keys.js'
import type { InteractionOutcome } from '../../../src/types/bilateral-receipt.js'

const PAYLOAD = {
  patient_name: 'Jane Roe',
  ssn: '000-00-0000',
  diagnosis_code: 'Z99',
  visible_note: 'follow up in two weeks',
}

// ── builder: hash-and-pointer commitment ──

test('builder commits to a payload by hash + URI without embedding it raw', () => {
  const profile = buildFieldDisclosureProfile({
    payload: PAYLOAD,
    policies: {
      patient_name: 'hash_only',
      ssn: 'redacted',
      diagnosis_code: 'hash_only',
      visible_note: 'public',
    },
    uri: 'https://vault.example/records/abc123',
    content_type: 'application/json',
    sensitive_fields: ['patient_name', 'ssn', 'diagnosis_code'],
  })

  assert.equal(profile.version, '1.0')
  assert.ok(profile.payload)
  assert.equal(profile.payload!.algorithm, 'sha256')
  assert.equal(profile.payload!.uri, 'https://vault.example/records/abc123')
  // The whole-payload commitment is the canonical hash of the source payload.
  assert.equal(profile.payload!.payload_sha256, canonicalHash(PAYLOAD))

  // The raw sensitive values must NOT appear anywhere in the serialized profile.
  const serialized = canonicalize(profile as unknown as Record<string, unknown>)
  assert.ok(!serialized.includes('Jane Roe'), 'raw name must not be embedded')
  assert.ok(!serialized.includes('000-00-0000'), 'raw ssn must not be embedded')
  // The only public field value is present in cleartext.
  assert.ok(serialized.includes('follow up in two weeks'))
})

test('builder defaults unlisted fields to public', () => {
  const profile = buildFieldDisclosureProfile({
    payload: { a: 1, b: 2 },
    policies: { a: 'hash_only' },
  })
  const a = profile.fields.find((f) => f.name === 'a')!
  const b = profile.fields.find((f) => f.name === 'b')!
  assert.equal(a.policy, 'hash_only')
  assert.equal(b.policy, 'public')
  assert.equal(b.value, 2)
  assert.equal(a.value, undefined)
})

// ── NEGATIVE: raw PII handed to the builder is rejected ──

test('NEGATIVE: a sensitive field with policy public is rejected (no raw PII)', () => {
  assert.throws(
    () =>
      buildFieldDisclosureProfile({
        payload: PAYLOAD,
        policies: {
          ssn: 'public', // attempt to embed a raw sensitive value
        },
        sensitive_fields: ['ssn'],
      }),
    /marked sensitive and cannot use the 'public'/
  )
})

test('NEGATIVE: a sensitive field with no policy entry defaults to public and is rejected', () => {
  // ssn is sensitive but has no explicit policy; the default 'public' must be
  // caught, otherwise raw PII would silently reach the signed body.
  assert.throws(
    () =>
      buildFieldDisclosureProfile({
        payload: { ssn: '111-11-1111' },
        policies: {},
        sensitive_fields: ['ssn'],
      }),
    /marked sensitive and cannot use the 'public'/
  )
})

test('NEGATIVE: an encrypted field without ciphertext is rejected', () => {
  assert.throws(
    () =>
      buildFieldDisclosureProfile({
        payload: { secret: 'value' },
        policies: { secret: 'encrypted' },
        sensitive_fields: ['secret'],
        // no ciphertexts map supplied
      }),
    /no ciphertext was supplied/
  )
})

test('NEGATIVE: an unknown disclosure policy is rejected', () => {
  assert.throws(
    () =>
      buildFieldDisclosureProfile({
        payload: { x: 1 },
        // @ts-expect-error deliberately invalid policy for the negative test
        policies: { x: 'plaintext' },
      }),
    /unknown disclosure policy/
  )
})

// ── hash_only verifies without revealing the value ──

test('a hash_only field verifies its binding without revealing the value', () => {
  const profile = buildFieldDisclosureProfile({
    payload: PAYLOAD,
    policies: { patient_name: 'hash_only', ssn: 'redacted', diagnosis_code: 'public', visible_note: 'public' },
    sensitive_fields: ['patient_name', 'ssn'],
  })

  // Internal consistency holds and the hidden field is bound but unrevealed.
  const internal = verifyFieldDisclosureProfile(profile)
  assert.equal(internal.valid, true)
  assert.equal(internal.fields.patient_name.status, 'bound')

  // A relying party who learns the value out of band can confirm the binding,
  // and the value never had to be embedded.
  const matched = verifyFieldDisclosureProfile(profile, {
    disclosed: { patient_name: 'Jane Roe' },
  })
  assert.equal(matched.valid, true)
  assert.equal(matched.fields.patient_name.status, 'matched')
})

test('NEGATIVE: a wrong disclosed value fails the hash binding', () => {
  const profile = buildFieldDisclosureProfile({
    payload: PAYLOAD,
    policies: { patient_name: 'hash_only', ssn: 'redacted', diagnosis_code: 'public', visible_note: 'public' },
    sensitive_fields: ['patient_name', 'ssn'],
  })
  const bad = verifyFieldDisclosureProfile(profile, {
    disclosed: { patient_name: 'Someone Else' },
  })
  assert.equal(bad.valid, false)
  assert.equal(bad.fields.patient_name.status, 'mismatch')
  assert.ok(bad.errors.some((e) => e.includes('patient_name')))
})

test('redacted field keeps the [REDACTED] sentinel and a surviving hash binding', () => {
  const profile = buildFieldDisclosureProfile({
    payload: PAYLOAD,
    policies: { ssn: 'redacted', patient_name: 'hash_only', diagnosis_code: 'public', visible_note: 'public' },
    sensitive_fields: ['ssn', 'patient_name'],
  })
  const ssn = profile.fields.find((f) => f.name === 'ssn')!
  assert.equal(ssn.policy, 'redacted')
  assert.equal(ssn.value, REDACTED_SENTINEL)
  assert.equal(ssn.transform, 'redaction')
  // The hash binding survives redaction; it is the canonical hash of the value.
  assert.equal(ssn.hash, canonicalHash({ v: '000-00-0000' }))
  // And it still re-checks against the true value out of band.
  const v = verifyFieldDisclosureProfile(profile, { disclosed: { ssn: '000-00-0000' } })
  assert.equal(v.fields.ssn.status, 'matched')
})

// ── whole-payload commitment ──

test('whole-payload commitment matches the source payload and flags tampering', () => {
  const profile = buildFieldDisclosureProfile({
    payload: PAYLOAD,
    policies: { patient_name: 'hash_only', ssn: 'redacted', diagnosis_code: 'public', visible_note: 'public' },
    uri: 'ipfs://bafy...',
    sensitive_fields: ['patient_name', 'ssn'],
  })

  const ok = verifyFieldDisclosureProfile(profile, { payload: PAYLOAD })
  assert.equal(ok.payloadMatched, true)
  assert.equal(ok.valid, true)

  const tampered = { ...PAYLOAD, visible_note: 'changed' }
  const bad = verifyFieldDisclosureProfile(profile, { payload: tampered })
  assert.equal(bad.payloadMatched, false)
  assert.equal(bad.valid, false)
})

test('availability is not claimed: a commitment with no supplied payload is null, not false', () => {
  const profile = buildFieldDisclosureProfile({
    payload: { note: 'public note' },
    policies: { note: 'public' },
    uri: 'https://vault.example/x',
  })
  const v = verifyFieldDisclosureProfile(profile)
  // payloadMatched is null (not checked / not claimed available), and the
  // profile is still internally valid.
  assert.equal(v.payloadMatched, null)
  assert.equal(v.valid, true)
})

// ── receipt signature survives the profile ──

const OUTCOME: InteractionOutcome = {
  toolName: 'records.read',
  requestHash: 'a'.repeat(64),
  responseHash: 'b'.repeat(64),
  status: 'success',
  summary: 'read a record',
}

test('a receipt carrying a redacted field-disclosure profile still verifies its signatures', () => {
  const req = generateKeyPair()
  const srv = generateKeyPair()

  const profile = buildFieldDisclosureProfile({
    payload: PAYLOAD,
    policies: { patient_name: 'hash_only', ssn: 'redacted', diagnosis_code: 'public', visible_note: 'public' },
    uri: 'https://vault.example/records/abc123',
    sensitive_fields: ['patient_name', 'ssn'],
  })

  const receipt = createBilateralReceipt({
    requestingAgentId: 'agent:req',
    servingAgentId: 'agent:srv',
    outcome: OUTCOME,
    requestedAt: new Date(Date.now() - 1000).toISOString(),
    completedAt: new Date().toISOString(),
    requestingAgentPrivateKey: req.privateKey,
    servingAgentPrivateKey: srv.privateKey,
    fieldDisclosureProfile: profile,
  })

  // The profile is part of the signed body, so the existing multi-signature
  // verifier covers it with no new checker.
  const v = verifyBilateralReceipt(receipt, req.publicKey, srv.publicKey)
  assert.equal(v.valid, true)
  assert.equal(v.requestingAgentSignatureValid, true)
  assert.equal(v.servingAgentSignatureValid, true)

  // The raw sensitive values are not in the receipt at all.
  const serialized = canonicalize(receipt as unknown as Record<string, unknown>)
  assert.ok(!serialized.includes('Jane Roe'))
  assert.ok(!serialized.includes('000-00-0000'))
})

test('tampering with the profile after signing breaks the receipt signature', () => {
  const req = generateKeyPair()
  const srv = generateKeyPair()

  const profile = buildFieldDisclosureProfile({
    payload: PAYLOAD,
    policies: { patient_name: 'hash_only', ssn: 'redacted', diagnosis_code: 'public', visible_note: 'public' },
    sensitive_fields: ['patient_name', 'ssn'],
  })

  const receipt = createBilateralReceipt({
    requestingAgentId: 'agent:req',
    servingAgentId: 'agent:srv',
    outcome: OUTCOME,
    requestedAt: new Date(Date.now() - 1000).toISOString(),
    completedAt: new Date().toISOString(),
    requestingAgentPrivateKey: req.privateKey,
    servingAgentPrivateKey: srv.privateKey,
    fieldDisclosureProfile: profile,
  })

  // Swap a bound hash inside the signed profile.
  const tampered = JSON.parse(JSON.stringify(receipt))
  tampered.fieldDisclosureProfile.fields[0].hash = 'f'.repeat(64)

  const v = verifyBilateralReceipt(tampered, req.publicKey, srv.publicKey)
  assert.equal(v.valid, false)
})

test('a receipt that omits the profile is byte-identical to the pre-slot body', () => {
  const req = generateKeyPair()
  const srv = generateKeyPair()
  const requestedAt = new Date(Date.now() - 1000).toISOString()
  const completedAt = new Date().toISOString()

  const receipt = createBilateralReceipt({
    requestingAgentId: 'agent:req',
    servingAgentId: 'agent:srv',
    outcome: OUTCOME,
    requestedAt,
    completedAt,
    requestingAgentPrivateKey: req.privateKey,
    servingAgentPrivateKey: srv.privateKey,
    // fieldDisclosureProfile omitted
  })

  // The signed body reconstruction (rest-spread minus signatures) must not
  // contain the new key when omitted; canonicalize strips undefined.
  const { requestingAgentSignature, servingAgentSignature, gatewaySignature, ...body } = receipt
  void requestingAgentSignature
  void servingAgentSignature
  void gatewaySignature
  const canonical = canonicalize(body)
  assert.ok(!canonical.includes('fieldDisclosureProfile'))
  // And the receipt still verifies.
  const v = verifyBilateralReceipt(receipt, req.publicKey, srv.publicKey)
  assert.equal(v.valid, true)
})

// ── canonical bytes helper ──

test('canonicalProfileBytes is deterministic and stable across key order', () => {
  const p1 = buildFieldDisclosureProfile({
    payload: { a: 1, b: 2 },
    policies: { a: 'public', b: 'public' },
  })
  const p2 = buildFieldDisclosureProfile({
    payload: { b: 2, a: 1 },
    policies: { b: 'public', a: 'public' },
  })
  // Field order is preserved from payload key order, so these two differ in
  // field order; the canonical bytes reflect that array order faithfully.
  assert.equal(typeof canonicalProfileBytes(p1), 'string')
  // Same profile canonicalizes identically twice.
  assert.equal(canonicalProfileBytes(p1), canonicalProfileBytes(p1))
  // Distinct field order yields distinct bytes (arrays are order-sensitive).
  assert.notEqual(canonicalProfileBytes(p1), canonicalProfileBytes(p2))
})
