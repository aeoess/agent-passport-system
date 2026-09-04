// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// The creator does not mint an attestation its own verifier rejects.
// ══════════════════════════════════════════════════════════════════
// verifyExecutionAttestation reads the two execution timestamps as instants.
// The creator copied whatever it was handed into the signed body, so a
// spelling the verifier cannot read produced a signed, immutable, permanently
// unverifiable attestation, and the attestor found out only when a relying
// party rejected it. Zone-less values are the ordinary way this happened:
// Python's datetime.isoformat() emits one, and a local time names no instant.
//
// The creator refuses them now. It does not rewrite them: no normalization
// convention governs this artifact, and rewriting a caller's value into bytes
// the attestor signs would put an instant in the record the attestor never
// wrote.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import {
  createExecutionAttestation, verifyExecutionAttestation,
} from '../src/core/execution-attestation.js'
import type { CreateExecutionAttestationInput } from '../src/types/execution-attestation.js'

const attestor = generateKeyPair()

function input(startedAt: string, completedAt: string): CreateExecutionAttestationInput {
  return {
    agentId: 'agent-1',
    attestorId: 'attestor-1',
    attestorType: 'gateway',
    toolName: 'search',
    actualParameters: { q: 'x' },
    actualResult: { ok: true },
    intentParameters: { q: 'x' },
    policyReceiptId: 'prec_1',
    executionFrameId: 'frame_1',
    executionStartedAt: startedAt,
    executionCompletedAt: completedAt,
  } as CreateExecutionAttestationInput
}

/** Spellings the verifier reads as instants. Every one must round-trip. */
const ACCEPTED: Array<[string, string, string]> = [
  ['UTC with milliseconds', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:01.000Z'],
  ['UTC without fraction', '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z'],
  ['zero offset written out', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:01+00:00'],
  ['a non-zero offset', '2026-01-01T09:00:00+09:00', '2026-01-01T09:00:01+09:00'],
  ['lowercase t and z', '2026-01-01t00:00:00z', '2026-01-01t00:00:01z'],
  ['nine fractional digits', '2026-01-01T00:00:00.123456789Z', '2026-01-01T00:00:01.000000000Z'],
  ['started and completed at one instant', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z'],
]

/** Spellings the verifier cannot read. The creator must refuse them. */
const REFUSED: Array<[string, string]> = [
  ['zone-less, as Python datetime.isoformat() emits', '2026-01-01T00:00:00'],
  ['offset without a colon', '2026-01-01T00:00:00+0000'],
  ['space instead of T', '2026-01-01 00:00:00Z'],
  ['date only', '2026-01-01'],
  ['not a date at all', 'not-a-date'],
  ['empty', ''],
  ['a day that does not exist in its month', '2026-02-30T00:00:00Z'],
  ['the hour-24 end-of-day spelling', '2026-01-01T24:00:00Z'],
]

describe('every attestation the creator returns verifies', () => {
  for (const [label, startedAt, completedAt] of ACCEPTED) {
    it(`round-trips ${label}`, () => {
      const attestation = createExecutionAttestation(input(startedAt, completedAt), attestor.privateKey)
      const result = verifyExecutionAttestation(attestation, attestor.publicKey)
      assert.equal(result.valid, true, result.errors.join('; '))
      assert.equal(result.timingValid, true)
      assert.equal(result.signatureValid, true)
    })
  }

  it('the timestamps reach the signed body exactly as supplied', () => {
    // No rewriting: what the attestor signs is what the caller wrote.
    const attestation = createExecutionAttestation(
      input('2026-01-01T09:00:00+09:00', '2026-01-01T09:00:01+09:00'), attestor.privateKey)
    assert.equal(attestation.executionStartedAt, '2026-01-01T09:00:00+09:00')
    assert.equal(attestation.executionCompletedAt, '2026-01-01T09:00:01+09:00')
  })
})

describe('the creator refuses what the verifier could not read', () => {
  for (const [label, bad] of REFUSED) {
    it(`refuses ${label} as executionStartedAt`, () => {
      assert.throws(
        () => createExecutionAttestation(input(bad, '2026-01-01T00:00:01.000Z'), attestor.privateKey),
        /executionStartedAt must be an RFC 3339 instant/)
    })

    it(`refuses ${label} as executionCompletedAt`, () => {
      assert.throws(
        () => createExecutionAttestation(input('2026-01-01T00:00:00.000Z', bad), attestor.privateKey),
        /executionCompletedAt must be an RFC 3339 instant/)
    })
  }

  it('refuses completion before start, which the verifier would refuse on ordering', () => {
    // Same rule as the spellings above: the creator does not mint what its own
    // verifier will not accept. An execution cannot complete before it starts.
    assert.throws(
      () => createExecutionAttestation(
        input('2026-01-01T00:00:01.000Z', '2026-01-01T00:00:00.000Z'), attestor.privateKey),
      /executionCompletedAt is before executionStartedAt/)

    // One millisecond is enough to be wrong.
    assert.throws(
      () => createExecutionAttestation(
        input('2026-01-01T00:00:00.001Z', '2026-01-01T00:00:00.000Z'), attestor.privateKey),
      /executionCompletedAt is before executionStartedAt/)

    // Across offsets, where the text order and the temporal order differ:
    // 09:00+09:00 is 00:00Z, so this completion is an hour before its start.
    assert.throws(
      () => createExecutionAttestation(
        input('2026-01-01T01:00:00.000Z', '2026-01-01T09:00:00.000+09:00'), attestor.privateKey),
      /executionCompletedAt is before executionStartedAt/)
  })

  it('allows completion at the same instant as start, as the verifier does', () => {
    // The verifier's rule is `end >= start`; the creator's must not be tighter,
    // or a zero-duration execution becomes unrecordable.
    const same = createExecutionAttestation(
      input('2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z'), attestor.privateKey)
    assert.equal(verifyExecutionAttestation(same, attestor.publicKey).valid, true)

    // And the same instant written two ways is still the same instant.
    const spelled = createExecutionAttestation(
      input('2026-01-01T00:00:00.000Z', '2026-01-01T09:00:00.000+09:00'), attestor.privateKey)
    assert.equal(verifyExecutionAttestation(spelled, attestor.publicKey).valid, true)
  })

  it('refuses before signing, so no unverifiable attestation exists to hand out', () => {
    let returned: unknown = 'nothing was returned'
    try {
      returned = createExecutionAttestation(
        input('2026-01-01T00:00:00', '2026-01-01T00:00:01'), attestor.privateKey)
    } catch {
      // expected
    }
    assert.equal(returned, 'nothing was returned')
  })
})
