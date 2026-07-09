// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// cognitive_attestation signal_type (v0.1): tests
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

import { generateKeyPair, publicKeyFromPrivate } from '../../../crypto/keys.js'

import {
  signCognitiveAttestation,
  verifyCognitiveAttestation,
  isCognitiveAttestation,
  canonicalizeForSignature,
} from '../index.js'

import type {
  CandidateSetPayload,
  CognitiveAttestationEnvelope,
  DecisionPathPayload,
  PreconditionSetPayload,
  UnsignedCandidateSetEnvelope,
  UnsignedCognitiveAttestationEnvelope,
  UnsignedDecisionPathEnvelope,
  UnsignedPreconditionSetEnvelope,
} from '../types.js'

function sha256Hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

const FIXED_TIMESTAMP_MS = 1748275200000 // 2026-05-26T16:00:00Z

const PRECONDITION_PAYLOAD: PreconditionSetPayload = (() => {
  const sorted = ['policy.4.2', 'scope.commerce.purchase', 'tool.email_send']
  return {
    available_preconditions: sorted,
    precondition_hashes: sorted.map(sha256Hex),
  }
})()

const CANDIDATE_PAYLOAD: CandidateSetPayload = {
  evaluated_candidates: [
    { candidate_ref: sha256Hex('action.transfer'), eliminated: true, elimination_reason: 'violates policy 4.2' },
    { candidate_ref: sha256Hex('action.deny'), eliminated: false },
    { candidate_ref: sha256Hex('action.escalate'), eliminated: true, elimination_reason: 'no human available in scope' },
  ],
}

const DECISION_PATH_PAYLOAD: DecisionPathPayload = {
  chosen_path_ref: sha256Hex('chosen.deny'),
  confidence: 0.91,
  reasoning_chain_hashes: [
    sha256Hex('step.1.precondition-check'),
    sha256Hex('step.2.candidate-eval'),
    sha256Hex('step.3.policy-match'),
  ],
}

type UnsignedFor<T extends 'precondition_set' | 'candidate_set' | 'decision_path'> =
  T extends 'precondition_set' ? UnsignedPreconditionSetEnvelope :
  T extends 'candidate_set' ? UnsignedCandidateSetEnvelope :
  UnsignedDecisionPathEnvelope

function makeUnsigned<T extends 'precondition_set' | 'candidate_set' | 'decision_path'>(
  klass: T,
  agent_id: string,
): UnsignedFor<T> {
  const decision_ref = sha256Hex('decision.test.001')
  const base = {
    signal_type: 'cognitive_attestation' as const,
    agent_id,
    decision_ref,
    timestamp_ms: FIXED_TIMESTAMP_MS,
  }
  if (klass === 'precondition_set') {
    return { ...base, class: 'precondition_set' as const, class_payload: PRECONDITION_PAYLOAD } as UnsignedFor<T>
  }
  if (klass === 'candidate_set') {
    return { ...base, class: 'candidate_set' as const, class_payload: CANDIDATE_PAYLOAD } as UnsignedFor<T>
  }
  return { ...base, class: 'decision_path' as const, class_payload: DECISION_PATH_PAYLOAD } as UnsignedFor<T>
}

// ── Round-trip per class ─────────────────────────────────────────

describe('cognitive_attestation: round-trip per class', () => {
  for (const klass of ['precondition_set', 'candidate_set', 'decision_path'] as const) {
    it(`sign + verify round-trips a ${klass} envelope`, () => {
      const kp = generateKeyPair()
      const signed = signCognitiveAttestation(kp.privateKey, makeUnsigned(klass, kp.publicKey))
      assert.equal(signed.signal_type, 'cognitive_attestation')
      assert.equal(signed.class, klass)
      assert.equal(signed.agent_id, kp.publicKey)
      assert.equal(signed.signature.length, 128)
      const result = verifyCognitiveAttestation(signed)
      assert.equal(result.valid, true, `expected valid, got reason=${result.reason}`)
    })
  }
})

// ── Tamper detection ────────────────────────────────────────────

describe('cognitive_attestation: tamper detection', () => {
  it('flipping one byte of class_payload causes verification to fail', () => {
    const kp = generateKeyPair()
    const signed = signCognitiveAttestation(kp.privateKey, makeUnsigned('decision_path', kp.publicKey))
    // Mutate the confidence by a hair: still a valid two-decimal number but a
    // different signed byte sequence.
    const tampered = {
      ...signed,
      class_payload: { ...signed.class_payload, confidence: 0.92 },
    } as CognitiveAttestationEnvelope
    const result = verifyCognitiveAttestation(tampered)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'SIGNATURE_INVALID')
  })

  it('mutating a precondition_set hash causes verification to fail', () => {
    const kp = generateKeyPair()
    const signed = signCognitiveAttestation(kp.privateKey, makeUnsigned('precondition_set', kp.publicKey))
    const mutatedHashes = [...signed.class_payload.precondition_hashes]
    // Flip the last character of the first hash to a different hex digit.
    const first = mutatedHashes[0]
    const lastChar = first.slice(-1)
    const flippedChar = lastChar === '0' ? '1' : '0'
    mutatedHashes[0] = first.slice(0, -1) + flippedChar
    const tampered = {
      ...signed,
      class_payload: { ...signed.class_payload, precondition_hashes: mutatedHashes },
    } as CognitiveAttestationEnvelope
    const result = verifyCognitiveAttestation(tampered)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'SIGNATURE_INVALID')
  })
})

// ── Wrong-key detection ────────────────────────────────────────

describe('cognitive_attestation: wrong-key detection', () => {
  it('envelope signed with key A but claiming agent_id of key B fails', () => {
    const keyA = generateKeyPair()
    const keyB = generateKeyPair()
    // Sign with A but rewrite agent_id to B's public key without re-signing.
    const signedByA = signCognitiveAttestation(keyA.privateKey, makeUnsigned('candidate_set', keyA.publicKey))
    const lyingEnvelope = { ...signedByA, agent_id: keyB.publicKey } as CognitiveAttestationEnvelope
    const result = verifyCognitiveAttestation(lyingEnvelope)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'SIGNATURE_INVALID')
  })

  it('signCognitiveAttestation always overwrites agent_id to match the signing key', () => {
    const keyA = generateKeyPair()
    const keyB = generateKeyPair()
    // Caller hands in agent_id = B but signs with A. Helper overwrites to A.
    const unsigned = makeUnsigned('precondition_set', keyB.publicKey)
    const signed = signCognitiveAttestation(keyA.privateKey, unsigned)
    assert.equal(signed.agent_id, publicKeyFromPrivate(keyA.privateKey))
    const result = verifyCognitiveAttestation(signed)
    assert.equal(result.valid, true)
  })
})

// ── Canonicalization stability ─────────────────────────────────

describe('cognitive_attestation: canonicalization stability', () => {
  it('two envelopes with the same logical content but different field order produce the same signature', () => {
    const kp = generateKeyPair()
    const decision_ref = sha256Hex('decision.test.canon')
    const ordering1 = {
      signal_type: 'cognitive_attestation' as const,
      agent_id: kp.publicKey,
      class: 'decision_path' as const,
      class_payload: DECISION_PATH_PAYLOAD,
      decision_ref,
      timestamp_ms: FIXED_TIMESTAMP_MS,
    }
    const ordering2 = {
      class_payload: DECISION_PATH_PAYLOAD,
      decision_ref,
      timestamp_ms: FIXED_TIMESTAMP_MS,
      class: 'decision_path' as const,
      agent_id: kp.publicKey,
      signal_type: 'cognitive_attestation' as const,
    }
    const signed1 = signCognitiveAttestation(kp.privateKey, ordering1 as UnsignedCognitiveAttestationEnvelope)
    const signed2 = signCognitiveAttestation(kp.privateKey, ordering2 as UnsignedCognitiveAttestationEnvelope)
    assert.equal(signed1.signature, signed2.signature)

    // Canonical bytes equal across orderings, with the signature field emptied.
    const canon1 = canonicalizeForSignature(ordering1 as UnsignedCognitiveAttestationEnvelope)
    const canon2 = canonicalizeForSignature(ordering2 as UnsignedCognitiveAttestationEnvelope)
    assert.equal(canon1, canon2)
  })
})

// ── Class discriminator ────────────────────────────────────────

describe('cognitive_attestation: class discriminator', () => {
  it('isCognitiveAttestation accepts each of the three v0.1 class envelopes', () => {
    const kp = generateKeyPair()
    for (const klass of ['precondition_set', 'candidate_set', 'decision_path'] as const) {
      const signed = signCognitiveAttestation(kp.privateKey, makeUnsigned(klass, kp.publicKey))
      assert.equal(isCognitiveAttestation(signed), true, `failed for ${klass}`)
    }
  })

  it('isCognitiveAttestation rejects envelopes carrying pre_commit_chain (v0.2 deferred)', () => {
    const kp = generateKeyPair()
    const v0_2_attempt = {
      signal_type: 'cognitive_attestation',
      class: 'pre_commit_chain',
      agent_id: kp.publicKey,
      decision_ref: sha256Hex('decision.v0_2'),
      class_payload: {
        // Whatever shape might land in v0.2 is irrelevant; the discriminator
        // rejects the class name itself.
        chained_commitments: [],
      },
      timestamp_ms: FIXED_TIMESTAMP_MS,
      signature: '0'.repeat(128),
    }
    assert.equal(isCognitiveAttestation(v0_2_attempt), false)
  })

  it('isCognitiveAttestation rejects non-object inputs, wrong signal_type, malformed agent_id', () => {
    assert.equal(isCognitiveAttestation(null), false)
    assert.equal(isCognitiveAttestation('string'), false)
    assert.equal(isCognitiveAttestation({}), false)
    assert.equal(isCognitiveAttestation({ signal_type: 'reasoning_integrity' }), false)
    const kp = generateKeyPair()
    const signed = signCognitiveAttestation(kp.privateKey, makeUnsigned('decision_path', kp.publicKey))
    assert.equal(isCognitiveAttestation({ ...signed, agent_id: 'not-hex' }), false)
    assert.equal(isCognitiveAttestation({ ...signed, signature: 'short' }), false)
  })

  it('isCognitiveAttestation rejects a candidate_set entry with eliminated=false carrying a reason', () => {
    const kp = generateKeyPair()
    const signed = signCognitiveAttestation(kp.privateKey, makeUnsigned('candidate_set', kp.publicKey))
    const bad = {
      ...signed,
      class_payload: {
        evaluated_candidates: [
          { candidate_ref: sha256Hex('a'), eliminated: false, elimination_reason: 'should not be present' },
        ],
      },
    }
    assert.equal(isCognitiveAttestation(bad), false)
  })
})

// ── Verifier rejects malformed inputs without throwing ─────────

describe('cognitive_attestation: verifier shape failures', () => {
  it('returns INVALID_SIGNAL_TYPE for a non-object input', () => {
    assert.deepEqual(verifyCognitiveAttestation(null), { valid: false, reason: 'INVALID_SIGNAL_TYPE' })
  })
  it('returns INVALID_CLASS for an unknown class', () => {
    const kp = generateKeyPair()
    const signed = signCognitiveAttestation(kp.privateKey, makeUnsigned('decision_path', kp.publicKey))
    const result = verifyCognitiveAttestation({ ...signed, class: 'pre_commit_chain' })
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'INVALID_CLASS')
  })
  it('returns INVALID_AGENT_ID for a malformed agent_id', () => {
    const kp = generateKeyPair()
    const signed = signCognitiveAttestation(kp.privateKey, makeUnsigned('candidate_set', kp.publicKey))
    const result = verifyCognitiveAttestation({ ...signed, agent_id: 'XYZ' })
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'INVALID_AGENT_ID')
  })
})
