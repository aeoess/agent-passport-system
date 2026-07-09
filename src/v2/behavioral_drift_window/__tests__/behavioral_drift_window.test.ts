// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// behavioral_drift_window signal_type (v0.1): tests
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

import { generateKeyPair } from '../../../crypto/keys.js'

import {
  signBehavioralDriftWindow,
  verifyBehavioralDriftWindow,
  isBehavioralDriftWindow,
} from '../index.js'

import type {
  BehavioralDriftWindowEnvelope,
  UnsignedBehavioralDriftWindowEnvelope,
} from '../types.js'

function sha256Hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

const WINDOW_START = '2026-05-25T00:00:00Z'
const WINDOW_END = '2026-05-26T00:00:00Z'

function makeUnsigned(overrides: Partial<UnsignedBehavioralDriftWindowEnvelope> & {
  subject_agent_id: string
  observer_id: string
}): UnsignedBehavioralDriftWindowEnvelope {
  return {
    signal_type: 'behavioral_drift_window',
    window_start: WINDOW_START,
    window_end: WINDOW_END,
    constituent_attestations: [],
    metrics: {
      decision_count: 0,
      class_distribution: { precondition_set: 0, candidate_set: 0, decision_path: 0 },
    },
    ...overrides,
  }
}

// ── 1. Self-attestation round-trip ─────────────────────────────

describe('behavioral_drift_window: self-attestation round-trip', () => {
  it('observer_id === subject_agent_id, single constituent, class_distribution sums match', () => {
    const kp = generateKeyPair()
    const constituentHash = sha256Hex('cognitive.attestation.envelope.1')
    const unsigned = makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
      constituent_attestations: [constituentHash],
      metrics: {
        decision_count: 1,
        class_distribution: { precondition_set: 0, candidate_set: 0, decision_path: 1 },
        confidence_mean: 0.87,
        confidence_stddev: 0.0,
      },
    })
    const signed = signBehavioralDriftWindow(kp.privateKey, unsigned)
    assert.equal(signed.signal_type, 'behavioral_drift_window')
    assert.equal(signed.observer_id, kp.publicKey)
    assert.equal(signed.subject_agent_id, kp.publicKey)
    assert.equal(signed.signature.length, 128)
    const result = verifyBehavioralDriftWindow(signed)
    assert.equal(result.valid, true, `expected valid, got reason=${result.reason}`)
    assert.equal(isBehavioralDriftWindow(signed), true)
  })
})

// ── 2. Third-party attestation round-trip ─────────────────────

describe('behavioral_drift_window: third-party attestation round-trip', () => {
  it('observer_id !== subject_agent_id, three constituents across all three classes', () => {
    const subject = generateKeyPair()
    const observer = generateKeyPair()
    const c1 = sha256Hex('attestation.precondition.1')
    const c2 = sha256Hex('attestation.candidate.1')
    const c3 = sha256Hex('attestation.decision.1')
    const unsigned = makeUnsigned({
      subject_agent_id: subject.publicKey,
      observer_id: observer.publicKey,
      constituent_attestations: [c1, c2, c3],
      metrics: {
        decision_count: 3,
        class_distribution: { precondition_set: 1, candidate_set: 1, decision_path: 1 },
      },
    })
    const signed = signBehavioralDriftWindow(observer.privateKey, unsigned)
    assert.equal(signed.observer_id, observer.publicKey)
    assert.notEqual(signed.observer_id, signed.subject_agent_id)
    const result = verifyBehavioralDriftWindow(signed)
    assert.equal(result.valid, true, `expected valid, got reason=${result.reason}`)
  })

  it('round-trip with baseline_ref + divergence_score paired', () => {
    const subject = generateKeyPair()
    const observer = generateKeyPair()
    const unsigned = makeUnsigned({
      subject_agent_id: subject.publicKey,
      observer_id: observer.publicKey,
      metrics: {
        decision_count: 0,
        class_distribution: { precondition_set: 0, candidate_set: 0, decision_path: 0 },
        baseline_ref: sha256Hex('baseline.window.q1'),
        divergence_score: 0.42,
      },
    })
    const signed = signBehavioralDriftWindow(observer.privateKey, unsigned)
    const result = verifyBehavioralDriftWindow(signed)
    assert.equal(result.valid, true, `expected valid, got reason=${result.reason}`)
  })
})

// ── 3. Empty window ───────────────────────────────────────────

describe('behavioral_drift_window: empty window', () => {
  it('decision_count=0 with empty constituents and zero class_distribution is valid (records absence)', () => {
    const kp = generateKeyPair()
    const unsigned = makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
    })
    const signed = signBehavioralDriftWindow(kp.privateKey, unsigned)
    const result = verifyBehavioralDriftWindow(signed)
    assert.equal(result.valid, true, `expected valid, got reason=${result.reason}`)
  })
})

// ── 4. Window backwards ───────────────────────────────────────

describe('behavioral_drift_window: window ordering', () => {
  it('window_end < window_start returns WINDOW_INVALID', () => {
    const kp = generateKeyPair()
    const unsigned = makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
      window_start: WINDOW_END,
      window_end: WINDOW_START,
    })
    const signed = signBehavioralDriftWindow(kp.privateKey, unsigned)
    const result = verifyBehavioralDriftWindow(signed)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'WINDOW_INVALID')
  })

  it('window_end === window_start returns WINDOW_INVALID', () => {
    const kp = generateKeyPair()
    const unsigned = makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
      window_start: WINDOW_START,
      window_end: WINDOW_START,
    })
    const signed = signBehavioralDriftWindow(kp.privateKey, unsigned)
    const result = verifyBehavioralDriftWindow(signed)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'WINDOW_INVALID')
  })
})

// ── 5. Metrics drift ──────────────────────────────────────────

describe('behavioral_drift_window: metrics consistency', () => {
  it('decision_count=3 but class_distribution sums to 4 returns METRICS_INCONSISTENT', () => {
    const kp = generateKeyPair()
    const hashes = [sha256Hex('a'), sha256Hex('b'), sha256Hex('c')]
    const unsigned = makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
      constituent_attestations: hashes,
      metrics: {
        decision_count: 3,
        class_distribution: { precondition_set: 2, candidate_set: 1, decision_path: 1 },
      },
    })
    const signed = signBehavioralDriftWindow(kp.privateKey, unsigned)
    const result = verifyBehavioralDriftWindow(signed)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'METRICS_INCONSISTENT')
  })

  it('decision_count !== constituent_attestations.length returns METRICS_INCONSISTENT', () => {
    const kp = generateKeyPair()
    const hashes = [sha256Hex('a'), sha256Hex('b')]
    const unsigned = makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
      constituent_attestations: hashes,
      metrics: {
        decision_count: 3,
        class_distribution: { precondition_set: 1, candidate_set: 1, decision_path: 1 },
      },
    })
    const signed = signBehavioralDriftWindow(kp.privateKey, unsigned)
    const result = verifyBehavioralDriftWindow(signed)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'METRICS_INCONSISTENT')
  })
})

// ── 6. Constituent duplicate ─────────────────────────────────

describe('behavioral_drift_window: constituent uniqueness', () => {
  it('two identical hashes in constituent_attestations returns CONSTITUENT_HASH_DUPLICATE', () => {
    const kp = generateKeyPair()
    const dup = sha256Hex('attestation.duplicate')
    const unsigned = makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
      constituent_attestations: [dup, dup],
      metrics: {
        decision_count: 2,
        class_distribution: { precondition_set: 0, candidate_set: 0, decision_path: 2 },
      },
    })
    const signed = signBehavioralDriftWindow(kp.privateKey, unsigned)
    const result = verifyBehavioralDriftWindow(signed)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'CONSTITUENT_HASH_DUPLICATE')
  })
})

// ── 7. Tamper ────────────────────────────────────────────────

describe('behavioral_drift_window: tamper detection', () => {
  it('mutating one byte in a constituent hash post-signing returns SIGNATURE_INVALID', () => {
    const kp = generateKeyPair()
    const c1 = sha256Hex('attestation.original.1')
    const c2 = sha256Hex('attestation.original.2')
    const unsigned = makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
      constituent_attestations: [c1, c2],
      metrics: {
        decision_count: 2,
        class_distribution: { precondition_set: 0, candidate_set: 1, decision_path: 1 },
      },
    })
    const signed = signBehavioralDriftWindow(kp.privateKey, unsigned)
    const mutated = [...signed.constituent_attestations]
    const lastChar = mutated[0].slice(-1)
    const flipped = lastChar === '0' ? '1' : '0'
    mutated[0] = mutated[0].slice(0, -1) + flipped
    const tampered: BehavioralDriftWindowEnvelope = {
      ...signed,
      constituent_attestations: mutated,
    }
    const result = verifyBehavioralDriftWindow(tampered)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'SIGNATURE_INVALID')
  })
})

// ── 8. Wrong-key ─────────────────────────────────────────────

describe('behavioral_drift_window: wrong-key detection', () => {
  it('envelope signed with key A but claiming observer_id of key B returns SIGNATURE_INVALID', () => {
    const subject = generateKeyPair()
    const keyA = generateKeyPair()
    const keyB = generateKeyPair()
    const unsigned = makeUnsigned({
      subject_agent_id: subject.publicKey,
      observer_id: keyA.publicKey,
    })
    const signed = signBehavioralDriftWindow(keyA.privateKey, unsigned)
    // Rewrite observer_id to B's public key without re-signing.
    const lying: BehavioralDriftWindowEnvelope = { ...signed, observer_id: keyB.publicKey }
    const result = verifyBehavioralDriftWindow(lying)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'SIGNATURE_INVALID')
  })

  it('signBehavioralDriftWindow always overwrites observer_id to match the signing key', () => {
    const subject = generateKeyPair()
    const keyA = generateKeyPair()
    const keyB = generateKeyPair()
    // Caller hands in observer_id = B but signs with A. Helper overwrites to A.
    const unsigned = makeUnsigned({
      subject_agent_id: subject.publicKey,
      observer_id: keyB.publicKey,
    })
    const signed = signBehavioralDriftWindow(keyA.privateKey, unsigned)
    assert.equal(signed.observer_id, keyA.publicKey)
    const result = verifyBehavioralDriftWindow(signed)
    assert.equal(result.valid, true)
  })
})

// ── 9. Canonicalization: constituent order matters ──────────

describe('behavioral_drift_window: canonicalization', () => {
  it('reordering constituent hashes changes canonical bytes and invalidates the signature', () => {
    const kp = generateKeyPair()
    const c1 = sha256Hex('attestation.alpha')
    const c2 = sha256Hex('attestation.beta')
    const c3 = sha256Hex('attestation.gamma')
    const unsigned = makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
      constituent_attestations: [c1, c2, c3],
      metrics: {
        decision_count: 3,
        class_distribution: { precondition_set: 1, candidate_set: 1, decision_path: 1 },
      },
    })
    const signed = signBehavioralDriftWindow(kp.privateKey, unsigned)

    // Reorder without re-signing: JCS preserves array order, so the canonical
    // bytes change and the signature should not verify.
    const reordered: BehavioralDriftWindowEnvelope = {
      ...signed,
      constituent_attestations: [c3, c2, c1],
    }
    const result = verifyBehavioralDriftWindow(reordered)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'SIGNATURE_INVALID')
  })
})

// ── 10. Baseline pairing ─────────────────────────────────────

describe('behavioral_drift_window: baseline pairing', () => {
  it('baseline_ref present without divergence_score returns BASELINE_PAIRING_INVALID', () => {
    const kp = generateKeyPair()
    const unsigned = makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
      metrics: {
        decision_count: 0,
        class_distribution: { precondition_set: 0, candidate_set: 0, decision_path: 0 },
        baseline_ref: sha256Hex('baseline.window.lonely'),
      },
    })
    const signed = signBehavioralDriftWindow(kp.privateKey, unsigned)
    const result = verifyBehavioralDriftWindow(signed)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'BASELINE_PAIRING_INVALID')
  })

  it('divergence_score present without baseline_ref returns BASELINE_PAIRING_INVALID', () => {
    const kp = generateKeyPair()
    const unsigned = makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
      metrics: {
        decision_count: 0,
        class_distribution: { precondition_set: 0, candidate_set: 0, decision_path: 0 },
        divergence_score: 0.17,
      },
    })
    const signed = signBehavioralDriftWindow(kp.privateKey, unsigned)
    const result = verifyBehavioralDriftWindow(signed)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'BASELINE_PAIRING_INVALID')
  })
})

// ── 11. Confidence range ─────────────────────────────────────

describe('behavioral_drift_window: confidence range', () => {
  it('confidence_mean = 1.5 returns CONFIDENCE_RANGE_INVALID', () => {
    const kp = generateKeyPair()
    const unsigned = makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
      metrics: {
        decision_count: 0,
        class_distribution: { precondition_set: 0, candidate_set: 0, decision_path: 0 },
        confidence_mean: 1.5,
        confidence_stddev: 0.1,
      },
    })
    const signed = signBehavioralDriftWindow(kp.privateKey, unsigned)
    const result = verifyBehavioralDriftWindow(signed)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'CONFIDENCE_RANGE_INVALID')
  })

  it('confidence_mean present without confidence_stddev returns CONFIDENCE_RANGE_INVALID', () => {
    const kp = generateKeyPair()
    const unsigned = makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
      metrics: {
        decision_count: 0,
        class_distribution: { precondition_set: 0, candidate_set: 0, decision_path: 0 },
        confidence_mean: 0.5,
      },
    })
    const signed = signBehavioralDriftWindow(kp.privateKey, unsigned)
    const result = verifyBehavioralDriftWindow(signed)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'CONFIDENCE_RANGE_INVALID')
  })

  it('confidence_stddev negative returns CONFIDENCE_RANGE_INVALID', () => {
    const kp = generateKeyPair()
    const unsigned = makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
      metrics: {
        decision_count: 0,
        class_distribution: { precondition_set: 0, candidate_set: 0, decision_path: 0 },
        confidence_mean: 0.5,
        confidence_stddev: -0.1,
      },
    })
    const signed = signBehavioralDriftWindow(kp.privateKey, unsigned)
    const result = verifyBehavioralDriftWindow(signed)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'CONFIDENCE_RANGE_INVALID')
  })
})

// ── 12. Shape failures ───────────────────────────────────────

describe('behavioral_drift_window: shape failures', () => {
  it('missing metrics field returns SHAPE_INVALID', () => {
    const kp = generateKeyPair()
    const unsigned = makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
    })
    const signed = signBehavioralDriftWindow(kp.privateKey, unsigned)
    const noMetrics = { ...signed } as Record<string, unknown>
    delete noMetrics.metrics
    const result = verifyBehavioralDriftWindow(noMetrics)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'SHAPE_INVALID')
  })

  it('null envelope returns SHAPE_INVALID', () => {
    assert.deepEqual(verifyBehavioralDriftWindow(null), { valid: false, reason: 'SHAPE_INVALID' })
  })

  it('wrong signal_type returns SHAPE_INVALID', () => {
    const kp = generateKeyPair()
    const signed = signBehavioralDriftWindow(kp.privateKey, makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
    }))
    const result = verifyBehavioralDriftWindow({ ...signed, signal_type: 'cognitive_attestation' })
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'SHAPE_INVALID')
  })

  it('malformed observer_id returns OBSERVER_ID_INVALID_FORMAT', () => {
    const kp = generateKeyPair()
    const signed = signBehavioralDriftWindow(kp.privateKey, makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
    }))
    const result = verifyBehavioralDriftWindow({ ...signed, observer_id: 'XYZ' })
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'OBSERVER_ID_INVALID_FORMAT')
  })

  it('malformed subject_agent_id returns SUBJECT_AGENT_ID_INVALID_FORMAT', () => {
    const kp = generateKeyPair()
    const signed = signBehavioralDriftWindow(kp.privateKey, makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
    }))
    const result = verifyBehavioralDriftWindow({ ...signed, subject_agent_id: 'XYZ' })
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'SUBJECT_AGENT_ID_INVALID_FORMAT')
  })

  it('unparseable ISO 8601 timestamp returns TIMESTAMP_FORMAT_INVALID', () => {
    const kp = generateKeyPair()
    const unsigned = makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
      window_start: 'not-a-date',
    })
    const signed = signBehavioralDriftWindow(kp.privateKey, unsigned)
    const result = verifyBehavioralDriftWindow(signed)
    assert.equal(result.valid, false)
    assert.equal(result.reason, 'TIMESTAMP_FORMAT_INVALID')
  })
})

// ── isBehavioralDriftWindow type guard ────────────────────

describe('behavioral_drift_window: isBehavioralDriftWindow', () => {
  it('accepts a freshly signed envelope', () => {
    const kp = generateKeyPair()
    const signed = signBehavioralDriftWindow(kp.privateKey, makeUnsigned({
      subject_agent_id: kp.publicKey,
      observer_id: kp.publicKey,
    }))
    assert.equal(isBehavioralDriftWindow(signed), true)
  })

  it('rejects non-object inputs and wrong signal_type', () => {
    assert.equal(isBehavioralDriftWindow(null), false)
    assert.equal(isBehavioralDriftWindow('string'), false)
    assert.equal(isBehavioralDriftWindow({}), false)
    assert.equal(isBehavioralDriftWindow({ signal_type: 'cognitive_attestation' }), false)
  })
})
