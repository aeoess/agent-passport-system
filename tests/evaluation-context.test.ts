// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Tests for EvaluationContext + BehavioralAttestationResult (Issue #9)

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createEvaluationContext,
  createBehavioralAttestationResult,
  validateAttestationResult,
} from '../src/index.js'
import type { EvaluationContext, BehavioralAttestationResult } from '../src/index.js'

const sampleContext: EvaluationContext = {
  substrate: 'claude-opus-4-20250514',
  responseFormatSchema: 'relational-fidelity-v0.1.0',
  normalizationMethod: 'z-score-cross-substrate',
  evaluationProtocolVersion: 'sha256:abc123def456',
  sampleSize: 50,
  evaluatedAt: '2026-04-06T12:00:00Z',
}

describe('EvaluationContext', () => {
  it('creates context and hash is deterministic', () => {
    const r1 = createEvaluationContext(sampleContext)
    const r2 = createEvaluationContext(sampleContext)
    assert.deepStrictEqual(r1.context, r2.context)
    assert.equal(r1.hash, r2.hash)
    assert.ok(r1.hash.length === 64, 'hash should be 64 hex chars (sha256)')
  })

  it('different context produces different hash', () => {
    const r1 = createEvaluationContext(sampleContext)
    const r2 = createEvaluationContext({ ...sampleContext, sampleSize: 100 })
    assert.notEqual(r1.hash, r2.hash)
  })
})

describe('BehavioralAttestationResult', () => {
  it('auto-computes aggregateScore from weighted dimensions', () => {
    const result = createBehavioralAttestationResult({
      context: sampleContext,
      dimensionScores: {
        coherence: { score: 0.8, weight: 0.5 },
        accuracy: { score: 0.6, weight: 0.5 },
      },
      classification: 'hold',
      confidence: 0.9,
      formatArtifactCorrected: false,
    })
    // (0.8*0.5 + 0.6*0.5) / 1.0 = 0.7
    assert.equal(result.aggregateScore, 0.7)
  })

  it('auto-computes evaluationContextHash from canonical context', () => {
    const { hash } = createEvaluationContext(sampleContext)
    const result = createBehavioralAttestationResult({
      context: sampleContext,
      dimensionScores: {
        coherence: { score: 0.8, weight: 1.0 },
      },
      classification: 'hold',
      confidence: 0.95,
      formatArtifactCorrected: false,
    })
    assert.equal(result.evaluationContextHash, hash)
  })

  it('detects dimensional inversion when dimensions disagree', () => {
    const result = createBehavioralAttestationResult({
      context: sampleContext,
      dimensionScores: {
        coherence: { score: 0.9, weight: 0.5 },
        accuracy: { score: 0.3, weight: 0.5 },
      },
      classification: 'bend',
      confidence: 0.7,
      formatArtifactCorrected: false,
    })
    // aggregate = 0.6, coherence is 0.3 above, accuracy is 0.3 below
    assert.equal(result.dimensionalInversionDetected, true)
  })

  it('no inversion when dimensions agree', () => {
    const result = createBehavioralAttestationResult({
      context: sampleContext,
      dimensionScores: {
        coherence: { score: 0.75, weight: 0.5 },
        accuracy: { score: 0.85, weight: 0.5 },
      },
      classification: 'hold',
      confidence: 0.9,
      formatArtifactCorrected: false,
    })
    assert.equal(result.dimensionalInversionDetected, false)
  })
})

describe('validateAttestationResult', () => {
  it('validates a correct result', () => {
    const result = createBehavioralAttestationResult({
      context: sampleContext,
      dimensionScores: {
        coherence: { score: 0.8, weight: 0.5 },
        accuracy: { score: 0.6, weight: 0.5 },
      },
      classification: 'hold',
      confidence: 0.9,
      formatArtifactCorrected: false,
    })
    const validation = validateAttestationResult(result)
    assert.equal(validation.valid, true)
    assert.equal(validation.errors.length, 0)
  })

  it('catches mismatched aggregate', () => {
    const result = createBehavioralAttestationResult({
      context: sampleContext,
      dimensionScores: {
        coherence: { score: 0.8, weight: 0.5 },
        accuracy: { score: 0.6, weight: 0.5 },
      },
      classification: 'hold',
      confidence: 0.9,
      formatArtifactCorrected: false,
    })
    // Tamper with aggregate
    const tampered = { ...result, aggregateScore: 0.99 }
    const validation = validateAttestationResult(tampered)
    assert.equal(validation.valid, false)
    assert.ok(validation.errors.some(e => e.includes('aggregateScore')))
  })

  it('catches self-declared inversion that contradicts dimensions', () => {
    const result = createBehavioralAttestationResult({
      context: sampleContext,
      dimensionScores: {
        coherence: { score: 0.75, weight: 0.5 },
        accuracy: { score: 0.85, weight: 0.5 },
      },
      classification: 'hold',
      confidence: 0.9,
      formatArtifactCorrected: false,
    })
    // dimensions agree (no inversion), but tamper to say inversion detected
    const tampered = { ...result, dimensionalInversionDetected: true }
    const validation = validateAttestationResult(tampered)
    assert.equal(validation.valid, false)
    assert.ok(validation.errors.some(e => e.includes('dimensionalInversionDetected')))
  })

  it('catches confidence out of range', () => {
    const result = createBehavioralAttestationResult({
      context: sampleContext,
      dimensionScores: {
        coherence: { score: 0.8, weight: 1.0 },
      },
      classification: 'hold',
      confidence: 0.9,
      formatArtifactCorrected: false,
    })
    const tampered = { ...result, confidence: 1.5 }
    const validation = validateAttestationResult(tampered)
    assert.equal(validation.valid, false)
    assert.ok(validation.errors.some(e => e.includes('confidence')))
  })

  it('catches weights not summing to ~1.0', () => {
    const result = createBehavioralAttestationResult({
      context: sampleContext,
      dimensionScores: {
        coherence: { score: 0.8, weight: 0.5 },
        accuracy: { score: 0.6, weight: 0.5 },
      },
      classification: 'hold',
      confidence: 0.9,
      formatArtifactCorrected: false,
    })
    // Tamper weights
    const tampered: BehavioralAttestationResult = {
      ...result,
      dimensionScores: {
        coherence: { score: 0.8, weight: 0.3 },
        accuracy: { score: 0.6, weight: 0.3 },
      },
    }
    const validation = validateAttestationResult(tampered)
    assert.equal(validation.valid, false)
    assert.ok(validation.errors.some(e => e.includes('weights')))
  })

  it('round-trip: create -> serialize -> deserialize -> validate -> pass', () => {
    const result = createBehavioralAttestationResult({
      context: sampleContext,
      dimensionScores: {
        coherence: { score: 0.8, weight: 0.4 },
        accuracy: { score: 0.7, weight: 0.3 },
        faithfulness: { score: 0.9, weight: 0.3 },
      },
      classification: 'hold',
      confidence: 0.85,
      formatArtifactCorrected: true,
    })
    const serialized = JSON.stringify(result)
    const deserialized: BehavioralAttestationResult = JSON.parse(serialized)
    const validation = validateAttestationResult(deserialized)
    assert.equal(validation.valid, true)
    assert.equal(validation.errors.length, 0)
  })
})
