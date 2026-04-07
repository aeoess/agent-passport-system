// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Behavioral Evaluation Context — Issue #9 (lowkey-divine schema)
// Separates evaluation input conditions from evaluation output results.

import { createHash } from 'crypto'
import { canonicalize } from './canonical.js'
import type { EvaluationContext, BehavioralAttestationResult } from '../types/attestation.js'

function sha256Hex(input: string): string {
  return createHash('sha256').update(input).digest('hex')
}

/** Create and hash an evaluation context */
export function createEvaluationContext(opts: EvaluationContext): {
  context: EvaluationContext
  hash: string
} {
  const context: EvaluationContext = {
    measurementType: opts.measurementType || 'behavioral_fidelity',
    substrate: opts.substrate,
    responseFormatSchema: opts.responseFormatSchema,
    normalizationMethod: opts.normalizationMethod,
    evaluationProtocolVersion: opts.evaluationProtocolVersion,
    sampleSize: opts.sampleSize,
    evaluatedAt: opts.evaluatedAt,
  }
  const hash = sha256Hex(canonicalize(context))
  return { context, hash }
}

/** Create a result that validates internal consistency */
export function createBehavioralAttestationResult(opts: {
  context: EvaluationContext
  dimensionScores: Record<string, { score: number; weight: number }>
  classification: 'hold' | 'bend' | 'break'
  confidence: number
  formatArtifactCorrected: boolean
}): BehavioralAttestationResult {
  const evaluationContextHash = sha256Hex(canonicalize(opts.context))

  // Auto-compute aggregate from weighted dimensions
  let weightedSum = 0
  let totalWeight = 0
  const entries = Object.entries(opts.dimensionScores)

  for (const [, dim] of entries) {
    weightedSum += dim.score * dim.weight
    totalWeight += dim.weight
  }
  const aggregateScore = totalWeight > 0 ? weightedSum / totalWeight : 0

  // Auto-detect dimensional inversion: dimensions disagree in direction
  // (some well above aggregate, some well below) despite aggregate looking normal
  const dimensionalInversionDetected = detectDimensionalInversion(opts.dimensionScores, aggregateScore)

  return {
    evaluationContextHash,
    dimensionScores: opts.dimensionScores,
    aggregateScore: Math.round(aggregateScore * 10000) / 10000,
    classification: opts.classification,
    confidence: opts.confidence,
    formatArtifactCorrected: opts.formatArtifactCorrected,
    dimensionalInversionDetected,
  }
}

/** Detect dimensional inversion: dimensions pulling in opposite directions */
function detectDimensionalInversion(
  scores: Record<string, { score: number; weight: number }>,
  aggregate: number
): boolean {
  const entries = Object.values(scores)
  if (entries.length < 2) return false

  // Inversion = at least one dimension significantly above AND at least one significantly below
  const threshold = 0.2
  let hasHigh = false
  let hasLow = false
  for (const dim of entries) {
    if (dim.score - aggregate > threshold) hasHigh = true
    if (aggregate - dim.score > threshold) hasLow = true
  }
  return hasHigh && hasLow
}

/** Validate internal consistency of a result */
export function validateAttestationResult(result: BehavioralAttestationResult): {
  valid: boolean
  errors: string[]
} {
  const errors: string[] = []

  // Check confidence in [0,1]
  if (result.confidence < 0 || result.confidence > 1) {
    errors.push(`confidence must be in [0,1], got ${result.confidence}`)
  }

  // Check all weights sum to ~1.0
  const entries = Object.values(result.dimensionScores)
  if (entries.length > 0) {
    const totalWeight = entries.reduce((sum, d) => sum + d.weight, 0)
    if (Math.abs(totalWeight - 1.0) > 0.01) {
      errors.push(`dimension weights must sum to ~1.0, got ${totalWeight}`)
    }
  }

  // Check aggregate matches weighted dimension sum
  if (entries.length > 0) {
    let weightedSum = 0
    let totalWeight = 0
    for (const dim of entries) {
      weightedSum += dim.score * dim.weight
      totalWeight += dim.weight
    }
    const expectedAggregate = totalWeight > 0 ? weightedSum / totalWeight : 0
    const rounded = Math.round(expectedAggregate * 10000) / 10000
    if (Math.abs(result.aggregateScore - rounded) > 0.001) {
      errors.push(`aggregateScore ${result.aggregateScore} does not match weighted dimension sum ${rounded}`)
    }
  }

  // Check dimensionalInversionDetected matches actual dimension analysis
  const actualInversion = detectDimensionalInversion(result.dimensionScores, result.aggregateScore)
  if (result.dimensionalInversionDetected !== actualInversion) {
    errors.push(`dimensionalInversionDetected is ${result.dimensionalInversionDetected} but analysis shows ${actualInversion}`)
  }

  return { valid: errors.length === 0, errors }
}
