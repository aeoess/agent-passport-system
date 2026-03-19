// Oracle Witness Diversity — Module 28 (Gap 4)
// Ensures no single oracle controls protocol-critical observations.
// Multiple independent witnesses attest; consensus requires both
// quorum AND diversity. Shannon entropy over provider distribution
// prevents Sybil-style oracle manipulation.
//
// Strengthens INV-1 (Attenuation): oracle attestations are scoped
// evidence — they can only narrow what the protocol accepts, never
// widen it beyond what the delegation chain permits.

import { randomUUID } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type {
  WitnessAttestation, WitnessPool, WitnessPoolConfig,
  DiversityScore, WitnessConsensusResult,
} from '../types/oracle-witness.js'

// ══════════════════════════════════════
// CREATE POOL
// ══════════════════════════════════════

export function createWitnessPool(config: WitnessPoolConfig): WitnessPool {
  return {
    poolId: `wp_${randomUUID().slice(0, 8)}`,
    context: config.context,
    quorum: config.quorum ?? 3,
    minDiversityScore: config.minDiversityScore ?? 0.5,
    attestations: [],
    createdAt: new Date().toISOString(),
    status: 'collecting',
  }
}

// ══════════════════════════════════════
// CREATE & VERIFY ATTESTATION
// ══════════════════════════════════════

export function createAttestation(params: {
  witnessId: string
  publicKey: string
  privateKey: string
  provider: string
  modelFamily: string
  observation: string
  confidence: number
}): WitnessAttestation {
  if (params.confidence < 0 || params.confidence > 1) {
    throw new Error('Confidence must be between 0 and 1')
  }
  const timestamp = new Date().toISOString()
  const payload = canonicalize({
    witnessId: params.witnessId,
    observation: params.observation,
    confidence: params.confidence,
    timestamp,
  })
  const signature = sign(payload, params.privateKey)
  return {
    witnessId: params.witnessId,
    publicKey: params.publicKey,
    provider: params.provider,
    modelFamily: params.modelFamily,
    observation: params.observation,
    confidence: params.confidence,
    signature,
    timestamp,
  }
}

export function verifyWitnessAttestation(att: WitnessAttestation): boolean {
  const payload = canonicalize({
    witnessId: att.witnessId,
    observation: att.observation,
    confidence: att.confidence,
    timestamp: att.timestamp,
  })
  return verify(payload, att.signature, att.publicKey)
}

// ══════════════════════════════════════
// ADD ATTESTATION TO POOL
// ══════════════════════════════════════

export function addAttestation(pool: WitnessPool, att: WitnessAttestation): WitnessPool {
  if (pool.status === 'consensus_reached' || pool.status === 'failed') {
    throw new Error(`Pool is ${pool.status} — cannot add attestations`)
  }
  if (!verifyWitnessAttestation(att)) {
    throw new Error(`Attestation signature invalid for witness ${att.witnessId}`)
  }
  // Reject duplicate witness
  if (pool.attestations.some(a => a.witnessId === att.witnessId)) {
    throw new Error(`Witness ${att.witnessId} already attested`)
  }
  const updated = {
    ...pool,
    attestations: [...pool.attestations, att],
  }
  if (updated.attestations.length >= pool.quorum) {
    updated.status = 'quorum_met'
  }
  return updated
}

// ══════════════════════════════════════
// DIVERSITY SCORING
// ══════════════════════════════════════

/** Shannon entropy: H = -Σ p_i * log2(p_i). Normalized to [0,1]. */
function shannonEntropy(counts: number[]): number {
  const total = counts.reduce((s, c) => s + c, 0)
  if (total === 0) return 0
  const maxEntropy = Math.log2(counts.length)
  if (maxEntropy === 0) return 0
  let entropy = 0
  for (const c of counts) {
    if (c === 0) continue
    const p = c / total
    entropy -= p * Math.log2(p)
  }
  return entropy / maxEntropy  // normalize to [0,1]
}

function countBy<T>(items: T[], key: (item: T) => string): Map<string, number> {
  const map = new Map<string, number>()
  for (const item of items) {
    const k = key(item)
    map.set(k, (map.get(k) ?? 0) + 1)
  }
  return map
}

export function computeDiversityScore(attestations: WitnessAttestation[]): DiversityScore {
  if (attestations.length === 0) {
    return {
      overall: 0, providerCount: 0, modelFamilyCount: 0,
      witnessCount: 0, providerEntropy: 0, singleProviderDominant: false,
    }
  }

  const providerCounts = countBy(attestations, a => a.provider)
  const familyCounts = countBy(attestations, a => a.modelFamily)
  const witnessCounts = countBy(attestations, a => a.witnessId)

  const providerEntropy = shannonEntropy([...providerCounts.values()])
  const familyEntropy = shannonEntropy([...familyCounts.values()])

  const maxProviderCount = Math.max(...providerCounts.values())
  const singleProviderDominant = maxProviderCount > attestations.length / 2

  // Overall = weighted average: provider entropy 50%, family entropy 30%,
  // witness count factor 20% (capped at 1.0 for 5+ unique witnesses)
  const witnessCountFactor = Math.min(witnessCounts.size / 5, 1.0)
  const overall = providerEntropy * 0.5 + familyEntropy * 0.3 + witnessCountFactor * 0.2

  return {
    overall,
    providerCount: providerCounts.size,
    modelFamilyCount: familyCounts.size,
    witnessCount: witnessCounts.size,
    providerEntropy,
    singleProviderDominant,
  }
}

// ══════════════════════════════════════
// CONSENSUS EVALUATION
// ══════════════════════════════════════

export function evaluateWitnessConsensus(pool: WitnessPool, config?: {
  minAgreementRatio?: number
  minWeightedConfidence?: number
}): WitnessConsensusResult {
  const minAgreement = config?.minAgreementRatio ?? 0.66
  const minConfidence = config?.minWeightedConfidence ?? 0.6

  if (pool.attestations.length < pool.quorum) {
    return {
      reached: false, consensusObservation: null,
      agreementCount: 0, totalCount: pool.attestations.length,
      agreementRatio: 0, weightedConfidence: 0,
      diversityScore: computeDiversityScore(pool.attestations),
      failureReason: 'below_quorum',
    }
  }

  // Group by observation
  const groups = countBy(pool.attestations, a => a.observation)
  let bestObs = ''
  let bestCount = 0
  for (const [obs, count] of groups) {
    if (count > bestCount) { bestObs = obs; bestCount = count }
  }

  const ratio = bestCount / pool.attestations.length
  const agreeing = pool.attestations.filter(a => a.observation === bestObs)
  const weightedConfidence = agreeing.length > 0
    ? agreeing.reduce((s, a) => s + a.confidence, 0) / agreeing.length
    : 0

  const diversityScore = computeDiversityScore(agreeing)

  // Check failure conditions
  if (ratio < minAgreement) {
    return {
      reached: false, consensusObservation: bestObs,
      agreementCount: bestCount, totalCount: pool.attestations.length,
      agreementRatio: ratio, weightedConfidence, diversityScore,
      failureReason: 'no_majority',
    }
  }
  if (diversityScore.overall < pool.minDiversityScore) {
    return {
      reached: false, consensusObservation: bestObs,
      agreementCount: bestCount, totalCount: pool.attestations.length,
      agreementRatio: ratio, weightedConfidence, diversityScore,
      failureReason: 'low_diversity',
    }
  }
  if (weightedConfidence < minConfidence) {
    return {
      reached: false, consensusObservation: bestObs,
      agreementCount: bestCount, totalCount: pool.attestations.length,
      agreementRatio: ratio, weightedConfidence, diversityScore,
      failureReason: 'low_confidence',
    }
  }

  // Consensus reached
  return {
    reached: true, consensusObservation: bestObs,
    agreementCount: bestCount, totalCount: pool.attestations.length,
    agreementRatio: ratio, weightedConfidence, diversityScore,
  }
}

// ══════════════════════════════════════
// DIVERSITY HELPER
// ══════════════════════════════════════

/**
 * Check if adding a hypothetical witness would increase the pool's diversity.
 * Used by routing/scheduling to decide which oracle to query next.
 */
export function wouldIncreaseDiversity(
  pool: WitnessPool,
  candidateProvider: string,
  candidateModelFamily: string,
): boolean {
  const current = computeDiversityScore(pool.attestations)
  // Simulate adding a new attestation with this provider/family
  const simulated: WitnessAttestation[] = [
    ...pool.attestations,
    {
      witnessId: '__simulated__', publicKey: '', provider: candidateProvider,
      modelFamily: candidateModelFamily, observation: '', confidence: 0,
      signature: '', timestamp: '',
    },
  ]
  const after = computeDiversityScore(simulated)
  return after.overall > current.overall
}
