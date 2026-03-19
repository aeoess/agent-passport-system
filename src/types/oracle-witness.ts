// ══════════════════════════════════════════════════════════════════
// Oracle Witness Diversity — Types
// ══════════════════════════════════════════════════════════════════
// Gap 4 (Oracle Problem): When agents rely on external data sources
// (LLMs, APIs, sensors), protocol correctness depends on oracle
// correctness. Witness diversity ensures no single oracle controls
// the outcome. Multiple independent witnesses must attest to the
// same observation before it becomes protocol-admissible evidence.
// ══════════════════════════════════════════════════════════════════

/** An individual witness attestation — one oracle's signed claim about an observation */
export interface WitnessAttestation {
  witnessId: string
  /** Ed25519 public key of the attesting oracle */
  publicKey: string
  /** What provider/platform runs this oracle (e.g., "anthropic", "openai", "google") */
  provider: string
  /** Model family (e.g., "claude", "gpt", "gemini") */
  modelFamily: string
  /** The observation being attested to */
  observation: string
  /** Confidence score 0-1 */
  confidence: number
  /** Ed25519 signature over canonical(witnessId + observation + confidence + timestamp) */
  signature: string
  timestamp: string
}

/** A pool of witnesses for a specific observation context */
export interface WitnessPool {
  poolId: string
  /** The question or observation context */
  context: string
  /** Required minimum number of attestations */
  quorum: number
  /** Required minimum diversity score (0-1) */
  minDiversityScore: number
  /** Collected attestations */
  attestations: WitnessAttestation[]
  createdAt: string
  closedAt?: string
  status: 'collecting' | 'quorum_met' | 'consensus_reached' | 'failed'
}

/** Diversity score breakdown */
export interface DiversityScore {
  /** Overall diversity 0-1 */
  overall: number
  /** Number of distinct providers */
  providerCount: number
  /** Number of distinct model families */
  modelFamilyCount: number
  /** Number of distinct witness identities */
  witnessCount: number
  /** Provider entropy (Shannon entropy over provider distribution) */
  providerEntropy: number
  /** Whether a single provider has >50% of attestations */
  singleProviderDominant: boolean
}

/** Result of evaluating consensus across attestations in a pool */
export interface WitnessConsensusResult {
  /** Whether consensus was reached */
  reached: boolean
  /** The consensus observation (majority answer), or null if no consensus */
  consensusObservation: string | null
  /** How many attestations agree with the consensus observation */
  agreementCount: number
  /** Total attestations evaluated */
  totalCount: number
  /** Agreement ratio (agreementCount / totalCount) */
  agreementRatio: number
  /** Weighted confidence of agreeing attestations */
  weightedConfidence: number
  /** Diversity score of the agreeing witnesses */
  diversityScore: DiversityScore
  /** Reason if consensus was not reached */
  failureReason?: 'below_quorum' | 'no_majority' | 'low_diversity' | 'low_confidence'
}

/** Configuration for creating a witness pool */
export interface WitnessPoolConfig {
  context: string
  quorum?: number           // default: 3
  minDiversityScore?: number // default: 0.5
  /** Minimum agreement ratio for consensus (default: 0.66) */
  minAgreementRatio?: number
  /** Minimum weighted confidence for consensus (default: 0.6) */
  minWeightedConfidence?: number
}
