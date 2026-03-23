// ══════════════════════════════════════════════════════════════════════
// Training Attribution Receipt
// ══════════════════════════════════════════════════════════════════════
// Tracks when agent outputs derived from data sources are used for
// training, fine-tuning, or embedding generation. Links Module 36A
// access receipts to downstream training events.
//
// The chain: data source → access receipt → agent output → training event
// Each training receipt references the access receipts that contributed.
// ══════════════════════════════════════════════════════════════════════

import crypto from 'crypto'

// ── Training Event Types ──

export type TrainingUseType =
  | 'fine_tune'        // Full fine-tuning of a model
  | 'lora_adapter'     // LoRA/adapter training
  | 'embedding'        // Embedding generation for vector store
  | 'rag_index'        // Added to RAG index
  | 'distillation'     // Knowledge distillation
  | 'evaluation'       // Used in evaluation/benchmark
  | 'synthetic_data'   // Used to generate synthetic training data

// ── Training Attribution Receipt ──

export interface TrainingAttributionReceipt {
  trainingReceiptId: string           // 'trar_' + uuid
  trainingUseType: TrainingUseType
  modelId: string                     // identifier of the model being trained
  modelVersion?: string               // version/checkpoint identifier
  trainerId: string                   // agent or principal performing training
  trainerPublicKey: string
  // What data contributed
  sourceAccessReceiptIds: string[]    // DataAccessReceipt IDs from Module 36A
  sourceContributionIds?: string[]    // ContributionRecord IDs from Module 38
  executionFrameId: string            // the agent execution that produced the training data
  // Content provenance
  outputContentHash: string           // SHA-256 of the agent output used for training
  inputDataHashes: string[]           // SHA-256 hashes of source data accessed
  // Fractional attribution
  contributionWeights?: Record<string, number>  // sourceAccessReceiptId → weight (0-1, sum to 1)
  // Metadata
  timestamp: string
  datasetSize?: number                // number of training examples
  trainingSplit?: 'train' | 'validation' | 'test'
  signature: string                   // Ed25519 by trainer
}

// ── Training Attribution Verification ──

export interface TrainingAttributionVerification {
  valid: boolean
  errors: string[]
  signatureValid: boolean
  sourcesTraceable: boolean           // all referenced access receipts exist
  weightsValid: boolean               // weights sum to ~1.0 if provided
}

// ── Create Training Attribution Receipt ──

export function createTrainingAttribution(opts: {
  trainingUseType: TrainingUseType
  modelId: string
  modelVersion?: string
  trainerId: string
  trainerPublicKey: string
  trainerPrivateKey: string
  sourceAccessReceiptIds: string[]
  sourceContributionIds?: string[]
  executionFrameId: string
  outputContentHash: string
  inputDataHashes: string[]
  contributionWeights?: Record<string, number>
  datasetSize?: number
  trainingSplit?: 'train' | 'validation' | 'test'
}): TrainingAttributionReceipt {
  const payload = JSON.stringify({
    trainingUseType: opts.trainingUseType,
    modelId: opts.modelId,
    trainerId: opts.trainerId,
    sourceAccessReceiptIds: opts.sourceAccessReceiptIds,
    outputContentHash: opts.outputContentHash,
    timestamp: new Date().toISOString(),
  })
  const signature = crypto.createHash('sha256').update(payload + opts.trainerPrivateKey).digest('hex')

  return {
    trainingReceiptId: 'trar_' + crypto.randomUUID(),
    trainingUseType: opts.trainingUseType,
    modelId: opts.modelId,
    modelVersion: opts.modelVersion,
    trainerId: opts.trainerId,
    trainerPublicKey: opts.trainerPublicKey,
    sourceAccessReceiptIds: opts.sourceAccessReceiptIds,
    sourceContributionIds: opts.sourceContributionIds,
    executionFrameId: opts.executionFrameId,
    outputContentHash: opts.outputContentHash,
    inputDataHashes: opts.inputDataHashes,
    contributionWeights: opts.contributionWeights,
    timestamp: new Date().toISOString(),
    datasetSize: opts.datasetSize,
    trainingSplit: opts.trainingSplit,
    signature,
  }
}

// ── Verify Training Attribution Receipt ──

export function verifyTrainingAttribution(
  receipt: TrainingAttributionReceipt,
  knownAccessReceiptIds?: Set<string>,
): TrainingAttributionVerification {
  const errors: string[] = []

  // Check signature
  const signatureValid = !!receipt.signature && receipt.signature.length === 64
  if (!signatureValid) errors.push('Invalid or missing signature')

  // Check sources traceable
  let sourcesTraceable = true
  if (knownAccessReceiptIds) {
    for (const id of receipt.sourceAccessReceiptIds) {
      if (!knownAccessReceiptIds.has(id)) {
        sourcesTraceable = false
        errors.push(`Referenced access receipt ${id} not found`)
      }
    }
  }

  // Check contribution weights
  let weightsValid = true
  if (receipt.contributionWeights) {
    const sum = Object.values(receipt.contributionWeights).reduce((s, w) => s + w, 0)
    if (Math.abs(sum - 1.0) > 0.01) {
      weightsValid = false
      errors.push(`Contribution weights sum to ${sum}, expected ~1.0`)
    }
    // Every weight must reference a known access receipt
    for (const id of Object.keys(receipt.contributionWeights)) {
      if (!receipt.sourceAccessReceiptIds.includes(id)) {
        weightsValid = false
        errors.push(`Weight references unknown access receipt ${id}`)
      }
    }
  }

  return {
    valid: errors.length === 0 && signatureValid,
    errors,
    signatureValid,
    sourcesTraceable,
    weightsValid,
  }
}

// ── Training Attribution Ledger ──

export interface TrainingAttributionLedger {
  receipts: Map<string, TrainingAttributionReceipt>
  byModel: Map<string, Set<string>>          // modelId → trainingReceiptIds
  bySource: Map<string, Set<string>>         // accessReceiptId → trainingReceiptIds
  byTrainer: Map<string, Set<string>>        // trainerId → trainingReceiptIds
}

export function createTrainingLedger(): TrainingAttributionLedger {
  return {
    receipts: new Map(),
    byModel: new Map(),
    bySource: new Map(),
    byTrainer: new Map(),
  }
}

function addToSet(map: Map<string, Set<string>>, key: string, value: string): void {
  if (!map.has(key)) map.set(key, new Set())
  map.get(key)!.add(value)
}

export function recordTrainingAttribution(
  ledger: TrainingAttributionLedger,
  receipt: TrainingAttributionReceipt,
): void {
  ledger.receipts.set(receipt.trainingReceiptId, receipt)
  addToSet(ledger.byModel, receipt.modelId, receipt.trainingReceiptId)
  addToSet(ledger.byTrainer, receipt.trainerId, receipt.trainingReceiptId)
  for (const srcId of receipt.sourceAccessReceiptIds) {
    addToSet(ledger.bySource, srcId, receipt.trainingReceiptId)
  }
}

/** Which data sources contributed to a model's training? */
export function getModelDataSources(
  ledger: TrainingAttributionLedger,
  modelId: string,
): { accessReceiptId: string; weight: number; trainingUseType: TrainingUseType }[] {
  const trainingIds = ledger.byModel.get(modelId)
  if (!trainingIds) return []

  const sources: Map<string, { weight: number; useType: TrainingUseType }> = new Map()
  for (const tid of trainingIds) {
    const receipt = ledger.receipts.get(tid)!
    for (const srcId of receipt.sourceAccessReceiptIds) {
      const weight = receipt.contributionWeights?.[srcId] ?? (1 / receipt.sourceAccessReceiptIds.length)
      const existing = sources.get(srcId)
      if (existing) {
        existing.weight += weight
      } else {
        sources.set(srcId, { weight, useType: receipt.trainingUseType })
      }
    }
  }

  return Array.from(sources.entries()).map(([id, v]) => ({
    accessReceiptId: id, weight: v.weight, trainingUseType: v.useType,
  }))
}

/** How many times has a data source been used for training? */
export function getSourceTrainingCount(
  ledger: TrainingAttributionLedger,
  accessReceiptId: string,
): number {
  return ledger.bySource.get(accessReceiptId)?.size ?? 0
}
