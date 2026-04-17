// Receipt Ledger — Merkle-Committed Audit Primitives (Module 23)
// ══════════════════════════════════════════════════════════════════════
// SDK retains: types, ledger factory + addReceipt mutation, Merkle
// inclusion proof primitives, signed batch verification primitives.
// MOVED to @aeoess/gateway src/sdk-migrated/core/receipt-ledger-impl.ts:
//   commitBatch — the workflow that signs a batch from the pending queue,
//   chains epochs, and mutates ledger state.
// Reuses Merkle infrastructure from attribution.ts (Layer 3).

import { verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import {
  buildMerkleRoot, generateMerkleProof, verifyMerkleProof,
} from './attribution.js'
import type { MerkleProof, MerkleProofNode } from '../types/passport.js'

// ══════════════════════════════════════
// TYPES
// ══════════════════════════════════════

export interface ReceiptBatch {
  batchId: string
  merkleRoot: string
  receiptCount: number
  receiptHashes: string[]
  epoch: number
  previousBatchId: string | null
  previousMerkleRoot: string | null
  committedAt: string
  committedBy: string
  signature: string
}

export interface ReceiptInclusionProof {
  batchId: string
  merkleRoot: string
  receiptHash: string
  proof: MerkleProofNode[]
  leafIndex: number
  verified: boolean
}

export interface ReceiptLedger {
  batches: ReceiptBatch[]
  pendingReceipts: string[]
}

export interface BatchVerification {
  valid: boolean
  errors: string[]
  signatureValid: boolean
  rootValid: boolean
  chainValid: boolean
}

export interface BatchChainVerification {
  valid: boolean
  errors: string[]
  batchCount: number
  totalReceipts: number
}

// ══════════════════════════════════════
// LEDGER PRIMITIVES (factory + queue mutation)
// ══════════════════════════════════════

export function createReceiptLedger(): ReceiptLedger {
  return { batches: [], pendingReceipts: [] }
}

export function addReceipt(ledger: ReceiptLedger, receiptHash: string): void {
  ledger.pendingReceipts.push(receiptHash)
}

// ══════════════════════════════════════
// commitBatch — moved to gateway
// ══════════════════════════════════════

export function commitBatch(_opts: {
  ledger: ReceiptLedger
  committerPrivateKey: string
  committerPublicKey: string
}): ReceiptBatch {
  throw new Error(
    'commitBatch moved to @aeoess/gateway src/sdk-migrated/core/receipt-ledger-impl.ts. ' +
    'Use ReceiptLedgerImpl from the gateway, or call signBatch/buildMerkleRoot primitives directly.'
  )
}

// ══════════════════════════════════════
// PROVE & VERIFY INCLUSION (pure primitives)
// ══════════════════════════════════════

export function proveInclusion(batch: ReceiptBatch, receiptHash: string): ReceiptInclusionProof {
  const merkleProof = generateMerkleProof(batch.receiptHashes, receiptHash)
  if (!merkleProof) {
    return { batchId: batch.batchId, merkleRoot: batch.merkleRoot, receiptHash, proof: [], leafIndex: -1, verified: false }
  }
  const verified = verifyMerkleProof(merkleProof)
  return { batchId: batch.batchId, merkleRoot: batch.merkleRoot, receiptHash, proof: merkleProof.proof, leafIndex: merkleProof.index, verified }
}

export function verifyInclusion(proof: ReceiptInclusionProof): boolean {
  if (proof.leafIndex === -1 || proof.proof.length === 0) return false
  const merkleProof: MerkleProof = { receiptHash: proof.receiptHash, root: proof.merkleRoot, proof: proof.proof, index: proof.leafIndex }
  return verifyMerkleProof(merkleProof)
}

// ══════════════════════════════════════
// VERIFY BATCH (pure)
// ══════════════════════════════════════

export function verifyBatch(batch: ReceiptBatch, previousBatch?: ReceiptBatch | null): BatchVerification {
  const errors: string[] = []
  const expectedRoot = buildMerkleRoot(batch.receiptHashes)
  const rootValid = expectedRoot === batch.merkleRoot
  if (!rootValid) errors.push('Merkle root does not match receipt hashes')
  if (batch.receiptCount !== batch.receiptHashes.length) errors.push('Receipt count mismatch')

  const signable = {
    batchId: batch.batchId, merkleRoot: batch.merkleRoot,
    receiptCount: batch.receiptCount, epoch: batch.epoch,
    previousBatchId: batch.previousBatchId, previousMerkleRoot: batch.previousMerkleRoot,
    committedAt: batch.committedAt, committedBy: batch.committedBy,
  }
  const canonical = canonicalize(signable)
  let signatureValid = false
  try { signatureValid = verify(canonical, batch.signature, batch.committedBy) } catch { signatureValid = false }
  if (!signatureValid) errors.push('Invalid batch signature')

  let chainValid = true
  if (previousBatch) {
    if (batch.previousBatchId !== previousBatch.batchId) { chainValid = false; errors.push('Previous batch ID mismatch') }
    if (batch.previousMerkleRoot !== previousBatch.merkleRoot) { chainValid = false; errors.push('Previous Merkle root mismatch') }
    if (batch.epoch !== previousBatch.epoch + 1) { chainValid = false; errors.push(`Epoch not sequential: expected ${previousBatch.epoch + 1}, got ${batch.epoch}`) }
  } else if (previousBatch === null) {
    if (batch.previousBatchId !== null) { chainValid = false; errors.push('First batch should have null previousBatchId') }
    if (batch.epoch !== 0) { chainValid = false; errors.push('First batch should have epoch 0') }
  }

  return { valid: errors.length === 0, errors, signatureValid, rootValid, chainValid }
}

// ══════════════════════════════════════
// VERIFY BATCH CHAIN (pure)
// ══════════════════════════════════════

export function verifyBatchChain(batches: ReceiptBatch[]): BatchChainVerification {
  const errors: string[] = []
  let totalReceipts = 0
  if (batches.length === 0) return { valid: true, errors: [], batchCount: 0, totalReceipts: 0 }
  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i]
    const previousBatch = i > 0 ? batches[i - 1] : null
    const result = verifyBatch(batch, previousBatch)
    if (!result.valid) {
      for (const err of result.errors) errors.push(`Batch ${i} (epoch ${batch.epoch}): ${err}`)
    }
    totalReceipts += batch.receiptCount
  }
  return { valid: errors.length === 0, errors, batchCount: batches.length, totalReceipts }
}
