// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Bilateral Completion Receipt — closes the permit-execute-complete loop.
// The permit receipt proves authorization. The completion receipt proves execution outcome.
// linkPermitAndCompletion() cryptographically binds the two.

import { v4 as uuidv4 } from 'uuid'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import { createHash } from 'node:crypto'

export interface CompletionReceiptOptions {
  permitReceiptHash: string
  executionResult: 'success' | 'failure' | 'partial' | 'timeout'
  resultSummary?: string
  resultHash?: string
  executedAt: string
  durationMs?: number
  privateKey: string
}

export interface CompletionReceipt {
  completionId: string
  permitReceiptHash: string
  executionResult: string
  resultSummary: string
  resultHash: string
  executedAt: string
  durationMs: number
  signature: string
  signedAt: string
}

const VALID_RESULTS = ['success', 'failure', 'partial', 'timeout']

export function createCompletionReceipt(opts: CompletionReceiptOptions): CompletionReceipt {
  if (!opts || typeof opts !== 'object') throw new Error('createCompletionReceipt: opts must be an object')
  if (!opts.permitReceiptHash || typeof opts.permitReceiptHash !== 'string') throw new Error('createCompletionReceipt: permitReceiptHash required')
  if (!VALID_RESULTS.includes(opts.executionResult)) throw new Error(`createCompletionReceipt: executionResult must be one of ${VALID_RESULTS.join(', ')}`)
  if (!opts.executedAt || typeof opts.executedAt !== 'string') throw new Error('createCompletionReceipt: executedAt required')
  if (!opts.privateKey || typeof opts.privateKey !== 'string') throw new Error('createCompletionReceipt: privateKey required')

  const body: Omit<CompletionReceipt, 'signature'> = {
    completionId: 'cmp_' + uuidv4().slice(0, 12),
    permitReceiptHash: opts.permitReceiptHash,
    executionResult: opts.executionResult,
    resultSummary: opts.resultSummary || '',
    resultHash: opts.resultHash || '',
    executedAt: opts.executedAt,
    durationMs: opts.durationMs ?? 0,
    signedAt: new Date().toISOString(),
  }

  const canonical = canonicalize(body)
  const signature = sign(canonical, opts.privateKey)

  return { ...body, signature }
}

export function verifyCompletionReceipt(
  receipt: CompletionReceipt,
  publicKey: string,
): { valid: boolean; errors: string[] } {
  const errors: string[] = []

  const { signature, ...unsigned } = receipt
  const canonical = canonicalize(unsigned)
  const sigValid = verify(canonical, signature, publicKey)
  if (!sigValid) errors.push('Invalid completion receipt signature')

  if (!receipt.completionId) errors.push('Missing completionId')
  if (!receipt.permitReceiptHash) errors.push('Missing permitReceiptHash')
  if (!VALID_RESULTS.includes(receipt.executionResult)) errors.push(`Invalid executionResult: ${receipt.executionResult}`)

  return { valid: errors.length === 0, errors }
}

export function linkPermitAndCompletion(
  permitReceipt: Record<string, unknown>,
  completionReceipt: CompletionReceipt,
): { linked: boolean; permitHash: string; completionClaimsHash: string; errors: string[] } {
  const errors: string[] = []

  // Hash the canonicalized permit receipt (strip its signature first)
  const { signature: _sig, ...permitUnsigned } = permitReceipt
  const permitCanonical = canonicalize(permitUnsigned)
  const permitHash = createHash('sha256').update(permitCanonical).digest('hex')

  const completionClaimsHash = completionReceipt.permitReceiptHash

  if (permitHash !== completionClaimsHash) {
    errors.push(`Hash mismatch: permit receipt hashes to ${permitHash}, completion claims ${completionClaimsHash}`)
  }

  return {
    linked: errors.length === 0,
    permitHash,
    completionClaimsHash,
    errors,
  }
}
