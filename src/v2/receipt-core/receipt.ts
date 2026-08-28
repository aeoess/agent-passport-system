// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto'
import { sign, verify } from '../../crypto/keys.js'
import { assertExactKeys, strictJCS } from './jcs.js'
import type { EvidenceRefV1, ReceiptSignatureV1, ReceiptSignerV1, ReceiptV1 } from './types.js'

export const RECEIPT_ID_TAG = 'APS-RECEIPT-ID-V1' as const
export const RECEIPT_SIG_TAG = 'APS-RECEIPT-SIG-V1' as const
const HEX64 = /^[0-9a-f]{64}$/
const HEX128 = /^[0-9a-f]{128}$/
const UTC_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
const sha256Hex = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex')
const compareUtf8 = (a: string, b: string): number => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'))

function compareEvidence(a: EvidenceRefV1, b: EvidenceRefV1): number {
  return compareUtf8(a.artifact_type, b.artifact_type) || compareUtf8(a.sha256, b.sha256)
}

function compareSignatures(a: Pick<ReceiptSignatureV1, 'signer' | 'key_id'>, b: Pick<ReceiptSignatureV1, 'signer' | 'key_id'>): number {
  return compareUtf8(a.signer, b.signer) || compareUtf8(a.key_id, b.key_id)
}

export function isExactUtcMilliseconds(value: string): boolean {
  if (!UTC_MS.test(value)) return false
  const parsed = new Date(value)
  return !Number.isNaN(parsed.valueOf()) && parsed.toISOString() === value
}

function receiptWithout<T extends 'receipt_id' | 'signatures'>(receipt: ReceiptV1, ...keys: T[]): Omit<ReceiptV1, T> {
  const copy = { ...receipt } as Record<string, unknown>
  keys.forEach(k => delete copy[k])
  return copy as Omit<ReceiptV1, T>
}

export function receiptIdPayloadV1(receipt: ReceiptV1): string {
  return `${RECEIPT_ID_TAG}\0${strictJCS(receiptWithout(receipt, 'receipt_id', 'signatures'))}`
}

export function computeReceiptIdV1(receipt: ReceiptV1): string {
  return sha256Hex(receiptIdPayloadV1(receipt))
}

export function receiptSignaturePayloadV1(receipt: ReceiptV1, descriptor: Omit<ReceiptSignatureV1, 'value'>): string {
  const form = { receipt: receiptWithout(receipt, 'signatures'), signer: descriptor }
  return `${RECEIPT_SIG_TAG}\0${strictJCS(form)}`
}

/**
 * This entrypoint validates the standalone ReceiptV1 structure and the fields available
 * within the receipt. It does not establish cross-document constraints involving the
 * referenced decision, including the requirement that decision valid_until be later than
 * receipt issued_at. Use verifyReceiptWithDecisionV1 when both artifacts are available.
 */
export function validateReceiptV1(receipt: ReceiptV1, requireValues = true): void {
  assertExactKeys(receipt as unknown as Record<string, unknown>,
    ['profile', 'receipt_id', 'receipt_type', 'issuer', 'subject_agent', 'action_ref', 'delegation_ref', 'decision_ref', 'issued_at', 'evidence_refs', 'result', 'prev', 'signatures'],
    ['profile', 'receipt_id', 'receipt_type', 'issuer', 'subject_agent', 'action_ref', 'delegation_ref', 'issued_at', 'evidence_refs', 'result', 'signatures'], 'ReceiptV1')
  strictJCS(receipt)
  if (receipt.profile !== 'aps-receipt-v1') throw new TypeError('ReceiptV1: profile')
  if (!receipt.receipt_type || !receipt.issuer || !receipt.subject_agent || !receipt.delegation_ref) throw new TypeError('ReceiptV1: empty identifier')
  if (requireValues && !HEX64.test(receipt.receipt_id)) throw new TypeError('ReceiptV1: receipt_id')
  if (!HEX64.test(receipt.action_ref)) throw new TypeError('ReceiptV1: action_ref')
  if (receipt.decision_ref !== undefined && !HEX64.test(receipt.decision_ref)) throw new TypeError('ReceiptV1: decision_ref')
  if (receipt.prev !== undefined && !HEX64.test(receipt.prev)) throw new TypeError('ReceiptV1: prev')
  if (!isExactUtcMilliseconds(receipt.issued_at)) throw new TypeError('ReceiptV1: issued_at')
  if (typeof receipt.result !== 'object' || receipt.result === null || Array.isArray(receipt.result)) throw new TypeError('ReceiptV1: result')
  if (!Array.isArray(receipt.evidence_refs) || !Array.isArray(receipt.signatures)) throw new TypeError('ReceiptV1: arrays')
  const seenEvidence = new Set<string>()
  receipt.evidence_refs.forEach((ref, i) => {
    assertExactKeys(ref as unknown as Record<string, unknown>, ['artifact_type', 'sha256'], ['artifact_type', 'sha256'], 'EvidenceRefV1')
    if (!ref.artifact_type || !HEX64.test(ref.sha256)) throw new TypeError('EvidenceRefV1: value')
    const key = `${ref.artifact_type}\0${ref.sha256}`
    if (seenEvidence.has(key)) throw new TypeError('ReceiptV1: duplicate evidence_ref')
    seenEvidence.add(key)
    if (i > 0 && compareEvidence(receipt.evidence_refs[i - 1], ref) >= 0) throw new TypeError('ReceiptV1: evidence_refs not sorted')
  })
  const seenSigs = new Set<string>()
  receipt.signatures.forEach((proof, i) => {
    assertExactKeys(proof as unknown as Record<string, unknown>, ['signer', 'key_id', 'alg', 'value'], ['signer', 'key_id', 'alg', 'value'], 'ReceiptSignatureV1')
    if (!proof.signer || !proof.key_id || proof.alg !== 'Ed25519' || (requireValues && !HEX128.test(proof.value))) throw new TypeError('ReceiptSignatureV1: value')
    const key = `${proof.signer}\0${proof.key_id}`
    if (seenSigs.has(key)) throw new TypeError('ReceiptV1: duplicate signature')
    seenSigs.add(key)
    if (i > 0 && compareSignatures(receipt.signatures[i - 1], proof) >= 0) throw new TypeError('ReceiptV1: signatures not sorted')
  })
  if (requireValues && !receipt.signatures.some(s => s.signer === receipt.issuer)) throw new TypeError('ReceiptV1: issuer signature missing')
}

export function createReceiptV1(
  fields: Omit<ReceiptV1, 'receipt_id' | 'signatures'>,
  signers: ReceiptSignerV1[],
): ReceiptV1 {
  if (signers.length === 0) throw new TypeError('ReceiptV1: at least one signer')
  const copiedFields = structuredClone(fields)
  const evidence_refs = [...copiedFields.evidence_refs].sort(compareEvidence)
  const descriptors = signers.map(s => ({ signer: s.signer, key_id: s.key_id, alg: 'Ed25519' as const, private_key: s.private_key }))
    .sort(compareSignatures)
  const draft = { ...copiedFields, evidence_refs, receipt_id: '0'.repeat(64), signatures: [] } as ReceiptV1
  validateReceiptV1(draft, false)
  draft.receipt_id = computeReceiptIdV1(draft)
  draft.signatures = descriptors.map(({ private_key, ...descriptor }) => ({
    ...descriptor,
    value: sign(receiptSignaturePayloadV1(draft, descriptor), private_key),
  }))
  validateReceiptV1(draft)
  return draft
}

export interface ReceiptVerificationV1 {
  valid: boolean
  receipt_id_valid: boolean
  signature_results: { signer: string; key_id: string; valid: boolean; reason?: string }[]
  errors: string[]
}

/**
 * This entrypoint validates the standalone ReceiptV1 structure and the fields available
 * within the receipt. It does not establish cross-document constraints involving the
 * referenced decision, including the requirement that decision valid_until be later than
 * receipt issued_at. Use verifyReceiptWithDecisionV1 when both artifacts are available.
 */
export function verifyReceiptV1(receipt: ReceiptV1, resolveKey: (signer: string, keyId: string, issuedAt: string) => string | undefined): ReceiptVerificationV1 {
  const errors: string[] = []
  try { validateReceiptV1(receipt) } catch (err) {
    return { valid: false, receipt_id_valid: false, signature_results: [], errors: [err instanceof Error ? err.message : String(err)] }
  }
  const receipt_id_valid = computeReceiptIdV1(receipt) === receipt.receipt_id
  if (!receipt_id_valid) errors.push('receipt_id_mismatch')
  const signature_results = receipt.signatures.map(proof => {
    try {
      const key = resolveKey(proof.signer, proof.key_id, receipt.issued_at)
      if (!key) return { signer: proof.signer, key_id: proof.key_id, valid: false, reason: 'key_unresolved' }
      const { value, ...descriptor } = proof
      return { signer: proof.signer, key_id: proof.key_id, valid: verify(receiptSignaturePayloadV1(receipt, descriptor), value, key) }
    } catch {
      return { signer: proof.signer, key_id: proof.key_id, valid: false, reason: 'key_resolution_error' }
    }
  })
  if (signature_results.some(r => !r.valid)) errors.push('signature_invalid')
  return { valid: errors.length === 0, receipt_id_valid, signature_results, errors }
}
