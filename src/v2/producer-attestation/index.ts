// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Producer attestation commitment, builders and checks
// ══════════════════════════════════════════════════════════════════
// Single-purpose helpers around one idea: bind an externally produced
// attestation into evidence by hash, never by embedding and never by
// interpretation. The hash logic composes the existing evidence-commitment
// helpers; nothing here re-implements hashing or signing.
//
// NON-GOALS, restated where the code lives: no TEE-quote checking, no EAT
// parsing, no vendor SDKs, no attestation-internal awareness. A relying
// party fetches the bytes (locator or out-of-band), recomputes the hash,
// and evaluates the attestation with its own tooling.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'crypto'
import { createEvidenceCommitment, verifyEvidenceCommitment } from '../../core/bilateral-receipt.js'
import type { VerificationSource } from '../verification-source/types.js'
import type {
  ProducerAttestationCommitment,
  CpaProducerAttestationRef,
  ProducerAttestationValidation,
} from './types.js'

export type {
  ProducerAttestationCommitment,
  CpaProducerAttestationRef,
  ProducerAttestationValidation,
} from './types.js'

const HEX_64 = /^[0-9a-f]{64}$/

function sha256hex(bytes: string): string {
  return createHash('sha256').update(bytes, 'utf-8').digest('hex')
}

/**
 * Structural validation for the receipt-side commitment. Fail closed:
 * a commitment of this kind without a format label, or whose hash is not
 * 64 lowercase hex, is invalid rather than loosely accepted.
 */
export function validateProducerAttestationCommitment(
  c: ProducerAttestationCommitment,
): ProducerAttestationValidation {
  const reasons: string[] = []
  if (c.type !== 'producer_attestation') reasons.push("type must be 'producer_attestation'")
  if (typeof c.attestationFormat !== 'string' || c.attestationFormat.trim().length === 0) {
    reasons.push('attestationFormat must be a non-empty string')
  }
  if (typeof c.credentialHash !== 'string' || !HEX_64.test(c.credentialHash)) {
    reasons.push('credentialHash must be sha256 lowercase hex (64 chars) of the attestation bytes')
  }
  if (c.locatorUri !== undefined && (typeof c.locatorUri !== 'string' || c.locatorUri.length === 0)) {
    reasons.push('locatorUri, when present, must be a non-empty string')
  }
  if (c.bindingNote !== undefined && typeof c.bindingNote !== 'string') {
    reasons.push('bindingNote, when present, must be a string')
  }
  return { valid: reasons.length === 0, reasons }
}

/**
 * Create a producer-attestation commitment from the attestation bytes.
 * Composes the existing createEvidenceCommitment (same hash semantics as
 * every other commitment kind) and adds the attestation fields by
 * conditional spread, so omitted options introduce no keys.
 */
export function createProducerAttestationCommitment(opts: {
  /** The attestation bytes as transmitted (e.g. the EAT JWT string). */
  attestation: string
  /** Format identifier, open set: 'eat+jwt', 'tee-quote', a vendor label. */
  format: string
  locatorUri?: string
  bindingNote?: string
  issuerKid?: string
  jwks?: string
  /** How the committing party obtained any key it used when it looked at
   *  the attestation, if it recorded that (src/v2/verification-source). */
  verificationSource?: VerificationSource
}): ProducerAttestationCommitment {
  if (typeof opts.format !== 'string' || opts.format.trim().length === 0) {
    throw new Error('createProducerAttestationCommitment: format must be a non-empty string')
  }
  if (typeof opts.attestation !== 'string' || opts.attestation.length === 0) {
    throw new Error('createProducerAttestationCommitment: attestation bytes are required')
  }
  const base = createEvidenceCommitment({
    type: 'producer_attestation',
    credential: opts.attestation,
    issuerKid: opts.issuerKid,
    jwks: opts.jwks,
    ...(opts.verificationSource !== undefined ? { verificationSource: opts.verificationSource } : {}),
  })
  const commitment: ProducerAttestationCommitment = {
    ...base,
    type: 'producer_attestation',
    attestationFormat: opts.format,
    ...(opts.locatorUri !== undefined ? { locatorUri: opts.locatorUri } : {}),
    ...(opts.bindingNote !== undefined ? { bindingNote: opts.bindingNote } : {}),
  }
  const check = validateProducerAttestationCommitment(commitment)
  if (!check.valid) {
    throw new Error(`createProducerAttestationCommitment: ${check.reasons.join('; ')}`)
  }
  return commitment
}

/**
 * Check an attestation against its commitment: structural validity plus
 * hash binding (recompute sha256 over the supplied bytes, compare). The
 * hash compare delegates to the existing verifyEvidenceCommitment. A pass
 * binds bytes to commitment; it says nothing about what the attestation
 * asserts or whether it is trustworthy.
 */
export function verifyProducerAttestationCommitment(
  commitment: ProducerAttestationCommitment,
  attestation: string,
): ProducerAttestationValidation {
  const structural = validateProducerAttestationCommitment(commitment)
  if (!structural.valid) return structural
  if (!verifyEvidenceCommitment(commitment, attestation)) {
    return { valid: false, reasons: ['attestation bytes do not match credentialHash'] }
  }
  return { valid: true, reasons: [] }
}

/**
 * Structural validation for the CPA-side reference. Same rules as the
 * receipt-side commitment, in the CPA's snake_case field style.
 */
export function validateCpaProducerAttestationRef(
  ref: CpaProducerAttestationRef,
): ProducerAttestationValidation {
  const reasons: string[] = []
  if (typeof ref.format !== 'string' || ref.format.trim().length === 0) {
    reasons.push('format must be a non-empty string')
  }
  if (typeof ref.content_hash !== 'string' || !HEX_64.test(ref.content_hash)) {
    reasons.push('content_hash must be sha256 lowercase hex (64 chars) of the attestation bytes')
  }
  if (ref.locator_uri !== undefined && (typeof ref.locator_uri !== 'string' || ref.locator_uri.length === 0)) {
    reasons.push('locator_uri, when present, must be a non-empty string')
  }
  if (ref.binding_note !== undefined && typeof ref.binding_note !== 'string') {
    reasons.push('binding_note, when present, must be a string')
  }
  return { valid: reasons.length === 0, reasons }
}

/**
 * Build a CPA-side reference from the attestation bytes (or a precomputed
 * hash). Conditional spread keeps omitted options keyless, which is what
 * keeps a slot-free CPA byte-identical under strict JCS.
 */
export function buildCpaProducerAttestationRef(input: {
  /** The attestation bytes; the hash is computed here. Exactly one of
   *  attestation / content_hash must be supplied. */
  attestation?: string
  /** Precomputed sha256 lowercase hex of the attestation bytes. */
  content_hash?: string
  format: string
  locator_uri?: string
  binding_note?: string
}): CpaProducerAttestationRef {
  const hasBytes = typeof input.attestation === 'string' && input.attestation.length > 0
  const hasHash = typeof input.content_hash === 'string'
  if (hasBytes === hasHash) {
    throw new Error('buildCpaProducerAttestationRef: supply exactly one of attestation bytes or content_hash')
  }
  const ref: CpaProducerAttestationRef = {
    format: input.format,
    content_hash: hasBytes ? sha256hex(input.attestation as string) : (input.content_hash as string),
    ...(input.locator_uri !== undefined ? { locator_uri: input.locator_uri } : {}),
    ...(input.binding_note !== undefined ? { binding_note: input.binding_note } : {}),
  }
  const check = validateCpaProducerAttestationRef(ref)
  if (!check.valid) {
    throw new Error(`buildCpaProducerAttestationRef: ${check.reasons.join('; ')}`)
  }
  return ref
}
