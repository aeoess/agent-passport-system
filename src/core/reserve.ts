// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Reserve Attestation — Pure Functions
// ══════════════════════════════════════════════════════════════════

import { v4 as uuidv4 } from 'uuid'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type {
  ReserveAttestation, ReserveAssuranceClass,
  ReserveAttestationLiability,
} from '../types/reserve.js'

// ══════════════════════════════════════
// CREATE RESERVE ATTESTATION
// ══════════════════════════════════════

export interface CreateReserveAttestationOptions {
  delegationId: string
  assuranceClass: ReserveAssuranceClass
  amount: number
  currency: string
  liability: ReserveAttestationLiability
  attesterPrivateKey: string
  attesterPublicKey: string
  charterAnchor?: string
  officeId?: string
  ttlSeconds?: number             // defaults to 24 hours
}

/** Create a signed reserve attestation. */
export function createReserveAttestation(opts: CreateReserveAttestationOptions): ReserveAttestation {
  const now = new Date().toISOString()
  const ttl = opts.ttlSeconds ?? 86400
  const expiresAt = new Date(Date.now() + ttl * 1000).toISOString()

  const attestation: Omit<ReserveAttestation, 'signature'> = {
    attestationId: 'res_' + uuidv4().slice(0, 12),
    delegationId: opts.delegationId,
    assuranceClass: opts.assuranceClass,
    attestedAmount: { value: opts.amount, currency: opts.currency },
    attestedBy: opts.attesterPublicKey,
    charterAnchor: opts.charterAnchor,
    officeId: opts.officeId,
    liability: opts.liability,
    attestedAt: now,
    expiresAt,
  }

  const canonical = canonicalize(attestation)
  const signature = sign(canonical, opts.attesterPrivateKey)
  return { ...attestation, signature }
}

// ══════════════════════════════════════
// VERIFY RESERVE ATTESTATION
// ══════════════════════════════════════

export interface ReserveAttestationVerification {
  valid: boolean
  signatureValid: boolean
  notExpired: boolean
  errors: string[]
}

/** Verify a reserve attestation's signature and expiry. */
export function verifyReserveAttestation(att: ReserveAttestation): ReserveAttestationVerification {
  const errors: string[] = []

  // Signature check
  const { signature, ...body } = att
  const canonical = canonicalize(body)
  let signatureValid = false
  try {
    signatureValid = verify(canonical, signature, att.attestedBy)
  } catch { signatureValid = false }
  if (!signatureValid) errors.push('Invalid attestation signature')

  // Expiry check
  const notExpired = new Date(att.expiresAt) > new Date()
  if (!notExpired) errors.push('Attestation expired')

  return {
    valid: errors.length === 0,
    signatureValid,
    notExpired,
    errors,
  }
}

// ══════════════════════════════════════
// ASSURANCE CLASS COMPARISON
// ══════════════════════════════════════

const ASSURANCE_ORDER: ReserveAssuranceClass[] = [
  'unbacked', 'self_attested', 'gateway_attested', 'escrow_backed', 'externally_attested'
]

/** Compare two assurance classes by strength. Returns negative if a < b, 0 if equal, positive if a > b. */
export function compareAssuranceClass(a: ReserveAssuranceClass, b: ReserveAssuranceClass): number {
  return ASSURANCE_ORDER.indexOf(a) - ASSURANCE_ORDER.indexOf(b)
}

/** Check if an assurance class meets a minimum requirement. */
export function meetsAssuranceRequirement(
  actual: ReserveAssuranceClass,
  minimum: ReserveAssuranceClass,
): boolean {
  return compareAssuranceClass(actual, minimum) >= 0
}
