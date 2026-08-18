// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Bilateral Receipt + Evidence Commitments + Compromise Window
// ══════════════════════════════════════════════════════════════════
// Three ecosystem-sourced improvements shipped as one module:
//
// 1. Bilateral receipts: both agents sign the same interaction.
//    Source: viftode4, IETF draft-pouwelse-trustchain-01
//
// 2. Evidence commitments: bind external attestations into receipts
//    by hash. Source: douglasborthwick-crypto (InsumerAPI)
//
// 3. Compromise window: distinguish breach time from detection time.
//    Source: desiorac on qntm#6
// ══════════════════════════════════════════════════════════════════

import { createHash, randomUUID } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import { isRecord } from './is-record.js'
import type {
  BilateralReceipt,
  BilateralReceiptVerification,
  InteractionOutcome,
  EvidenceCommitment,
  CompromiseWindowCheck,
  RevocationReason,
} from '../types/bilateral-receipt.js'

/**
 * Signing-preimage profile for this module.
 *
 * Profile: core BilateralReceipt v1.0, preimage = canonicalize(body) (legacy:
 * sorted keys, null and undefined members removed). Not RFC 8785. A JCS profile
 * would be a new versioned type.
 *
 * The distinction matters because the repository also ships an RFC 8785
 * canonicalizer, canonicalizeJCS(), and a fixture corpus under
 * fixtures/bilateral-delegation/ that exercises it. That corpus tests the
 * canonicalizer and the in-toto/DecisionReceipt envelope shapes, not this type,
 * so passing it establishes nothing about these signatures. The two serializers
 * differ in the way that matters here: legacy removes null and undefined
 * members, JCS preserves null and rejects undefined. They also differ on NaN,
 * Infinity, lone surrogates and circular references, which this type does not
 * carry.
 */

function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex')
}

// ══════════════════════════════════════════════════════════════════
// 1. Bilateral Receipt — both agents sign the same interaction
// ══════════════════════════════════════════════════════════════════

/**
 * Create a bilateral receipt. Called in two phases:
 *   Phase 1: Requesting agent proposes the outcome and signs
 *   Phase 2: Serving agent reviews, agrees, and countersigns
 *   Phase 3 (optional): Gateway witnesses and adds third signature
 */
export function createBilateralReceipt(opts: {
  requestingAgentId: string
  servingAgentId: string
  delegationId?: string
  outcome: InteractionOutcome
  requestedAt: string
  completedAt: string
  requestingAgentPrivateKey: string
  servingAgentPrivateKey: string
  gatewayPrivateKey?: string
  evidenceCommitments?: EvidenceCommitment[]
  /**
   * Optional audience binding. When set, both co-signers sign over it and the
   * receipt is bound to the named recipient(s). When omitted, the canonical
   * body (and therefore both signatures) is byte-identical to a receipt without
   * audience binding, since canonicalize() omits undefined keys.
   */
  aud?: import('../types/bilateral-receipt.js').BilateralReceipt['aud']
  /**
   * Optional native action_ref correlating the receipt to its request. When
   * set, both co-signers sign over it. When omitted, the canonical body (and
   * therefore both signatures) is byte-identical to a receipt without the
   * slot, since canonicalize() omits undefined keys.
   */
  action_ref?: string
  // Additive optional slot. When omitted the body and signatures are unchanged
  // (canonicalize() strips undefined keys), so receipts that do not carry a
  // field-disclosure profile keep their exact prior bytes.
  fieldDisclosureProfile?: unknown
}): BilateralReceipt {
  const now = new Date().toISOString()

  // Build the receipt body (everything both agents agree on)
  // Optional members use a conditional spread so an omitted option leaves the
  // key genuinely absent rather than present holding undefined. The signed
  // bytes are unchanged either way, because the legacy canonicalize() below
  // already removed undefined members; this keeps the returned object free of
  // undefined-valued keys, which is what #101 asks builders to do.
  const body = {
    receiptId: randomUUID(),
    version: '1.0' as const,
    requestingAgentId: opts.requestingAgentId,
    servingAgentId: opts.servingAgentId,
    ...(opts.delegationId !== undefined && { delegationId: opts.delegationId }),
    outcome: opts.outcome,
    requestedAt: opts.requestedAt,
    completedAt: opts.completedAt,
    agreedAt: now,
    ...(opts.evidenceCommitments !== undefined && {
      evidenceCommitments: opts.evidenceCommitments,
    }),
    ...(opts.aud !== undefined && { aud: opts.aud }),
    ...(opts.action_ref !== undefined && { action_ref: opts.action_ref }),
    ...(opts.fieldDisclosureProfile !== undefined && {
      fieldDisclosureProfile: opts.fieldDisclosureProfile,
    }),
  }

  // Both agents sign the SAME canonical body
  const canonical = canonicalize(body)
  const requestingAgentSignature = sign(canonical, opts.requestingAgentPrivateKey)
  const servingAgentSignature = sign(canonical, opts.servingAgentPrivateKey)

  // Optional gateway witness
  const gatewaySignature = opts.gatewayPrivateKey
    ? sign(canonical, opts.gatewayPrivateKey)
    : undefined

  return {
    ...body,
    requestingAgentSignature,
    servingAgentSignature,
    ...(gatewaySignature !== undefined && { gatewaySignature }),
  }
}

// ══════════════════════════════════════════════════════════════════
// verifyBilateralReceipt — check all signatures over same outcome
// ══════════════════════════════════════════════════════════════════
export function verifyBilateralReceipt(
  receipt: BilateralReceipt,
  requestingAgentPublicKey: string,
  servingAgentPublicKey: string,
  gatewayPublicKey?: string
): BilateralReceiptVerification {
  const errors: string[] = []

  // Null / undefined / non-object (attacker-deliverable JSON `null`) rejects
  // rather than throwing on the destructuring below.
  if (!isRecord(receipt)) {
    return {
      valid: false,
      requestingAgentSignatureValid: false,
      servingAgentSignatureValid: false,
      gatewaySignatureValid: null,
      outcomeConsistent: false,
      timingValid: false,
      errors: ['Invalid receipt: not an object'],
    }
  }

  // Reconstruct the body both agents signed
  const { requestingAgentSignature, servingAgentSignature, gatewaySignature, ...body } = receipt
  const canonical = canonicalize(body)

  // Verify requesting agent signature
  const reqValid = verify(canonical, requestingAgentSignature, requestingAgentPublicKey)
  if (!reqValid) errors.push('Requesting agent signature invalid')

  // Verify serving agent signature
  const srvValid = verify(canonical, servingAgentSignature, servingAgentPublicKey)
  if (!srvValid) errors.push('Serving agent signature invalid')

  // Verify gateway signature (if present)
  let gwValid: boolean | null = null
  if (gatewaySignature && gatewayPublicKey) {
    gwValid = verify(canonical, gatewaySignature, gatewayPublicKey)
    if (!gwValid) errors.push('Gateway witness signature invalid')
  } else if (gatewaySignature && !gatewayPublicKey) {
    gwValid = false
    errors.push('Gateway signature present but no public key provided')
  }

  // Timing sanity
  const req = new Date(receipt.requestedAt).getTime()
  const comp = new Date(receipt.completedAt).getTime()
  const agreed = new Date(receipt.agreedAt).getTime()
  const timingValid = comp >= req && agreed >= req
  if (!timingValid) errors.push('Timing invalid')

  return {
    valid: errors.length === 0,
    requestingAgentSignatureValid: reqValid,
    servingAgentSignatureValid: srvValid,
    gatewaySignatureValid: gwValid,
    outcomeConsistent: reqValid && srvValid, // both signed same canonical body
    timingValid,
    errors,
  }
}

// ══════════════════════════════════════════════════════════════════
// 2. Evidence Commitment — bind external attestations by hash
// ══════════════════════════════════════════════════════════════════

/**
 * Create an evidence commitment from an external credential.
 * The credential (JWT, JWS, signed JSON) is hashed — not embedded.
 * Verifiers fetch the credential out-of-band and check hash match.
 */
export function createEvidenceCommitment(opts: {
  type: string
  credential: string           // the full signed credential (JWT string, etc.)
  issuerKid?: string
  jwks?: string
  pass?: boolean
  // Optional record of how the committing party obtained the key used for
  // its credential check (src/v2/verification-source). Added by conditional
  // spread so an omitting commitment carries no key at all and stays
  // byte-identical to the pre-change shape under canonicalization.
  verificationSource?: import('../v2/verification-source/types.js').VerificationSource
}): EvidenceCommitment {
  return {
    type: opts.type,
    credentialHash: sha256(opts.credential),
    issuerKid: opts.issuerKid,
    jwks: opts.jwks,
    pass: opts.pass,
    committedAt: new Date().toISOString(),
    ...(opts.verificationSource !== undefined ? { verificationSource: opts.verificationSource } : {}),
  }
}

/**
 * Verify that a credential matches its commitment.
 */
export function verifyEvidenceCommitment(
  commitment: EvidenceCommitment,
  credential: string
): boolean {
  return sha256(credential) === commitment.credentialHash
}

// ══════════════════════════════════════════════════════════════════
// 3. Compromise Window — breach time vs detection time
// ══════════════════════════════════════════════════════════════════

/**
 * Check whether a proof timestamp falls within a compromise window.
 *
 * Three states:
 *   'safe'  — proof predates compromise, likely unaffected
 *   'warn'  — compromise window unknown, proof might be affected
 *   'error' — proof is definitely within the compromise window
 *
 * When revocationReason !== 'compromise', all pre-revocation
 * proofs are safe (key rotation, decommission, etc.).
 */
export function checkCompromiseWindow(opts: {
  proofTimestamp: string
  revokedAt: string
  revocationReason: RevocationReason
  compromisedSince?: string
}): CompromiseWindowCheck {
  const proof = new Date(opts.proofTimestamp).getTime()
  const revoked = new Date(opts.revokedAt).getTime()

  // Non-compromise revocations: pre-revocation proofs are safe
  if (opts.revocationReason !== 'compromise') {
    if (proof < revoked) {
      return {
        status: 'safe',
        reason: `Proof predates ${opts.revocationReason} revocation`,
        proofTimestamp: opts.proofTimestamp,
        revokedAt: opts.revokedAt,
      }
    }
    return {
      status: 'error',
      reason: `Proof created after ${opts.revocationReason} revocation`,
      proofTimestamp: opts.proofTimestamp,
      revokedAt: opts.revokedAt,
    }
  }

  // Compromise revocation: check the window
  if (opts.compromisedSince) {
    const breachStart = new Date(opts.compromisedSince).getTime()
    if (proof < breachStart) {
      return {
        status: 'safe',
        reason: 'Proof predates known compromise start',
        proofTimestamp: opts.proofTimestamp,
        revokedAt: opts.revokedAt,
        compromisedSince: opts.compromisedSince,
      }
    }
    return {
      status: 'error',
      reason: 'Proof created within known compromise window',
      proofTimestamp: opts.proofTimestamp,
      revokedAt: opts.revokedAt,
      compromisedSince: opts.compromisedSince,
    }
  }

  // Compromise but no compromisedSince: unknown window
  // All proofs from this key are suspect
  return {
    status: 'warn',
    reason: 'Key compromised, breach window unknown — all proofs suspect',
    proofTimestamp: opts.proofTimestamp,
    revokedAt: opts.revokedAt,
  }
}
