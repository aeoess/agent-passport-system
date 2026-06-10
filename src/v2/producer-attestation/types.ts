// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Producer attestation commitment, an external attestation bound by hash
// ══════════════════════════════════════════════════════════════════
// APS consumes attestations, it never produces them. An external producer
// attestation (an EAT per RFC 9711, a TEE quote, a vendor report) can be
// bound into receipt evidence and into a CPA by reference: format label,
// sha256 of the attestation bytes, optional locator, optional note of what
// the attestation covers.
//
// EXPLICIT NON-GOALS. APS does not check TEE quotes or EAT tokens. There
// are no vendor SDKs here and no parsing of attestation internals. The
// commitment binds bytes by hash so a relying party can fetch the
// attestation and evaluate it with its own tooling. The receipt claim is
// custody of the reference, not validity of the attestation.
// ══════════════════════════════════════════════════════════════════

import type { EvidenceCommitment } from '../../types/bilateral-receipt.js'

/**
 * An EvidenceCommitment narrowed to the producer-attestation kind. Rides
 * on BilateralReceipt.evidenceCommitments inside the signed body, like any
 * other commitment. credentialHash carries the sha256 (lowercase hex) of
 * the attestation bytes; the attestation itself is never embedded.
 */
export interface ProducerAttestationCommitment extends EvidenceCommitment {
  type: 'producer_attestation'
  /** Format identifier, an open set: e.g. 'eat+jwt', 'tee-quote', a vendor
   *  report label. Opaque to APS; meaningful to the relying party's tooling. */
  attestationFormat: string
  /** Where a relying party can fetch the attestation bytes. Optional; the
   *  hash binding stands on its own. */
  locatorUri?: string
  /** Free-text note of what the attestation covers, e.g. producer identity,
   *  code measurement, environment. A note, not a taxonomy. */
  bindingNote?: string
}

/**
 * The CPA-side reference to the same external attestation, in the CPA's
 * snake_case field style. Carried on the optional producer_attestation
 * slot of a ContextProvenanceAttestation and signed with it.
 */
export interface CpaProducerAttestationRef {
  /** Format identifier, an open set: e.g. 'eat+jwt', 'tee-quote'. */
  format: string
  /** sha256, lowercase hex, of the attestation bytes. */
  content_hash: string
  /** Where a relying party can fetch the attestation bytes. */
  locator_uri?: string
  /** Free-text note of what the attestation covers. */
  binding_note?: string
}

/** Validation outcome. Fail closed: violations make the value invalid. */
export interface ProducerAttestationValidation {
  valid: boolean
  /** Human-readable rule violations, empty iff valid. */
  reasons: string[]
}
